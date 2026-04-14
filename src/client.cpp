/**
 * wtunnel client — local HTTP CONNECT proxy over TLS/H2 tunnel
 *
 * Flow:
 *   Browser ──HTTP CONNECT──> LocalProxy :8080
 *                              └──TLS(Chrome fingerprint)+H2 CONNECT──> TunnelServer :8443
 *                                                                            └──TCP──> Target
 *
 * Multiplexing: one persistent TLS+H2 connection to the server, one H2 stream per CONNECT.
 */

#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include "common/logging.h"
#include <nghttp2/nghttp2.h>

#ifdef _WIN32
#  include "common/posix_compat.h"
   // getopt is not available on MSVC; use a minimal inline implementation
   static int   optind_w = 1;
   static char* optarg_w = nullptr;
#  define optind optind_w
#  define optarg optarg_w
   static int getopt(int argc, char* argv[], const char* opts) {
       if (optind >= argc || argv[optind][0] != '-') return -1;
       char c = argv[optind][1];
       const char* p = strchr(opts, c);
       if (!p) return '?';
       optind++;
       if (*(p + 1) == ':') { optarg = argv[optind++]; }
       return c;
   }
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <fcntl.h>
#  include <unistd.h>
#  include <signal.h>
#  include <getopt.h>
#endif
#include <cstring>
#include <string>
#include <unordered_map>
#include <memory>
#include <deque>
#include <functional>
#include <vector>
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
// Forward declarations
// ─────────────────────────────────────────────────────────────────────────────
class TunnelConn;
class LocalSession;
class ProxyServer;

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────
static void set_nonblocking(int fd) {
#ifdef _WIN32
    SOCKET s = posix_compat::native_socket(fd);
    if (s != INVALID_SOCKET) { u_long m = 1; ioctlsocket(s, FIONBIO, &m); }
#else
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static void close_fd(int fd) {
#ifdef _WIN32
    close(fd);   // posix_compat::close via posix_compat.h
#else
    ::close(fd);
#endif
}

static ssize_t sock_recv(int fd, void* buf, size_t len, int flags) {
#ifdef _WIN32
    return posix_compat::recv_fd(fd, buf, len, flags);
#else
    return ::recv(fd, buf, len, flags);
#endif
}

static ssize_t sock_send(int fd, const void* buf, size_t len, int flags) {
#ifdef _WIN32
    return posix_compat::send_fd(fd, buf, len, flags);
#else
    return ::send(fd, buf, len, flags | MSG_NOSIGNAL);
#endif
}

static int tcp_connect(const std::string& host, uint16_t port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        PROXY_LOG_ERROR("[client] getaddrinfo failed for " << host << ":" << port);
        return -1;
    }
#ifdef _WIN32
    int fd = posix_compat::socket_fd(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (posix_compat::connect_fd(fd, res->ai_addr, (socklen_t)res->ai_addrlen) < 0) {
#else
    int fd = (int)socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (::connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
#endif
        freeaddrinfo(res);
        close_fd(fd);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

// ─────────────────────────────────────────────────────────────────────────────
// TunnelConn — one TLS+H2 connection to the tunnel server
//              multiplexes multiple streams (one per browser CONNECT)
// ─────────────────────────────────────────────────────────────────────────────
class TunnelConn : public std::enable_shared_from_this<TunnelConn> {
public:
    // Callbacks per stream
    struct StreamCbs {
        std::function<void()>                           on_ready;   // received 200
        std::function<void(const uint8_t*, size_t)>     on_data;
        std::function<void(uint32_t)>                   on_close;
    };

    explicit TunnelConn(Reactor& reactor)
        : reactor_(reactor), h2_(nullptr), fd_(-1)
        , state_(State::DISCONNECTED) {}

    ~TunnelConn() { disconnect(); }

    // Connect to server and perform TLS+H2 handshake (blocking for simplicity)
    bool connect(const std::string& host, uint16_t port) {
        server_host_ = host;

        fd_ = tcp_connect(host, port);
        if (fd_ < 0) {
            PROXY_LOG_ERROR("[tunnel] TCP connect failed to " << host << ":" << port);
            return false;
        }

        // TLS with Chrome fingerprint
        if (!tls_ctx_.init_client()) return false;
        SSL_CTX_set_verify(tls_ctx_.ctx(), SSL_VERIFY_NONE, nullptr);
        tls_ctx_.configure_chrome_fingerprint();
        tls_ctx_.set_alpn({"h2", "http/1.1"});

        if (!tls_sock_.connect(fd_, tls_ctx_, host)) {
            PROXY_LOG_ERROR("[tunnel] TLS connect initiation failed");
            close_fd(fd_);
            fd_ = -1;
            return false;
        }

        // Blocking TLS handshake
        while (!tls_sock_.is_connected()) {
            if (!tls_sock_.continue_handshake()) {
                PROXY_LOG_ERROR("[tunnel] TLS handshake failed");
                close_fd(fd_);
                fd_ = -1;
                return false;
            }
            if (!tls_sock_.is_connected()) {
                // wait for socket readiness (simple blocking poll)
                fd_set rset, wset;
                FD_ZERO(&rset); FD_ZERO(&wset);
                if (tls_sock_.want_read())  FD_SET(fd_, &rset);
                if (tls_sock_.want_write()) FD_SET(fd_, &wset);
                select(fd_ + 1, &rset, &wset, nullptr, nullptr);
            }
        }

        auto info = tls_sock_.get_tls_info();
        PROXY_LOG_INFO("[tunnel] TLS handshake done. version=" << info.version
                       << " cipher=" << info.cipher << " alpn=" << info.alpn);

        if (info.alpn != "h2") {
            PROXY_LOG_ERROR("[tunnel] Server did not negotiate h2 (got: " << info.alpn << ")");
            disconnect();
            return false;
        }

        // Initialize nghttp2 client session
        nghttp2_session_callbacks* cbs;
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_send_callback(cbs, on_send_cb);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_cb);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_cb);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_cb);
        nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
        int rv = nghttp2_session_client_new(&h2_, cbs, this);
        nghttp2_session_callbacks_del(cbs);
        if (rv != 0) {
            PROXY_LOG_ERROR("[tunnel] nghttp2_session_client_new failed: " << nghttp2_strerror(rv));
            disconnect();
            return false;
        }

        // Send client preface + initial SETTINGS
        nghttp2_settings_entry settings[] = {
            { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
            { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1 << 20 },  // 1 MB stream window
        };
        nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, settings, 2);
        // Also expand the connection-level flow-control window
        nghttp2_submit_window_update(h2_, NGHTTP2_FLAG_NONE, 0, (1 << 20) - 65535);
        flush_h2();

        state_ = State::CONNECTED;
        set_nonblocking(fd_);

        // Register with reactor
        auto self = shared_from_this();
        reactor_.add(fd_, Event::READABLE | Event::WRITABLE,
                     [self](int fd, int ev) { self->on_fd_event(fd, ev); });

        PROXY_LOG_INFO("[tunnel] Connected and H2 session established");
        return true;
    }

    // Open HTTP/2 CONNECT tunnel (RFC 7540 §8.3)
    int32_t open_stream(const std::string& target_host, uint16_t target_port, StreamCbs cbs) {
        if (state_ != State::CONNECTED) return -1;

        std::string authority = target_host + ":" + std::to_string(target_port);
        nghttp2_nv headers[] = {
            { (uint8_t*)":method",    (uint8_t*)"CONNECT",         7,                    authority.size(), NGHTTP2_NV_FLAG_NONE },
            { (uint8_t*)":authority", (uint8_t*)authority.c_str(), 10,                   authority.size(), NGHTTP2_NV_FLAG_NONE },
        };
        // Correct lengths
        headers[0].namelen  = 7;
        headers[0].valuelen = 7; // "CONNECT"
        headers[1].namelen  = 10;
        headers[1].valuelen = authority.size();

        int32_t sid = nghttp2_submit_headers(h2_, NGHTTP2_FLAG_NONE, -1, nullptr,
                                             headers, 2, nullptr);
        if (sid < 0) {
            PROXY_LOG_ERROR("[tunnel] nghttp2_submit_headers failed: " << nghttp2_strerror(sid));
            return -1;
        }

        streams_[sid] = StreamState{ std::move(cbs), false, {}, false };
        flush_h2();
        update_reactor();
        PROXY_LOG_INFO("[tunnel] Opened H2 CONNECT stream " << sid << " -> " << authority);
        return sid;
    }

    // Send data on a stream — uses a persistent per-stream data source
    void send_stream_data(int32_t sid, const uint8_t* data, size_t len, bool eof = false) {
        if (state_ != State::CONNECTED) return;
        auto it = streams_.find(sid);
        if (it == streams_.end()) return;
        StreamState& ss = it->second;

        if (!ss.tunnel_ready) {
            // Buffer until 200 arrives
            if (data && len > 0)
                ss.pre_buf.insert(ss.pre_buf.end(), data, data + len);
            if (eof) ss.pre_eof = true;
            return;
        }

        feed_data_src(sid, ss, data, len, eof);
        flush_h2();
        update_reactor();
    }

    void close_stream(int32_t sid) {
        send_stream_data(sid, nullptr, 0, /*eof=*/true);
    }

    bool is_connected() const { return state_ == State::CONNECTED; }

private:
    enum class State { DISCONNECTED, CONNECTED };

    // Persistent data source — shared between TunnelConn and nghttp2
    struct DataSrc {
        std::deque<std::vector<uint8_t>> chunks;
        bool eof = false;
        bool submitted = false;  // true after nghttp2_submit_data has been called once
    };

    struct StreamState {
        StreamCbs            cbs;
        bool                 tunnel_ready = false;
        std::vector<uint8_t> pre_buf;     // data buffered before tunnel_ready
        bool                 pre_eof      = false;
        DataSrc*             data_src     = nullptr;
    };

    static ssize_t stream_data_read_cb(nghttp2_session* /*session*/, int32_t /*sid*/,
                                        uint8_t* buf, size_t cap, uint32_t* flags,
                                        nghttp2_data_source* ds, void* /*ud*/) {
        auto* src = static_cast<DataSrc*>(ds->ptr);
        if (src->chunks.empty()) {
            if (src->eof) {
                *flags |= NGHTTP2_DATA_FLAG_EOF;
                delete src;
                ds->ptr = nullptr;
                return 0;
            }
            return NGHTTP2_ERR_DEFERRED;
        }
        auto& chunk = src->chunks.front();
        size_t n = std::min(chunk.size(), cap);
        memcpy(buf, chunk.data(), n);
        chunk.erase(chunk.begin(), chunk.begin() + n);
        if (chunk.empty()) src->chunks.pop_front();
        return (ssize_t)n;
    }

    // Add data to the per-stream data source; submit or resume as needed
    void feed_data_src(int32_t sid, StreamState& ss,
                        const uint8_t* data, size_t len, bool eof) {
        if (!ss.data_src) {
            ss.data_src = new DataSrc();
        }
        if (data && len > 0)
            ss.data_src->chunks.push_back(std::vector<uint8_t>(data, data + len));
        if (eof) ss.data_src->eof = true;

        // If provider not yet submitted, submit it; otherwise resume it
        // We track submission by the pointer being non-null in streams_
        // Re-submit check: a deferred provider is still the active one; just resume.
        // We use a simple convention: data_src != null means the provider IS active.
        // Submit only once (first call); all subsequent calls just resume.
        if (!ss.data_src->submitted) {
            ss.data_src->submitted = true;
            nghttp2_data_provider prov;
            prov.source.ptr = ss.data_src;
            prov.read_callback = stream_data_read_cb;
            int rv = nghttp2_submit_data(h2_, NGHTTP2_FLAG_NONE, sid, &prov);
            if (rv != 0) {
                PROXY_LOG_ERROR("[tunnel] nghttp2_submit_data failed: " << nghttp2_strerror(rv));
            }
        } else {
            nghttp2_session_resume_data(h2_, sid);
        }
    }

    // Flush pre-ready buffer after tunnel becomes available
    void flush_pre_buf(int32_t sid) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) return;
        StreamState& ss = it->second;
        bool has_data = !ss.pre_buf.empty();
        bool has_eof  = ss.pre_eof;
        if (has_data || has_eof) {
            const uint8_t* ptr = has_data ? ss.pre_buf.data() : nullptr;
            size_t         len = has_data ? ss.pre_buf.size() : 0;
            feed_data_src(sid, ss, ptr, len, has_eof);
            ss.pre_buf.clear();
        }
    }

    void on_fd_event(int /*fd*/, int events) {
        if (state_ != State::CONNECTED) return;

        if (events & Event::READABLE) {
            uint8_t buf[16384];
            do {
                ssize_t n = tls_sock_.read(buf, sizeof(buf));
                if (n > 0) {
                    ssize_t rv = nghttp2_session_mem_recv(h2_, buf, n);
                    if (rv < 0) {
                        PROXY_LOG_ERROR("[tunnel] nghttp2_session_mem_recv: " << nghttp2_strerror(rv));
                        disconnect();
                        return;
                    }
                } else if (n == 0) {
                    PROXY_LOG_INFO("[tunnel] Server closed connection");
                    disconnect();
                    return;
                } else {
                    break;
                }
            } while (tls_sock_.has_pending());
            flush_h2();
        }

        if (state_ == State::CONNECTED && (events & Event::WRITABLE)) {
            drain_write_buf();
            if (state_ == State::CONNECTED) flush_h2();
        }

        if (state_ == State::CONNECTED) update_reactor();
    }

    void flush_h2() {
        if (!h2_) return;
        int rv = nghttp2_session_send(h2_);
        if (rv != 0) {
            PROXY_LOG_ERROR("[tunnel] nghttp2_session_send: " << nghttp2_strerror(rv));
            disconnect();
        }
    }

    void drain_write_buf() {
        while (!write_buf_.empty()) {
            size_t chunk = std::min(write_buf_.size(), (size_t)16384);
            uint8_t tmp[16384];
            std::copy(write_buf_.begin(), write_buf_.begin() + chunk, tmp);
            ssize_t n = tls_sock_.write(tmp, chunk);
            if (n > 0) {
                write_buf_.erase(write_buf_.begin(), write_buf_.begin() + n);
            } else {
                break;
            }
        }
    }

    void update_reactor() {
        if (fd_ < 0) return;
        int ev = Event::READABLE;
        if (tls_sock_.want_write() || !write_buf_.empty()
            || (h2_ && nghttp2_session_want_write(h2_))) {
            ev |= Event::WRITABLE;
        }
        reactor_.modify(fd_, ev);
    }

    void disconnect() {
        if (state_ == State::DISCONNECTED) return;
        state_ = State::DISCONNECTED;
        if (fd_ >= 0) {
            reactor_.remove(fd_);
        }
        if (h2_) {
            nghttp2_session_del(h2_);
            h2_ = nullptr;
        }
        tls_sock_.close();
        // Notify all streams they're closed and free data sources
        for (auto& [sid, ss] : streams_) {
            delete ss.data_src;
            if (ss.cbs.on_close) ss.cbs.on_close(NGHTTP2_INTERNAL_ERROR);
        }
        streams_.clear();
        fd_ = -1;
    }

    // ── nghttp2 callbacks ────────────────────────────────────────────────────

    static ssize_t on_send_cb(nghttp2_session*, const uint8_t* data, size_t len,
                               int, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);

        if (!self->write_buf_.empty()) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        ssize_t n = self->tls_sock_.write(data, len);
        if (n < 0) {
            if (self->tls_sock_.want_write() || self->tls_sock_.want_read())
                return NGHTTP2_ERR_WOULDBLOCK;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if ((size_t)n < len) {
            self->write_buf_.insert(self->write_buf_.end(), data + n, data + len);
        }
        return (ssize_t)len;
    }

    static int on_frame_recv_cb(nghttp2_session*, const nghttp2_frame* frame, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);
        int32_t sid = frame->hd.stream_id;

        if (frame->hd.type == NGHTTP2_HEADERS
            && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            // Status is parsed in on_header_cb; here we check if tunnel is ready
            // (status 200 is set in on_header_cb)
            auto it = self->streams_.find(sid);
            if (it != self->streams_.end() && it->second.tunnel_ready) {
                PROXY_LOG_INFO("[tunnel] Stream " << sid << " tunnel ready");
                if (it->second.cbs.on_ready) it->second.cbs.on_ready();
                // Flush any data buffered before tunnel was ready
                self->flush_pre_buf(sid);
                self->flush_h2();
            }
        }

        if (frame->hd.type == NGHTTP2_RST_STREAM) {
            auto it = self->streams_.find(sid);
            if (it != self->streams_.end()) {
                if (it->second.cbs.on_close)
                    it->second.cbs.on_close(frame->rst_stream.error_code);
                self->streams_.erase(it);
            }
        }

        return 0;
    }

    static int on_header_cb(nghttp2_session*, const nghttp2_frame* frame,
                             const uint8_t* name, size_t namelen,
                             const uint8_t* value, size_t valuelen,
                             uint8_t, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);
        int32_t sid = frame->hd.stream_id;

        if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
            std::string status((const char*)value, valuelen);
            PROXY_LOG_DEBUG("[tunnel] Stream " << sid << " :status=" << status);
            if (status == "200") {
                auto it = self->streams_.find(sid);
                if (it != self->streams_.end()) {
                    it->second.tunnel_ready = true;
                }
            }
        }
        return 0;
    }

    static int on_data_chunk_cb(nghttp2_session* session, uint8_t, int32_t sid,
                                  const uint8_t* data, size_t len, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);
        // Acknowledge received bytes so nghttp2 sends WINDOW_UPDATE
        nghttp2_session_consume(session, sid, len);
        auto it = self->streams_.find(sid);
        if (it != self->streams_.end() && it->second.cbs.on_data) {
            it->second.cbs.on_data(data, len);
        }
        return 0;
    }

    static int on_stream_close_cb(nghttp2_session*, int32_t sid,
                                   uint32_t error_code, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);
        auto it = self->streams_.find(sid);
        if (it != self->streams_.end()) {
            PROXY_LOG_INFO("[tunnel] Stream " << sid << " closed err=" << error_code);
            delete it->second.data_src;
            if (it->second.cbs.on_close) it->second.cbs.on_close(error_code);
            self->streams_.erase(it);
        }
        return 0;
    }

    Reactor&       reactor_;
    TlsContext     tls_ctx_;
    TlsSocket      tls_sock_;
    nghttp2_session* h2_;
    int            fd_;
    State          state_;
    std::string    server_host_;
    std::deque<uint8_t> write_buf_;
    std::unordered_map<int32_t, StreamState> streams_;
};

// ─────────────────────────────────────────────────────────────────────────────
// LocalSession — one browser ↔ proxy connection
// ─────────────────────────────────────────────────────────────────────────────
class LocalSession : public std::enable_shared_from_this<LocalSession> {
public:
    using CleanupCb = std::function<void(int)>;

    LocalSession(int fd, Reactor& reactor,
                 std::shared_ptr<TunnelConn> tunnel,
                 CleanupCb on_close)
        : fd_(fd), reactor_(reactor), tunnel_(std::move(tunnel))
        , stream_id_(-1), state_(State::READ_CONNECT)
        , on_close_(std::move(on_close)) {}

    ~LocalSession() {
        if (stream_id_ >= 0) tunnel_->close_stream(stream_id_);
        reactor_.remove(fd_);
        close_fd(fd_);
    }

    void start() {
        auto self = shared_from_this();
        reactor_.add(fd_, Event::READABLE,
                     [self](int fd, int ev) { self->on_event(fd, ev); });
    }

private:
    enum class State { READ_CONNECT, WAIT_TUNNEL, TUNNELING, CLOSING };

    void on_event(int /*fd*/, int events) {
        if (state_ == State::CLOSING) return;

        if (events & Event::READABLE) {
            if (state_ == State::READ_CONNECT) {
                read_connect_request();
            } else if (state_ == State::TUNNELING) {
                forward_to_tunnel();
            }
        }
        if (events & Event::WRITABLE) {
            flush_to_browser();
        }
    }

    // Parse "CONNECT host:port HTTP/1.1\r\n..." from browser
    void read_connect_request() {
        char buf[4096];
        ssize_t n = sock_recv(fd_, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { do_close(); return; }
        buf[n] = '\0';
        incoming_buf_.insert(incoming_buf_.end(), buf, buf + n);

        // Look for end of HTTP headers
        std::string req(incoming_buf_.begin(), incoming_buf_.end());
        size_t hdr_end = req.find("\r\n\r\n");
        if (hdr_end == std::string::npos) return; // need more data

        // Parse first line: CONNECT host:port HTTP/1.x
        size_t line_end = req.find("\r\n");
        std::string first_line = req.substr(0, line_end);

        std::string method, authority, version;
        std::istringstream iss(first_line);
        iss >> method >> authority >> version;

        if (method != "CONNECT") {
            // Non-CONNECT: return 405
            const char* resp = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            sock_send(fd_, resp, strlen(resp), 0);
            do_close();
            return;
        }

        // Split authority into host:port
        size_t colon = authority.rfind(':');
        if (colon == std::string::npos) { do_close(); return; }
        std::string target_host = authority.substr(0, colon);
        uint16_t    target_port = (uint16_t)std::stoi(authority.substr(colon + 1));

        PROXY_LOG_INFO("[local] CONNECT " << target_host << ":" << target_port
                       << " fd=" << fd_);

        // Open H2 CONNECT stream on the tunnel
        state_ = State::WAIT_TUNNEL;
        incoming_buf_.clear();

        auto self = shared_from_this();
        stream_id_ = tunnel_->open_stream(target_host, target_port, {
            // on_ready: tunnel established, send 200 to browser
            [self]() {
                self->on_tunnel_ready();
            },
            // on_data: data from remote target → send to browser
            [self](const uint8_t* data, size_t len) {
                self->on_tunnel_data(data, len);
            },
            // on_close
            [self](uint32_t err) {
                PROXY_LOG_DEBUG("[local] Tunnel stream closed err=" << err << " fd=" << self->fd_);
                self->do_close();
            }
        });

        if (stream_id_ < 0) {
            const char* resp = "HTTP/1.1 503 Tunnel Failed\r\n\r\n";
            sock_send(fd_, resp, strlen(resp), 0);
            do_close();
        }
    }

    void on_tunnel_ready() {
        // Send "200 Connection Established" to browser
        const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        sock_send(fd_, resp, strlen(resp), 0);
        state_ = State::TUNNELING;
        reactor_.modify(fd_, Event::READABLE);
        PROXY_LOG_INFO("[local] Tunnel ready, relaying fd=" << fd_);
    }

    void on_tunnel_data(const uint8_t* data, size_t len) {
        // Buffer data from remote; flush immediately or queue if busy
        to_browser_buf_.insert(to_browser_buf_.end(), data, data + len);
        flush_to_browser();
    }

    void forward_to_tunnel() {
        // Read from browser, send to tunnel
        uint8_t buf[16384];
        ssize_t n = sock_recv(fd_, buf, sizeof(buf), 0);
        if (n <= 0) {
            tunnel_->close_stream(stream_id_);
            stream_id_ = -1;
            do_close();
            return;
        }
        tunnel_->send_stream_data(stream_id_, buf, n);
    }

    void flush_to_browser() {
        while (!to_browser_buf_.empty()) {
            size_t chunk = std::min(to_browser_buf_.size(), (size_t)16384);
            uint8_t tmp[16384];
            std::copy(to_browser_buf_.begin(), to_browser_buf_.begin() + chunk, tmp);
            ssize_t n = sock_send(fd_, tmp, chunk, 0);
            if (n > 0) {
                to_browser_buf_.erase(to_browser_buf_.begin(),
                                      to_browser_buf_.begin() + n);
            } else if (n < 0 && (
#ifdef _WIN32
                WSAGetLastError() == WSAEWOULDBLOCK
#else
                errno == EAGAIN || errno == EWOULDBLOCK
#endif
            )) {
                // Enable WRITABLE to retry
                reactor_.modify(fd_, Event::READABLE | Event::WRITABLE);
                return;
            } else {
                do_close();
                return;
            }
        }
        // Buffer drained, stop monitoring WRITABLE
        if (state_ == State::TUNNELING) {
            reactor_.modify(fd_, Event::READABLE);
        }
    }

    void do_close() {
        if (state_ == State::CLOSING) return;
        state_ = State::CLOSING;
        if (on_close_) on_close_(fd_);
    }

    int    fd_;
    Reactor& reactor_;
    std::shared_ptr<TunnelConn> tunnel_;
    int32_t stream_id_;
    State   state_;
    CleanupCb on_close_;
    std::vector<char>    incoming_buf_;
    std::deque<uint8_t>  to_browser_buf_;
};

// ─────────────────────────────────────────────────────────────────────────────
// ProxyServer — local HTTP proxy listener
// ─────────────────────────────────────────────────────────────────────────────
class ProxyServer {
public:
    ProxyServer(uint16_t local_port,
                const std::string& tunnel_host, uint16_t tunnel_port)
        : local_port_(local_port)
        , tunnel_host_(tunnel_host)
        , tunnel_port_(tunnel_port) {}

    bool run() {
        if (!reactor_.init()) return false;

        // Connect tunnel
        tunnel_ = std::make_shared<TunnelConn>(reactor_);
        if (!tunnel_->connect(tunnel_host_, tunnel_port_)) {
            PROXY_LOG_ERROR("[proxy] Failed to connect to tunnel server");
            return false;
        }

        // Listen locally
#ifdef _WIN32
        listen_fd_ = posix_compat::socket_fd(AF_INET, SOCK_STREAM, 0);
#else
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
#endif
        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1 only
        addr.sin_port        = htons(local_port_);
#ifdef _WIN32
        posix_compat::bind_fd(listen_fd_, (struct sockaddr*)&addr, sizeof(addr));
        posix_compat::listen_fd(listen_fd_, 128);
#else
        bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr));
        listen(listen_fd_, 128);
#endif
        set_nonblocking(listen_fd_);

        PROXY_LOG_INFO("[proxy] Local HTTP proxy listening on 127.0.0.1:" << local_port_);

        reactor_.add(listen_fd_, Event::READABLE, [this](int fd, int) {
            this->on_accept(fd);
        });

        while (true) {
            reactor_.wait(100);
        }
        return true;
    }

private:
    void on_accept(int listen_fd) {
        struct sockaddr_in addr{};
        socklen_t len = sizeof(addr);
#ifdef _WIN32
        int client_fd = posix_compat::accept_fd(listen_fd, (struct sockaddr*)&addr, &len);
#else
        int client_fd = ::accept(listen_fd, (struct sockaddr*)&addr, &len);
#endif
        if (client_fd < 0) return;
        set_nonblocking(client_fd);

        PROXY_LOG_INFO("[proxy] Accepted local connection fd=" << client_fd);

        auto cleanup = [this](int fd) {
            sessions_.erase(fd);
        };

        auto session = std::make_shared<LocalSession>(client_fd, reactor_, tunnel_, cleanup);
        sessions_[client_fd] = session;
        session->start();
    }

    uint16_t    local_port_;
    std::string tunnel_host_;
    uint16_t    tunnel_port_;
    int         listen_fd_ = -1;
    Reactor     reactor_;
    std::shared_ptr<TunnelConn> tunnel_;
    std::unordered_map<int, std::shared_ptr<LocalSession>> sessions_;
};

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -p <port>   Local HTTP proxy listen port (default: 8080)\n"
        "  -H <host>   Tunnel server host           (default: 127.0.0.1)\n"
        "  -P <port>   Tunnel server port           (default: 8443)\n"
        "  -h          Show this help message\n"
        "\n"
        "Example:\n"
        "  %s -p 8080 -H tunnel.example.com -P 8443\n",
        prog, prog);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    uint16_t    local_port   = 8080;
    std::string tunnel_host  = "127.0.0.1";
    uint16_t    tunnel_port  = 8443;

    int opt;
    while ((opt = getopt(argc, argv, "p:H:P:h")) != -1) {
        switch (opt) {
        case 'p': local_port  = (uint16_t)std::stoi(optarg); break;
        case 'H': tunnel_host = optarg;                       break;
        case 'P': tunnel_port = (uint16_t)std::stoi(optarg); break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    PROXY_LOG_INFO("[main] Starting wtunnel client");
    PROXY_LOG_INFO("[main] Local proxy  : 127.0.0.1:" << local_port);
    PROXY_LOG_INFO("[main] Tunnel server: " << tunnel_host << ":" << tunnel_port);

    ProxyServer proxy(local_port, tunnel_host, tunnel_port);
    proxy.run();
    return 0;
}
