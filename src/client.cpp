/**
 * wtunnel client — local HTTP CONNECT proxy over TLS/H2 tunnel
 *
 * Flow:
 *   Browser ──HTTP CONNECT──> LocalProxy :8080
 *                              └──TLS(Chrome fingerprint)+H2 CONNECT──> TunnelServer :8443
 *                                                                            └──TCP──> Target
 *
 * Connection model: one short-lived TLS+H2 connection per browser CONNECT request.
 * TLS 1.3 session tickets are cached so subsequent connections use 0-RTT resumption:
 * the H2 connection preface is sent in the first TLS flight, and the server can
 * start processing the CONNECT before the handshake completes.
 */

#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include "common/chrome_fingerprint.h"
#include "common/logging.h"
#include "reality_marker.h"
#include <nghttp2/nghttp2.h>

#ifdef _WIN32
#  include "common/posix_compat.h"
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
#include <fstream>
#include <algorithm>

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
    close(fd);
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

// Non-blocking TCP connect (returns fd in EINPROGRESS state).
static int tcp_connect_nb(const std::string& host, uint16_t port) {
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
#else
    int fd = (int)socket(res->ai_family, SOCK_STREAM, 0);
#endif
    if (fd < 0) { freeaddrinfo(res); return -1; }
    set_nonblocking(fd);
#ifdef _WIN32
    int r = posix_compat::connect_fd(fd, res->ai_addr, (socklen_t)res->ai_addrlen);
#else
    int r = ::connect(fd, res->ai_addr, res->ai_addrlen);
#endif
    freeaddrinfo(res);
    if (r < 0 && errno != EINPROGRESS) { close_fd(fd); return -1; }
    return fd;
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionCache — one cached TLS session ticket shared across all LocalSessions
// ─────────────────────────────────────────────────────────────────────────────
struct SessionCache {
    SSL_SESSION* sess = nullptr;

    ~SessionCache() { if (sess) SSL_SESSION_free(sess); }

    SSL_SESSION* get() const { return sess; }

    // Takes ownership of s (caller must have called SSL_SESSION_up_ref).
    void update(SSL_SESSION* s) {
        if (sess) SSL_SESSION_free(sess);
        sess = s;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// TunnelConfig — immutable per-server settings passed into each LocalSession
// ─────────────────────────────────────────────────────────────────────────────
struct TunnelConfig {
    std::string host;
    uint16_t    port            = 8443;
    std::string reality_psk;
    std::string fingerprint_path;
};

// ─────────────────────────────────────────────────────────────────────────────
// TunnelConn — one short-lived TLS+H2 connection to the tunnel server.
//
// Lifecycle: start_connect() → [TCP_CONNECTING → TLS_HANDSHAKING] → CONNECTED
//            → one or more open_stream() calls → disconnect() on last stream close.
//
// 0-RTT: if a session ticket is supplied and the server supports early data,
// the 24-byte H2 connection preface is sent in the first TLS flight so the
// server can start processing the CONNECT before the handshake finishes.
// ─────────────────────────────────────────────────────────────────────────────
class TunnelConn : public std::enable_shared_from_this<TunnelConn> {
public:
    struct StreamCbs {
        std::function<void()>                       on_ready;
        std::function<void(const uint8_t*, size_t)> on_data;
        std::function<void(uint32_t)>               on_close;
    };

    explicit TunnelConn(Reactor& reactor, std::string reality_psk = "",
                        std::string fingerprint_path = "")
        : reactor_(reactor), h2_(nullptr), fd_(-1)
        , state_(State::DISCONNECTED)
        , reality_psk_(std::move(reality_psk))
        , fingerprint_path_(std::move(fingerprint_path))
        , pending_session_(nullptr)
        , early_data_attempted_(false)
        , skip_h2_preface_(false) {}

    ~TunnelConn() { disconnect(); }

    // Async connect. on_ready(true) → connected; on_ready(false) → failed.
    // session: borrowed reference; TunnelConn does NOT free it.
    bool start_connect(const std::string& host, uint16_t port,
                       SSL_SESSION* session,
                       std::function<void(bool)> on_ready) {
        server_host_     = host;
        pending_session_ = session;
        on_connected_    = std::move(on_ready);
        early_data_attempted_ = false;
        skip_h2_preface_      = false;

        fd_ = tcp_connect_nb(host, port);
        if (fd_ < 0) {
            PROXY_LOG_ERROR("[tunnel] tcp_connect_nb failed to " << host << ":" << port);
            return false;
        }

        state_ = State::TCP_CONNECTING;
        auto self = shared_from_this();
        reactor_.add(fd_, Event::WRITABLE,
                     [self](int fd, int ev) { self->on_fd_event(fd, ev); });
        return true;
    }

    // After a successful connection, returns a new reference to the session ticket
    // (caller must SSL_SESSION_free when done).
    SSL_SESSION* take_session() {
        SSL_SESSION* s = tls_sock_.get_session();
        if (s) SSL_SESSION_up_ref(s);
        return s;
    }

    // Open HTTP/2 CONNECT tunnel (RFC 7540 §8.3).
    int32_t open_stream(const std::string& target_host, uint16_t target_port, StreamCbs cbs) {
        if (state_ != State::CONNECTED) return -1;

        std::string authority = target_host + ":" + std::to_string(target_port);
        nghttp2_nv headers[2];
        headers[0] = { (uint8_t*)":method",    (uint8_t*)"CONNECT",         7, 7,                    NGHTTP2_NV_FLAG_NONE };
        headers[1] = { (uint8_t*)":authority", (uint8_t*)authority.c_str(), 10, authority.size(), NGHTTP2_NV_FLAG_NONE };

        int32_t sid = nghttp2_submit_headers(h2_, NGHTTP2_FLAG_NONE, -1, nullptr,
                                             headers, 2, nullptr);
        if (sid < 0) {
            PROXY_LOG_ERROR("[tunnel] nghttp2_submit_headers: " << nghttp2_strerror(sid));
            return -1;
        }

        streams_[sid] = StreamState{ std::move(cbs), false, {}, false, nullptr };
        flush_h2();
        update_reactor();
        PROXY_LOG_INFO("[tunnel] Opened H2 stream " << sid << " -> " << authority);
        return sid;
    }

    void send_stream_data(int32_t sid, const uint8_t* data, size_t len, bool eof = false) {
        if (state_ != State::CONNECTED) return;
        auto it = streams_.find(sid);
        if (it == streams_.end()) return;
        StreamState& ss = it->second;

        if (!ss.tunnel_ready) {
            if (data && len > 0) ss.pre_buf.insert(ss.pre_buf.end(), data, data + len);
            if (eof) ss.pre_eof = true;
            return;
        }
        feed_data_src(sid, ss, data, len, eof);
        flush_h2();
        update_reactor();
    }

    void close_stream(int32_t sid) { send_stream_data(sid, nullptr, 0, true); }

    bool is_connected() const { return state_ == State::CONNECTED; }

private:
    enum class State { DISCONNECTED, TCP_CONNECTING, TLS_HANDSHAKING, CONNECTED };

    struct DataSrc {
        std::deque<std::vector<uint8_t>> chunks;
        bool eof       = false;
        bool submitted = false;
    };

    struct StreamState {
        StreamCbs            cbs;
        bool                 tunnel_ready = false;
        std::vector<uint8_t> pre_buf;
        bool                 pre_eof      = false;
        DataSrc*             data_src     = nullptr;
    };

    // ── Connection state machine ─────────────────────────────────────────────

    void on_fd_event(int fd, int events) {
        switch (state_) {
        case State::TCP_CONNECTING:  handle_tcp_connect(events);  break;
        case State::TLS_HANDSHAKING: handle_tls_handshake(events); break;
        case State::CONNECTED:       handle_data(fd, events);      break;
        default: break;
        }
    }

    void handle_tcp_connect(int events) {
        if (!(events & Event::WRITABLE)) return;

        int err = 0; socklen_t len = sizeof(err);
        getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            PROXY_LOG_ERROR("[tunnel] TCP connect failed: " << strerror(err));
            on_connect_fail(); return;
        }

        // TCP connected — set up TLS.
        if (!tls_ctx_.init_client()) { on_connect_fail(); return; }
        SSL_CTX_set_verify(tls_ctx_.ctx(), SSL_VERIFY_NONE, nullptr);
        tls_ctx_.enable_early_data();

        if (!fingerprint_path_.empty()) {
            ChromeFingerprint fp;
            if (ChromeFingerprint::parse_wireshark(fingerprint_path_, fp)) {
                PROXY_LOG_INFO("[tunnel] Loaded fingerprint from " << fingerprint_path_);
                tls_ctx_.configure_chrome_fingerprint(&fp);
            } else {
                PROXY_LOG_ERROR("[tunnel] Bad fingerprint file, using built-in preset");
                tls_ctx_.configure_chrome_fingerprint();
            }
        } else {
            tls_ctx_.configure_chrome_fingerprint();
        }
        tls_ctx_.set_alpn({"h2", "http/1.1"});

        if (!reality_psk_.empty()) {
            tls_ctx_.enable_reality_bind_client();
            tls_sock_.set_reality_bind(reality_psk_);
            PROXY_LOG_INFO("[tunnel] REALITY bind configured");
        }

        if (!tls_sock_.connect(fd_, tls_ctx_, server_host_, pending_session_)) {
            PROXY_LOG_ERROR("[tunnel] TLS connect initiation failed");
            on_connect_fail(); return;
        }

        state_ = State::TLS_HANDSHAKING;

        // In BoringSSL, SSL_in_early_data() may become true immediately after
        // SSL_connect() if the session is 0-RTT capable.  Try to send the H2
        // connection preface now; if not yet in the early-data window the call
        // is a no-op and we retry in handle_tls_handshake().
        try_send_h2_early_data();

        arm_handshake_events();
    }

    void handle_tls_handshake(int /*events*/) {
        // Try early data on every handshake event in case SSL_in_early_data()
        // became true only after the first WRITABLE (ClientHello fully sent).
        try_send_h2_early_data();

        if (!tls_sock_.continue_handshake()) {
            on_connect_fail(); return;
        }
        if (!tls_sock_.is_connected()) {
            arm_handshake_events(); return;
        }

        auto info = tls_sock_.get_tls_info();
        PROXY_LOG_INFO("[tunnel] TLS done. version=" << info.version
                       << " cipher=" << info.cipher << " alpn=" << info.alpn);

        if (!info.alpn.empty() && info.alpn != "h2") {
            PROXY_LOG_ERROR("[tunnel] Server did not negotiate h2 (got: " << info.alpn << ")");
            on_connect_fail(); return;
        }

        // If the server accepted our 0-RTT early data, the H2 preface is already
        // on the wire — suppress the duplicate that nghttp2 will try to send.
        if (early_data_attempted_ && tls_sock_.is_early_data_accepted()) {
            skip_h2_preface_ = true;
            PROXY_LOG_INFO("[tunnel] 0-RTT accepted");
        } else if (early_data_attempted_) {
            PROXY_LOG_INFO("[tunnel] 0-RTT rejected; H2 preface will be re-sent");
        }

        if (!init_h2()) { on_connect_fail(); return; }

        state_ = State::CONNECTED;
        update_reactor();

        auto cb = std::move(on_connected_);
        on_connected_ = nullptr;
        if (cb) cb(true);
    }

    void handle_data(int /*fd*/, int events) {
        if (events & Event::READABLE) {
            uint8_t buf[16384];
            do {
                ssize_t n = tls_sock_.read(buf, sizeof(buf));
                if (n > 0) {
                    ssize_t rv = nghttp2_session_mem_recv(h2_, buf, n);
                    if (rv < 0) {
                        PROXY_LOG_ERROR("[tunnel] nghttp2_session_mem_recv: " << nghttp2_strerror(rv));
                        disconnect(); return;
                    }
                } else if (n == 0) {
                    PROXY_LOG_INFO("[tunnel] Server closed connection");
                    disconnect(); return;
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

    void try_send_h2_early_data() {
        if (early_data_attempted_ || !pending_session_) return;
        static const uint8_t H2_MAGIC[24] = {
            'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n',
            '\r','\n','S','M','\r','\n','\r','\n'
        };
        if (tls_sock_.try_write_early_data(H2_MAGIC, sizeof(H2_MAGIC))) {
            early_data_attempted_ = true;
            PROXY_LOG_INFO("[tunnel] H2 magic sent as 0-RTT early data");
        }
    }

    void arm_handshake_events() {
        int ev = Event::READABLE;
        if (tls_sock_.want_write()) ev |= Event::WRITABLE;
        reactor_.modify(fd_, ev);
    }

    bool init_h2() {
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
            PROXY_LOG_ERROR("[tunnel] nghttp2_session_client_new: " << nghttp2_strerror(rv));
            return false;
        }
        nghttp2_settings_entry settings[] = {
            { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
            { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1 << 20 },
        };
        nghttp2_submit_settings(h2_, NGHTTP2_FLAG_NONE, settings, 2);
        nghttp2_submit_window_update(h2_, NGHTTP2_FLAG_NONE, 0, (1 << 20) - 65535);
        // flush_h2() triggers on_send_cb which will skip the H2 magic if 0-RTT accepted.
        flush_h2();
        return true;
    }

    void on_connect_fail() {
        state_ = State::DISCONNECTED;
        if (fd_ >= 0) { reactor_.remove(fd_); close_fd(fd_); fd_ = -1; }
        tls_sock_.close();
        auto cb = std::move(on_connected_);
        on_connected_ = nullptr;
        if (cb) cb(false);
    }

    // ── Data path helpers (same as before) ───────────────────────────────────

    static ssize_t stream_data_read_cb(nghttp2_session*, int32_t,
                                        uint8_t* buf, size_t cap, uint32_t* flags,
                                        nghttp2_data_source* ds, void*) {
        auto* src = static_cast<DataSrc*>(ds->ptr);
        if (src->chunks.empty()) {
            if (src->eof) { *flags |= NGHTTP2_DATA_FLAG_EOF; delete src; ds->ptr = nullptr; return 0; }
            return NGHTTP2_ERR_DEFERRED;
        }
        auto& chunk = src->chunks.front();
        size_t n = std::min(chunk.size(), cap);
        memcpy(buf, chunk.data(), n);
        chunk.erase(chunk.begin(), chunk.begin() + n);
        if (chunk.empty()) src->chunks.pop_front();
        return (ssize_t)n;
    }

    void feed_data_src(int32_t sid, StreamState& ss,
                        const uint8_t* data, size_t len, bool eof) {
        if (!ss.data_src) ss.data_src = new DataSrc();
        if (data && len > 0)
            ss.data_src->chunks.push_back(std::vector<uint8_t>(data, data + len));
        if (eof) ss.data_src->eof = true;

        if (!ss.data_src->submitted) {
            ss.data_src->submitted = true;
            nghttp2_data_provider prov;
            prov.source.ptr     = ss.data_src;
            prov.read_callback  = stream_data_read_cb;
            int rv = nghttp2_submit_data(h2_, NGHTTP2_FLAG_NONE, sid, &prov);
            if (rv != 0) PROXY_LOG_ERROR("[tunnel] nghttp2_submit_data: " << nghttp2_strerror(rv));
        } else {
            nghttp2_session_resume_data(h2_, sid);
        }
    }

    void flush_pre_buf(int32_t sid) {
        auto it = streams_.find(sid);
        if (it == streams_.end()) return;
        StreamState& ss = it->second;
        if (!ss.pre_buf.empty() || ss.pre_eof) {
            feed_data_src(sid, ss,
                          ss.pre_buf.empty() ? nullptr : ss.pre_buf.data(),
                          ss.pre_buf.size(), ss.pre_eof);
            ss.pre_buf.clear();
        }
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
            if (n > 0) write_buf_.erase(write_buf_.begin(), write_buf_.begin() + n);
            else break;
        }
    }

    void update_reactor() {
        if (fd_ < 0) return;
        int ev = Event::READABLE;
        if (tls_sock_.want_write() || !write_buf_.empty()
            || (h2_ && nghttp2_session_want_write(h2_)))
            ev |= Event::WRITABLE;
        reactor_.modify(fd_, ev);
    }

    void disconnect() {
        if (state_ == State::DISCONNECTED) return;
        state_ = State::DISCONNECTED;
        if (fd_ >= 0) { reactor_.remove(fd_); close_fd(fd_); fd_ = -1; }
        if (h2_) { nghttp2_session_del(h2_); h2_ = nullptr; }
        tls_sock_.close();
        for (auto& [sid, ss] : streams_) {
            delete ss.data_src;
            if (ss.cbs.on_close) ss.cbs.on_close(NGHTTP2_INTERNAL_ERROR);
        }
        streams_.clear();
    }

    // ── nghttp2 callbacks ─────────────────────────────────────────────────────

    static ssize_t on_send_cb(nghttp2_session*, const uint8_t* data, size_t len,
                               int, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);

        // If the H2 connection preface was already sent as 0-RTT early data,
        // suppress the copy that nghttp2 sends at session init time.
        if (self->skip_h2_preface_ && len == 24) {
            static const uint8_t H2_MAGIC[24] = {
                'P','R','I',' ','*',' ','H','T','T','P','/','2','.','0','\r','\n',
                '\r','\n','S','M','\r','\n','\r','\n'
            };
            if (memcmp(data, H2_MAGIC, 24) == 0) {
                self->skip_h2_preface_ = false;
                return 24; // pretend sent
            }
            self->skip_h2_preface_ = false;
        }

        if (!self->write_buf_.empty()) return NGHTTP2_ERR_WOULDBLOCK;
        ssize_t n = self->tls_sock_.write(data, len);
        if (n < 0) {
            if (self->tls_sock_.want_write() || self->tls_sock_.want_read())
                return NGHTTP2_ERR_WOULDBLOCK;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if ((size_t)n < len)
            self->write_buf_.insert(self->write_buf_.end(), data + n, data + len);
        return (ssize_t)len;
    }

    static int on_frame_recv_cb(nghttp2_session*, const nghttp2_frame* frame, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);
        int32_t sid = frame->hd.stream_id;

        if (frame->hd.type == NGHTTP2_HEADERS
            && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
            auto it = self->streams_.find(sid);
            if (it != self->streams_.end() && it->second.tunnel_ready) {
                PROXY_LOG_INFO("[tunnel] Stream " << sid << " tunnel ready");
                if (it->second.cbs.on_ready) it->second.cbs.on_ready();
                self->flush_pre_buf(sid);
                self->update_reactor();
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
                if (it != self->streams_.end()) it->second.tunnel_ready = true;
            }
        }
        return 0;
    }

    static int on_data_chunk_cb(nghttp2_session* session, uint8_t, int32_t sid,
                                  const uint8_t* data, size_t len, void* ud) {
        auto* self = static_cast<TunnelConn*>(ud);
        nghttp2_session_consume(session, sid, len);
        auto it = self->streams_.find(sid);
        if (it != self->streams_.end() && it->second.cbs.on_data)
            it->second.cbs.on_data(data, len);
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
    std::string    reality_psk_;
    std::string    fingerprint_path_;
    std::deque<uint8_t> write_buf_;
    std::unordered_map<int32_t, StreamState> streams_;

    std::function<void(bool)> on_connected_;
    SSL_SESSION*              pending_session_;     // borrowed, NOT owned
    bool                      early_data_attempted_;
    bool                      skip_h2_preface_;
};

// ─────────────────────────────────────────────────────────────────────────────
// LocalSession — one browser ↔ proxy connection.
// Creates its own TunnelConn when it receives the CONNECT request.
// ─────────────────────────────────────────────────────────────────────────────
class LocalSession : public std::enable_shared_from_this<LocalSession> {
public:
    using CleanupCb = std::function<void(int)>;

    LocalSession(int fd, Reactor& reactor,
                 TunnelConfig config,
                 std::shared_ptr<SessionCache> session_cache,
                 CleanupCb on_close)
        : fd_(fd), reactor_(reactor)
        , config_(std::move(config))
        , session_cache_(std::move(session_cache))
        , stream_id_(-1), state_(State::READ_CONNECT)
        , on_close_(std::move(on_close)) {}

    ~LocalSession() {
        if (stream_id_ >= 0 && tunnel_) tunnel_->close_stream(stream_id_);
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
            if      (state_ == State::READ_CONNECT) read_connect_request();
            else if (state_ == State::TUNNELING)    forward_to_tunnel();
        }
        if (events & Event::WRITABLE) flush_to_browser();
    }

    void read_connect_request() {
        char buf[4096];
        ssize_t n = sock_recv(fd_, buf, sizeof(buf) - 1, 0);
        if (n <= 0) { do_close(); return; }
        buf[n] = '\0';
        incoming_buf_.insert(incoming_buf_.end(), buf, buf + n);

        std::string req(incoming_buf_.begin(), incoming_buf_.end());
        size_t hdr_end = req.find("\r\n\r\n");
        if (hdr_end == std::string::npos) return;

        size_t line_end = req.find("\r\n");
        std::string first_line = req.substr(0, line_end);
        std::string method, authority, version;
        std::istringstream iss(first_line);
        iss >> method >> authority >> version;

        if (method != "CONNECT") {
            const char* resp = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            sock_send(fd_, resp, strlen(resp), 0);
            do_close(); return;
        }

        size_t colon = authority.rfind(':');
        if (colon == std::string::npos) { do_close(); return; }
        target_host_ = authority.substr(0, colon);
        target_port_ = (uint16_t)std::stoi(authority.substr(colon + 1));

        PROXY_LOG_INFO("[local] CONNECT " << target_host_ << ":" << target_port_
                       << " fd=" << fd_);

        state_ = State::WAIT_TUNNEL;
        incoming_buf_.clear();

        // Create a fresh TunnelConn and connect using any cached session ticket.
        tunnel_ = std::make_shared<TunnelConn>(reactor_, config_.reality_psk,
                                               config_.fingerprint_path);
        auto self = shared_from_this();
        SSL_SESSION* sess = session_cache_ ? session_cache_->get() : nullptr;

        if (!tunnel_->start_connect(config_.host, config_.port, sess,
                                    [self](bool ok) { self->on_tunnel_connected(ok); })) {
            const char* resp = "HTTP/1.1 503 Tunnel Failed\r\n\r\n";
            sock_send(fd_, resp, strlen(resp), 0);
            do_close();
        }
    }

    void on_tunnel_connected(bool ok) {
        if (state_ == State::CLOSING) return;

        if (!ok) {
            const char* resp = "HTTP/1.1 503 Tunnel Failed\r\n\r\n";
            sock_send(fd_, resp, strlen(resp), 0);
            do_close(); return;
        }

        // Persist the fresh session ticket for the next connection.
        if (session_cache_) {
            SSL_SESSION* new_sess = tunnel_->take_session();
            if (new_sess) session_cache_->update(new_sess);
        }

        auto self = shared_from_this();
        stream_id_ = tunnel_->open_stream(target_host_, target_port_, {
            [self]()                              { self->on_tunnel_ready(); },
            [self](const uint8_t* d, size_t len)  { self->on_tunnel_data(d, len); },
            [self](uint32_t err) {
                PROXY_LOG_DEBUG("[local] Stream closed err=" << err << " fd=" << self->fd_);
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
        const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        sock_send(fd_, resp, strlen(resp), 0);
        state_ = State::TUNNELING;
        reactor_.modify(fd_, Event::READABLE);
        PROXY_LOG_INFO("[local] Tunnel ready, relaying fd=" << fd_);
    }

    void on_tunnel_data(const uint8_t* data, size_t len) {
        to_browser_buf_.insert(to_browser_buf_.end(), data, data + len);
        flush_to_browser();
    }

    void forward_to_tunnel() {
        uint8_t buf[16384];
        ssize_t n = sock_recv(fd_, buf, sizeof(buf), 0);
        if (n <= 0) {
            tunnel_->close_stream(stream_id_);
            stream_id_ = -1;
            do_close(); return;
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
                reactor_.modify(fd_, Event::READABLE | Event::WRITABLE);
                return;
            } else {
                do_close(); return;
            }
        }
        if (state_ == State::TUNNELING) reactor_.modify(fd_, Event::READABLE);
    }

    void do_close() {
        if (state_ == State::CLOSING) return;
        state_ = State::CLOSING;
        if (on_close_) on_close_(fd_);
    }

    int    fd_;
    Reactor& reactor_;
    TunnelConfig config_;
    std::shared_ptr<SessionCache> session_cache_;
    std::shared_ptr<TunnelConn>   tunnel_;
    int32_t stream_id_;
    State   state_;
    CleanupCb on_close_;
    std::string  target_host_;
    uint16_t     target_port_ = 0;
    std::vector<char>    incoming_buf_;
    std::deque<uint8_t>  to_browser_buf_;
};

// ─────────────────────────────────────────────────────────────────────────────
// ProxyServer — local HTTP proxy listener
// ─────────────────────────────────────────────────────────────────────────────
class ProxyServer {
public:
    ProxyServer(uint16_t local_port,
                const std::string& tunnel_host, uint16_t tunnel_port,
                std::string reality_psk = "",
                std::string fingerprint_path = "")
        : local_port_(local_port)
        , config_({ tunnel_host, tunnel_port,
                    std::move(reality_psk), std::move(fingerprint_path) })
        , session_cache_(std::make_shared<SessionCache>()) {}

    bool run() {
        if (!reactor_.init()) return false;

#ifdef _WIN32
        listen_fd_ = posix_compat::socket_fd(AF_INET, SOCK_STREAM, 0);
#else
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
#endif
        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = htons(local_port_);
#ifdef _WIN32
        posix_compat::bind_fd(listen_fd_, (struct sockaddr*)&addr, sizeof(addr));
        posix_compat::listen_fd(listen_fd_, 128);
#else
        bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr));
        listen(listen_fd_, 128);
#endif
        set_nonblocking(listen_fd_);

        PROXY_LOG_INFO("[proxy] Local HTTP proxy listening on 0.0.0.0:" << local_port_);
        PROXY_LOG_INFO("[proxy] Tunnel server: " << config_.host << ":" << config_.port
                       << " (per-request connections, 0-RTT enabled)");

        reactor_.add(listen_fd_, Event::READABLE, [this](int fd, int) {
            this->on_accept(fd);
        });

        while (true) reactor_.wait(100);
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

        auto cleanup = [this](int fd) { sessions_.erase(fd); };
        auto session = std::make_shared<LocalSession>(
            client_fd, reactor_, config_, session_cache_, cleanup);
        sessions_[client_fd] = session;
        session->start();
    }

    uint16_t    local_port_;
    TunnelConfig config_;
    std::shared_ptr<SessionCache> session_cache_;
    int         listen_fd_ = -1;
    Reactor     reactor_;
    std::unordered_map<int, std::shared_ptr<LocalSession>> sessions_;
};

// ─────────────────────────────────────────────────────────────────────────────
// INI config
// ─────────────────────────────────────────────────────────────────────────────
struct ClientConfig {
    uint16_t    local_port       = 8080;
    std::string tunnel_host      = "127.0.0.1";
    uint16_t    tunnel_port      = 8443;
    std::string reality_psk;
    std::string fingerprint_path;
    int         verbose          = 0;
};

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

static ClientConfig load_ini(const std::string& path) {
    ClientConfig cfg;
    std::ifstream f(path);
    if (!f.is_open()) return cfg;

    std::string line, section;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        if (line[0] == '[') {
            size_t pos = line.find(']');
            if (pos != std::string::npos) section = trim(line.substr(1, pos - 1));
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key   = trim(line.substr(0, eq));
        std::string value = trim(line.substr(eq + 1));

        if (section == "client") {
            if      (key == "local_port")       cfg.local_port       = (uint16_t)std::stoi(value);
            else if (key == "tunnel_host")      cfg.tunnel_host      = value;
            else if (key == "tunnel_port")      cfg.tunnel_port      = (uint16_t)std::stoi(value);
            else if (key == "reality_psk")      cfg.reality_psk      = value;
            else if (key == "fingerprint_path") cfg.fingerprint_path = value;
            else if (key == "verbose")          cfg.verbose          = std::stoi(value);
        }
    }
    return cfg;
}

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
        "  -K <psk>    REALITY pre-shared key       (must match server -K)\n"
        "  -F <file>   Wireshark Client Hello text dump for TLS fingerprint\n"
        "  -c <file>   Config file path (default: /etc/wtunnel/client.ini)\n"
        "  -v          Verbose output (-v = info, -vv = debug, default: error only)\n"
        "  -h          Show this help message\n"
        "\n"
        "Example:\n"
        "  %s -p 8080 -H tunnel.example.com -P 443 -K mysecret -F chrome146.txt\n",
        prog, prog);
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    std::string config_path = "/etc/wtunnel/client.ini";
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-c") == 0) { config_path = argv[i + 1]; break; }
    }

    ClientConfig cfg = load_ini(config_path);

    optind = 1;
#ifdef _WIN32
    optind_w = 1;
#endif
    int opt;
    while ((opt = getopt(argc, argv, "p:H:P:K:F:c:vh")) != -1) {
        switch (opt) {
        case 'p': cfg.local_port       = (uint16_t)std::stoi(optarg); break;
        case 'H': cfg.tunnel_host      = optarg;                       break;
        case 'P': cfg.tunnel_port      = (uint16_t)std::stoi(optarg); break;
        case 'K': cfg.reality_psk      = optarg;                       break;
        case 'F': cfg.fingerprint_path = optarg;                       break;
        case 'v': ++cfg.verbose;                                        break;
        case 'c': break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }
    if (cfg.verbose >= 2)      set_log_level(LOG_DEBUG);
    else if (cfg.verbose == 1) set_log_level(LOG_INFO);

    PROXY_LOG_INFO("[main] Starting wtunnel client");
    PROXY_LOG_INFO("[main] Config file : " << config_path);
    PROXY_LOG_INFO("[main] Local proxy  : 0.0.0.0:" << cfg.local_port);
    PROXY_LOG_INFO("[main] Tunnel server: " << cfg.tunnel_host << ":" << cfg.tunnel_port);
    if (!cfg.reality_psk.empty())
        PROXY_LOG_INFO("[main] REALITY mode  : enabled");

    ProxyServer proxy(cfg.local_port, cfg.tunnel_host, cfg.tunnel_port,
                      cfg.reality_psk, cfg.fingerprint_path);
    proxy.run();
    return 0;
}
