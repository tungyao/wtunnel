#include "tls_session.h"
#include "common/logging.h"
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

// ─── 工具 ─────────────────────────────────────────────────────────────────────

static void set_nonblocking(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

// 解析 "host:port" → host + port（IPv6 形如 [::1]:443）
static bool parse_authority(const std::string& auth, std::string& host, uint16_t& port) {
    if (auth.empty()) return false;
    if (auth.front() == '[') {
        // IPv6
        auto rb = auth.rfind(']');
        if (rb == std::string::npos) return false;
        host = auth.substr(1, rb - 1);
        if (rb + 2 >= auth.size()) return false;
        port = (uint16_t)std::stoi(auth.substr(rb + 2));
    } else {
        auto col = auth.rfind(':');
        if (col == std::string::npos) return false;
        host = auth.substr(0, col);
        port = (uint16_t)std::stoi(auth.substr(col + 1));
    }
    return true;
}

static int tcp_connect_nb(const std::string& host, uint16_t port) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string ps = std::to_string(port);
    if (getaddrinfo(host.c_str(), ps.c_str(), &hints, &res) != 0 || !res)
        return -1;
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    set_nonblocking(fd);
    int r = ::connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (r < 0 && errno != EINPROGRESS) { ::close(fd); return -1; }
    return fd;
}

// ─── TlsSession ───────────────────────────────────────────────────────────────

TlsSession::TlsSession(int fd, Reactor& reactor, TlsContext& ctx, CleanupCallback on_close)
    : fd_(fd), is_server_(ctx.is_server()), reactor_(reactor),
      h2_session_(nullptr), state_(State::HANDSHAKING), ctx_(ctx),
      on_close_(std::move(on_close)) {
}

TlsSession::~TlsSession() {
    // Close all upstream connections
    for (auto& [sid, si] : streams_) {
        if (si.upstream_fd >= 0) {
            reactor_.remove(si.upstream_fd);
            ::close(si.upstream_fd);
        }
    }
    streams_.clear();
    if (h2_session_) {
        nghttp2_session_del(h2_session_);
        h2_session_ = nullptr;
    }
    tls_sock_.close();
}

// ── 启动 ──────────────────────────────────────────────────────────────────────

bool TlsSession::start_client(const std::string& hostname) {
    if (!tls_sock_.connect(fd_, ctx_, hostname)) return false;
    auto self = shared_from_this();
    reactor_.add(fd_, Event::READABLE | Event::WRITABLE,
                 [self](int fd, int ev) { self->on_event(fd, ev); });
    return true;
}

bool TlsSession::start_server() {
    if (!tls_sock_.accept(fd_, ctx_)) return false;
    auto self = shared_from_this();
    reactor_.add(fd_, Event::READABLE,
                 [self](int fd, int ev) { self->on_event(fd, ev); });
    return true;
}

// ── 事件分发 ──────────────────────────────────────────────────────────────────

void TlsSession::on_event(int fd, int events) {
    if (state_ == State::CLOSING) return;

    if (state_ == State::HANDSHAKING) {
        handle_handshake();
    } else if (state_ == State::DATA_TRANSFER) {
        if (events & Event::READABLE) handle_read();
        bool drive_write = (events & Event::WRITABLE)
                        || ((events & Event::READABLE) && tls_sock_.want_read()
                            && (!write_buffer_.empty()
                                || (h2_session_ && nghttp2_session_want_write(h2_session_))));
        if (state_ != State::CLOSING && drive_write) handle_write();
    }

    if (state_ == State::CLOSING) do_close();
    else update_reactor();
    (void)fd;
}

// ── 握手 ──────────────────────────────────────────────────────────────────────

void TlsSession::handle_handshake() {
    if (!tls_sock_.continue_handshake()) { state_ = State::CLOSING; return; }
    if (!tls_sock_.is_connected()) return;

    PROXY_LOG_INFO("[session] TLS handshake done fd=" << fd_);
    state_ = State::DATA_TRANSFER;

    nghttp2_session_callbacks* cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs, send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_callback);

    int rv;
    if (is_server_) {
        rv = nghttp2_session_server_new(&h2_session_, cbs, this);
        if (rv == 0) {
            nghttp2_settings_entry se[] = {
                { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
                { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1 << 20 },
            };
            nghttp2_submit_settings(h2_session_, NGHTTP2_FLAG_NONE, se, 2);
            nghttp2_submit_window_update(h2_session_, NGHTTP2_FLAG_NONE, 0, (1 << 20) - 65535);
        }
    } else {
        rv = nghttp2_session_client_new(&h2_session_, cbs, this);
        if (rv == 0) nghttp2_submit_settings(h2_session_, NGHTTP2_FLAG_NONE, nullptr, 0);
    }
    nghttp2_session_callbacks_del(cbs);

    if (rv != 0) { state_ = State::CLOSING; }
}

// ── 读 ────────────────────────────────────────────────────────────────────────

void TlsSession::handle_read() {
    uint8_t buf[16384];
    do {
        ssize_t nread = tls_sock_.read(buf, sizeof(buf));
        if (nread > 0) {
            ssize_t rv = nghttp2_session_mem_recv(h2_session_, buf, nread);
            if (rv < 0) { state_ = State::CLOSING; return; }
        } else if (nread == 0) {
            state_ = State::CLOSING; return;
        } else {
            break;
        }
    } while (tls_sock_.has_pending());
}

// ── 写 ────────────────────────────────────────────────────────────────────────

void TlsSession::handle_write() {
    while (!write_buffer_.empty()) {
        size_t chunk = std::min(write_buffer_.size(), (size_t)16384);
        uint8_t tmp[16384];
        std::copy(write_buffer_.begin(), write_buffer_.begin() + chunk, tmp);
        ssize_t n = tls_sock_.write(tmp, chunk);
        if (n > 0) write_buffer_.erase(write_buffer_.begin(), write_buffer_.begin() + n);
        else return;
    }
    int rv = nghttp2_session_send(h2_session_);
    if (rv != 0) { state_ = State::CLOSING; }
}

// ── 关闭 ──────────────────────────────────────────────────────────────────────

void TlsSession::do_close() {
    reactor_.remove(fd_);
    if (on_close_) on_close_(fd_);
}

// ── Reactor 更新 ──────────────────────────────────────────────────────────────

void TlsSession::update_reactor() {
    int ev = Event::READABLE;
    bool need_write = tls_sock_.want_write()
                   || !write_buffer_.empty()
                   || (h2_session_ && nghttp2_session_want_write(h2_session_));
    if (need_write) ev |= Event::WRITABLE;
    reactor_.modify(fd_, ev);
}

// ─── CONNECT 隧道 ─────────────────────────────────────────────────────────────

void TlsSession::open_upstream(int32_t stream_id, StreamInfo& si) {
    std::string host; uint16_t port = 0;
    if (!parse_authority(si.authority, host, port)) {
        PROXY_LOG_ERROR("[session] bad authority: " << si.authority);
        // Refuse with RST
        nghttp2_submit_rst_stream(h2_session_, NGHTTP2_FLAG_NONE,
                                   stream_id, NGHTTP2_REFUSED_STREAM);
        return;
    }

    int ufd = tcp_connect_nb(host, port);
    if (ufd < 0) {
        PROXY_LOG_ERROR("[session] upstream connect failed: " << host << ":" << port);
        nghttp2_nv hdr = { (uint8_t*)":status", (uint8_t*)"502", 7, 3, NGHTTP2_NV_FLAG_NONE };
        nghttp2_submit_headers(h2_session_, NGHTTP2_FLAG_END_STREAM,
                               stream_id, nullptr, &hdr, 1, nullptr);
        return;
    }

    si.upstream_fd = ufd;
    si.connected   = false;  // will be confirmed on WRITABLE

    PROXY_LOG_INFO("[session] upstream connecting fd=" << ufd
                   << " -> " << host << ":" << port << " stream=" << stream_id);

    auto self = shared_from_this();
    reactor_.add(ufd, Event::WRITABLE,
                 [self, stream_id, ufd](int, int ev) {
                     self->on_upstream_event(stream_id, ufd, ev);
                 });
}

void TlsSession::on_upstream_event(int32_t stream_id, int upstream_fd, int events) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    StreamInfo& si = it->second;

    if (!si.connected) {
        // Check if connect(2) completed
        int err = 0; socklen_t len = sizeof(err);
        getsockopt(upstream_fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            PROXY_LOG_ERROR("[session] upstream connect error stream=" << stream_id
                            << " err=" << strerror(err));
            close_stream(stream_id);
            return;
        }
        si.connected = true;
        PROXY_LOG_INFO("[session] upstream connected stream=" << stream_id
                       << " fd=" << upstream_fd);

        // Send 200 to client
        nghttp2_nv hdr = { (uint8_t*)":status", (uint8_t*)"200", 7, 3, NGHTTP2_NV_FLAG_NONE };
        nghttp2_submit_headers(h2_session_, NGHTTP2_FLAG_NONE,
                               stream_id, nullptr, &hdr, 1, nullptr);
        // Switch to READABLE | WRITABLE for upstream
        reactor_.modify(upstream_fd, Event::READABLE);
        update_reactor();  // drive H2 write immediately
        return;
    }

    if (events & Event::READABLE) relay_to_client(stream_id, si);
    if (events & Event::WRITABLE) relay_to_upstream(stream_id, si);

    // Update upstream event mask
    if (si.upstream_fd >= 0) {
        int uev = Event::READABLE;
        if (!si.up_write.empty()) uev |= Event::WRITABLE;
        reactor_.modify(upstream_fd, uev);
    }
    update_reactor();
}

void TlsSession::relay_to_upstream(int32_t stream_id, StreamInfo& si) {
    while (!si.up_write.empty()) {
        size_t chunk = std::min(si.up_write.size(), (size_t)16384);
        uint8_t tmp[16384];
        std::copy(si.up_write.begin(), si.up_write.begin() + chunk, tmp);
        ssize_t n = ::send(si.upstream_fd, tmp, chunk, MSG_NOSIGNAL);
        if (n > 0) {
            si.up_write.erase(si.up_write.begin(), si.up_write.begin() + n);
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            close_stream(stream_id);
            return;
        }
    }
}

ssize_t TlsSession::relay_data_read_cb(nghttp2_session* /*session*/, int32_t /*stream_id*/,
                                        uint8_t* buf, size_t cap, uint32_t* data_flags,
                                        nghttp2_data_source* source, void* /*user_data*/) {
    auto* src = static_cast<DataSrc*>(source->ptr);
    if (src->chunks.empty()) {
        if (src->eof) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            delete src;
            source->ptr = nullptr;
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

void TlsSession::relay_to_client(int32_t stream_id, StreamInfo& si) {
    uint8_t buf[16384];
    ssize_t n = ::recv(si.upstream_fd, buf, sizeof(buf), 0);
    if (n > 0) {
        if (!si.data_src) {
            // First data: create persistent data source and submit provider
            si.data_src = new DataSrc();
            si.data_src->chunks.push_back(std::vector<uint8_t>(buf, buf + n));
            nghttp2_data_provider prov;
            prov.source.ptr = si.data_src;
            prov.read_callback = relay_data_read_cb;
            nghttp2_submit_data(h2_session_, NGHTTP2_FLAG_NONE, stream_id, &prov);
        } else {
            // Subsequent data: add to queue and un-defer the provider
            si.data_src->chunks.push_back(std::vector<uint8_t>(buf, buf + n));
            nghttp2_session_resume_data(h2_session_, stream_id);
        }
    } else if (n == 0) {
        // Upstream closed — signal EOF through the data source
        if (si.data_src) {
            si.data_src->eof = true;
            nghttp2_session_resume_data(h2_session_, stream_id);
            si.data_src = nullptr;  // callback will free it
        } else {
            nghttp2_submit_rst_stream(h2_session_, NGHTTP2_FLAG_NONE,
                                       stream_id, NGHTTP2_NO_ERROR);
        }
        reactor_.remove(si.upstream_fd);
        ::close(si.upstream_fd);
        si.upstream_fd = -1;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        close_stream(stream_id);
    }
}

void TlsSession::close_stream(int32_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return;
    StreamInfo& si = it->second;
    // Free the data source before RST (nghttp2 won't call callback after RST)
    delete si.data_src;
    si.data_src = nullptr;
    if (si.upstream_fd >= 0) {
        reactor_.remove(si.upstream_fd);
        ::close(si.upstream_fd);
        si.upstream_fd = -1;
    }
    nghttp2_submit_rst_stream(h2_session_, NGHTTP2_FLAG_NONE,
                               stream_id, NGHTTP2_NO_ERROR);
    streams_.erase(it);
    update_reactor();
}

// ─── nghttp2 回调 ─────────────────────────────────────────────────────────────

ssize_t TlsSession::send_callback(nghttp2_session* /*session*/, const uint8_t* data,
                                   size_t length, int /*flags*/, void* user_data) {
    auto* self = static_cast<TlsSession*>(user_data);
    if (!self->write_buffer_.empty()) return NGHTTP2_ERR_WOULDBLOCK;
    ssize_t n = self->tls_sock_.write(data, length);
    if (n < 0) {
        if (self->tls_sock_.want_write() || self->tls_sock_.want_read())
            return NGHTTP2_ERR_WOULDBLOCK;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if ((size_t)n < length)
        self->write_buffer_.insert(self->write_buffer_.end(), data + n, data + length);
    return (ssize_t)length;
}

int TlsSession::on_header_callback(nghttp2_session* /*session*/,
                                    const nghttp2_frame* frame,
                                    const uint8_t* name, size_t namelen,
                                    const uint8_t* value, size_t valuelen,
                                    uint8_t /*flags*/, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    auto* self = static_cast<TlsSession*>(user_data);
    int32_t sid = frame->hd.stream_id;

    auto& si = self->streams_[sid];  // create if absent
    std::string n_str((const char*)name,  namelen);
    std::string v_str((const char*)value, valuelen);

    if (n_str == ":method")    si.method    = v_str;
    if (n_str == ":authority") si.authority = v_str;
    return 0;
}

int TlsSession::on_frame_recv_callback(nghttp2_session* /*session*/,
                                        const nghttp2_frame* frame, void* user_data) {
    auto* self = static_cast<TlsSession*>(user_data);
    PROXY_LOG_DEBUG("[session] fd=" << self->fd_
                    << " frame_recv type=" << (int)frame->hd.type);

    if (!self->is_server_) return 0;

    int32_t sid = frame->hd.stream_id;
    if (frame->hd.type == NGHTTP2_HEADERS
        && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        auto it = self->streams_.find(sid);
        if (it != self->streams_.end() && it->second.method == "CONNECT") {
            self->open_upstream(sid, it->second);
        }
    }
    return 0;
}

int TlsSession::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t /*flags*/,
                                             int32_t stream_id, const uint8_t* data,
                                             size_t len, void* user_data) {
    auto* self = static_cast<TlsSession*>(user_data);

    // Acknowledge received bytes so nghttp2 sends WINDOW_UPDATE to keep the window open
    nghttp2_session_consume(session, stream_id, len);

    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end() || it->second.upstream_fd < 0) return 0;

    StreamInfo& si = it->second;
    si.up_write.insert(si.up_write.end(), data, data + len);
    if (si.connected) {
        self->relay_to_upstream(stream_id, si);
        if (si.upstream_fd >= 0) {
            int uev = Event::READABLE;
            if (!si.up_write.empty()) uev |= Event::WRITABLE;
            self->reactor_.modify(si.upstream_fd, uev);
        }
    }
    return 0;
}

int TlsSession::on_stream_close_callback(nghttp2_session* /*session*/, int32_t stream_id,
                                          uint32_t error_code, void* user_data) {
    auto* self = static_cast<TlsSession*>(user_data);
    PROXY_LOG_DEBUG("[session] fd=" << self->fd_ << " stream=" << stream_id
                    << " closed err=" << error_code);
    auto it = self->streams_.find(stream_id);
    if (it != self->streams_.end()) {
        delete it->second.data_src;
        if (it->second.upstream_fd >= 0) {
            self->reactor_.remove(it->second.upstream_fd);
            ::close(it->second.upstream_fd);
        }
        self->streams_.erase(it);
    }
    return 0;
}
