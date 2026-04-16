#include "reality_session.h"
#include "tls_session.h"
#include "common/logging.h"
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <ctime>
#include <arpa/inet.h>

// ─── 工具 ─────────────────────────────────────────────────────────────────────

static void set_nb(int fd) {
    int f = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, f | O_NONBLOCK);
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
    set_nb(fd);
    int r = ::connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (r < 0 && errno != EINPROGRESS) { ::close(fd); return -1; }
    return fd;
}

// ─── RealitySession ───────────────────────────────────────────────────────────

RealitySession::RealitySession(int client_fd, Reactor& reactor, TlsContext& tls_ctx,
                               const RealityConfig& cfg, CleanupCallback on_close)
    : client_fd_(client_fd), site_fd_(-1),
      reactor_(reactor), tls_ctx_(tls_ctx),
      cfg_(cfg), on_close_(std::move(on_close)),
      state_(State::PEEKING) {}

RealitySession::~RealitySession() {
    if (site_fd_ >= 0) {
        reactor_.remove(site_fd_);
        ::close(site_fd_);
    }
}

bool RealitySession::start() {
    auto self = shared_from_this();
    reactor_.add(client_fd_, Event::READABLE,
                 [self](int fd, int ev) { self->on_client_readable(fd, ev); });
    return true;
}

// ─── PEEKING：判断客户端类型 ──────────────────────────────────────────────────

void RealitySession::on_client_readable(int fd, int events) {
    if (state_ == State::CLOSING) return;

    if (state_ == State::PEEKING) {
        uint8_t buf[PEEK_LEN];
        // MSG_PEEK：不消耗数据，ClientHello 留在内核缓冲区供后续 TLS 读取
        ssize_t n = recv(client_fd_, buf, PEEK_LEN, MSG_PEEK);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            state_ = State::CLOSING;
            do_close(); return;
        }
        if (n == 0) { state_ = State::CLOSING; do_close(); return; }

        // 需要至少收到完整 TLS 记录头（5 字节）才能判断
        if ((size_t)n < 5) return;

        if (reality_verify_client_hello(buf, (size_t)n, cfg_.psk, TIMESTAMP_WINDOW)) {
            // ── 是我们的客户端 ──────────────────────────────────────────────
            // 数据不消耗，直接交给 TlsSession，它会从 recv 读到完整 ClientHello
            PROXY_LOG_INFO("[reality] identified our client fd=" << client_fd_);
            state_ = State::DELEGATED;
            reactor_.remove(client_fd_);

            auto self = shared_from_this();
            auto cleanup = [self](int fd) {
                PROXY_LOG_INFO("[reality] tls session closed fd=" << fd);
                if (self->on_close_) self->on_close_(fd);
            };
            delegated_ = std::make_shared<TlsSession>(
                client_fd_, reactor_, tls_ctx_, std::move(cleanup));
            if (!delegated_->start_server()) {
                ::close(client_fd_);
                delegated_.reset();
            }
        } else {
            // ── 不是我们的客户端，透传给真实网站 ────────────────────────────
            // 数据仍在内核缓冲区，透传时会自然读出（包含完整 ClientHello）
            PROXY_LOG_INFO("[reality] unknown client, proxying to "
                           << cfg_.target_host << ":" << cfg_.target_port
                           << " fd=" << client_fd_);
            if (!start_proxy()) {
                state_ = State::CLOSING;
                do_close();
            }
        }
        return;
    }

    if (state_ == State::PROXYING) {
        // client → site
        uint8_t buf[16384];
        ssize_t n = recv(client_fd_, buf, sizeof(buf), 0);
        if (n > 0) {
            c2s_buf_.insert(c2s_buf_.end(), buf, buf + n);
            proxy_flush_client_to_site();
        } else if (n == 0) {
            state_ = State::CLOSING; do_close(); return;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            state_ = State::CLOSING; do_close(); return;
        }
        update_site_events();
    }
    (void)fd; (void)events;
}

// ─── 透传代理 ─────────────────────────────────────────────────────────────────

bool RealitySession::start_proxy() {
    site_fd_ = tcp_connect_nb(cfg_.target_host, cfg_.target_port);
    if (site_fd_ < 0) {
        PROXY_LOG_ERROR("[reality] cannot connect to "
                        << cfg_.target_host << ":" << cfg_.target_port);
        return false;
    }
    state_ = State::CONNECTING;
    auto self = shared_from_this();
    reactor_.add(site_fd_, Event::WRITABLE,
                 [self](int fd, int ev) { self->on_site_event(fd, ev); });
    return true;
}

void RealitySession::on_site_event(int fd, int events) {
    if (state_ == State::CLOSING) return;

    if (state_ == State::CONNECTING) {
        int err = 0; socklen_t len = sizeof(err);
        getsockopt(site_fd_, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            PROXY_LOG_ERROR("[reality] site connect failed: " << strerror(err));
            state_ = State::CLOSING; do_close(); return;
        }
        PROXY_LOG_INFO("[reality] site connected fd=" << site_fd_);
        state_ = State::PROXYING;
        reactor_.modify(site_fd_, Event::READABLE);
        // 更新 client 端侧事件（可能有待写数据）
        reactor_.modify(client_fd_, Event::READABLE);
        return;
    }

    if (state_ == State::PROXYING) {
        if (events & Event::READABLE) {
            // site → client
            uint8_t buf[16384];
            ssize_t n = recv(site_fd_, buf, sizeof(buf), 0);
            if (n > 0) {
                s2c_buf_.insert(s2c_buf_.end(), buf, buf + n);
                proxy_flush_site_to_client();
            } else if (n == 0) {
                state_ = State::CLOSING; do_close(); return;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                state_ = State::CLOSING; do_close(); return;
            }
        }
        if (events & Event::WRITABLE) {
            proxy_flush_client_to_site();
        }
        update_site_events();
    }
    (void)fd;
}

void RealitySession::proxy_flush_client_to_site() {
    while (!c2s_buf_.empty() && site_fd_ >= 0) {
        size_t chunk = std::min(c2s_buf_.size(), (size_t)16384);
        uint8_t tmp[16384];
        std::copy(c2s_buf_.begin(), c2s_buf_.begin() + chunk, tmp);
        ssize_t n = send(site_fd_, tmp, chunk, MSG_NOSIGNAL);
        if (n > 0) c2s_buf_.erase(c2s_buf_.begin(), c2s_buf_.begin() + n);
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else { state_ = State::CLOSING; do_close(); return; }
    }
}

void RealitySession::proxy_flush_site_to_client() {
    while (!s2c_buf_.empty()) {
        size_t chunk = std::min(s2c_buf_.size(), (size_t)16384);
        uint8_t tmp[16384];
        std::copy(s2c_buf_.begin(), s2c_buf_.begin() + chunk, tmp);
        ssize_t n = send(client_fd_, tmp, chunk, MSG_NOSIGNAL);
        if (n > 0) s2c_buf_.erase(s2c_buf_.begin(), s2c_buf_.begin() + n);
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        else { state_ = State::CLOSING; do_close(); return; }
    }
}

void RealitySession::update_site_events() {
    if (site_fd_ < 0 || state_ != State::PROXYING) return;
    int ev = Event::READABLE;
    if (!c2s_buf_.empty()) ev |= Event::WRITABLE;
    reactor_.modify(site_fd_, ev);
}

void RealitySession::do_close() {
    state_ = State::CLOSING;
    if (site_fd_ >= 0) {
        reactor_.remove(site_fd_);
        ::close(site_fd_);
        site_fd_ = -1;
    }
    reactor_.remove(client_fd_);
    if (on_close_) on_close_(client_fd_);
}
