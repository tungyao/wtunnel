#include "reactor.h"
#include "logging.h"
#ifdef _WIN32
#  include "posix_compat.h"
#endif

// ── helpers ──────────────────────────────────────────────────────────────────

// Convert our Event flags → libuv poll events
static int to_uv_events(int ev) {
    int uv_ev = 0;
    if (ev & Event::READABLE) uv_ev |= UV_READABLE;
    if (ev & Event::WRITABLE) uv_ev |= UV_WRITABLE;
    return uv_ev;
}

// Convert libuv poll events → our Event flags
static int from_uv_events(int uv_ev, int status) {
    int ev = 0;
    if (status < 0) {
        // libuv signals errors via negative status
        ev |= Event::ERROR | Event::READABLE;
        return ev;
    }
    if (uv_ev & UV_READABLE)    ev |= Event::READABLE;
    if (uv_ev & UV_WRITABLE)    ev |= Event::WRITABLE;
    if (uv_ev & UV_DISCONNECT)  ev |= Event::READABLE; // peer half-close → treat as readable
    return ev;
}

// ── Reactor ───────────────────────────────────────────────────────────────────

Reactor::Reactor()
    : loop_(nullptr)
    , loop_owned_(false)
    , initialized_(false) {}

Reactor::~Reactor() {
    shutdown();
}

bool Reactor::init() {
    if (initialized_) return true;

    loop_ = new uv_loop_t;
    if (uv_loop_init(loop_) != 0) {
        PROXY_LOG_ERROR("uv_loop_init failed");
        delete loop_;
        loop_ = nullptr;
        return false;
    }
    loop_owned_ = true;
    initialized_ = true;
    return true;
}

void Reactor::shutdown() {
    if (!initialized_) return;

    // Stop and close every poll handle
    for (auto& [fd, info] : fds_) {
        uv_poll_stop(&info->handle);
        uv_close(reinterpret_cast<uv_handle_t*>(&info->handle), nullptr);
    }
    // Run the loop once so libuv can process the close callbacks
    if (loop_) uv_run(loop_, UV_RUN_NOWAIT);

    for (auto& [fd, info] : fds_) delete info;
    fds_.clear();

    if (loop_owned_ && loop_) {
        uv_loop_close(loop_);
        delete loop_;
        loop_ = nullptr;
    }
    initialized_ = false;
}

// ── poll callback (static) ────────────────────────────────────────────────────

void Reactor::poll_cb(uv_poll_t* handle, int status, int uv_events) {
    auto* info = static_cast<FdInfo*>(handle->data);
    if (!info->armed) return;

    int ev = from_uv_events(uv_events, status);
    if (ev && info->callback) {
        info->callback(info->fd, ev);
    }
}

// ── public API ────────────────────────────────────────────────────────────────

bool Reactor::add(int fd, int events, Callback callback) {
    if (!initialized_) return false;
    if (fds_.count(fd)) return false;

    auto* info = new FdInfo;
    info->fd       = fd;
    info->events   = events;
    info->callback = std::move(callback);
    info->armed    = true;
    info->handle.data = info;

#ifdef _WIN32
    SOCKET sock = posix_compat::native_socket(fd);
    int uv_init_ret = (sock != INVALID_SOCKET)
        ? uv_poll_init_socket(loop_, &info->handle, sock)
        : uv_poll_init(loop_, &info->handle, fd);
#else
    int uv_init_ret = uv_poll_init(loop_, &info->handle, fd);
#endif
    if (uv_init_ret != 0) {
        PROXY_LOG_ERROR("uv_poll_init failed for fd=" << fd);
        delete info;
        return false;
    }

    int uv_ev = to_uv_events(events);
    if (uv_ev && uv_poll_start(&info->handle, uv_ev, poll_cb) != 0) {
        PROXY_LOG_ERROR("uv_poll_start failed for fd=" << fd);
        uv_close(reinterpret_cast<uv_handle_t*>(&info->handle), nullptr);
        uv_run(loop_, UV_RUN_NOWAIT);
        delete info;
        return false;
    }

    fds_[fd] = info;
    return true;
}

bool Reactor::modify(int fd, int events) {
    if (!initialized_) return false;
    auto it = fds_.find(fd);
    if (it == fds_.end()) return false;

    FdInfo* info = it->second;
    info->events = events;
    info->armed  = true;

    int uv_ev = to_uv_events(events);
    if (uv_ev) {
        uv_poll_start(&info->handle, uv_ev, poll_cb);
    } else {
        uv_poll_stop(&info->handle);
    }
    return true;
}

bool Reactor::remove(int fd) {
    if (!initialized_) return false;
    auto it = fds_.find(fd);
    if (it == fds_.end()) return false;

    FdInfo* info = it->second;
    uv_poll_stop(&info->handle);
    uv_close(reinterpret_cast<uv_handle_t*>(&info->handle),
             [](uv_handle_t* h) {
                 delete static_cast<FdInfo*>(h->data);
             });
    fds_.erase(it);
    return true;
}

bool Reactor::arm(int fd, int events) {
    return modify(fd, events);   // arm = modify + set armed flag (already done in modify)
}

bool Reactor::disarm(int fd) {
    if (!initialized_) return false;
    auto it = fds_.find(fd);
    if (it == fds_.end()) return false;

    FdInfo* info = it->second;
    info->armed = false;
    uv_poll_stop(&info->handle);
    return true;
}

int Reactor::wait(int timeout_ms) {
    if (!initialized_) return -1;

    // UV_RUN_NOWAIT processes ready events without blocking.
    // For a timed wait we use a one-shot timer to break out of UV_RUN_ONCE.
    if (timeout_ms == 0) {
        return uv_run(loop_, UV_RUN_NOWAIT);
    }

    uv_timer_t timer;
    uv_timer_init(loop_, &timer);
    // Dummy callback — just wakes the loop
    uv_timer_start(&timer, [](uv_timer_t*) {}, timeout_ms, 0);

    uv_run(loop_, UV_RUN_ONCE);

    uv_timer_stop(&timer);
    uv_close(reinterpret_cast<uv_handle_t*>(&timer), nullptr);
    uv_run(loop_, UV_RUN_NOWAIT); // drain the close callback

    return 0; // libuv doesn't give a triggered-count; callers only check >=0
}
