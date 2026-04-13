#include "reactor.h"
#include "logging.h"
#include <algorithm>
#include <unistd.h>

Reactor::Reactor()
    : epoll_fd_(-1)
    , initialized_(false) {
}

Reactor::~Reactor() {
    shutdown();
}

bool Reactor::init() {
    if (initialized_) {
        return true;
    }

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        PROXY_LOG_ERROR("epoll_create1 failed: " << errno);
        return false;
    }
    initialized_ = true;
    return true;
}

void Reactor::shutdown() {
    if (!initialized_) return;

    if (epoll_fd_ >= 0) {
#ifdef _WIN32
        epoll_close(epoll_fd_);
#else
        close(epoll_fd_);
#endif
        epoll_fd_ = -1;
    }
    fds_.clear();
    initialized_ = false;
}

bool Reactor::add(int fd, int events, Callback callback) {
    if (!initialized_) return false;

    if (fds_.find(fd) != fds_.end()) {
        return false;
    }
    
    struct epoll_event ev;
    ev.events = 0;
    if (events & Event::READABLE) ev.events |= EPOLLIN;
    if (events & Event::WRITABLE) ev.events |= EPOLLOUT;
    ev.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        PROXY_LOG_ERROR("epoll_ctl ADD failed for fd=" << fd << " errno=" << errno);
        return false;
    }
    
    FdInfo info;
    info.events = events;
    info.callback = std::move(callback);
    info.armed = true;
    fds_[fd] = info;
    return true;
}

bool Reactor::modify(int fd, int events) {
    if (!initialized_) return false;

    auto it = fds_.find(fd);
    if (it == fds_.end()) {
        return false;
    }
    
    struct epoll_event ev;
    ev.events = 0;
    if (events & Event::READABLE) ev.events |= EPOLLIN;
    if (events & Event::WRITABLE) ev.events |= EPOLLOUT;
    ev.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
        PROXY_LOG_ERROR("epoll_ctl MOD failed for fd=" << fd << " errno=" << errno);
        return false;
    }
    
    it->second.events = events;
    return true;
}

bool Reactor::remove(int fd) {
    if (!initialized_) return false;

    auto it = fds_.find(fd);
    if (it == fds_.end()) {
        return false;
    }
    
    struct epoll_event ev;
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, &ev);
    fds_.erase(it);
    return true;
}

bool Reactor::arm(int fd, int events) {
    if (!initialized_) return false;

    auto it = fds_.find(fd);
    if (it == fds_.end()) {
        return false;
    }
    
    struct epoll_event ev;
    ev.events = 0;
    if (events & Event::READABLE) ev.events |= EPOLLIN;
    if (events & Event::WRITABLE) ev.events |= EPOLLOUT;
    ev.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
        return false;
    }
    
    it->second.armed = true;
    it->second.events = events;
    return true;
}

bool Reactor::disarm(int fd) {
    if (!initialized_) return false;

    auto it = fds_.find(fd);
    if (it == fds_.end()) {
        return false;
    }
    
    struct epoll_event ev;
    ev.events = 0;
    ev.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
        return false;
    }
    
    it->second.armed = false;
    return true;
}

int Reactor::wait(int timeout_ms) {
    if (!initialized_) return -1;

    const int MAX_EVENTS = 128;
    struct epoll_event events[MAX_EVENTS];
    
    int n = epoll_wait(epoll_fd_, events, MAX_EVENTS, timeout_ms);
    if (n <= 0) {
        return n;
    }
    
    int triggered = 0;
    for (int i = 0; i < n; ++i) {
        int fd = events[i].data.fd;
        auto it = fds_.find(fd);
        if (it == fds_.end() || !it->second.armed) continue;
        
        int ev = 0;
        if (events[i].events & EPOLLIN) ev |= Event::READABLE;
        if (events[i].events & EPOLLOUT) ev |= Event::WRITABLE;
        
        bool has_error = (events[i].events & (EPOLLERR | EPOLLHUP)) != 0;
        bool has_read = (events[i].events & EPOLLIN) != 0;
        bool has_write = (events[i].events & EPOLLOUT) != 0;
        
        if (has_error) {
            if (has_read || has_write) {
                ev |= Event::ERROR;
            }
        }
        
        if (ev && it->second.callback) {
            it->second.callback(fd, ev);
            triggered++;
        }
    }
    
    return triggered;
}
