#pragma once

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

constexpr int EPOLL_CLOEXEC = 0x80000;
constexpr int EPOLL_CTL_ADD = 1;
constexpr int EPOLL_CTL_DEL = 2;
constexpr int EPOLL_CTL_MOD = 3;

constexpr uint32_t EPOLLIN = 0x001;
constexpr uint32_t EPOLLOUT = 0x004;
constexpr uint32_t EPOLLERR = 0x008;
constexpr uint32_t EPOLLHUP = 0x010;

struct epoll_event {
    uint32_t events;
    union {
        void* ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
    } data;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, epoll_event* event);
int epoll_wait(int epfd, epoll_event* events, int maxevents, int timeout);
int epoll_close(int epfd);

#endif

