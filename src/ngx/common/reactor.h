#pragma once

#include <functional>
#include <unordered_map>

#ifdef _WIN32
    #include "epoll_compat_win.h"
    #ifdef ERROR
        #undef ERROR
    #endif
#else
    #include <sys/epoll.h>
#endif

namespace Event {
    constexpr int READABLE = 0x01;
    constexpr int WRITABLE = 0x02;
    constexpr int ERROR = 0x04;
}

class Reactor {
public:
    using Callback = std::function<void(int fd, int events)>;
    
    Reactor();
    ~Reactor();
    
    bool init();
    void shutdown();
    
    bool add(int fd, int events, Callback callback);
    bool modify(int fd, int events);
    bool remove(int fd);
    
    bool arm(int fd, int events);
    bool disarm(int fd);
    
    int wait(int timeout_ms);

private:
    struct FdInfo {
        int events;
        Callback callback;
        bool armed;
    };
    
    int epoll_fd_;
    std::unordered_map<int, FdInfo> fds_;
    
    bool initialized_;
};
