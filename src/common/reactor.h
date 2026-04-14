#pragma once

#include <functional>
#include <unordered_map>
#include <uv.h>

// uv.h on Windows pulls in windows.h which defines ERROR as a macro
#ifdef ERROR
    #undef ERROR
#endif

namespace Event {
    constexpr int READABLE = 0x01;
    constexpr int WRITABLE = 0x02;
    constexpr int ERROR    = 0x04;
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
        int       fd;
        int       events;
        Callback  callback;
        bool      armed;
        uv_poll_t handle;   // libuv poll handle (one per fd)
    };

    static void poll_cb(uv_poll_t* handle, int status, int uv_events);

    uv_loop_t*  loop_;
    bool        loop_owned_;   // true → we created the loop, we must free it
    bool        initialized_;
    std::unordered_map<int, FdInfo*> fds_;  // heap-allocated so address is stable
};
