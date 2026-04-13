#ifdef _WIN32

#include "epoll_compat_win.h"
#include "posix_compat.h"

#include <unordered_map>
#include <vector>
#include <mutex>
#include <memory>

namespace {

struct EpollInstance {
    struct Registered {
        SOCKET socket;
        epoll_event event;
    };
    std::unordered_map<int, Registered> registry;
};

std::mutex g_mu;
std::unordered_map<int, std::unique_ptr<EpollInstance>> g_instances;
int g_next_id = 1;

EpollInstance* lookup_instance(int epfd) {
    auto it = g_instances.find(epfd);
    if (it == g_instances.end()) {
        return nullptr;
    }
    return it->second.get();
}

}  // namespace

int epoll_create1(int /*flags*/) {
    std::lock_guard<std::mutex> lock(g_mu);
    const int id = g_next_id++;
    g_instances[id] = std::make_unique<EpollInstance>();
    return id;
}

int epoll_ctl(int epfd, int op, int fd, epoll_event* event) {
    std::lock_guard<std::mutex> lock(g_mu);
    EpollInstance* inst = lookup_instance(epfd);
    if (!inst) {
        WSASetLastError(WSAEBADF);
        return -1;
    }

    auto it = inst->registry.find(fd);

    switch (op) {
    case EPOLL_CTL_ADD:
        if (!event || it != inst->registry.end()) {
            WSASetLastError(WSAEINVAL);
            return -1;
        }
        {
            const SOCKET sock = posix_compat::native_socket(fd);
            if (sock == INVALID_SOCKET) {
                WSASetLastError(WSAENOTSOCK);
                return -1;
            }
            inst->registry[fd] = EpollInstance::Registered{sock, *event};
        }
        return 0;
    case EPOLL_CTL_MOD:
        if (!event || it == inst->registry.end()) {
            WSASetLastError(WSAEINVAL);
            return -1;
        }
        it->second.event = *event;
        return 0;
    case EPOLL_CTL_DEL:
        if (it == inst->registry.end()) {
            WSASetLastError(WSAEINVAL);
            return -1;
        }
        inst->registry.erase(it);
        return 0;
    default:
        WSASetLastError(WSAEINVAL);
        return -1;
    }
}

int epoll_wait(int epfd, epoll_event* events, int maxevents, int timeout) {
    if (!events || maxevents <= 0) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }

    std::vector<WSAPOLLFD> pfds;
    std::vector<epoll_event> metadata;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        EpollInstance* inst = lookup_instance(epfd);
        if (!inst) {
            WSASetLastError(WSAEBADF);
            return -1;
        }

        pfds.reserve(inst->registry.size());
        metadata.reserve(inst->registry.size());
        for (const auto& [fd, reg] : inst->registry) {
            WSAPOLLFD pfd{};
            pfd.fd = reg.socket;
            if (reg.event.events & EPOLLIN) {
                pfd.events |= POLLRDNORM;
            }
            if (reg.event.events & EPOLLOUT) {
                pfd.events |= POLLWRNORM;
            }
            pfds.push_back(pfd);
            metadata.push_back(reg.event);
            metadata.back().data.fd = fd;
        }
    }

    if (pfds.empty()) {
        if (timeout > 0) {
            Sleep(timeout);
        }
        return 0;
    }

    const int rc = WSAPoll(pfds.data(), static_cast<ULONG>(pfds.size()), timeout);
    if (rc <= 0) {
        return rc;
    }

    int out = 0;
    for (size_t i = 0; i < pfds.size() && out < maxevents; ++i) {
        short re = pfds[i].revents;
        if (re == 0) {
            continue;
        }

        epoll_event out_ev = metadata[i];
        out_ev.events = 0;
        if (re & (POLLRDNORM | POLLRDBAND | POLLIN)) {
            out_ev.events |= EPOLLIN;
        }
        if (re & (POLLWRNORM | POLLWRBAND | POLLOUT)) {
            out_ev.events |= EPOLLOUT;
        }
        if (re & POLLERR) {
            out_ev.events |= EPOLLERR;
        }
        if (re & POLLHUP) {
            out_ev.events |= EPOLLHUP;
        }
        if (out_ev.events != 0) {
            events[out++] = out_ev;
        }
    }

    return out;
}

int epoll_close(int epfd) {
    std::lock_guard<std::mutex> lock(g_mu);
    auto it = g_instances.find(epfd);
    if (it == g_instances.end()) {
        WSASetLastError(WSAEBADF);
        return -1;
    }
    g_instances.erase(it);
    return 0;
}

#endif
