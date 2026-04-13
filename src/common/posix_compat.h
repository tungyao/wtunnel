#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <unordered_map>

using ssize_t = SSIZE_T;
using socklen_t = int;

#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 0x800
#endif
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 0x80000
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SO_REUSEPORT
#define SO_REUSEPORT SO_REUSEADDR
#endif

namespace posix_compat {

inline std::mutex g_fd_map_mu;
inline std::unordered_map<int, SOCKET> g_fd_to_socket;
inline std::unordered_map<SOCKET, int> g_socket_to_fd;
inline std::atomic<int> g_next_fd{100};

inline int register_socket(SOCKET s) {
    if (s == INVALID_SOCKET) {
        return -1;
    }
    std::lock_guard<std::mutex> lock(g_fd_map_mu);
    const int fd = g_next_fd.fetch_add(1);
    g_fd_to_socket[fd] = s;
    g_socket_to_fd[s] = fd;
    return fd;
}

inline SOCKET native_socket(int fd) {
    std::lock_guard<std::mutex> lock(g_fd_map_mu);
    const auto it = g_fd_to_socket.find(fd);
    if (it == g_fd_to_socket.end()) {
        return INVALID_SOCKET;
    }
    return it->second;
}

inline int unregister_socket_fd(int fd, SOCKET* out_socket = nullptr) {
    std::lock_guard<std::mutex> lock(g_fd_map_mu);
    const auto it = g_fd_to_socket.find(fd);
    if (it == g_fd_to_socket.end()) {
        return -1;
    }
    const SOCKET s = it->second;
    g_fd_to_socket.erase(it);
    g_socket_to_fd.erase(s);
    if (out_socket) {
        *out_socket = s;
    }
    return 0;
}

inline int socket_fd(int af, int type, int protocol) {
    const SOCKET s = ::WSASocket(af, type, protocol, nullptr, 0, 0);
    return register_socket(s);
}

inline int accept_fd(int fd, sockaddr* addr, socklen_t* addrlen) {
    SOCKET s = native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    const SOCKET accepted = ::accept(s, addr, addrlen);
    return register_socket(accepted);
}

inline int bind_fd(int fd, const sockaddr* name, socklen_t namelen) {
    SOCKET s = native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::bind(s, name, namelen);
}

inline int listen_fd(int fd, int backlog) {
    SOCKET s = native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::listen(s, backlog);
}

inline int connect_fd(int fd, const sockaddr* name, socklen_t namelen) {
    SOCKET s = native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::connect(s, name, namelen);
}

inline ssize_t recv_fd(int fd, void* buf, size_t len, int flags) {
    SOCKET s = native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::recv(s, static_cast<char*>(buf), static_cast<int>(len), flags);
}

inline ssize_t send_fd(int fd, const void* buf, size_t len, int flags) {
    SOCKET s = native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::send(s, static_cast<const char*>(buf), static_cast<int>(len), flags);
}

inline int eventfd(unsigned int /*initval*/, int flags) {
    SOCKET s = ::WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, 0);
    if (s == INVALID_SOCKET) {
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        ::closesocket(s);
        return -1;
    }

    int addr_len = sizeof(addr);
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &addr_len) == SOCKET_ERROR) {
        ::closesocket(s);
        return -1;
    }

    if (::connect(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        ::closesocket(s);
        return -1;
    }

    if (flags & EFD_NONBLOCK) {
        u_long mode = 1;
        ::ioctlsocket(s, FIONBIO, &mode);
    }

    return register_socket(s);
}

} // namespace posix_compat

inline ssize_t read(int fd, void* buf, size_t len) {
    return posix_compat::recv_fd(fd, buf, len, 0);
}

inline ssize_t write(int fd, const void* buf, size_t len) {
    return posix_compat::send_fd(fd, buf, len, 0);
}

inline int close(int fd) {
    SOCKET s = INVALID_SOCKET;
    if (posix_compat::unregister_socket_fd(fd, &s) != 0 || s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::closesocket(s);
}

inline int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    SOCKET s = posix_compat::native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::setsockopt(s, level, optname,
                        reinterpret_cast<const char*>(optval), optlen);
}

inline int getsockopt(int fd, int level, int optname, void* optval, socklen_t* optlen) {
    SOCKET s = posix_compat::native_socket(fd);
    if (s == INVALID_SOCKET) {
        WSASetLastError(WSAENOTSOCK);
        return -1;
    }
    return ::getsockopt(s, level, optname,
                        reinterpret_cast<char*>(optval), optlen);
}

inline int eventfd(unsigned int initval, int flags) {
    return posix_compat::eventfd(initval, flags);
}

inline void* memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    if (needle_len == 0) return const_cast<void*>(haystack);
    if (haystack_len < needle_len) return nullptr;
    const unsigned char* h = static_cast<const unsigned char*>(haystack);
    const unsigned char* n = static_cast<const unsigned char*>(needle);
    for (size_t i = 0; i + needle_len <= haystack_len; ++i) {
        if (std::memcmp(h + i, n, needle_len) == 0) {
            return const_cast<unsigned char*>(h + i);
        }
    }
    return nullptr;
}

#endif
