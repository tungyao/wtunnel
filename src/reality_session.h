#pragma once
#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include <string>
#include <functional>
#include <deque>
#include <vector>
#include <memory>

// 前向声明：只有服务端才实例化 TlsSession
class TlsSession;

#include "reality_marker.h"

struct RealityConfig {
    std::string target_host;    // 伪装的真实网站 host，e.g. "www.microsoft.com"
    uint16_t    target_port = 443;
    std::string psk;            // 预共享密钥，用于 HMAC 验证
};

// RealitySession 在普通 TCP accept 之后、TLS 之前工作。
// 它 peek 足够覆盖完整 ClientHello 的字节，解析其中的 TLS 扩展：
//   - 找到并验证 REALITY_EXT_TYPE 扩展 → 移交给 TlsSession（数据留在内核缓冲区）
//   - 未找到 → 透传给真实网站 (raw TCP proxy)
class RealitySession : public std::enable_shared_from_this<RealitySession> {
public:
    using CleanupCallback = std::function<void(int fd)>;

    RealitySession(int client_fd, Reactor& reactor, TlsContext& tls_ctx,
                   const RealityConfig& cfg, CleanupCallback on_close = nullptr);
    ~RealitySession();

    // 将 client_fd 注册到 Reactor，启动探测
    bool start();

private:
    // peek 缓冲大小：足以覆盖任何合理的 ClientHello（含所有扩展）
    static constexpr size_t PEEK_LEN = 1024;
    static constexpr int    TIMESTAMP_WINDOW = 30; // 秒，防重放

    enum class State {
        PEEKING,        // 等待可读，peek ClientHello
        CONNECTING,     // 正在 connect 到真实网站
        PROXYING,       // 透传模式：client <-> real site
        DELEGATED,      // 已移交给 TlsSession
        CLOSING
    };

    void on_client_readable(int fd, int events);
    void on_site_event(int fd, int events);
    bool start_proxy();                          // 连接真实网站并开始透传
    void proxy_flush_client_to_site();
    void proxy_flush_site_to_client();
    void update_site_events();
    void do_close();

    int            client_fd_;
    int            site_fd_;
    Reactor&       reactor_;
    TlsContext&    tls_ctx_;
    RealityConfig  cfg_;
    CleanupCallback on_close_;
    State          state_;

    std::deque<uint8_t> c2s_buf_;  // client → site
    std::deque<uint8_t> s2c_buf_;  // site → client

    // TlsSession 接管后的句柄（仅用于延长生命周期）
    std::shared_ptr<TlsSession> delegated_;
};
