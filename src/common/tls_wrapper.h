#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include "posix_compat.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// 每连接 REALITY 客户端数据（存入 SSL ex_data，供 ClientHello 回调读取）
struct RealityBindData {
    bool        active = false;
    std::string psk;
};

// 全局 ex_data 索引（进程内唯一，由 tls_wrapper.cpp 初始化）
extern int g_reality_ex_idx;

#ifdef _WIN32
    #ifdef read
        #undef read
    #endif
    #ifdef write
        #undef write
    #endif
#endif

struct TlsInfo {
    std::string version;
    std::string cipher;
    std::string alpn;
    bool ech_accepted;
    std::string peer_cert_subject;
    std::string peer_cert_issuer;
};

class TlsContext {
public:
    TlsContext();
    ~TlsContext();
    
    bool init_server(const std::string& cert_path = "", 
                     const std::string& key_path = "");
    bool init_client();
    
    void configure_chrome_fingerprint();
    void set_alpn(const std::vector<std::string>& protocols);
    
    SSL_CTX* ctx() const { return ctx_; }
    bool is_server() const { return is_server_; }

    // 在 SSL_CTX 上注册 REALITY 握手绑定扩展（各调一次，幂等）
    void enable_reality_bind_client();
    void enable_reality_bind_server();

private:
    SSL_CTX* ctx_;
    bool is_server_;
    bool reality_client_registered_ = false;
    bool reality_server_registered_ = false;
    bool generate_self_signed_cert(const std::string& cert_path, 
                                   const std::string& key_path);
};

class TlsSocket {
public:
    TlsSocket();
    ~TlsSocket();
    
    bool accept(int fd, TlsContext& ctx);
    bool connect(int fd, TlsContext& ctx, const std::string& hostname = "");
    
    bool continue_handshake();
    
    ssize_t read(void* buf, size_t len);
    ssize_t write(const void* buf, size_t len);
    
    void close();
    bool is_connected() const { return ssl_ != nullptr; }
    int fd() const { return fd_; }
    
    bool want_read() const { return want_read_; }
    bool want_write() const { return want_write_; }

    TlsInfo get_tls_info() const;

    bool has_pending() const;
    SSL* ssl() { return ssl_; }

    // 设置本连接的 REALITY PSK；须在 connect() 前调用
    void set_reality_bind(const std::string& psk);
    
    static constexpr size_t DEFAULT_BUFFER_SIZE = 16384;
    static constexpr long DEFAULT_SSL_MODE = 
        SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

private:
    SSL* ssl_;
    BIO* bio_;
    int fd_;
    bool want_read_;
    bool want_write_;
    RealityBindData bind_data_;
};
