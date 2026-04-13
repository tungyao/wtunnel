#pragma once

#include <string>
#include <vector>
#include <memory>
#include "posix_compat.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

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

private:
    SSL_CTX* ctx_;
    bool is_server_;
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
    
    static constexpr size_t DEFAULT_BUFFER_SIZE = 16384;
    static constexpr long DEFAULT_SSL_MODE = 
        SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;

private:
    SSL* ssl_;
    BIO* bio_;
    int fd_;
    bool want_read_;
    bool want_write_;
};
