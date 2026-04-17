#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include "posix_compat.h"
#include "chrome_fingerprint.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

struct RealityBindData {
    bool        active = false;
    std::string psk;
};

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
    void configure_chrome_fingerprint(const ChromeFingerprint* fp);
    void set_alpn(const std::vector<std::string>& protocols);

    // Enable TLS 1.3 0-RTT early data.
    // Client: allows sending early data; server: allows receiving up to 16 KiB.
    void enable_early_data();
    bool has_early_data() const { return early_data_enabled_; }

    SSL_CTX* ctx() const { return ctx_; }
    bool is_server() const { return is_server_; }

    void enable_reality_bind_client();
    void enable_reality_bind_server();

private:
    SSL_CTX* ctx_;
    bool is_server_;
    bool reality_client_registered_ = false;
    bool reality_server_registered_ = false;
    bool early_data_enabled_        = false;
    bool generate_self_signed_cert(const std::string& cert_path,
                                   const std::string& key_path);
};

class TlsSocket {
public:
    TlsSocket();
    ~TlsSocket();

    bool accept(int fd, TlsContext& ctx);

    // session: optional TLS session for 0-RTT resumption; pass nullptr for a fresh handshake.
    // Must be called before connect() to take effect.
    bool connect(int fd, TlsContext& ctx, const std::string& hostname = "",
                 SSL_SESSION* session = nullptr);

    bool continue_handshake();

    ssize_t read(void* buf, size_t len);
    ssize_t write(const void* buf, size_t len);

    void close();
    bool is_connected() const { return ssl_ != nullptr; }
    int fd() const { return fd_; }

    bool want_read()  const { return want_read_; }
    bool want_write() const { return want_write_; }

    TlsInfo get_tls_info() const;
    bool has_pending() const;
    SSL* ssl() { return ssl_; }

    void set_reality_bind(const std::string& psk);

    // ── Session ticket / 0-RTT ──────────────────────────────────────────────

    // Borrowed reference valid until TlsSocket::close(); caller must SSL_SESSION_up_ref to store.
    SSL_SESSION* get_session() const;

    // True if the server accepted our 0-RTT early data (check after handshake).
    bool is_early_data_accepted() const;

    // True while the handshake is in the 0-RTT early-data send window.
    // Clients may call SSL_write() via write() to send early data at this point.
    bool in_early_data() const;

    // Client: attempt to write buf as 0-RTT early data.
    // Only succeeds while in_early_data() is true; uses regular SSL_write().
    bool try_write_early_data(const void* buf, size_t len);

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
