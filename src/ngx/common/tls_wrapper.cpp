#include "tls_wrapper.h"
#include "logging.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <cstring>

namespace {

struct X509Deleter {
    void operator()(X509* x) const { X509_free(x); }
};

struct EVPKeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

struct EVPKeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};

struct BIODeleter {
    void operator()(BIO* b) const { BIO_free(b); }
};

}

TlsContext::TlsContext()
    : ctx_(nullptr)
    , is_server_(false) {
}

TlsContext::~TlsContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
}

bool TlsContext::init_server(const std::string& cert_path, 
                              const std::string& key_path) {
    is_server_ = true;
    
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) {
        PROXY_LOG_ERROR("[tls] Failed to create SSL_CTX");
        return false;
    }
    
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
    
    const char* ciphers = 
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    SSL_CTX_set_cipher_list(ctx_, ciphers);
    
    SSL_CTX_set_options(ctx_, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_mode(ctx_, TlsSocket::DEFAULT_SSL_MODE);
    
    if (cert_path.empty() || key_path.empty()) {
        std::string cert_file = "/tmp/qtunnel_cert.pem";
        std::string key_file = "/tmp/qtunnel_key.pem";
        
        if (!generate_self_signed_cert(cert_file, key_file)) {
            PROXY_LOG_ERROR("[tls] Failed to generate self-signed certificate");
            return false;
        }
        
        if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            PROXY_LOG_ERROR("[tls] Failed to load certificate: " << err_buf);
            return false;
        }
        
        if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            PROXY_LOG_ERROR("[tls] Failed to load private key");
            return false;
        }
    } else {
        if (SSL_CTX_use_certificate_file(ctx_, cert_path.c_str(), SSL_FILETYPE_PEM) != 1) {
            PROXY_LOG_ERROR("[tls] Failed to load certificate: " << cert_path);
            return false;
        }
        
        if (SSL_CTX_use_PrivateKey_file(ctx_, key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
            PROXY_LOG_ERROR("[tls] Failed to load private key: " << key_path);
            return false;
        }
    }
    
    if (SSL_CTX_check_private_key(ctx_) != 1) {
        PROXY_LOG_ERROR("[tls] Private key does not match certificate");
        return false;
    }
    
    PROXY_LOG_INFO("[tls] TLS server context initialized");
    return true;
}

bool TlsContext::init_client() {
    is_server_ = false;
    
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) {
        PROXY_LOG_ERROR("[tls] Failed to create client SSL_CTX");
        return false;
    }
    
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_mode(ctx_, TlsSocket::DEFAULT_SSL_MODE);
    
    PROXY_LOG_INFO("[tls] TLS client context initialized");
    return true;
}

void TlsContext::configure_chrome_fingerprint() {
    if (!ctx_) return;
    
    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    
    SSL_CTX_set_options(ctx_, SSL_OP_NO_COMPRESSION);
    SSL_CTX_clear_options(ctx_, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_CLIENT);
    
    const char* alpn_protos = "\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx_, (const unsigned char*)alpn_protos, 12);
    
    const char* ciphers = 
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    SSL_CTX_set_cipher_list(ctx_, ciphers);
    
    SSL_CTX_set_grease_enabled(ctx_, 1);
    
    PROXY_LOG_INFO("[tls] Chrome 146 TLS fingerprint configured");
}

void TlsContext::set_alpn(const std::vector<std::string>& protocols) {
    if (!ctx_ || protocols.empty()) return;
    
    std::string alpn;
    for (const auto& proto : protocols) {
        alpn += static_cast<char>(proto.size());
        alpn += proto;
    }
    SSL_CTX_set_alpn_protos(ctx_, (const unsigned char*)alpn.data(), alpn.size());
}

bool TlsContext::generate_self_signed_cert(const std::string& cert_path,
                                            const std::string& key_path) {
    PROXY_LOG_INFO("[tls] Generating self-signed certificate...");
    
    std::unique_ptr<EVP_PKEY_CTX, EVPKeyCtxDeleter> pkey_ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!pkey_ctx) {
        PROXY_LOG_ERROR("[tls] Failed to create EVP_PKEY_CTX");
        return false;
    }
    
    if (EVP_PKEY_keygen_init(pkey_ctx.get()) <= 0) {
        PROXY_LOG_ERROR("[tls] Failed to init keygen");
        return false;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx.get(), 2048) <= 0) {
        PROXY_LOG_ERROR("[tls] Failed to set key size");
        return false;
    }
    
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pkey_ctx.get(), &pkey_raw) <= 0) {
        PROXY_LOG_ERROR("[tls] Failed to generate key");
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVPKeyDeleter> pkey(pkey_raw);
    
    std::unique_ptr<X509, X509Deleter> x509(X509_new());
    if (!x509) {
        PROXY_LOG_ERROR("[tls] Failed to create X509");
        return false;
    }
    
    X509_set_version(x509.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L);
    
    X509_set_pubkey(x509.get(), pkey.get());
    
    X509_NAME* name = X509_get_subject_name(x509.get());
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                               (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, 
                               (unsigned char*)"California", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, 
                               (unsigned char*)"San Francisco", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, 
                               (unsigned char*)"CloudDocs Inc", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                               (unsigned char*)"clouddocs.example.com", -1, -1, 0);
    
    X509_set_issuer_name(x509.get(), name);
    
    GENERAL_NAMES* san_names_raw = GENERAL_NAMES_new();
    if (!san_names_raw) {
        PROXY_LOG_ERROR("[tls] Failed to create SAN structures");
        return false;
    }
    std::unique_ptr<GENERAL_NAMES, void(*)(GENERAL_NAMES*)> san_names(
        san_names_raw, GENERAL_NAMES_free);
    
    GENERAL_NAME* san_name1 = GENERAL_NAME_new();
    GENERAL_NAME* san_name2 = GENERAL_NAME_new();
    if (!san_name1 || !san_name2) {
        PROXY_LOG_ERROR("[tls] Failed to create SAN names");
        return false;
    }
    
    ASN1_IA5STRING* dns1 = ASN1_IA5STRING_new();
    ASN1_IA5STRING* dns2 = ASN1_IA5STRING_new();
    if (!dns1 || !dns2) {
        PROXY_LOG_ERROR("[tls] Failed to create DNS IA5 strings");
        if (san_name1) GENERAL_NAME_free(san_name1);
        if (san_name2) GENERAL_NAME_free(san_name2);
        return false;
    }
    
    ASN1_STRING_set(dns1, "clouddocs.example.com", -1);
    ASN1_STRING_set(dns2, "www.clouddocs.example.com", -1);
    
    san_name1->type = GEN_DNS;
    san_name1->d.dNSName = dns1;
    san_name2->type = GEN_DNS;
    san_name2->d.dNSName = dns2;
    
    sk_GENERAL_NAME_push(san_names.get(), san_name1);
    sk_GENERAL_NAME_push(san_names.get(), san_name2);
    
    X509_EXTENSION* san_ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, san_names.get());
    if (!san_ext) {
        PROXY_LOG_ERROR("[tls] Failed to create SAN extension");
        return false;
    }
    
    X509_add_ext(x509.get(), san_ext, -1);
    X509_EXTENSION_free(san_ext);
    
    if (X509_sign(x509.get(), pkey.get(), EVP_sha256()) == 0) {
        PROXY_LOG_ERROR("[tls] Failed to sign certificate");
        return false;
    }
    
    FILE* fp = fopen(cert_path.c_str(), "w");
    if (!fp) {
        PROXY_LOG_ERROR("[tls] Failed to open cert file for writing");
        return false;
    }
    PEM_write_X509(fp, x509.get());
    fclose(fp);
    
    fp = fopen(key_path.c_str(), "w");
    if (!fp) {
        PROXY_LOG_ERROR("[tls] Failed to open key file for writing");
        return false;
    }
    PEM_write_PrivateKey(fp, pkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
    fclose(fp);
    
    PROXY_LOG_INFO("[tls] Self-signed certificate generated: " << cert_path);
    return true;
}

TlsSocket::TlsSocket()
    : ssl_(nullptr)
    , bio_(nullptr)
    , fd_(-1)
    , want_read_(false)
    , want_write_(false) {
}

TlsSocket::~TlsSocket() {
    close();
}

bool TlsSocket::accept(int fd, TlsContext& ctx) {
    fd_ = fd;
    ssl_ = SSL_new(ctx.ctx());
    if (!ssl_) {
        PROXY_LOG_ERROR("[tls] SSL_new failed");
        return false;
    }
    
    #ifdef _WIN32
    const SOCKET native_fd = posix_compat::native_socket(fd_);
    if (native_fd == INVALID_SOCKET) {
        PROXY_LOG_ERROR("[tls] BIO_new_socket failed: invalid socket mapping for fd=" << fd_);
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }
    bio_ = BIO_new_socket(native_fd, BIO_NOCLOSE);
    #else
    bio_ = BIO_new_socket(fd_, BIO_NOCLOSE);
    #endif
    
    if (!bio_) {
        PROXY_LOG_ERROR("[tls] BIO_new_socket failed");
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }
    
    SSL_set_bio(ssl_, bio_, bio_);
    
    int ret = SSL_accept(ssl_);
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ) {
            want_read_ = true;
            return true;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            want_write_ = true;
            return true;
        }
        
        PROXY_LOG_ERROR("[tls] SSL_accept failed: " << err);
        SSL_free(ssl_);
        ssl_ = nullptr;
        bio_ = nullptr;
        return false;
    }
    
    PROXY_LOG_DEBUG("[tls] TLS handshake completed on fd=" << fd);
    return true;
}

bool TlsSocket::continue_handshake() {
    if (!ssl_) return false;
    
    int ret = SSL_do_handshake(ssl_);
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ) {
            want_read_ = true;
            want_write_ = false;
            return true;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            want_write_ = true;
            want_read_ = false;
            return true;
        }
        
        unsigned long e = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(e, err_buf, sizeof(err_buf));
        PROXY_LOG_ERROR("[tls] SSL_do_handshake failed: " << err << " - " << err_buf);
        return false;
    }
    
    want_read_ = false;
    want_write_ = false;
    PROXY_LOG_DEBUG("[tls] TLS handshake completed on fd=" << fd_);
    return true;
}

bool TlsSocket::connect(int fd, TlsContext& ctx, const std::string& hostname) {
    fd_ = fd;
    ssl_ = SSL_new(ctx.ctx());
    if (!ssl_) {
        return false;
    }
    
    if (!hostname.empty()) {
        SSL_set_tlsext_host_name(ssl_, hostname.c_str());
    }
    
    #ifdef _WIN32
    const SOCKET native_fd = posix_compat::native_socket(fd_);
    if (native_fd == INVALID_SOCKET) {
        PROXY_LOG_ERROR("[tls] BIO_new_socket failed: invalid socket mapping for fd=" << fd_);
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }
    bio_ = BIO_new_socket(native_fd, BIO_NOCLOSE);
    #else
    bio_ = BIO_new_socket(fd_, BIO_NOCLOSE);
    #endif
    
    if (!bio_) {
        PROXY_LOG_ERROR("[tls] BIO_new_socket failed");
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }
    
    SSL_set_bio(ssl_, bio_, bio_);
    
    int ret = SSL_connect(ssl_);
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ) {
            want_read_ = true;
            return true;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            want_write_ = true;
            return true;
        }
        
        SSL_free(ssl_);
        ssl_ = nullptr;
        bio_ = nullptr;
        return false;
    }
    
    return true;
}

ssize_t TlsSocket::read(void* buf, size_t len) {
    if (!ssl_) return -1;
    
    want_read_ = false;
    want_write_ = false;
    
    int ret = SSL_read(ssl_, buf, len);
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ) {
            want_read_ = true;
            return -1;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            want_write_ = true;
            return -1;
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        return -1;
    }
    
    return ret;
}

ssize_t TlsSocket::write(const void* buf, size_t len) {
    if (!ssl_) return -1;
    
    want_read_ = false;
    want_write_ = false;
    
    int ret = SSL_write(ssl_, buf, len);
    if (ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ) {
            want_read_ = true;
            return -1;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            want_write_ = true;
            return -1;
        }
        return -1;
    }
    
    return ret;
}

void TlsSocket::close() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
        bio_ = nullptr;
    }
    fd_ = -1;
}

TlsInfo TlsSocket::get_tls_info() const {
    TlsInfo info;
    
    if (!ssl_) return info;
    
    const char* version = SSL_get_version(ssl_);
    if (version) {
        info.version = version;
    }
    
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);
    if (cipher) {
        const char* cipher_name = SSL_CIPHER_get_name(cipher);
        if (cipher_name) {
            info.cipher = cipher_name;
        }
    }
    
    const unsigned char* alpn = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl_, &alpn, &alpn_len);
    if (alpn && alpn_len > 0) {
        info.alpn.assign((const char*)alpn, alpn_len);
    }
    
    info.ech_accepted = false;
    
    X509* cert = SSL_get_peer_certificate(ssl_);
    if (cert) {
        X509_NAME* subject = X509_get_subject_name(cert);
        if (subject) {
            char buf[256];
            X509_NAME_oneline(subject, buf, sizeof(buf));
            info.peer_cert_subject = buf;
        }
        
        X509_NAME* issuer = X509_get_issuer_name(cert);
        if (issuer) {
            char buf[256];
            X509_NAME_oneline(issuer, buf, sizeof(buf));
            info.peer_cert_issuer = buf;
        }
        
        X509_free(cert);
    }
    
    return info;
}

bool TlsSocket::has_pending() const {
    if (!ssl_) return false;
    return SSL_pending(ssl_) > 0;
}
