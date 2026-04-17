#include "tls_wrapper.h"
#include "chrome_fingerprint.h"
#include "logging.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../reality_marker.h"
#ifndef _WIN32
#  include <unistd.h>
#endif
#include <cstring>
#include <chrono>

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
        // 释放 set_alpn 为服务端分配的 AlpnData
        struct AlpnData { std::string wire; };
        if (is_server_) {
            auto* alpn_data = static_cast<AlpnData*>(SSL_CTX_get_app_data(ctx_));
            delete alpn_data;
        }
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

// Map a cipher suite ID to an OpenSSL cipher string name.
// Returns nullptr for IDs BoringSSL does not support (RSA key-exchange, SCSV).
static const char* cipher_id_to_name(uint16_t id) {
    switch (id) {
    case 0xcca8: return "ECDHE-RSA-CHACHA20-POLY1305";
    case 0xcca9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
    case 0xc02b: return "ECDHE-ECDSA-AES128-GCM-SHA256";
    case 0xc02f: return "ECDHE-RSA-AES128-GCM-SHA256";
    case 0xc02c: return "ECDHE-ECDSA-AES256-GCM-SHA384";
    case 0xc030: return "ECDHE-RSA-AES256-GCM-SHA384";
    case 0xc013: return "ECDHE-RSA-AES128-SHA";
    case 0xc014: return "ECDHE-RSA-AES256-SHA";
    default:     return nullptr; // RSA key-exchange, SCSV, TLS 1.3 — skip
    }
}

void TlsContext::configure_chrome_fingerprint() {
    configure_chrome_fingerprint(nullptr);
}

void TlsContext::configure_chrome_fingerprint(const ChromeFingerprint* fp) {
    if (!ctx_) return;

    SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);
    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx_, SSL_OP_NO_COMPRESSION);
    SSL_CTX_clear_options(ctx_, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_CLIENT);

    // Enable Chrome fingerprint mode (controls extension ordering etc.)
    SSL_CTX_enable_chrome_fingerprint_mode(ctx_);

    if (!fp || fp->cipher_suites.empty()) {
        PROXY_LOG_ERROR("[tls] Chrome fingerprint: no cipher suites in fingerprint; "
                        "use -F <capture.txt> to load a Wireshark dump");
        return;
    }

    // ── GREASE ──────────────────────────────────────────────────────────────
    SSL_CTX_set_grease_enabled(ctx_, fp->grease ? 1 : 0);

    // ── OCSP status_request ──────────────────────────────────────────────────
    // Enable stapling so BoringSSL emits the status_request extension.
    if (fp->status_request) {
        SSL_CTX_enable_ocsp_stapling(ctx_);
    }

    // ── Full wire cipher list (verbatim from capture) ────────────────────────
    // Passed as-is; BoringSSL writes these bytes directly into ClientHello.
    SSL_CTX_set_chrome_cipher_wire(ctx_, fp->cipher_suites.data(),
                                   fp->cipher_suites.size());

    // ── TLS 1.2 cipher list for actual negotiation ───────────────────────────
    // BoringSSL can only negotiate ciphers it knows; build cipher string from
    // the supported subset of the fingerprint's TLS 1.2 entries.
    std::string cipher_str;
    for (uint16_t id : fp->cipher_suites) {
        const char* name = cipher_id_to_name(id);
        if (name) {
            if (!cipher_str.empty()) cipher_str += ':';
            cipher_str += name;
        }
    }
    if (!cipher_str.empty()) {
        SSL_CTX_set_cipher_list(ctx_, cipher_str.c_str());
    }

    // ── Supported groups (curves) ────────────────────────────────────────────
    if (!fp->curves.empty()) {
        SSL_CTX_set1_curves(ctx_, (const int*)fp->curves.data(),
                            fp->curves.size());
    }

    // ── Signature algorithms ─────────────────────────────────────────────────
    if (!fp->sig_algs.empty()) {
        SSL_CTX_set_verify_algorithm_prefs(ctx_, fp->sig_algs.data(),
                                           fp->sig_algs.size());
    }

    // ── Supported versions (exact list from capture) ─────────────────────────
    if (!fp->versions.empty()) {
        SSL_CTX_set_chrome_versions(ctx_, fp->versions.data(),
                                    fp->versions.size());
    }

    // ── Extension order (exact order from capture) ────────────────────────────
    // Extensions are emitted in exactly this order; those absent from fp->extensions
    // are not sent. This replaces all per-flag suppression logic.
    if (!fp->extensions.empty()) {
        SSL_CTX_set_chrome_ext_order(ctx_, fp->extensions.data(),
                                     fp->extensions.size());
    }

    // ── ec_point_formats (exact list from capture) ────────────────────────────
    if (!fp->ec_point_formats.empty()) {
        SSL_CTX_set_chrome_ec_point_formats(ctx_, fp->ec_point_formats.data(),
                                            fp->ec_point_formats.size());
    }

    PROXY_LOG_INFO("[tls] Chrome TLS fingerprint configured from Wireshark dump: "
                   << fp->cipher_suites.size() << " ciphers, "
                   << fp->extensions.size() << " extensions, "
                   << fp->versions.size() << " versions, "
                   << fp->ec_point_formats.size() << " ec_point_formats, "
                   << "grease=" << (fp->grease ? "yes" : "no"));
}

void TlsContext::set_alpn(const std::vector<std::string>& protocols) {
    if (!ctx_ || protocols.empty()) return;

    // 编码为 wire 格式：\x02h2\x08http/1.1
    std::string wire;
    for (const auto& proto : protocols) {
        wire += static_cast<char>(proto.size());
        wire += proto;
    }

    if (is_server_) {
        // 服务端：注册 select callback，从客户端列表里挑选我们支持的协议
        // 把 wire 格式存进 SSL_CTX 的 app data 供回调使用
        // 最简单：直接用 lambda 捕获（C 风格需要 static/全局，用 app_data 传递）
        struct AlpnData {
            std::string wire;
        };
        auto* alpn_data = new AlpnData{wire};
        SSL_CTX_set_app_data(ctx_, alpn_data);

        SSL_CTX_set_alpn_select_cb(ctx_,
            [](SSL*, const unsigned char** out, unsigned char* outlen,
               const unsigned char* in, unsigned int inlen, void* arg) -> int {
                auto* data = static_cast<AlpnData*>(arg);
                if (SSL_select_next_proto(
                        const_cast<unsigned char**>(out), outlen,
                        (const unsigned char*)data->wire.data(), data->wire.size(),
                        in, inlen) == OPENSSL_NPN_NEGOTIATED) {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_NOACK;
            },
            alpn_data);
    } else {
        // 客户端：声明本端支持的协议列表
        SSL_CTX_set_alpn_protos(ctx_, (const unsigned char*)wire.data(), wire.size());
    }
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

    // 若已调用 set_reality_bind()，现在把 bind_data_ 挂到 SSL ex_data
    if (bind_data_.active && g_reality_ex_idx >= 0) {
        SSL_set_ex_data(ssl_, g_reality_ex_idx, &bind_data_);
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
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
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

// 在 TlsSocket 类中确保实现此函数
bool TlsSocket::has_pending() const {
    if (!ssl_) return false;
    // SSL_pending 返回已解密但在应用层缓冲区的数据
    // SSL_has_pending 检查是否有未处理的 TLS 记录（BoringSSL 特有）
    return (SSL_pending(ssl_) > 0) || SSL_has_pending(ssl_);
}

// ─── REALITY 客户端 session_id 嵌入 ─────────────────────────────────────────

// 全局 ex_data 索引：每个 SSL 对象上挂 RealityBindData*
int g_reality_ex_idx = -1;

// session_id 回调：BoringSSL 生成随机 session_id 后调用，我们把标记写入前 16 字节
// 后 16 字节保持 BoringSSL 生成的随机值，整体仍像 32 字节随机数
static void reality_session_id_cb(SSL* ssl, uint8_t session_id[32], void* /*arg*/) {
    auto* bd = static_cast<RealityBindData*>(
        SSL_get_ex_data(ssl, g_reality_ex_idx));
    if (!bd || !bd->active) return;

    // 覆写前 16 字节，后 16 字节（已由 BoringSSL 随机填充）保持不动
    reality_make_marker(bd->psk, session_id);
}

void TlsContext::enable_reality_bind_client() {
    if (reality_client_registered_ || !ctx_) return;
    if (g_reality_ex_idx < 0) {
        g_reality_ex_idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    }
    SSL_CTX_set_client_session_id_cb(ctx_, reality_session_id_cb, nullptr);
    reality_client_registered_ = true;
}

void TlsContext::enable_reality_bind_server() {
    // 服务端通过 reality_verify_client_hello() 解析原始字节，无需 TLS 回调
}

void TlsSocket::set_reality_bind(const std::string& psk) {
    bind_data_.active = true;
    bind_data_.psk    = psk;
    if (ssl_ && g_reality_ex_idx >= 0) {
        SSL_set_ex_data(ssl_, g_reality_ex_idx, &bind_data_);
    }
}