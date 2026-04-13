/*
 * ngx_ssl_handshake.c - TLS 1.3 Handshake Implementation with BoringSSL
 *
 * 实现完整的 TLS 1.3 握手流程，包括：
 * - ALPN 协商 (HTTP/2)
 * - 会话恢复 (Session Ticket / PSK)
 * - 0-RTT Early Data
 * - 证书验证
 */

#include "ngx_ssl_h2_core.h"
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * ============================================================================
 * 内部数据结构
 * ============================================================================
 */

/* ALPN 协议列表 - 优先 HTTP/2 */
static const uint8_t ngx_ssl_alpn_protocols[] = {
    /* h2 */
    2, 'h', '2',
    /* http/1.1 */
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

/* TLS 1.3 密码套件 (BoringSSL 格式) */
static const char *ngx_ssl_default_ciphers = 
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256";

/* 椭圆曲线列表 */
static const int ngx_ssl_curves[] = {
    NID_X25519,
    NID_X9_62_prime256v1,  /* P-256 */
    NID_secp384r1,         /* P-384 */
    NID_secp521r1          /* P-521 */
};

/*
 * ============================================================================
 * 辅助函数
 * ============================================================================
 */

static uint64_t
ngx_ssl_get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void
ngx_ssl_set_error(ngx_ssl_h2_connection_t *conn, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(conn->error_msg, sizeof(conn->error_msg), fmt, args);
    va_end(args);
    
    /* 记录 OpenSSL 错误 */
    unsigned long err = ERR_peek_last_error();
    if (err) {
        size_t len = strlen(conn->error_msg);
        snprintf(conn->error_msg + len, sizeof(conn->error_msg) - len,
                 ": %s", ERR_reason_error_string(err));
    }
}

/*
 * ============================================================================
 * ALPN 回调 - 服务端选择协议
 * ============================================================================
 */
static int
ngx_ssl_alpn_select_cb(SSL *ssl,
                       const unsigned char **out,
                       unsigned char *outlen,
                       const unsigned char *in,
                       unsigned int inlen,
                       void *arg)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)arg;
    const unsigned char *p = in;
    const unsigned char *end = in + inlen;
    
    /* 优先选择 h2 */
    while (p < end) {
        uint8_t len = *p++;
        if (p + len > end) {
            break;
        }
        
        /* 检查是否为 h2 */
        if (len == 2 && memcmp(p, "h2", 2) == 0) {
            *out = p;
            *outlen = len;
            
            conn->session_info.alpn_protocol = "h2";
            conn->session_info.alpn_protocol_len = 2;
            
            return SSL_TLSEXT_ERR_OK;
        }
        
        p += len;
    }
    
    /* 如果没有 h2，选择 http/1.1 */
    p = in;
    while (p < end) {
        uint8_t len = *p++;
        if (p + len > end) {
            break;
        }
        
        if (len == 8 && memcmp(p, "http/1.1", 8) == 0) {
            *out = p;
            *outlen = len;
            
            conn->session_info.alpn_protocol = "http/1.1";
            conn->session_info.alpn_protocol_len = 8;
            
            return SSL_TLSEXT_ERR_OK;
        }
        
        p += len;
    }
    
    /* 无匹配协议 */
    return SSL_TLSEXT_ERR_NOACK;
}

/*
 * ============================================================================
 * 证书验证回调
 * ============================================================================
 */
static int
ngx_ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, 
                    SSL_get_ex_data_X509_STORE_CTX_idx());
    ngx_ssl_h2_connection_t *conn = SSL_get_app_data(ssl);
    
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    
    if (!preverify_ok) {
        /* 记录验证错误但可能继续 */
        char buf[256];
        X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
        
        ngx_ssl_set_error(conn, "Certificate verify error at depth %d: %s (%s)",
                          depth, X509_verify_cert_error_string(err), buf);
        
        /* 根据配置决定是否继续 */
        if (conn->config && !conn->config->verify_peer) {
            return 1;  /* 忽略验证错误 */
        }
    }
    
    return preverify_ok;
}

/*
 * ============================================================================
 * SSL_CTX 初始化
 * ============================================================================
 */
static int
ngx_ssl_ctx_init(ngx_ssl_h2_connection_t *conn, ngx_ssl_h2_config_t *config)
{
    const SSL_METHOD *method;
    
    /* 选择 TLS 方法 */
    if (conn->is_server) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }
    
    conn->ssl_ctx = SSL_CTX_new(method);
    if (!conn->ssl_ctx) {
        ngx_ssl_set_error(conn, "SSL_CTX_new failed");
        return NGX_SSL_H2_ERROR;
    }
    
    /* 设置选项 - 类似 nginx 的配置 */
    SSL_CTX_set_options(conn->ssl_ctx,
        SSL_OP_NO_SSLv2 |
        SSL_OP_NO_SSLv3 |
        SSL_OP_NO_TLSv1 |
        SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_SINGLE_ECDH_USE
    );
    
    /* 设置最小版本为 TLS 1.2 */
    SSL_CTX_set_min_proto_version(conn->ssl_ctx, 
        config ? config->min_tls_version : TLS1_2_VERSION);
    
    /* 设置最大版本为 TLS 1.3 */
    SSL_CTX_set_max_proto_version(conn->ssl_ctx,
        config ? config->max_tls_version : TLS1_3_VERSION);
    
    /* 设置密码套件 */
    const char *ciphers = (config && config->ciphers) ? 
                          config->ciphers : ngx_ssl_default_ciphers;
    if (!SSL_CTX_set_cipher_list(conn->ssl_ctx, ciphers)) {
        ngx_ssl_set_error(conn, "SSL_CTX_set_cipher_list failed");
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
        return NGX_SSL_H2_ERROR;
    }
    
    /* 设置椭圆曲线 */
    if (!SSL_CTX_set1_curves(conn->ssl_ctx, ngx_ssl_curves, 
                             sizeof(ngx_ssl_curves)/sizeof(ngx_ssl_curves[0]))) {
        ngx_ssl_set_error(conn, "SSL_CTX_set1_curves failed");
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
        return NGX_SSL_H2_ERROR;
    }
    
    /* 服务端配置 */
    if (conn->is_server) {
        /* 加载证书 */
        if (config && config->cert_file) {
            if (SSL_CTX_use_certificate_chain_file(conn->ssl_ctx, 
                    config->cert_file) != 1) {
                ngx_ssl_set_error(conn, "Failed to load certificate: %s",
                                  config->cert_file);
                SSL_CTX_free(conn->ssl_ctx);
                conn->ssl_ctx = NULL;
                return NGX_SSL_H2_ERROR;
            }
        }
        
        /* 加载私钥 */
        if (config && config->key_file) {
            if (SSL_CTX_use_PrivateKey_file(conn->ssl_ctx,
                    config->key_file, SSL_FILETYPE_PEM) != 1) {
                ngx_ssl_set_error(conn, "Failed to load private key: %s",
                                  config->key_file);
                SSL_CTX_free(conn->ssl_ctx);
                conn->ssl_ctx = NULL;
                return NGX_SSL_H2_ERROR;
            }
        }
        
        /* 设置 ALPN 回调 */
        SSL_CTX_set_alpn_select_cb(conn->ssl_ctx, ngx_ssl_alpn_select_cb, conn);
        
        /* 设置会话缓存 */
        SSL_CTX_set_session_cache_mode(conn->ssl_ctx,
            SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
    } else {
        /* 客户端 ALPN 设置 */
        SSL_CTX_set_alpn_protos(conn->ssl_ctx, ngx_ssl_alpn_protocols,
                                sizeof(ngx_ssl_alpn_protocols));
    }
    
    /* 证书验证 */
    if (config && config->verify_peer) {
        SSL_CTX_set_verify(conn->ssl_ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            ngx_ssl_verify_callback);
        
        SSL_CTX_set_verify_depth(conn->ssl_ctx,
            config->verify_depth > 0 ? config->verify_depth : 4);
        
        if (config->ca_file) {
            if (!SSL_CTX_load_verify_locations(conn->ssl_ctx,
                    config->ca_file, NULL)) {
                ngx_ssl_set_error(conn, "Failed to load CA file: %s",
                                  config->ca_file);
                SSL_CTX_free(conn->ssl_ctx);
                conn->ssl_ctx = NULL;
                return NGX_SSL_H2_ERROR;
            }
        }
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * SSL 对象初始化
 * ============================================================================
 */
static int
ngx_ssl_init(ngx_ssl_h2_connection_t *conn)
{
    conn->ssl = SSL_new(conn->ssl_ctx);
    if (!conn->ssl) {
        ngx_ssl_set_error(conn, "SSL_new failed");
        return NGX_SSL_H2_ERROR;
    }
    
    /* 保存连接指针到 SSL 对象 */
    SSL_set_app_data(conn->ssl, conn);
    
    /* 创建 BIO 对 */
    if (!BIO_new_bio_pair(&conn->rbio, 0, &conn->wbio, 0)) {
        ngx_ssl_set_error(conn, "BIO_new_bio_pair failed");
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        return NGX_SSL_H2_ERROR;
    }
    
    /* 设置 BIO - 注意：SSL 拥有 rbio 的所有权 */
    SSL_set_bio(conn->ssl, conn->rbio, conn->rbio);
    
    /* 根据角色设置连接模式 */
    if (conn->is_server) {
        SSL_set_accept_state(conn->ssl);
    } else {
        SSL_set_connect_state(conn->ssl);
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * TLS 握手主函数
 * ============================================================================
 */
int
ngx_ssl_h2_handshake(ngx_ssl_h2_connection_t *conn)
{
    int ret;
    int ssl_err;
    uint64_t start_time;
    
    if (!conn) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 记录开始时间 */
    if (conn->handshake_state == NGX_SSL_HANDSHAKE_INIT) {
        start_time = ngx_ssl_get_time_us();
    }
    
    /* 初始化 SSL (如果尚未初始化) */
    if (!conn->ssl) {
        if (ngx_ssl_init(conn) != NGX_SSL_H2_OK) {
            conn->handshake_state = NGX_SSL_HANDSHAKE_FAILED;
            return NGX_SSL_H2_ERROR;
        }
    }
    
    /* 执行握手 */
    ERR_clear_error();
    ret = SSL_do_handshake(conn->ssl);
    
    if (ret == 1) {
        /* 握手成功 */
        conn->handshake_state = NGX_SSL_HANDSHAKE_COMPLETE;
        conn->handshake_complete = 1;
        
        /* 记录握手时间 */
        conn->stats.handshake_time_us = ngx_ssl_get_time_us() - start_time;
        
        /* 提取会话信息 */
        ngx_ssl_extract_session_info(conn);
        
        return NGX_SSL_H2_OK;
    }
    
    ssl_err = SSL_get_error(conn->ssl, ret);
    
    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        /* 需要从网络读取更多数据 */
        conn->handshake_state = NGX_SSL_HANDSHAKE_CLIENT_HELLO;
        return NGX_SSL_H2_WANT_READ;
        
    case SSL_ERROR_WANT_WRITE:
        /* 需要向网络写入数据 */
        return NGX_SSL_H2_WANT_WRITE;
        
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
        /* 握手失败 */
        conn->handshake_state = NGX_SSL_HANDSHAKE_FAILED;
        ngx_ssl_set_error(conn, "SSL handshake failed");
        return NGX_SSL_H2_ERROR;
        
    default:
        conn->handshake_state = NGX_SSL_HANDSHAKE_FAILED;
        ngx_ssl_set_error(conn, "SSL handshake error: %d", ssl_err);
        return NGX_SSL_H2_ERROR;
    }
}

/*
 * ============================================================================
 * 提取 TLS 会话信息
 * ============================================================================
 */
void
ngx_ssl_extract_session_info(ngx_ssl_h2_connection_t *conn)
{
    if (!conn || !conn->ssl) {
        return;
    }
    
    /* TLS 版本 */
    conn->session_info.tls_version = SSL_version(conn->ssl);
    
    /* 密码套件 */
    const SSL_CIPHER *cipher = SSL_get_current_cipher(conn->ssl);
    if (cipher) {
        conn->session_info.cipher_suite = SSL_CIPHER_get_protocol_id(cipher);
        conn->session_info.cipher_name = SSL_CIPHER_get_name(cipher);
    }
    
    /* ALPN 结果 (客户端侧) */
    if (!conn->is_server) {
        const unsigned char *alpn;
        unsigned int alpn_len;
        SSL_get0_alpn_selected(conn->ssl, &alpn, &alpn_len);
        if (alpn && alpn_len > 0) {
            conn->session_info.alpn_protocol = (const char *)alpn;
            conn->session_info.alpn_protocol_len = alpn_len;
        }
    }
    
    /* 会话恢复 */
    conn->session_info.session_reused = SSL_session_reused(conn->ssl);
    conn->session_info.session = SSL_get_session(conn->ssl);
    
    /* 对端证书 */
    conn->session_info.peer_cert = SSL_get_peer_certificate(conn->ssl);
    conn->session_info.peer_cert_chain = SSL_get_peer_cert_chain(conn->ssl);
    
    /* 密钥交换信息 */
    int kex_nid = SSL_get_negotiated_group(conn->ssl);
    if (kex_nid > 0) {
        conn->session_info.kex_name = OBJ_nid2sn(kex_nid);
        /* 获取密钥位数 */
        switch (kex_nid) {
        case NID_X25519:
            conn->session_info.kex_bits = 253;
            break;
        case NID_X9_62_prime256v1:
            conn->session_info.kex_bits = 256;
            break;
        case NID_secp384r1:
            conn->session_info.kex_bits = 384;
            break;
        case NID_secp521r1:
            conn->session_info.kex_bits = 521;
            break;
        default:
            conn->session_info.kex_bits = 0;
        }
    }
    
    /* 0-RTT 状态 */
    conn->session_info.early_data_accepted = 
        SSL_early_data_accepted(conn->ssl);
}

/*
 * ============================================================================
 * TLS 数据读取
 * ============================================================================
 */
int
ngx_ssl_read(ngx_ssl_h2_connection_t *conn, uint8_t *buf, size_t len)
{
    int ret;
    int ssl_err;
    
    if (!conn || !conn->ssl || !buf || len == 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    ERR_clear_error();
    ret = SSL_read(conn->ssl, buf, (int)len);
    
    if (ret > 0) {
        conn->stats.bytes_received += ret;
        return ret;
    }
    
    ssl_err = SSL_get_error(conn->ssl, ret);
    
    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        return NGX_SSL_H2_WANT_READ;
        
    case SSL_ERROR_WANT_WRITE:
        return NGX_SSL_H2_WANT_WRITE;
        
    case SSL_ERROR_ZERO_RETURN:
        /* 对端关闭连接 */
        return 0;
        
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
        ngx_ssl_set_error(conn, "SSL read error");
        return NGX_SSL_H2_ERROR;
        
    default:
        return NGX_SSL_H2_ERROR;
    }
}

/*
 * ============================================================================
 * TLS 数据写入
 * ============================================================================
 */
int
ngx_ssl_write(ngx_ssl_h2_connection_t *conn, const uint8_t *buf, size_t len)
{
    int ret;
    int ssl_err;
    
    if (!conn || !conn->ssl || !buf || len == 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    ERR_clear_error();
    ret = SSL_write(conn->ssl, buf, (int)len);
    
    if (ret > 0) {
        conn->stats.bytes_sent += ret;
        return ret;
    }
    
    ssl_err = SSL_get_error(conn->ssl, ret);
    
    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        return NGX_SSL_H2_WANT_READ;
        
    case SSL_ERROR_WANT_WRITE:
        return NGX_SSL_H2_WANT_WRITE;
        
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
        ngx_ssl_set_error(conn, "SSL write error");
        return NGX_SSL_H2_ERROR;
        
    default:
        return NGX_SSL_H2_ERROR;
    }
}

/*
 * ============================================================================
 * TLS 关闭
 * ============================================================================
 */
int
ngx_ssl_shutdown(ngx_ssl_h2_connection_t *conn)
{
    int ret;
    int ssl_err;
    
    if (!conn || !conn->ssl) {
        return NGX_SSL_H2_OK;
    }
    
    /* 清除之前的错误 */
    ERR_clear_error();
    
    ret = SSL_shutdown(conn->ssl);
    
    if (ret == 1) {
        /* 双向关闭完成 */
        return NGX_SSL_H2_OK;
    }
    
    if (ret == 0) {
        /* 发送了 close_notify，等待对端响应 */
        ret = SSL_shutdown(conn->ssl);
        if (ret == 1) {
            return NGX_SSL_H2_OK;
        }
    }
    
    ssl_err = SSL_get_error(conn->ssl, ret);
    
    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
        return NGX_SSL_H2_WANT_READ;
        
    case SSL_ERROR_WANT_WRITE:
        return NGX_SSL_H2_WANT_WRITE;
        
    default:
        /* 忽略关闭时的错误 */
        return NGX_SSL_H2_OK;
    }
}

/*
 * ============================================================================
 * 获取握手状态字符串
 * ============================================================================
 */
const char *
ngx_ssl_handshake_state_str(ngx_ssl_handshake_state_t state)
{
    static const char *state_strings[] = {
        "INIT",
        "CLIENT_HELLO",
        "SERVER_HELLO",
        "ENCRYPTED_EXTENSIONS",
        "CERTIFICATE",
        "CERTIFICATE_VERIFY",
        "FINISHED",
        "COMPLETE",
        "FAILED"
    };
    
    if (state < sizeof(state_strings) / sizeof(state_strings[0])) {
        return state_strings[state];
    }
    
    return "UNKNOWN";
}

/*
 * ============================================================================
 * 获取 TLS 版本字符串
 * ============================================================================
 */
const char *
ngx_ssl_version_str(uint16_t version)
{
    switch (version) {
    case TLS1_VERSION:
        return "TLSv1.0";
    case TLS1_1_VERSION:
        return "TLSv1.1";
    case TLS1_2_VERSION:
        return "TLSv1.2";
    case TLS1_3_VERSION:
        return "TLSv1.3";
    default:
        return "Unknown";
    }
}
