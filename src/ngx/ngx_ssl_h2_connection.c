/*
 * ngx_ssl_h2_connection.c - Connection Management and Global Initialization
 *
 * 连接生命周期管理：
 * - 全局初始化/清理
 * - 连接创建/销毁
 * - 配置管理
 * - 事件循环集成
 */

#include "ngx_ssl_h2_core.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>

/*
 * ============================================================================
 * 全局状态
 * ============================================================================
 */

static pthread_once_t ngx_ssl_h2_init_once = PTHREAD_ONCE_INIT;
static int ngx_ssl_h2_initialized = 0;

/*
 * ============================================================================
 * 全局初始化
 * ============================================================================
 */

static void
ngx_ssl_h2_init_internal(void)
{
    /* 初始化 BoringSSL */
    CRYPTO_library_init();
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    
    /* OpenSSL 线程安全已在 BoringSSL 中自动处理 */
    
    ngx_ssl_h2_initialized = 1;
}

int
ngx_ssl_h2_global_init(void)
{
    pthread_once(&ngx_ssl_h2_init_once, ngx_ssl_h2_init_internal);
    
    if (!ngx_ssl_h2_initialized) {
        return NGX_SSL_H2_ERROR;
    }
    
    return NGX_SSL_H2_OK;
}

void
ngx_ssl_h2_global_cleanup(void)
{
    if (ngx_ssl_h2_initialized) {
        /* BoringSSL 清理 */
        EVP_cleanup();
        ERR_free_strings();
        
        ngx_ssl_h2_initialized = 0;
    }
}

/*
 * ============================================================================
 * 配置管理
 * ============================================================================
 */

ngx_ssl_h2_config_t *
ngx_ssl_h2_config_create(void)
{
    ngx_ssl_h2_config_t *config;
    
    config = calloc(1, sizeof(ngx_ssl_h2_config_t));
    if (!config) {
        return NULL;
    }
    
    /* 设置默认值 */
    ngx_ssl_h2_config_set_default(config);
    
    return config;
}

void
ngx_ssl_h2_config_destroy(ngx_ssl_h2_config_t *config)
{
    if (config) {
        /* 注意：字符串字段是外部指针，不需要释放 */
        free(config);
    }
}

int
ngx_ssl_h2_config_set_default(ngx_ssl_h2_config_t *config)
{
    if (!config) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* TLS 默认配置 */
    config->cert_file = NULL;
    config->key_file = NULL;
    config->ca_file = NULL;
    config->ciphers = NULL;  /* 使用内部默认值 */
    config->curves = NULL;
    config->min_tls_version = TLS1_2_VERSION;
    config->max_tls_version = TLS1_3_VERSION;
    config->verify_peer = false;
    config->verify_depth = 4;
    
    /* HTTP/2 默认配置 (参考 nginx 默认值) */
    config->max_concurrent_streams = 128;
    config->initial_window_size = 65535;
    config->max_frame_size = 16384;
    config->max_header_list_size = 65536;
    config->header_table_size = 4096;
    config->enable_push = false;
    
    /* 超时默认配置 */
    config->handshake_timeout_ms = 60000;   /* 60 秒 */
    config->idle_timeout_ms = 300000;       /* 5 分钟 */
    config->read_timeout_ms = 60000;        /* 60 秒 */
    config->write_timeout_ms = 60000;       /* 60 秒 */
    
    /* 缓冲区默认配置 */
    config->read_buffer_size = 16384;
    config->write_buffer_size = 16384;
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * 缓冲区管理
 * ============================================================================
 */

static int
ngx_ssl_h2_buffer_init(ngx_ssl_h2_buffer_t *buf, size_t capacity)
{
    if (!buf) {
        return NGX_SSL_H2_ERROR;
    }
    
    buf->data = malloc(capacity);
    if (!buf->data) {
        return NGX_SSL_H2_ERROR;
    }
    
    buf->capacity = capacity;
    buf->size = 0;
    buf->read_pos = 0;
    buf->write_pos = 0;
    
    return NGX_SSL_H2_OK;
}

static void
ngx_ssl_h2_buffer_destroy(ngx_ssl_h2_buffer_t *buf)
{
    if (buf && buf->data) {
        free(buf->data);
        buf->data = NULL;
        buf->capacity = 0;
        buf->size = 0;
    }
}

/*
 * ============================================================================
 * Socket 配置
 * ============================================================================
 */

static int
ngx_ssl_h2_configure_socket(int fd)
{
    int flags;
    int optval;
    
    /* 设置非阻塞 */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return NGX_SSL_H2_ERROR;
    }
    
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 禁用 Nagle 算法 */
    optval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 启用 TCP keepalive */
    optval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) == -1) {
        return NGX_SSL_H2_ERROR;
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * 连接创建
 * ============================================================================
 */

/* 外部声明 - 在 ngx_ssl_handshake.c 中实现 */
extern int ngx_ssl_ctx_init(ngx_ssl_h2_connection_t *conn, ngx_ssl_h2_config_t *config);
extern int ngx_h2_session_init(ngx_ssl_h2_connection_t *conn);

ngx_ssl_h2_connection_t *
ngx_ssl_h2_connection_create(int fd,
                              ngx_ssl_h2_config_t *config,
                              bool is_server)
{
    ngx_ssl_h2_connection_t *conn;
    
    /* 确保全局初始化完成 */
    if (ngx_ssl_h2_global_init() != NGX_SSL_H2_OK) {
        return NULL;
    }
    
    /* 分配连接结构 */
    conn = calloc(1, sizeof(ngx_ssl_h2_connection_t));
    if (!conn) {
        return NULL;
    }
    
    conn->fd = fd;
    conn->is_server = is_server ? 1 : 0;
    conn->config = config;
    conn->handshake_state = NGX_SSL_HANDSHAKE_INIT;
    
    /* 配置 socket */
    if (ngx_ssl_h2_configure_socket(fd) != NGX_SSL_H2_OK) {
        free(conn);
        return NULL;
    }
    
    /* 初始化缓冲区 */
    size_t read_buf_size = config ? config->read_buffer_size : 16384;
    size_t write_buf_size = config ? config->write_buffer_size : 16384;
    
    if (ngx_ssl_h2_buffer_init(&conn->read_buffer, read_buf_size) != NGX_SSL_H2_OK) {
        free(conn);
        return NULL;
    }
    
    if (ngx_ssl_h2_buffer_init(&conn->write_buffer, write_buf_size) != NGX_SSL_H2_OK) {
        ngx_ssl_h2_buffer_destroy(&conn->read_buffer);
        free(conn);
        return NULL;
    }
    
    /* 初始化 SSL 上下文 */
    if (ngx_ssl_ctx_init(conn, config) != NGX_SSL_H2_OK) {
        ngx_ssl_h2_buffer_destroy(&conn->read_buffer);
        ngx_ssl_h2_buffer_destroy(&conn->write_buffer);
        free(conn);
        return NULL;
    }
    
    return conn;
}

/*
 * ============================================================================
 * 连接销毁
 * ============================================================================
 */

void
ngx_ssl_h2_connection_destroy(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return;
    }
    
    /* 销毁所有流 */
    ngx_h2_stream_t *stream = conn->streams_head;
    while (stream) {
        ngx_h2_stream_t *next = stream->next;
        ngx_h2_stream_destroy(stream);
        stream = next;
    }
    
    /* 销毁 nghttp2 会话 */
    if (conn->h2_session) {
        nghttp2_session_del(conn->h2_session);
    }
    
    if (conn->h2_callbacks) {
        nghttp2_session_callbacks_del(conn->h2_callbacks);
    }
    
    if (conn->h2_options) {
        nghttp2_option_del(conn->h2_options);
    }
    
    /* 销毁 SSL */
    if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }
    
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
    }
    
    /* 释放证书信息 */
    if (conn->session_info.peer_cert) {
        X509_free(conn->session_info.peer_cert);
    }
    /* 注意: peer_cert_chain 由 SSL 拥有，不需要单独释放 */
    
    /* 销毁缓冲区 */
    ngx_ssl_h2_buffer_destroy(&conn->read_buffer);
    ngx_ssl_h2_buffer_destroy(&conn->write_buffer);
    
    /* 关闭 socket */
    if (conn->fd >= 0) {
        close(conn->fd);
    }
    
    free(conn);
}

/*
 * ============================================================================
 * 连接完整握手流程
 * ============================================================================
 */

int
ngx_ssl_h2_connection_start(ngx_ssl_h2_connection_t *conn)
{
    int ret;
    
    if (!conn) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 执行 TLS 握手 */
    ret = ngx_ssl_h2_handshake(conn);
    if (ret != NGX_SSL_H2_OK) {
        return ret;
    }
    
    /* 检查 ALPN 协商结果 */
    if (conn->session_info.alpn_protocol &&
        conn->session_info.alpn_protocol_len == 2 &&
        memcmp(conn->session_info.alpn_protocol, "h2", 2) == 0) {
        
        /* 初始化 HTTP/2 会话 */
        ret = ngx_h2_session_init(conn);
        if (ret != NGX_SSL_H2_OK) {
            snprintf(conn->error_msg, sizeof(conn->error_msg),
                     "Failed to initialize HTTP/2 session");
            return NGX_SSL_H2_ERROR;
        }
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * I/O 事件处理
 * ============================================================================
 */

int
ngx_ssl_h2_read(ngx_ssl_h2_connection_t *conn)
{
    int ret;
    ssize_t n;
    
    if (!conn) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 从 socket 读取到 SSL BIO */
    uint8_t buf[16384];
    n = read(conn->fd, buf, sizeof(buf));
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return NGX_SSL_H2_WANT_READ;
        }
        snprintf(conn->error_msg, sizeof(conn->error_msg),
                 "Socket read error: %s", strerror(errno));
        return NGX_SSL_H2_ERROR;
    }
    
    if (n == 0) {
        /* 连接关闭 */
        return 0;
    }
    
    /* 写入 BIO */
    if (conn->wbio) {
        int written = BIO_write(conn->wbio, buf, (int)n);
        if (written <= 0) {
            return NGX_SSL_H2_ERROR;
        }
    }
    
    /* 如果握手未完成，继续握手 */
    if (!conn->handshake_complete) {
        ret = ngx_ssl_h2_handshake(conn);
        if (ret == NGX_SSL_H2_OK && !conn->h2_session) {
            /* 握手完成，初始化 HTTP/2 */
            if (conn->session_info.alpn_protocol &&
                memcmp(conn->session_info.alpn_protocol, "h2", 2) == 0) {
                ngx_h2_session_init(conn);
            }
        }
        return ret;
    }
    
    /* 处理 HTTP/2 数据 */
    if (conn->h2_session) {
        return ngx_ssl_h2_process(conn);
    }
    
    return NGX_SSL_H2_OK;
}

int
ngx_ssl_h2_write(ngx_ssl_h2_connection_t *conn)
{
    int pending;
    ssize_t n;
    
    if (!conn) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 从 SSL BIO 读取数据并写入 socket */
    while ((pending = BIO_ctrl_pending(conn->rbio)) > 0) {
        uint8_t buf[16384];
        int to_read = pending < (int)sizeof(buf) ? pending : (int)sizeof(buf);
        int nread = BIO_read(conn->rbio, buf, to_read);
        
        if (nread <= 0) {
            break;
        }
        
        n = write(conn->fd, buf, nread);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return NGX_SSL_H2_WANT_WRITE;
            }
            snprintf(conn->error_msg, sizeof(conn->error_msg),
                     "Socket write error: %s", strerror(errno));
            return NGX_SSL_H2_ERROR;
        }
    }
    
    return NGX_SSL_H2_OK;
}

int
ngx_ssl_h2_flush(ngx_ssl_h2_connection_t *conn)
{
    int ret;
    
    if (!conn) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 发送所有待处理的 HTTP/2 帧 */
    if (conn->h2_session) {
        ret = nghttp2_session_send(conn->h2_session);
        if (ret != 0 && ret != NGHTTP2_ERR_WOULDBLOCK) {
            return NGX_SSL_H2_ERROR;
        }
    }
    
    /* 刷新到 socket */
    return ngx_ssl_h2_write(conn);
}

/*
 * ============================================================================
 * 状态检查
 * ============================================================================
 */

bool
ngx_ssl_h2_is_readable(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return false;
    }
    
    /* 检查 SSL 是否有待读取的数据 */
    if (conn->ssl && SSL_pending(conn->ssl) > 0) {
        return true;
    }
    
    /* 检查 BIO 是否有待处理的数据 */
    if (conn->wbio && BIO_ctrl_pending(conn->wbio) > 0) {
        return true;
    }
    
    return false;
}

bool
ngx_ssl_h2_is_writable(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return false;
    }
    
    /* 检查是否有待发送的 HTTP/2 数据 */
    if (conn->h2_session && nghttp2_session_want_write(conn->h2_session)) {
        return true;
    }
    
    /* 检查 BIO 是否有待发送的数据 */
    if (conn->rbio && BIO_ctrl_pending(conn->rbio) > 0) {
        return true;
    }
    
    return false;
}

bool
ngx_ssl_h2_want_read(ngx_ssl_h2_connection_t *conn)
{
    if (!conn || !conn->h2_session) {
        return false;
    }
    
    return nghttp2_session_want_read(conn->h2_session) != 0;
}

bool
ngx_ssl_h2_want_write(ngx_ssl_h2_connection_t *conn)
{
    if (!conn || !conn->h2_session) {
        return false;
    }
    
    return nghttp2_session_want_write(conn->h2_session) != 0;
}

/*
 * ============================================================================
 * 连接信息获取
 * ============================================================================
 */

const char *
ngx_ssl_h2_get_alpn_protocol(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return NULL;
    }
    
    return conn->session_info.alpn_protocol;
}

const char *
ngx_ssl_h2_get_cipher_name(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return NULL;
    }
    
    return conn->session_info.cipher_name;
}

uint16_t
ngx_ssl_h2_get_tls_version(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return 0;
    }
    
    return conn->session_info.tls_version;
}

bool
ngx_ssl_h2_is_session_reused(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return false;
    }
    
    return conn->session_info.session_reused;
}

const ngx_ssl_h2_stats_t *
ngx_ssl_h2_get_stats(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return NULL;
    }
    
    return &conn->stats;
}

const char *
ngx_ssl_h2_get_error_msg(ngx_ssl_h2_connection_t *conn)
{
    if (!conn) {
        return "Invalid connection";
    }
    
    return conn->error_msg[0] ? conn->error_msg : NULL;
}
