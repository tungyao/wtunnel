/*
 * ngx_ssl_h2_core.h - TLS Handshake & HTTP/2 Multiplexing Core Module
 * 
 * 结合 nginx TLS 处理逻辑、BoringSSL 和 nghttp2
 * 实现 TLS 1.3 握手、ALPN 协商和 HTTP/2 多路复用
 */

#ifndef _NGX_SSL_H2_CORE_H_
#define _NGX_SSL_H2_CORE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* BoringSSL headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

/* nghttp2 headers */
#include <nghttp2/nghttp2.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * 常量定义
 * ============================================================================
 */

#define NGX_SSL_H2_OK                    0
#define NGX_SSL_H2_ERROR                -1
#define NGX_SSL_H2_AGAIN                -2
#define NGX_SSL_H2_WANT_READ            -3
#define NGX_SSL_H2_WANT_WRITE           -4

#define NGX_SSL_H2_MAX_STREAMS          256
#define NGX_SSL_H2_FRAME_BUFFER_SIZE    16384
#define NGX_SSL_H2_HEADER_TABLE_SIZE    4096
#define NGX_SSL_H2_INITIAL_WINDOW_SIZE  65535
#define NGX_SSL_H2_MAX_FRAME_SIZE       16384
#define NGX_SSL_H2_MAX_HEADER_LIST_SIZE 65536

/* TLS 握手状态 */
typedef enum {
    NGX_SSL_HANDSHAKE_INIT = 0,
    NGX_SSL_HANDSHAKE_CLIENT_HELLO,
    NGX_SSL_HANDSHAKE_SERVER_HELLO,
    NGX_SSL_HANDSHAKE_ENCRYPTED_EXTENSIONS,
    NGX_SSL_HANDSHAKE_CERTIFICATE,
    NGX_SSL_HANDSHAKE_CERTIFICATE_VERIFY,
    NGX_SSL_HANDSHAKE_FINISHED,
    NGX_SSL_HANDSHAKE_COMPLETE,
    NGX_SSL_HANDSHAKE_FAILED
} ngx_ssl_handshake_state_t;

/* HTTP/2 流状态 (RFC 7540) */
typedef enum {
    NGX_H2_STREAM_IDLE = 0,
    NGX_H2_STREAM_RESERVED_LOCAL,
    NGX_H2_STREAM_RESERVED_REMOTE,
    NGX_H2_STREAM_OPEN,
    NGX_H2_STREAM_HALF_CLOSED_LOCAL,
    NGX_H2_STREAM_HALF_CLOSED_REMOTE,
    NGX_H2_STREAM_CLOSED
} ngx_h2_stream_state_t;

/*
 * ============================================================================
 * 数据结构定义
 * ============================================================================
 */

/* 前向声明 */
typedef struct ngx_ssl_h2_connection_s ngx_ssl_h2_connection_t;
typedef struct ngx_h2_stream_s ngx_h2_stream_t;
typedef struct ngx_ssl_h2_config_s ngx_ssl_h2_config_t;

/* 缓冲区结构 */
typedef struct {
    uint8_t        *data;
    size_t          size;
    size_t          capacity;
    size_t          read_pos;
    size_t          write_pos;
} ngx_ssl_h2_buffer_t;

/* HTTP/2 头部对 */
typedef struct {
    const char     *name;
    size_t          name_len;
    const char     *value;
    size_t          value_len;
    uint8_t         flags;
} ngx_h2_header_t;

/* HTTP/2 流结构 */
struct ngx_h2_stream_s {
    int32_t                     stream_id;
    ngx_h2_stream_state_t       state;
    
    /* 流级别的流控 */
    int32_t                     recv_window_size;
    int32_t                     send_window_size;
    
    /* 请求/响应数据 */
    ngx_h2_header_t            *headers;
    size_t                      header_count;
    ngx_ssl_h2_buffer_t         data_buffer;
    
    /* 流优先级 */
    int32_t                     dependency;
    uint8_t                     weight;
    bool                        exclusive;
    
    /* 用户数据 */
    void                       *user_data;
    
    /* 链表指针 */
    ngx_h2_stream_t            *next;
    ngx_h2_stream_t            *prev;
    
    /* 所属连接 */
    ngx_ssl_h2_connection_t    *connection;
};

/* TLS 会话信息 */
typedef struct {
    /* 协商的协议版本 */
    uint16_t                    tls_version;
    
    /* 密码套件 */
    uint16_t                    cipher_suite;
    const char                 *cipher_name;
    
    /* ALPN 协商结果 */
    const char                 *alpn_protocol;
    size_t                      alpn_protocol_len;
    
    /* 会话恢复 */
    bool                        session_reused;
    SSL_SESSION                *session;
    
    /* 证书信息 */
    X509                       *peer_cert;
    STACK_OF(X509)             *peer_cert_chain;
    
    /* 密钥交换信息 */
    const char                 *kex_name;
    int                         kex_bits;
    
    /* 0-RTT 状态 */
    bool                        early_data_accepted;
} ngx_ssl_session_info_t;

/* 连接统计 */
typedef struct {
    uint64_t                    bytes_sent;
    uint64_t                    bytes_received;
    uint64_t                    frames_sent;
    uint64_t                    frames_received;
    uint32_t                    streams_created;
    uint32_t                    streams_closed;
    uint64_t                    handshake_time_us;
} ngx_ssl_h2_stats_t;

/* 主连接结构 */
struct ngx_ssl_h2_connection_s {
    /* 文件描述符 */
    int                         fd;
    
    /* BoringSSL 上下文 */
    SSL_CTX                    *ssl_ctx;
    SSL                        *ssl;
    BIO                        *rbio;
    BIO                        *wbio;
    
    /* TLS 状态 */
    ngx_ssl_handshake_state_t   handshake_state;
    ngx_ssl_session_info_t      session_info;
    
    /* nghttp2 会话 */
    nghttp2_session            *h2_session;
    nghttp2_session_callbacks  *h2_callbacks;
    nghttp2_option             *h2_options;
    
    /* HTTP/2 设置 */
    nghttp2_settings_entry      local_settings[6];
    nghttp2_settings_entry      remote_settings[6];
    
    /* 流管理 */
    ngx_h2_stream_t            *streams_head;
    ngx_h2_stream_t            *streams_tail;
    uint32_t                    stream_count;
    int32_t                     last_stream_id;
    
    /* 连接级别流控 */
    int32_t                     recv_window_size;
    int32_t                     send_window_size;
    
    /* I/O 缓冲区 */
    ngx_ssl_h2_buffer_t         read_buffer;
    ngx_ssl_h2_buffer_t         write_buffer;
    
    /* 配置 */
    ngx_ssl_h2_config_t        *config;
    
    /* 统计信息 */
    ngx_ssl_h2_stats_t          stats;
    
    /* 状态标志 */
    unsigned                    is_server:1;
    unsigned                    handshake_complete:1;
    unsigned                    goaway_sent:1;
    unsigned                    goaway_received:1;
    unsigned                    closing:1;
    
    /* 用户数据 */
    void                       *user_data;
    
    /* 错误信息 */
    int                         last_error;
    char                        error_msg[256];
};

/* 配置结构 */
struct ngx_ssl_h2_config_s {
    /* TLS 配置 */
    const char                 *cert_file;
    const char                 *key_file;
    const char                 *ca_file;
    const char                 *ciphers;
    const char                 *curves;
    uint16_t                    min_tls_version;
    uint16_t                    max_tls_version;
    bool                        verify_peer;
    int                         verify_depth;
    
    /* HTTP/2 配置 */
    uint32_t                    max_concurrent_streams;
    uint32_t                    initial_window_size;
    uint32_t                    max_frame_size;
    uint32_t                    max_header_list_size;
    uint32_t                    header_table_size;
    bool                        enable_push;
    
    /* 超时配置 */
    uint32_t                    handshake_timeout_ms;
    uint32_t                    idle_timeout_ms;
    uint32_t                    read_timeout_ms;
    uint32_t                    write_timeout_ms;
    
    /* 缓冲区配置 */
    size_t                      read_buffer_size;
    size_t                      write_buffer_size;
};

/*
 * ============================================================================
 * 回调函数类型定义
 * ============================================================================
 */

/* TLS 握手完成回调 */
typedef void (*ngx_ssl_handshake_cb)(
    ngx_ssl_h2_connection_t *conn,
    int status,
    void *user_data
);

/* HTTP/2 流回调 */
typedef int (*ngx_h2_on_stream_begin_cb)(
    ngx_ssl_h2_connection_t *conn,
    ngx_h2_stream_t *stream,
    void *user_data
);

typedef int (*ngx_h2_on_stream_headers_cb)(
    ngx_ssl_h2_connection_t *conn,
    ngx_h2_stream_t *stream,
    const ngx_h2_header_t *headers,
    size_t header_count,
    bool end_stream,
    void *user_data
);

typedef int (*ngx_h2_on_stream_data_cb)(
    ngx_ssl_h2_connection_t *conn,
    ngx_h2_stream_t *stream,
    const uint8_t *data,
    size_t len,
    bool end_stream,
    void *user_data
);

typedef void (*ngx_h2_on_stream_close_cb)(
    ngx_ssl_h2_connection_t *conn,
    ngx_h2_stream_t *stream,
    uint32_t error_code,
    void *user_data
);

/* 回调集合 */
typedef struct {
    ngx_ssl_handshake_cb        on_handshake_complete;
    ngx_h2_on_stream_begin_cb   on_stream_begin;
    ngx_h2_on_stream_headers_cb on_stream_headers;
    ngx_h2_on_stream_data_cb    on_stream_data;
    ngx_h2_on_stream_close_cb   on_stream_close;
    void                       *user_data;
} ngx_ssl_h2_callbacks_t;

/*
 * ============================================================================
 * API 函数声明
 * ============================================================================
 */

/* 初始化和销毁 */
int ngx_ssl_h2_global_init(void);
void ngx_ssl_h2_global_cleanup(void);

ngx_ssl_h2_config_t *ngx_ssl_h2_config_create(void);
void ngx_ssl_h2_config_destroy(ngx_ssl_h2_config_t *config);
int ngx_ssl_h2_config_set_default(ngx_ssl_h2_config_t *config);

/* 连接管理 */
ngx_ssl_h2_connection_t *ngx_ssl_h2_connection_create(
    int fd,
    ngx_ssl_h2_config_t *config,
    bool is_server
);
void ngx_ssl_h2_connection_destroy(ngx_ssl_h2_connection_t *conn);

int ngx_ssl_h2_set_callbacks(
    ngx_ssl_h2_connection_t *conn,
    const ngx_ssl_h2_callbacks_t *callbacks
);

/* TLS 握手 */
int ngx_ssl_h2_handshake(ngx_ssl_h2_connection_t *conn);
int ngx_ssl_h2_handshake_async(
    ngx_ssl_h2_connection_t *conn,
    ngx_ssl_handshake_cb callback,
    void *user_data
);

/* I/O 操作 */
int ngx_ssl_h2_read(ngx_ssl_h2_connection_t *conn);
int ngx_ssl_h2_write(ngx_ssl_h2_connection_t *conn);
int ngx_ssl_h2_flush(ngx_ssl_h2_connection_t *conn);

/* HTTP/2 流操作 */
ngx_h2_stream_t *ngx_h2_stream_create(
    ngx_ssl_h2_connection_t *conn,
    int32_t stream_id
);
void ngx_h2_stream_destroy(ngx_h2_stream_t *stream);

int ngx_h2_submit_request(
    ngx_ssl_h2_connection_t *conn,
    const ngx_h2_header_t *headers,
    size_t header_count,
    const uint8_t *data,
    size_t data_len,
    int32_t *stream_id
);

int ngx_h2_submit_response(
    ngx_ssl_h2_connection_t *conn,
    int32_t stream_id,
    const ngx_h2_header_t *headers,
    size_t header_count,
    const uint8_t *data,
    size_t data_len
);

int ngx_h2_send_data(
    ngx_ssl_h2_connection_t *conn,
    int32_t stream_id,
    const uint8_t *data,
    size_t len,
    bool end_stream
);

int ngx_h2_send_goaway(
    ngx_ssl_h2_connection_t *conn,
    int32_t last_stream_id,
    uint32_t error_code
);

int ngx_h2_send_rst_stream(
    ngx_ssl_h2_connection_t *conn,
    int32_t stream_id,
    uint32_t error_code
);

int ngx_h2_send_window_update(
    ngx_ssl_h2_connection_t *conn,
    int32_t stream_id,
    int32_t window_size_increment
);

/* 流查询 */
ngx_h2_stream_t *ngx_h2_stream_find(
    ngx_ssl_h2_connection_t *conn,
    int32_t stream_id
);

/* 工具函数 */
const char *ngx_ssl_h2_strerror(int error);
const char *ngx_ssl_handshake_state_str(ngx_ssl_handshake_state_t state);
const char *ngx_h2_stream_state_str(ngx_h2_stream_state_t state);

#ifdef __cplusplus
}
#endif

#endif /* _NGX_SSL_H2_CORE_H_ */
