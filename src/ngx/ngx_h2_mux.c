/*
 * ngx_h2_mux.c - HTTP/2 Multiplexing Implementation with nghttp2
 *
 * 实现 HTTP/2 多路复用核心功能，包括：
 * - 帧处理与流管理
 * - 流量控制
 * - 头部压缩 (HPACK)
 * - 流优先级
 * - GOAWAY 处理
 */

#include "ngx_ssl_h2_core.h"
#include <stdlib.h>
#include <string.h>

/*
 * ============================================================================
 * HTTP/2 连接前言 (Connection Preface)
 * ============================================================================
 */

/* 客户端连接前言 - RFC 7540 Section 3.5 */
static const uint8_t NGX_H2_CLIENT_PREFACE[] = {
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,  /* PRI * HT */
    0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,  /* TP/2.0\r\n */
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a   /* \r\nSM\r\n\r\n */
};

#define NGX_H2_CLIENT_PREFACE_LEN 24

/*
 * ============================================================================
 * nghttp2 回调函数
 * ============================================================================
 */

/*
 * 发送回调 - nghttp2 需要发送数据时调用
 */
static ssize_t
ngx_h2_send_callback(nghttp2_session *session,
                     const uint8_t *data,
                     size_t length,
                     int flags,
                     void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    
    (void)session;
    (void)flags;
    
    /* 写入 TLS 层 */
    int ret = ngx_ssl_write(conn, data, length);
    
    if (ret == NGX_SSL_H2_WANT_WRITE) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    
    if (ret < 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    conn->stats.frames_sent++;
    return ret;
}

/*
 * 接收回调 - nghttp2 需要接收数据时调用
 */
static ssize_t
ngx_h2_recv_callback(nghttp2_session *session,
                     uint8_t *buf,
                     size_t length,
                     int flags,
                     void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    
    (void)session;
    (void)flags;
    
    int ret = ngx_ssl_read(conn, buf, length);
    
    if (ret == NGX_SSL_H2_WANT_READ) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    
    if (ret == 0) {
        return NGHTTP2_ERR_EOF;
    }
    
    if (ret < 0) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    conn->stats.frames_received++;
    return ret;
}

/*
 * 帧接收开始回调
 */
static int
ngx_h2_on_begin_frame_callback(nghttp2_session *session,
                               const nghttp2_frame_hd *hd,
                               void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    
    (void)session;
    (void)conn;
    
    /* 可以在这里进行帧类型验证 */
    switch (hd->type) {
    case NGHTTP2_DATA:
    case NGHTTP2_HEADERS:
    case NGHTTP2_PRIORITY:
    case NGHTTP2_RST_STREAM:
    case NGHTTP2_SETTINGS:
    case NGHTTP2_PUSH_PROMISE:
    case NGHTTP2_PING:
    case NGHTTP2_GOAWAY:
    case NGHTTP2_WINDOW_UPDATE:
    case NGHTTP2_CONTINUATION:
        return 0;
    default:
        /* 忽略未知帧类型 */
        return 0;
    }
}

/*
 * 帧接收完成回调
 */
static int
ngx_h2_on_frame_recv_callback(nghttp2_session *session,
                              const nghttp2_frame *frame,
                              void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    ngx_h2_stream_t *stream;
    
    switch (frame->hd.type) {
    case NGHTTP2_SETTINGS:
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            /* SETTINGS ACK 收到 */
            break;
        }
        
        /* 记录远端设置 */
        for (size_t i = 0; i < frame->settings.niv; i++) {
            nghttp2_settings_entry *entry = &frame->settings.iv[i];
            switch (entry->settings_id) {
            case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
                /* 记录最大并发流数 */
                break;
            case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
                /* 更新初始窗口大小 */
                break;
            case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
                /* 更新最大帧大小 */
                break;
            }
        }
        break;
        
    case NGHTTP2_GOAWAY:
        conn->goaway_received = 1;
        conn->last_stream_id = frame->goaway.last_stream_id;
        break;
        
    case NGHTTP2_WINDOW_UPDATE:
        if (frame->hd.stream_id == 0) {
            /* 连接级窗口更新 */
            conn->send_window_size += frame->window_update.window_size_increment;
        } else {
            /* 流级窗口更新 */
            stream = ngx_h2_stream_find(conn, frame->hd.stream_id);
            if (stream) {
                stream->send_window_size += frame->window_update.window_size_increment;
            }
        }
        break;
        
    case NGHTTP2_DATA:
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream = ngx_h2_stream_find(conn, frame->hd.stream_id);
            if (stream) {
                if (stream->state == NGX_H2_STREAM_OPEN) {
                    stream->state = NGX_H2_STREAM_HALF_CLOSED_REMOTE;
                } else if (stream->state == NGX_H2_STREAM_HALF_CLOSED_LOCAL) {
                    stream->state = NGX_H2_STREAM_CLOSED;
                }
            }
        }
        break;
        
    case NGHTTP2_HEADERS:
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream = ngx_h2_stream_find(conn, frame->hd.stream_id);
            if (stream) {
                if (stream->state == NGX_H2_STREAM_OPEN) {
                    stream->state = NGX_H2_STREAM_HALF_CLOSED_REMOTE;
                }
            }
        }
        break;
        
    case NGHTTP2_RST_STREAM:
        stream = ngx_h2_stream_find(conn, frame->hd.stream_id);
        if (stream) {
            stream->state = NGX_H2_STREAM_CLOSED;
            conn->stats.streams_closed++;
        }
        break;
        
    default:
        break;
    }
    
    return 0;
}

/*
 * 流关闭回调
 */
static int
ngx_h2_on_stream_close_callback(nghttp2_session *session,
                                int32_t stream_id,
                                uint32_t error_code,
                                void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    ngx_h2_stream_t *stream;
    
    (void)session;
    
    stream = ngx_h2_stream_find(conn, stream_id);
    if (stream) {
        stream->state = NGX_H2_STREAM_CLOSED;
        conn->stats.streams_closed++;
        
        /* 从链表中移除 */
        if (stream->prev) {
            stream->prev->next = stream->next;
        } else {
            conn->streams_head = stream->next;
        }
        
        if (stream->next) {
            stream->next->prev = stream->prev;
        } else {
            conn->streams_tail = stream->prev;
        }
        
        conn->stream_count--;
        
        /* 这里可以调用用户的 stream close 回调 */
        (void)error_code;
    }
    
    return 0;
}

/*
 * 头部接收开始回调
 */
static int
ngx_h2_on_begin_headers_callback(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    ngx_h2_stream_t *stream;
    
    (void)session;
    
    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }
    
    /* 对于服务端，创建新流来处理请求 */
    if (conn->is_server && 
        frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        
        stream = ngx_h2_stream_create(conn, frame->hd.stream_id);
        if (!stream) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        
        stream->state = NGX_H2_STREAM_OPEN;
        conn->stats.streams_created++;
    }
    
    return 0;
}

/*
 * 单个头部接收回调
 */
static int
ngx_h2_on_header_callback(nghttp2_session *session,
                          const nghttp2_frame *frame,
                          const uint8_t *name,
                          size_t namelen,
                          const uint8_t *value,
                          size_t valuelen,
                          uint8_t flags,
                          void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    ngx_h2_stream_t *stream;
    
    (void)session;
    (void)flags;
    
    stream = ngx_h2_stream_find(conn, frame->hd.stream_id);
    if (!stream) {
        return 0;
    }
    
    /* 动态扩展头部数组 */
    size_t new_count = stream->header_count + 1;
    ngx_h2_header_t *new_headers = realloc(stream->headers,
                                           new_count * sizeof(ngx_h2_header_t));
    if (!new_headers) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    stream->headers = new_headers;
    
    /* 复制头部数据 */
    ngx_h2_header_t *hdr = &stream->headers[stream->header_count];
    
    hdr->name = strndup((const char *)name, namelen);
    hdr->name_len = namelen;
    hdr->value = strndup((const char *)value, valuelen);
    hdr->value_len = valuelen;
    hdr->flags = flags;
    
    stream->header_count = new_count;
    
    return 0;
}

/*
 * 数据块接收回调
 */
static int
ngx_h2_on_data_chunk_recv_callback(nghttp2_session *session,
                                   uint8_t flags,
                                   int32_t stream_id,
                                   const uint8_t *data,
                                   size_t len,
                                   void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    ngx_h2_stream_t *stream;
    
    (void)session;
    (void)flags;
    
    stream = ngx_h2_stream_find(conn, stream_id);
    if (!stream) {
        return 0;
    }
    
    /* 写入流的数据缓冲区 */
    ngx_ssl_h2_buffer_t *buf = &stream->data_buffer;
    
    /* 扩展缓冲区 */
    size_t required = buf->size + len;
    if (required > buf->capacity) {
        size_t new_capacity = buf->capacity ? buf->capacity * 2 : 4096;
        while (new_capacity < required) {
            new_capacity *= 2;
        }
        
        uint8_t *new_data = realloc(buf->data, new_capacity);
        if (!new_data) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    
    /* 更新接收窗口 - 自动流控 */
    stream->recv_window_size -= len;
    conn->recv_window_size -= len;
    
    /* 如果窗口太小，发送 WINDOW_UPDATE */
    if (stream->recv_window_size < NGX_SSL_H2_INITIAL_WINDOW_SIZE / 2) {
        int32_t increment = NGX_SSL_H2_INITIAL_WINDOW_SIZE - stream->recv_window_size;
        nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, stream_id, increment);
        stream->recv_window_size += increment;
    }
    
    if (conn->recv_window_size < NGX_SSL_H2_INITIAL_WINDOW_SIZE / 2) {
        int32_t increment = NGX_SSL_H2_INITIAL_WINDOW_SIZE - conn->recv_window_size;
        nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, increment);
        conn->recv_window_size += increment;
    }
    
    return 0;
}

/*
 * 无效帧接收回调
 */
static int
ngx_h2_on_invalid_frame_recv_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame,
                                      int lib_error_code,
                                      void *user_data)
{
    ngx_ssl_h2_connection_t *conn = (ngx_ssl_h2_connection_t *)user_data;
    
    (void)session;
    (void)frame;
    
    snprintf(conn->error_msg, sizeof(conn->error_msg),
             "Invalid frame received: %s",
             nghttp2_strerror(lib_error_code));
    
    return 0;
}

/*
 * ============================================================================
 * HTTP/2 会话初始化
 * ============================================================================
 */
int
ngx_h2_session_init(ngx_ssl_h2_connection_t *conn)
{
    int rv;
    nghttp2_session_callbacks *callbacks;
    nghttp2_option *option;
    
    if (!conn) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 创建回调对象 */
    rv = nghttp2_session_callbacks_new(&callbacks);
    if (rv != 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 设置回调函数 */
    nghttp2_session_callbacks_set_send_callback(callbacks, ngx_h2_send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, ngx_h2_recv_callback);
    nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks, ngx_h2_on_begin_frame_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, ngx_h2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, ngx_h2_on_stream_close_callback);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, ngx_h2_on_begin_headers_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, ngx_h2_on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, ngx_h2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(callbacks, ngx_h2_on_invalid_frame_recv_callback);
    
    conn->h2_callbacks = callbacks;
    
    /* 创建选项对象 */
    rv = nghttp2_option_new(&option);
    if (rv != 0) {
        nghttp2_session_callbacks_del(callbacks);
        return NGX_SSL_H2_ERROR;
    }
    
    /* 设置选项 */
    nghttp2_option_set_no_auto_window_update(option, 0);
    nghttp2_option_set_peer_max_concurrent_streams(option, NGX_SSL_H2_MAX_STREAMS);
    
    conn->h2_options = option;
    
    /* 创建会话 */
    if (conn->is_server) {
        rv = nghttp2_session_server_new2(&conn->h2_session, callbacks, conn, option);
    } else {
        rv = nghttp2_session_client_new2(&conn->h2_session, callbacks, conn, option);
    }
    
    if (rv != 0) {
        nghttp2_option_del(option);
        nghttp2_session_callbacks_del(callbacks);
        return NGX_SSL_H2_ERROR;
    }
    
    /* 设置本地 SETTINGS */
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 
         conn->config ? conn->config->max_concurrent_streams : NGX_SSL_H2_MAX_STREAMS},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
         conn->config ? conn->config->initial_window_size : NGX_SSL_H2_INITIAL_WINDOW_SIZE},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
         conn->config ? conn->config->max_frame_size : NGX_SSL_H2_MAX_FRAME_SIZE},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
         conn->config ? conn->config->max_header_list_size : NGX_SSL_H2_MAX_HEADER_LIST_SIZE},
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
         conn->config ? conn->config->header_table_size : NGX_SSL_H2_HEADER_TABLE_SIZE},
        {NGHTTP2_SETTINGS_ENABLE_PUSH,
         conn->config ? conn->config->enable_push : 0}
    };
    
    rv = nghttp2_submit_settings(conn->h2_session, NGHTTP2_FLAG_NONE,
                                 settings, sizeof(settings)/sizeof(settings[0]));
    if (rv != 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 初始化窗口大小 */
    conn->recv_window_size = NGX_SSL_H2_INITIAL_WINDOW_SIZE;
    conn->send_window_size = NGX_SSL_H2_INITIAL_WINDOW_SIZE;
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * 流管理
 * ============================================================================
 */

ngx_h2_stream_t *
ngx_h2_stream_create(ngx_ssl_h2_connection_t *conn, int32_t stream_id)
{
    ngx_h2_stream_t *stream;
    
    if (!conn) {
        return NULL;
    }
    
    /* 检查流数量限制 */
    if (conn->stream_count >= NGX_SSL_H2_MAX_STREAMS) {
        return NULL;
    }
    
    stream = calloc(1, sizeof(ngx_h2_stream_t));
    if (!stream) {
        return NULL;
    }
    
    stream->stream_id = stream_id;
    stream->state = NGX_H2_STREAM_IDLE;
    stream->recv_window_size = NGX_SSL_H2_INITIAL_WINDOW_SIZE;
    stream->send_window_size = NGX_SSL_H2_INITIAL_WINDOW_SIZE;
    stream->weight = 16;  /* 默认权重 */
    stream->connection = conn;
    
    /* 添加到链表尾部 */
    stream->prev = conn->streams_tail;
    stream->next = NULL;
    
    if (conn->streams_tail) {
        conn->streams_tail->next = stream;
    } else {
        conn->streams_head = stream;
    }
    conn->streams_tail = stream;
    
    conn->stream_count++;
    
    return stream;
}

void
ngx_h2_stream_destroy(ngx_h2_stream_t *stream)
{
    if (!stream) {
        return;
    }
    
    /* 释放头部 */
    for (size_t i = 0; i < stream->header_count; i++) {
        free((void *)stream->headers[i].name);
        free((void *)stream->headers[i].value);
    }
    free(stream->headers);
    
    /* 释放数据缓冲区 */
    free(stream->data_buffer.data);
    
    free(stream);
}

ngx_h2_stream_t *
ngx_h2_stream_find(ngx_ssl_h2_connection_t *conn, int32_t stream_id)
{
    ngx_h2_stream_t *stream;
    
    if (!conn) {
        return NULL;
    }
    
    for (stream = conn->streams_head; stream; stream = stream->next) {
        if (stream->stream_id == stream_id) {
            return stream;
        }
    }
    
    return NULL;
}

/*
 * ============================================================================
 * HTTP/2 请求/响应提交
 * ============================================================================
 */

/*
 * 数据提供者回调 - 用于分块发送数据
 */
typedef struct {
    const uint8_t  *data;
    size_t          len;
    size_t          pos;
} ngx_h2_data_source_t;

static ssize_t
ngx_h2_data_source_read_callback(nghttp2_session *session,
                                 int32_t stream_id,
                                 uint8_t *buf,
                                 size_t length,
                                 uint32_t *data_flags,
                                 nghttp2_data_source *source,
                                 void *user_data)
{
    ngx_h2_data_source_t *ds = (ngx_h2_data_source_t *)source->ptr;
    
    (void)session;
    (void)stream_id;
    (void)user_data;
    
    size_t remaining = ds->len - ds->pos;
    size_t nread = length < remaining ? length : remaining;
    
    memcpy(buf, ds->data + ds->pos, nread);
    ds->pos += nread;
    
    if (ds->pos >= ds->len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    
    return (ssize_t)nread;
}

int
ngx_h2_submit_request(ngx_ssl_h2_connection_t *conn,
                      const ngx_h2_header_t *headers,
                      size_t header_count,
                      const uint8_t *data,
                      size_t data_len,
                      int32_t *stream_id)
{
    int rv;
    nghttp2_nv *nva;
    nghttp2_data_provider data_prd;
    ngx_h2_data_source_t *ds = NULL;
    
    if (!conn || !conn->h2_session || conn->is_server) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 转换头部格式 */
    nva = calloc(header_count, sizeof(nghttp2_nv));
    if (!nva) {
        return NGX_SSL_H2_ERROR;
    }
    
    for (size_t i = 0; i < header_count; i++) {
        nva[i].name = (uint8_t *)headers[i].name;
        nva[i].namelen = headers[i].name_len;
        nva[i].value = (uint8_t *)headers[i].value;
        nva[i].valuelen = headers[i].value_len;
        nva[i].flags = NGHTTP2_NV_FLAG_NONE;
    }
    
    /* 设置数据提供者 */
    if (data && data_len > 0) {
        ds = malloc(sizeof(ngx_h2_data_source_t));
        if (!ds) {
            free(nva);
            return NGX_SSL_H2_ERROR;
        }
        
        ds->data = data;
        ds->len = data_len;
        ds->pos = 0;
        
        data_prd.source.ptr = ds;
        data_prd.read_callback = ngx_h2_data_source_read_callback;
    }
    
    /* 提交请求 */
    rv = nghttp2_submit_request(conn->h2_session, NULL, nva, header_count,
                                (data && data_len > 0) ? &data_prd : NULL,
                                ds);
    
    free(nva);
    
    if (rv < 0) {
        free(ds);
        return NGX_SSL_H2_ERROR;
    }
    
    if (stream_id) {
        *stream_id = rv;
    }
    
    /* 创建流对象 */
    ngx_h2_stream_t *stream = ngx_h2_stream_create(conn, rv);
    if (stream) {
        stream->state = NGX_H2_STREAM_OPEN;
        conn->stats.streams_created++;
    }
    
    return NGX_SSL_H2_OK;
}

int
ngx_h2_submit_response(ngx_ssl_h2_connection_t *conn,
                       int32_t stream_id,
                       const ngx_h2_header_t *headers,
                       size_t header_count,
                       const uint8_t *data,
                       size_t data_len)
{
    int rv;
    nghttp2_nv *nva;
    nghttp2_data_provider data_prd;
    ngx_h2_data_source_t *ds = NULL;
    
    if (!conn || !conn->h2_session || !conn->is_server) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 转换头部格式 */
    nva = calloc(header_count, sizeof(nghttp2_nv));
    if (!nva) {
        return NGX_SSL_H2_ERROR;
    }
    
    for (size_t i = 0; i < header_count; i++) {
        nva[i].name = (uint8_t *)headers[i].name;
        nva[i].namelen = headers[i].name_len;
        nva[i].value = (uint8_t *)headers[i].value;
        nva[i].valuelen = headers[i].value_len;
        nva[i].flags = NGHTTP2_NV_FLAG_NONE;
    }
    
    /* 设置数据提供者 */
    if (data && data_len > 0) {
        ds = malloc(sizeof(ngx_h2_data_source_t));
        if (!ds) {
            free(nva);
            return NGX_SSL_H2_ERROR;
        }
        
        ds->data = data;
        ds->len = data_len;
        ds->pos = 0;
        
        data_prd.source.ptr = ds;
        data_prd.read_callback = ngx_h2_data_source_read_callback;
    }
    
    /* 提交响应 */
    rv = nghttp2_submit_response(conn->h2_session, stream_id, nva, header_count,
                                 (data && data_len > 0) ? &data_prd : NULL);
    
    free(nva);
    
    if (rv != 0) {
        free(ds);
        return NGX_SSL_H2_ERROR;
    }
    
    /* 更新流状态 */
    ngx_h2_stream_t *stream = ngx_h2_stream_find(conn, stream_id);
    if (stream && stream->state == NGX_H2_STREAM_OPEN) {
        if (!data || data_len == 0) {
            stream->state = NGX_H2_STREAM_HALF_CLOSED_LOCAL;
        }
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * 控制帧发送
 * ============================================================================
 */

int
ngx_h2_send_goaway(ngx_ssl_h2_connection_t *conn,
                   int32_t last_stream_id,
                   uint32_t error_code)
{
    int rv;
    
    if (!conn || !conn->h2_session) {
        return NGX_SSL_H2_ERROR;
    }
    
    rv = nghttp2_submit_goaway(conn->h2_session, NGHTTP2_FLAG_NONE,
                               last_stream_id, error_code, NULL, 0);
    
    if (rv != 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    conn->goaway_sent = 1;
    
    return NGX_SSL_H2_OK;
}

int
ngx_h2_send_rst_stream(ngx_ssl_h2_connection_t *conn,
                       int32_t stream_id,
                       uint32_t error_code)
{
    int rv;
    
    if (!conn || !conn->h2_session) {
        return NGX_SSL_H2_ERROR;
    }
    
    rv = nghttp2_submit_rst_stream(conn->h2_session, NGHTTP2_FLAG_NONE,
                                   stream_id, error_code);
    
    if (rv != 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    return NGX_SSL_H2_OK;
}

int
ngx_h2_send_window_update(ngx_ssl_h2_connection_t *conn,
                          int32_t stream_id,
                          int32_t window_size_increment)
{
    int rv;
    
    if (!conn || !conn->h2_session) {
        return NGX_SSL_H2_ERROR;
    }
    
    rv = nghttp2_submit_window_update(conn->h2_session, NGHTTP2_FLAG_NONE,
                                      stream_id, window_size_increment);
    
    if (rv != 0) {
        return NGX_SSL_H2_ERROR;
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * I/O 处理
 * ============================================================================
 */

int
ngx_ssl_h2_process(ngx_ssl_h2_connection_t *conn)
{
    int rv;
    
    if (!conn || !conn->h2_session) {
        return NGX_SSL_H2_ERROR;
    }
    
    /* 接收数据 */
    rv = nghttp2_session_recv(conn->h2_session);
    if (rv != 0 && rv != NGHTTP2_ERR_WOULDBLOCK) {
        snprintf(conn->error_msg, sizeof(conn->error_msg),
                 "nghttp2_session_recv failed: %s", nghttp2_strerror(rv));
        return NGX_SSL_H2_ERROR;
    }
    
    /* 发送数据 */
    rv = nghttp2_session_send(conn->h2_session);
    if (rv != 0 && rv != NGHTTP2_ERR_WOULDBLOCK) {
        snprintf(conn->error_msg, sizeof(conn->error_msg),
                 "nghttp2_session_send failed: %s", nghttp2_strerror(rv));
        return NGX_SSL_H2_ERROR;
    }
    
    return NGX_SSL_H2_OK;
}

/*
 * ============================================================================
 * 工具函数
 * ============================================================================
 */

const char *
ngx_h2_stream_state_str(ngx_h2_stream_state_t state)
{
    static const char *state_strings[] = {
        "IDLE",
        "RESERVED_LOCAL",
        "RESERVED_REMOTE",
        "OPEN",
        "HALF_CLOSED_LOCAL",
        "HALF_CLOSED_REMOTE",
        "CLOSED"
    };
    
    if (state < sizeof(state_strings) / sizeof(state_strings[0])) {
        return state_strings[state];
    }
    
    return "UNKNOWN";
}

const char *
ngx_ssl_h2_strerror(int error)
{
    switch (error) {
    case NGX_SSL_H2_OK:
        return "OK";
    case NGX_SSL_H2_ERROR:
        return "Error";
    case NGX_SSL_H2_AGAIN:
        return "Again";
    case NGX_SSL_H2_WANT_READ:
        return "Want read";
    case NGX_SSL_H2_WANT_WRITE:
        return "Want write";
    default:
        return "Unknown error";
    }
}
