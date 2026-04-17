#pragma once
#include "common/tls_wrapper.h"
#include "common/reactor.h"
#include <nghttp2/nghttp2.h>
#include <functional>
#include <memory>
#include <deque>
#include <string>
#include <unordered_map>

class TlsSession : public std::enable_shared_from_this<TlsSession> {
public:
    using CleanupCallback = std::function<void(int fd)>;

    TlsSession(int fd, Reactor& reactor, TlsContext& ctx, CleanupCallback on_close = nullptr);
    ~TlsSession();

    bool start_client(const std::string& hostname);
    bool start_server();

    // Reactor 回调入口
    void on_event(int fd, int events);

private:
    // 逻辑阶段
    enum class State { HANDSHAKING, DATA_TRANSFER, CLOSING };

    void handle_handshake();
    void handle_read();
    void handle_write();
    void update_reactor();
    void do_close();

    // ── CONNECT 隧道相关 ────────────────────────────────────────────────────

    // Persistent data source: fed incrementally, deferred when empty
    struct DataSrc {
        std::deque<std::vector<uint8_t>> chunks;
        bool eof = false;
    };

    struct StreamInfo {
        std::string          method;
        std::string          authority;   // host:port
        int                  upstream_fd = -1;
        bool                 connected   = false;
        std::deque<uint8_t>  up_write;   // client→upstream 缓冲
        DataSrc*             data_src    = nullptr; // upstream→client relay
    };
    void open_upstream(int32_t stream_id, StreamInfo& si);
    void on_upstream_event(int32_t stream_id, int upstream_fd, int events);
    void relay_to_upstream(int32_t stream_id, StreamInfo& si);
    void relay_to_client(int32_t stream_id, StreamInfo& si);
    void close_stream(int32_t stream_id);

    // nghttp2 回调适配
    static ssize_t send_callback(nghttp2_session* session, const uint8_t* data,
                                 size_t length, int flags, void* user_data);
    static int on_frame_recv_callback(nghttp2_session* session,
                                      const nghttp2_frame* frame, void* user_data);
    static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame,
                                   const uint8_t* name, size_t namelen,
                                   const uint8_t* value, size_t valuelen,
                                   uint8_t flags, void* user_data);
    static ssize_t relay_data_read_cb(nghttp2_session* session, int32_t stream_id,
                                       uint8_t* buf, size_t len, uint32_t* data_flags,
                                       nghttp2_data_source* source, void* user_data);
    static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
                                           int32_t stream_id, const uint8_t* data,
                                           size_t len, void* user_data);
    static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
                                        uint32_t error_code, void* user_data);

    int fd_;
    bool is_server_;
    Reactor& reactor_;
    TlsSocket tls_sock_;
    nghttp2_session* h2_session_;
    State state_;
    TlsContext& ctx_;
    CleanupCallback on_close_;
    std::deque<uint8_t> write_buffer_;
    std::unordered_map<int32_t, StreamInfo> streams_;

};
