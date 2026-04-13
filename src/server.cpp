#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include "common/logging.h"
#include "tls_session.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <signal.h>

class SimpleTlsServer {
public:
    SimpleTlsServer(uint16_t port) : port_(port) {}


    
    bool run() {
        if (!reactor_.init()) return false;

        // 1. 初始化 TLS 上下文 (配置服务端证书)
        if (!tls_ctx_.init_server()) {
            // 如果没有证书，init_server 内部会生成自签名证书
        }
        tls_ctx_.set_alpn({"h2", "http/1.1"});

        // 2. 创建监听 Socket
        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port_);
        
        bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
        listen(listen_fd, 128);
        set_nonblocking(listen_fd);
        PROXY_LOG_INFO("[server] server listen " <<  port_ );
        
        // 3. 将监听 FD 加入 Reactor
        reactor_.add(listen_fd, Event::READABLE, [this](int fd, int ev) {
            this->on_accept(fd);
        });

        // 4. 事件循环
        while (true) {
            reactor_.wait(100); // 每一轮 wait 都会触发回调
        }
    }

private:
    void on_accept(int listen_fd) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
        PROXY_LOG_INFO("[server] on_accept fd=" << client_fd);
        if (client_fd < 0) return;

        set_nonblocking(client_fd);

        // cleanup callback：session 关闭时从 map 中移除，shared_ptr 引用归零后析构
        auto cleanup = [this](int fd) {
            PROXY_LOG_INFO("[server] session closed fd=" << fd);
            sessions_.erase(fd);
        };

        auto session = std::make_shared<TlsSession>(client_fd, reactor_, tls_ctx_, cleanup);

        if (!session->start_server()) {
            // start_server 失败时 tls_sock_ 未持有 fd，需要手动关闭
            ::close(client_fd);
        } else {
            sessions_[client_fd] = std::move(session);
        }
    }

    void set_nonblocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    uint16_t port_;
    Reactor reactor_;
    TlsContext tls_ctx_;
    std::unordered_map<int, std::shared_ptr<TlsSession>> sessions_;
};

int main() {
    signal(SIGPIPE, SIG_IGN); // 写已关闭 socket 返回 EPIPE 而非崩溃
    SimpleTlsServer server(8443);
    server.run();
    return 0;
}