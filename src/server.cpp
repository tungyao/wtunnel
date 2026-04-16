#include "common/reactor.h"
#include "common/tls_wrapper.h"
#include "common/logging.h"
#include "tls_session.h"
#include "reality_session.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <cstdio>
#include <string>
#include <unordered_map>

class SimpleTlsServer {
public:
    SimpleTlsServer(uint16_t port, const std::string& bind_addr,
                    RealityConfig reality = {})
        : port_(port), bind_addr_(bind_addr), reality_(std::move(reality)) {}


    
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
        
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port_);
        if (inet_pton(AF_INET, bind_addr_.c_str(), &addr.sin_addr) != 1) {
            PROXY_LOG_ERROR("[server] invalid bind address: " << bind_addr_);
            return false;
        }

        bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
        listen(listen_fd, 128);
        set_nonblocking(listen_fd);
        PROXY_LOG_INFO("[server] listening on " << bind_addr_ << ":" << port_);
        
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

        // cleanup callback：session 关闭时从 map 中移除
        auto cleanup = [this](int fd) {
            PROXY_LOG_INFO("[server] session closed fd=" << fd);
            sessions_.erase(fd);
            reality_sessions_.erase(fd);
        };

        if (!reality_.psk.empty()) {
            // REALITY 模式：先探测客户端身份
            auto rsession = std::make_shared<RealitySession>(
                client_fd, reactor_, tls_ctx_, reality_, cleanup);
            if (!rsession->start()) {
                ::close(client_fd);
            } else {
                reality_sessions_[client_fd] = std::move(rsession);
            }
        } else {
            // 普通 TLS 模式
            auto session = std::make_shared<TlsSession>(
                client_fd, reactor_, tls_ctx_, cleanup);
            if (!session->start_server()) {
                ::close(client_fd);
            } else {
                sessions_[client_fd] = std::move(session);
            }
        }
    }

    void set_nonblocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    uint16_t    port_;
    std::string bind_addr_;
    RealityConfig reality_;
    Reactor reactor_;
    TlsContext tls_ctx_;
    std::unordered_map<int, std::shared_ptr<TlsSession>>    sessions_;
    std::unordered_map<int, std::shared_ptr<RealitySession>> reality_sessions_;
};

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -p <port>         Listen port              (default: 8443)\n"
        "  -b <addr>         Bind address             (default: 0.0.0.0)\n"
        "  -R <host[:port]>  REALITY: real site target (e.g. www.microsoft.com)\n"
        "  -K <psk>          REALITY: pre-shared key for client auth\n"
        "  -h                Show this help message\n"
        "\n"
        "REALITY mode (both -R and -K required):\n"
        "  Verified clients get a normal TLS tunnel.\n"
        "  All other connections are transparently proxied to the real site,\n"
        "  so scanners see the real site's certificate.\n"
        "\n"
        "Example:\n"
        "  %s -p 443 -R www.microsoft.com -K mysecret\n",
        prog, prog);
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    uint16_t    port       = 8443;
    std::string bind_addr  = "0.0.0.0";
    RealityConfig reality;

    int opt;
    while ((opt = getopt(argc, argv, "p:b:R:K:h")) != -1) {
        switch (opt) {
        case 'p': port             = (uint16_t)std::stoi(optarg); break;
        case 'b': bind_addr        = optarg;                       break;
        case 'K': reality.psk      = optarg;                       break;
        case 'R': {
            // 解析 host 或 host:port
            std::string s = optarg;
            auto col = s.rfind(':');
            if (col != std::string::npos) {
                reality.target_host = s.substr(0, col);
                reality.target_port = (uint16_t)std::stoi(s.substr(col + 1));
            } else {
                reality.target_host = s;
                reality.target_port = 443;
            }
            break;
        }
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (!reality.psk.empty() && reality.target_host.empty()) {
        fprintf(stderr, "Error: -K requires -R <target_host>\n");
        return 1;
    }

    SimpleTlsServer server(port, bind_addr, std::move(reality));
    server.run();
    return 0;
}