#include "dns_resolver.h"
#include "common/logging.h"
#include <sys/eventfd.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <algorithm>
#include <cstring>

DnsResolver::DnsResolver(size_t thread_count)
    : thread_count_(thread_count)
    , event_fd_(-1)
    , default_ttl_(300)
    , running_(true) {
    
    event_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event_fd_ < 0) {
        PROXY_LOG_ERROR("eventfd creation failed: " << errno);
    }
    
    for (size_t i = 0; i < thread_count_; ++i) {
        threads_.emplace_back(&DnsResolver::worker_thread, this);
    }
}

DnsResolver::~DnsResolver() {
    running_ = false;
    queue_cv_.notify_all();
    
    for (auto& t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    if (event_fd_ >= 0) {
        close(event_fd_);
    }
}

bool DnsResolver::resolve(const std::string& hostname) {
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = cache_.find(hostname);
        if (it != cache_.end()) {
            auto now = std::chrono::steady_clock::now();
            if (now < it->second.expire_time) {
                std::lock_guard<std::mutex> rlock(results_mutex_);
                completed_results_.push_back(it->second);
                notify();
                return true;
            }
        }
    }
    
    std::lock_guard<std::mutex> lock(queue_mutex_);
    pending_queue_.push(hostname);
    queue_cv_.notify_one();
    return true;
}

std::vector<DnsResult> DnsResolver::drain_results() {
    std::vector<DnsResult> results;
    
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results = std::move(completed_results_);
        completed_results_.clear();
    }
    
    uint64_t count = 0;
    if (event_fd_ >= 0) {
        ssize_t ret = read(event_fd_, &count, sizeof(count));
        (void)ret;
    }
    
    return results;
}

void DnsResolver::worker_thread() {
    while (running_) {
        std::string hostname;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !pending_queue_.empty() || !running_;
            });
            
            if (!running_) break;
            
            if (pending_queue_.empty()) continue;
            
            hostname = pending_queue_.front();
            pending_queue_.pop();
        }
        
        DnsResult result;
        result.hostname = hostname;
        
        if (resolve_hostname(hostname, result)) {
            result.success = true;
            result.expire_time = std::chrono::steady_clock::now() + 
                                std::chrono::seconds(default_ttl_);
            
            {
                std::lock_guard<std::mutex> lock(cache_mutex_);
                cache_[hostname] = result;
            }
        } else {
            result.success = false;
        }
        
        {
            std::lock_guard<std::mutex> lock(results_mutex_);
            completed_results_.push_back(result);
        }
        
        notify();
    }
}

void DnsResolver::notify() {
    if (event_fd_ >= 0) {
        uint64_t count = 1;
        ssize_t ret = write(event_fd_, &count, sizeof(count));
        (void)ret;
    }
}

bool DnsResolver::resolve_hostname(const std::string& hostname, DnsResult& result) {
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        PROXY_LOG_ERROR("DNS resolve failed for " << hostname << ": " 
                       << gai_strerror(status));
        return false;
    }
    
    std::vector<std::string> ipv4_addrs;
    std::vector<std::string> ipv6_addrs;
    
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char ipstr[INET6_ADDRSTRLEN];
        void* addr;
        
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            if (inet_ntop(AF_INET, addr, ipstr, sizeof(ipstr))) {
                ipv4_addrs.push_back(ipstr);
            }
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            if (inet_ntop(AF_INET6, addr, ipstr, sizeof(ipstr))) {
                ipv6_addrs.push_back(ipstr);
            }
        }
    }
    
    freeaddrinfo(res);
    
    result.ip_addresses = ipv4_addrs;
    result.ip_addresses.insert(result.ip_addresses.end(), 
                               ipv6_addrs.begin(), ipv6_addrs.end());
    
    return !result.ip_addresses.empty();
}

bool DnsResolver::is_ipv4(const std::string& ip) const {
    return ip.find(':') == std::string::npos;
}
