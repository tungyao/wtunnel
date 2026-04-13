#pragma once

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <chrono>
#include <functional>
#include <atomic>

struct DnsResult {
    std::string hostname;
    std::vector<std::string> ip_addresses;
    bool success;
    std::string error;
    std::chrono::steady_clock::time_point expire_time;
};

class DnsResolver {
public:
    explicit DnsResolver(size_t thread_count = 4);
    ~DnsResolver();
    
    bool resolve(const std::string& hostname);
    std::vector<DnsResult> drain_results();
    
    int get_eventfd() const { return event_fd_; }
    
    void set_default_ttl(int seconds) { default_ttl_ = seconds; }

private:
    void worker_thread();
    void notify();
    bool resolve_hostname(const std::string& hostname, DnsResult& result);
    bool is_ipv4(const std::string& ip) const;

private:
    size_t thread_count_;
    std::vector<std::thread> threads_;
    std::queue<std::string> pending_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    std::vector<DnsResult> completed_results_;
    std::mutex results_mutex_;
    
    std::unordered_map<std::string, DnsResult> cache_;
    std::mutex cache_mutex_;
    
    int event_fd_;
    int default_ttl_;
    std::atomic<bool> running_;
};
