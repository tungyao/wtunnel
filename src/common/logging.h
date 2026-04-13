#pragma once

#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>

inline std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

#define PROXY_LOG(level, msg) \
    do { \
        std::stringstream ss; \
        ss << "[" << get_timestamp() << "] [" << level << "] " << msg; \
        std::cout << ss.str() << std::endl; \
    } while(0)

#define PROXY_LOG_INFO(msg) PROXY_LOG("INFO", msg)
#define PROXY_LOG_DEBUG(msg) PROXY_LOG("DEBUG", msg)
#define PROXY_LOG_ERROR(msg) PROXY_LOG("ERROR", msg)
#define PROXY_LOG_WARN(msg) PROXY_LOG("WARN", msg)
