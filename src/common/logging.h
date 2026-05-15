#pragma once

#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>

enum LogLevel {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3,
};

inline LogLevel g_log_level = LOG_ERROR;

inline void set_log_level(LogLevel level) { g_log_level = level; }

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

#define PROXY_LOG_ERROR(msg) do { if (::g_log_level >= LOG_ERROR) { PROXY_LOG("ERROR", msg); } } while(0)
#define PROXY_LOG_WARN(msg)  do { if (::g_log_level >= LOG_WARN)  { PROXY_LOG("WARN", msg);  } } while(0)
#define PROXY_LOG_INFO(msg)  do { if (::g_log_level >= LOG_INFO)  { PROXY_LOG("INFO", msg);  } } while(0)
#define PROXY_LOG_DEBUG(msg) do { if (::g_log_level >= LOG_DEBUG) { PROXY_LOG("DEBUG", msg); } } while(0)
