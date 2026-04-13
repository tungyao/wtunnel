#pragma once

#include <cstddef>
#include <atomic>
#include <mutex>
#include <vector>

struct Buffer {
    char* data;
    size_t size;
    size_t capacity;
};

class BufferPool {
public:
    BufferPool(size_t max_blocks = 1024);
    ~BufferPool();
    
    Buffer* acquire();
    void release(Buffer* buffer);
    
    size_t available_blocks() const;
    size_t total_blocks() const;

private:
    size_t max_blocks_;
    std::atomic<size_t> total_blocks_;
    std::atomic<size_t> available_blocks_;
    std::mutex mutex_;
    std::vector<Buffer*> free_list_;
    static constexpr size_t BLOCK_SIZE = 65536; // 64KB
};
