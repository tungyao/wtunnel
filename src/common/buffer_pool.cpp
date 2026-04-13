#include "buffer_pool.h"
#include <cstdlib>
#include <cstring>

BufferPool::BufferPool(size_t max_blocks)
    : max_blocks_(max_blocks)
    , total_blocks_(0)
    , available_blocks_(0) {
}

BufferPool::~BufferPool() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (Buffer* buf : free_list_) {
        if (buf) {
            ::free(buf->data);
            delete buf;
        }
    }
    free_list_.clear();
}

Buffer* BufferPool::acquire() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!free_list_.empty()) {
        Buffer* buf = free_list_.back();
        free_list_.pop_back();
        available_blocks_--;
        buf->size = 0;
        return buf;
    }
    
    if (total_blocks_ >= max_blocks_) {
        return nullptr;
    }
    
    char* data = static_cast<char*>(::malloc(BLOCK_SIZE));
    if (!data) {
        return nullptr;
    }
    
    Buffer* buf = new Buffer();
    buf->data = data;
    buf->size = 0;
    buf->capacity = BLOCK_SIZE;
    
    total_blocks_++;
    
    return buf;
}

void BufferPool::release(Buffer* buffer) {
    if (!buffer) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    free_list_.push_back(buffer);
    available_blocks_++;
}

size_t BufferPool::available_blocks() const {
    return available_blocks_.load();
}

size_t BufferPool::total_blocks() const {
    return total_blocks_.load();
}
