#include "obfuscator.h"
#include "tunnel_protocol.h"
#include <openssl/rand.h>
#include <cstring>

namespace tunnel {

Obfuscator::Obfuscator()
    : min_padding_(MIN_PADDING)
    , max_padding_(MAX_PADDING) {
    std::random_device rd;
    rng_.seed(rd());
}

void Obfuscator::set_padding_range(uint16_t min_pad, uint16_t max_pad) {
    min_padding_ = min_pad;
    max_padding_ = max_pad;
}

uint16_t Obfuscator::generate_random_padding() {
    if (min_padding_ >= max_padding_) {
        return min_padding_;
    }
    std::uniform_int_distribution<uint16_t> dist(min_padding_, max_padding_);
    return dist(rng_);
}

void Obfuscator::generate_random_bytes(uint8_t* buf, size_t len) {
    if (len == 0) return;
    
    if (RAND_bytes(buf, len) != 1) {
        for (size_t i = 0; i < len; ++i) {
            buf[i] = static_cast<uint8_t>(rng_() & 0xFF);
        }
    }
}

std::vector<uint8_t> Obfuscator::obfuscate(const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;
    
    uint16_t padding_len = generate_random_padding();
    
    result.resize(2 + padding_len + len);
    
    result[0] = (padding_len >> 8) & 0xFF;
    result[1] = padding_len & 0xFF;
    
    generate_random_bytes(result.data() + 2, padding_len);
    
    if (len > 0 && data) {
        memcpy(result.data() + 2 + padding_len, data, len);
    }
    
    return result;
}

std::vector<uint8_t> Obfuscator::deobfuscate(const uint8_t* data, size_t len) {
    if (len < 2) {
        return {};
    }
    
    uint16_t padding_len = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    
    if (len < static_cast<size_t>(2 + padding_len)) {
        return {};
    }
    
    size_t payload_offset = 2 + padding_len;
    size_t payload_len = len - payload_offset;
    
    std::vector<uint8_t> result(payload_len);
    if (payload_len > 0) {
        memcpy(result.data(), data + payload_offset, payload_len);
    }
    
    return result;
}

}
