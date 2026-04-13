#pragma once

#include <cstdint>
#include <vector>
#include <random>

namespace tunnel {

class Obfuscator {
public:
    Obfuscator();
    ~Obfuscator() = default;
    
    std::vector<uint8_t> obfuscate(const uint8_t* data, size_t len);
    std::vector<uint8_t> deobfuscate(const uint8_t* data, size_t len);
    
    void set_padding_range(uint16_t min_pad, uint16_t max_pad);
    
private:
    uint16_t generate_random_padding();
    void generate_random_bytes(uint8_t* buf, size_t len);
    
private:
    std::mt19937 rng_;
    uint16_t min_padding_;
    uint16_t max_padding_;
};

}
