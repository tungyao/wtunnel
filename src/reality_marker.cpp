#include "reality_marker.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <cstring>
#include <algorithm>

bool reality_make_marker(const std::string& psk, uint8_t out[16]) {
    if (RAND_bytes(out, 8) != 1) return false;
    uint8_t digest[32];
    unsigned int dlen = 0;
    if (!HMAC(EVP_sha256(),
              psk.data(), (int)psk.size(),
              out, 8,
              digest, &dlen)) {
        return false;
    }
    memcpy(out + 8, digest, 8);
    return true;
}
