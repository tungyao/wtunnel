#include "reality_marker.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <chrono>
#include <cstring>
#include <algorithm>

// ─── 共用 HMAC 工具 ───────────────────────────────────────────────────────────

static bool hmac_sha256_trunc(const std::string& key,
                               const uint8_t* data, size_t data_len,
                               uint8_t* out, size_t out_len) {
    uint8_t digest[32];
    unsigned int dlen = 0;
    if (!HMAC(EVP_sha256(),
              key.data(), (int)key.size(),
              data, data_len,
              digest, &dlen)) {
        return false;
    }
    memcpy(out, digest, std::min((size_t)dlen, out_len));
    return true;
}

// ─── 生成标记（客户端用）─────────────────────────────────────────────────────

bool reality_make_marker(const std::string& psk, uint8_t out[16]) {
    // out[0..3]：当前时间槽（30 秒粒度），大端序，用于重放防护
    auto now = std::chrono::system_clock::now();
    uint64_t epoch = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                         now.time_since_epoch()).count();
    uint32_t slot = (uint32_t)(epoch / 30);
    out[0] = (slot >> 24) & 0xFF;
    out[1] = (slot >> 16) & 0xFF;
    out[2] = (slot >>  8) & 0xFF;
    out[3] =  slot        & 0xFF;

    // out[4..7]：随机字节，防止同一时间槽内的碰撞
    if (RAND_bytes(out + 4, 4) != 1) return false;

    // out[8..15]：HMAC-SHA256(psk, slot||rand)[0:8]
    return hmac_sha256_trunc(psk, out, 8, out + 8, 8);
}

// ─── 解析 ClientHello 的 legacy_session_id 并验证（服务端用）─────────────────

bool reality_verify_client_hello(const uint8_t* buf, size_t len,
                                 const std::string& psk,
                                 int timestamp_window) {
    // ── TLS 记录层：ContentType(1) Version(2) Length(2) ──────────────────────
    if (len < 5) return false;
    if (buf[0] != 0x16) return false;           // 必须是 Handshake
    uint16_t record_len = ((uint16_t)buf[3] << 8) | buf[4];
    if (len < (size_t)(5 + record_len)) return false;

    const uint8_t* hs = buf + 5;
    size_t hs_avail = record_len;

    // ── 握手层：HandshakeType(1) Length(3) ───────────────────────────────────
    if (hs_avail < 4) return false;
    if (hs[0] != 0x01) return false;            // 必须是 ClientHello
    uint32_t ch_len = ((uint32_t)hs[1] << 16) | ((uint32_t)hs[2] << 8) | hs[3];
    if (hs_avail < (size_t)(4 + ch_len)) return false;

    const uint8_t* p = hs + 4;
    size_t rem = ch_len;

    // version(2) + random(32)：跳过
    if (rem < 34) return false;
    p += 34; rem -= 34;

    // legacy_session_id：length(1) + data
    if (rem < 1) return false;
    uint8_t sid_len = *p; p++; rem--;

    // 必须是 32 字节才可能包含我们的标记
    if (sid_len != 32 || rem < 32) return false;
    const uint8_t* session_id = p;

    // 验证前 16 字节（slot[4] | rand[4] | HMAC[8]）
    uint32_t cli_slot = ((uint32_t)session_id[0] << 24) | ((uint32_t)session_id[1] << 16)
                      | ((uint32_t)session_id[2] <<  8) |  (uint32_t)session_id[3];

    auto now = std::chrono::system_clock::now();
    uint64_t epoch = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                         now.time_since_epoch()).count();
    uint32_t cur_slot = (uint32_t)(epoch / (uint32_t)timestamp_window);

    if (cli_slot < cur_slot - 1 || cli_slot > cur_slot + 1) return false;

    uint8_t expected[8];
    if (!hmac_sha256_trunc(psk, session_id, 8, expected, 8)) return false;
    return memcmp(expected, session_id + 8, 8) == 0;
}
