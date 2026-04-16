#pragma once
#include <string>
#include <cstdint>

// 生成 16 字节 REALITY 身份标记（客户端在 TLS 握手前发送）
// 格式：nonce[8] | HMAC-SHA256(psk, nonce)[0:8]
// out 必须至少 16 字节
bool reality_make_marker(const std::string& psk, uint8_t out[16]);
