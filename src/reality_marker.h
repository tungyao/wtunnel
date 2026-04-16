#pragma once
#include <string>
#include <cstdint>

// 生成 16 字节 REALITY 身份标记，写入 ClientHello 的 legacy_session_id 前 16 字节
// 格式：slot[4] | rand[4] | HMAC-SHA256(psk, slot||rand)[0:8]
//   slot = big-endian uint32_t(unix_epoch_seconds / 30)，用于重放防护
// session_id 必须指向至少 32 字节的缓冲区（后 16 字节已由 BoringSSL 随机填充，保持不变）
bool reality_make_marker(const std::string& psk, uint8_t out[16]);

// 服务端：从原始 TLS 记录字节（MSG_PEEK 所得）中解析 ClientHello，
// 提取 legacy_session_id 的前 16 字节并验证 HMAC 及时间窗口。
// buf/len：至少覆盖完整 ClientHello 记录的原始字节
// timestamp_window：时间槽粒度（秒，默认 30），允许 ±1 个槽的偏差
bool reality_verify_client_hello(const uint8_t* buf, size_t len,
                                 const std::string& psk,
                                 int timestamp_window = 30);
