#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Parsed TLS Client Hello fingerprint (from Wireshark text export)
struct ChromeFingerprint {
    // Cipher suites in order (raw uint16 IDs)
    std::vector<uint16_t> cipher_suites;

    // Extensions present (type IDs, in order)
    std::vector<uint16_t> extensions;

    // supported_groups (curves) in order
    std::vector<uint16_t> curves;

    // ec_point_formats in order (0=uncompressed, 1=compressed_prime, 2=compressed_char2)
    std::vector<uint8_t> ec_point_formats;

    // signature_algorithms in order (combined uint16: high byte = hash, low byte = sig)
    std::vector<uint16_t> sig_algs;

    // supported_versions in order (0x0304=TLS1.3, 0x0303=TLS1.2, ...)
    std::vector<uint16_t> versions;

    // Features derived from extensions presence
    bool session_ticket         = false;
    bool status_request         = false;   // OCSP
    bool encrypt_then_mac       = false;
    bool extended_master_secret = false;
    bool grease                 = false;   // set true if GREASE values detected in capture

    // Parse a Wireshark "File > Export Packet Dissections > As Plain Text" dump.
    // Returns true on success (at least cipher suites found).
    static bool parse_wireshark(const std::string& path, ChromeFingerprint& out);
    static bool parse_wireshark_text(const std::string& text, ChromeFingerprint& out);
};
