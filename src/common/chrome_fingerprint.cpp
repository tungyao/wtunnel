#include "chrome_fingerprint.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>

// ── helpers ──────────────────────────────────────────────────────────────────

static uint16_t parse_hex16(const std::string& s) {
    return (uint16_t)std::stoul(s, nullptr, 16);
}

// Extract the first hex value in parentheses, e.g. "(0x1302)" → 0x1302
// Returns 0xffff if not found.
static uint16_t extract_paren_hex(const std::string& line) {
    auto lp = line.rfind("(0x");
    if (lp == std::string::npos) return 0xffff;
    auto rp = line.find(')', lp);
    if (rp == std::string::npos) return 0xffff;
    return parse_hex16(line.substr(lp + 3, rp - lp - 3));
}

// Trim leading whitespace
static std::string ltrim(const std::string& s) {
    auto it = std::find_if(s.begin(), s.end(), [](unsigned char c){ return !std::isspace(c); });
    return std::string(it, s.end());
}

// ── parser ───────────────────────────────────────────────────────────────────

bool ChromeFingerprint::parse_wireshark_text(const std::string& text, ChromeFingerprint& out) {
    out = {};

    std::istringstream stream(text);
    std::string line;

    // State machine sections
    bool in_cipher_suites      = false;
    bool in_extensions         = false;
    bool in_supported_groups   = false;
    bool in_sig_algs           = false;
    bool in_supported_versions = false;
    bool in_ec_point_formats   = false;
    bool just_saw_extension    = false;  // next "Type:" line holds the ext ID

    while (std::getline(stream, line)) {
        std::string t = ltrim(line);

        // ── Section detection ──────────────────────────────────────────────

        if (t.find("Cipher Suites (") != std::string::npos ||
            t.find("Cipher Suites Length:") != std::string::npos) {
            in_cipher_suites      = true;
            in_extensions         = false;
            in_supported_groups   = false;
            in_sig_algs           = false;
            in_supported_versions = false;
            continue;
        }

        if (t.find("Extensions Length:") != std::string::npos) {
            in_cipher_suites      = false;
            in_extensions         = true;
            in_supported_groups   = false;
            in_sig_algs           = false;
            in_supported_versions = false;
            continue;
        }

        if (t.find("Elliptic curves point formats (") != std::string::npos ||
            t.find("EC point formats Length:") != std::string::npos) {
            in_cipher_suites      = false;
            in_supported_groups   = false;
            in_sig_algs           = false;
            in_supported_versions = false;
            in_ec_point_formats   = true;
            continue;
        }

        if (t.find("Supported Groups List Length:") != std::string::npos ||
            t.find("Supported Groups (") != std::string::npos) {
            in_cipher_suites      = false;
            in_supported_groups   = true;
            in_sig_algs           = false;
            in_supported_versions = false;
            in_ec_point_formats   = false;
            continue;
        }

        if (t.find("Signature Hash Algorithms Length:") != std::string::npos ||
            t.find("Signature Hash Algorithms (") != std::string::npos) {
            in_cipher_suites      = false;
            in_supported_groups   = false;
            in_sig_algs           = true;
            in_supported_versions = false;
            continue;
        }

        if (t.find("Supported Versions length:") != std::string::npos) {
            in_cipher_suites      = false;
            in_supported_groups   = false;
            in_sig_algs           = false;
            in_supported_versions = true;
            continue;
        }

        // Detect entering a new top-level Extension block (resets sub-sections)
        if (t.rfind("Extension: ", 0) == 0) {
            in_cipher_suites      = false;
            in_supported_groups   = false;
            in_sig_algs           = false;
            in_supported_versions = false;
            in_ec_point_formats   = false;
            just_saw_extension    = true;  // next "Type:" line gives the ID

            // Feature flags from extension presence (names on Extension: line)
            if (t.find("session_ticket") != std::string::npos)
                out.session_ticket = true;
            if (t.find("status_request") != std::string::npos)
                out.status_request = true;
            if (t.find("encrypt_then_mac") != std::string::npos)
                out.encrypt_then_mac = true;
            if (t.find("extended_master_secret") != std::string::npos)
                out.extended_master_secret = true;
            continue;
        }

        // "Type: name (decimal)" sub-line immediately after "Extension: " gives
        // the numeric extension type ID (Wireshark uses decimal, not hex here).
        if (just_saw_extension && t.rfind("Type:", 0) == 0) {
            just_saw_extension = false;
            auto lp = t.rfind('(');
            auto rp = t.rfind(')');
            if (lp != std::string::npos && rp != std::string::npos && rp > lp) {
                try {
                    uint16_t id = (uint16_t)std::stoul(t.substr(lp + 1, rp - lp - 1));
                    out.extensions.push_back(id);
                } catch (...) {}
            }
            continue;
        }
        if (just_saw_extension && !t.empty()) {
            // Non-Type line resets (shouldn't happen in well-formed dumps)
            just_saw_extension = false;
        }

        // ── Data collection ────────────────────────────────────────────────

        if (in_cipher_suites && t.rfind("Cipher Suite:", 0) == 0) {
            uint16_t id = extract_paren_hex(t);
            if (id != 0xffff) {
                out.cipher_suites.push_back(id);
                // Detect GREASE cipher: low byte == 0x0a and both bytes equal
                if ((id & 0x0f0f) == 0x0a0a && (id >> 8) == (id & 0xff))
                    out.grease = true;
            }
            continue;
        }

        if (in_supported_groups && t.rfind("Supported Group:", 0) == 0) {
            uint16_t id = extract_paren_hex(t);
            if (id != 0xffff) out.curves.push_back(id);
            continue;
        }

        if (in_sig_algs && t.rfind("Signature Algorithm:", 0) == 0) {
            uint16_t id = extract_paren_hex(t);
            if (id != 0xffff) out.sig_algs.push_back(id);
            continue;
        }

        if (in_supported_versions && t.rfind("Supported Version:", 0) == 0) {
            uint16_t id = extract_paren_hex(t);
            if (id != 0xffff) out.versions.push_back(id);
            continue;
        }

        if (in_ec_point_formats && t.rfind("EC point format:", 0) == 0) {
            // Wireshark writes decimal: "EC point format: uncompressed (0)"
            auto lp = t.rfind('(');
            auto rp = t.rfind(')');
            if (lp != std::string::npos && rp != std::string::npos && rp > lp) {
                try {
                    uint8_t v = (uint8_t)std::stoul(t.substr(lp + 1, rp - lp - 1));
                    out.ec_point_formats.push_back(v);
                } catch (...) {}
            }
            continue;
        }
    }

    return !out.cipher_suites.empty();
}

bool ChromeFingerprint::parse_wireshark(const std::string& path, ChromeFingerprint& out) {
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string text((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());
    return parse_wireshark_text(text, out);
}
