// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 6 <-> Module 3 seam implementation

#include "scanning/scan_bridge.hpp"

#include <format>

#include "core/log.hpp"

namespace hyprnova::scanning {

namespace {

/// One detection line. The family is included because that is what an analyst
/// triages on; the rule name alone is often "suspicious_strings_in_memory".
[[nodiscard]] std::string describe(std::string_view where, const Match& m) noexcept {
    std::string s = std::string(where) + " :: " + m.rule;
    if (!m.family.empty()) s += " [" + m.family + "]";
    if (!m.description.empty()) s += " -- " + m.description;
    if (m.occurrence_count > 1) s += std::format(" (x{})", m.occurrence_count);
    return s;
}

}  // namespace

std::vector<std::string> ScannerBridge::scan_paths(const std::vector<std::string>& paths) {
    std::vector<std::string> out;
    for (const auto& p : paths) {
        if (p.empty()) continue;
        try {
            const auto matches = engine_.scan_file(p);
            for (const auto& m : matches) out.push_back(describe(p, m));
        } catch (const std::exception& e) {
            // A malformed sample must not abort an escalation that is already
            // mid-flight with a frozen process; log and continue with the rest.
            SERROR("scan-bridge", "scanning '{}' threw: {}", p, e.what());
        }
    }
    return out;
}

std::vector<std::string> ScannerBridge::scan_strings(const std::vector<std::string>& strings,
                                                     std::string_view label) {
    std::vector<std::string> out;
    if (strings.empty()) return out;
    try {
        const auto matches = engine_.scan_strings(strings, label);
        for (const auto& m : matches) out.push_back(describe("memory:" + std::string(label), m));
    } catch (const std::exception& e) {
        SERROR("scan-bridge", "memory scan of '{}' threw: {}", label, e.what());
    }
    return out;
}

}  // namespace hyprnova::scanning
