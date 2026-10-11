// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 6 <-> Module 3 seam
//
// RemediationEngine must be able to signature-scan a suspect's lineage (escalation
// step 3) and a frozen process's memory strings (step 2) without depending on the
// scanning module's types. This is that seam: a small implementation of
// remediation::ScannerBridge that forwards to scanning::SignatureEngine.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "remediation/remediation_engine.hpp"
#include "scanning/yara_engine.hpp"

namespace hyprnova::scanning {

class ScannerBridge final : public ::hyprnova::remediation::ScannerBridge {
public:
    /// The engine is borrowed, never owned: it outlives the bridge because the
    /// agent holds it for the whole run. It is const because both scan entry
    /// points are const -- the bridge can never mutate the loaded rule set out
    /// from under the scanner sensor that owns it.
    explicit ScannerBridge(const SignatureEngine& engine) noexcept : engine_(engine) {}

    /// Scan each path and return "path :: rule [family]" per detection.
    std::vector<std::string> scan_paths(const std::vector<std::string>& paths) override;

    /// Match extracted memory strings against the same rule set.
    std::vector<std::string> scan_strings(const std::vector<std::string>& strings,
                                          std::string_view label) override;

    [[nodiscard]] std::size_t rules() const noexcept { return engine_.rule_count(); }
    [[nodiscard]] std::size_t patterns() const noexcept { return engine_.pattern_count(); }

private:
    const SignatureEngine& engine_;
};

}  // namespace hyprnova::scanning
