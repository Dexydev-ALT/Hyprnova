// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Weak-settings scanner — sshd_config audit (Module 10b).
//
// The kernel-hardening sensor already audits sysctls and its fixer writes a
// sysctl.d drop-in. This module covers the OTHER half of "weak system
// settings": the SSH daemon. Every weak knob carries the reason it is weak and
// the exact line that fixes it — the FIXER renders commands, an operator (or
// the hardening apply path with root) runs them. HyprNova never edits
// sshd_config itself: a broken sshd can lock the operator out of a remote box,
// which is a worse outcome than the weakness.

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace hyprnova::hardening {

struct SshdWeakness {
    std::string key;         // e.g. "PermitRootLogin"
    std::string value;       // the weak value found ("" = knob absent where a default is weak)
    std::string why;         // one honest sentence
    std::string fix;         // exact sshd_config line + the follow-up command
};

/// Parse sshd_config TEXT. Pure function of the text: the self-test drives it
/// with fixtures, production with the file's contents. First-wins semantics
/// per sshd_config(5).
[[nodiscard]] std::vector<SshdWeakness> audit_sshd_config(std::string_view text) noexcept;

/// Read + strip comments from the real config (or "" if unreadable).
[[nodiscard]] std::string load_sshd_config(const std::string& path = "/etc/ssh/sshd_config") noexcept;

}  // namespace hyprnova::hardening
