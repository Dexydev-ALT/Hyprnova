// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 6 — shadow copies (snapshot / restore)
//
// The recovery half of active remediation. Quarantine preserves a malicious
// FILE; a shadow copy preserves the STATE the agent is about to defend, so that
// "the PC is very bad" has an answer that is not "reinstall".
//
// Semantics, matching how the product is described to operators:
//
//   * A shadow copy is taken at EVERY agent start ("every restart"), plus on
//     demand. It is a point-in-time file-level copy of the configured roots --
//     the agent's own state, its configuration, the canary key directory --
//     into <state_dir>/shadow/<UTC timestamp>-<pid>/.
//   * Old ones are deleted: retention keeps the newest `shadow.keep` snapshots
//     and removes the rest. Snapshots are timestamp-prefixed so the directory
//     listing IS the age ordering; no database is needed.
//   * Restore puts the files back, verifying every file's SHA-256 against the
//     manifest before it is written. A snapshot whose manifest does not match
//     its contents is refused, not partially applied.
//   * Every snapshot carries manifest.json (hashes, modes, sizes, original
//     paths) and meta.json (when, why, how many files, how many bytes). The
//     files are plain files on disk: if the agent is dead and the host is "very
//     bad", an operator can restore with `cp` and the manifest by hand.
//
// Safety properties, because this code writes to arbitrary paths on demand:
//   * Restore is refuse-by-default on anything unexpected: a manifest that does
//     not parse, a hash mismatch, a path that would escape the destination.
//   * Snapshot refuses to follow a symlink out of a root, and skips sockets,
//     fifos and device nodes rather than copying them.
//   * Per-snapshot caps on total bytes and file count, so a runaway root cannot
//     fill the disk the shadow copies live on.
//   * The snapshot itself is written with O_NOFOLLOW + 0600/0700 modes.

#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace hyprnova::core { struct AgentConfig; }

namespace hyprnova::remediation {

struct ShadowMeta {
    std::string id;            // directory name, e.g. 20260408T165501Z-3725
    std::time_t created{0};    // UTC
    std::string reason;        // "agent start", "operator request", ...
    std::uint64_t files{0};    // files captured
    std::uint64_t bytes{0};    // bytes captured
    std::uint64_t skipped{0};  // files skipped (too large, special, unreadable)
    std::vector<std::string> roots;      // original absolute roots, in order
    std::vector<std::string> missing;    // configured roots that did not exist
};

struct ShadowEntry {
    ShadowMeta meta;
    std::string dir;           // absolute path of the snapshot directory
};

struct ShadowRestoreReport {
    std::string id;
    std::uint64_t restored{0};
    std::uint64_t verified{0};
    std::uint64_t failed{0};
    std::vector<std::string> failures;   // first few, for the operator
    bool ok{false};
    std::string detail;
};

class ShadowCopyEngine {
public:
    explicit ShadowCopyEngine(const core::AgentConfig& cfg) noexcept;

    ShadowCopyEngine(const ShadowCopyEngine&) = delete;
    ShadowCopyEngine& operator=(const ShadowCopyEngine&) = delete;

    /// Take a snapshot now and prune to retention. Returns the new snapshot id,
    /// or an empty string on failure (reason in `detail`).
    [[nodiscard]] std::string take(std::string_view reason, std::string& detail) noexcept;

    /// Snapshots, newest first.
    [[nodiscard]] std::vector<ShadowEntry> list() const noexcept;

    /// Re-hash every file in a snapshot against its manifest. True == intact.
    [[nodiscard]] bool verify(std::string_view id, std::string& detail) const noexcept;

    /// Restore a snapshot. With no destination, files return to their original
    /// absolute paths; with `dest`, they land under dest/<root index>/<rel>.
    /// Every file is hash-verified against the manifest before it is written.
    [[nodiscard]] ShadowRestoreReport restore(std::string_view id, std::string_view dest,
                                              std::string& detail) noexcept;

    /// Delete all but the newest `keep` snapshots.
    [[nodiscard]] std::size_t prune() noexcept;

    [[nodiscard]] const std::string& root_dir() const noexcept { return root_; }

private:
    [[nodiscard]] std::string snapshot_dir_for(std::string_view id) const noexcept;
    [[nodiscard]] bool load_meta(const std::string& dir, ShadowMeta& out) const noexcept;

    const core::AgentConfig& cfg_;
    std::string root_;          // <state_dir>/shadow
    mutable std::mutex mu_;
};

}  // namespace hyprnova::remediation
