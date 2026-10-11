// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4c — Process memory inspection & bounded acquisition.
//
// WHAT THIS IS: a reusable, user-facing version of the escalation pipeline's
// step 2. For ONE process the agent can already see, it reads /proc/<pid>/maps
// and /proc/<pid>/mem: classifies W^X violations, extracts strings from
// anonymous executable regions, matches them against the signature engine, and
// (only when the operator explicitly asks) copies readable regions to a 0600
// dump for offline analysis.
//
// WHAT THIS IS NOT (stated everywhere it matters): full system-memory
// forensics. No kernel objects, no other users' processes without root, no
// timeline reconstruction, no Volatility profiles. The external tools module
// below PRObes for Volatility3 / MemProcFS / LiME and reports their real
// availability instead of pretending.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/config.hpp"
#include "core/proc.hpp"

namespace hyprnova::scanning { class SignatureEngine; }

namespace hyprnova::forensics {

/// One writable+executable mapping: where injected shellcode lives.
struct WxRegion {
    std::uint64_t start{0};
    std::uint64_t end{0};
    std::string path;   // "" for anonymous
};

struct MemInspection {
    pid_t pid{0};
    std::uint64_t start_time_ticks{0};   // identity anchor at inspection time
    std::string exe;
    bool readable{false};                // may read /proc/pid/mem at all?
    std::size_t regions_scanned{0};
    std::size_t bytes_scanned{0};
    std::vector<WxRegion> wx;            // W^X violations
    std::vector<std::string> matches;    // signature rule names hit in memory
    std::vector<std::string> findings;   // human-readable, ordered
    std::string limit_note;              // why coverage stopped short, if it did
    [[nodiscard]] bool suspicious() const noexcept { return !wx.empty() || !matches.empty(); }
};

/// Result of an acquisition attempt.
struct MemDumpResult {
    bool ok{false};
    std::string path;
    std::uint64_t bytes{0};
    std::string error;                   // honest reason on failure
};

/// One external acquisition/analysis tool, probed for existence.
struct ExternalTool {
    std::string name;        // "Volatility3", "MemProcFS", "LiME"
    bool available{false};
    std::string detail;      // binary path / module path / why absent
};

class MemInspector {
public:
    explicit MemInspector(const core::AgentConfig& cfg) : cfg_(cfg) {}

    /// The signature engine is owned by the scanner sensor; wired after build.
    /// Const: matching is read-only and the inspector never mutates the engine.
    void set_engine(const scanning::SignatureEngine* engine) noexcept { engine_ = engine; }

    /// Inspect one process. Identity is captured first and re-checked before
    /// every /proc/pid/mem read batch; a recycled pid aborts the inspection
    /// with the reason in findings. Bounded by cfg values (regions, bytes).
    [[nodiscard]] MemInspection inspect(pid_t pid) const noexcept;

    /// Copy the process's readable regions to <state_dir>/memory/<pid>-<ticks>.dump
    /// (0600). Opt-in by definition: memory may contain credentials, so callers
    /// must surface a privacy warning and require explicit confirmation.
    /// `max_bytes` hard-bounds the dump; the file records what was skipped.
    [[nodiscard]] MemDumpResult dump(pid_t pid, std::uint64_t max_bytes) const noexcept;

    /// Probe external acquisition/analysis tooling. Honest: absence is a result.
    [[nodiscard]] static std::vector<ExternalTool> external_tools() noexcept;

    /// The exact limits text the GUI banner renders (single source of truth).
    [[nodiscard]] static std::string_view limits_text() noexcept;

    /// Where dumps go and whether that directory is usable.
    [[nodiscard]] std::string dump_dir() const noexcept;

private:
    const core::AgentConfig& cfg_;
    const scanning::SignatureEngine* engine_{nullptr};
};

}  // namespace hyprnova::forensics
