// SPDX-License-Identifier: Apache-2.0
// HyprNova :: rescue environment boot (Module 8d).
//
// Some rootkits cannot be judged from inside the running system: they own the
// kernel, hook the syscalls the scanner would use, and "hide" from any userspace
// process — including us. Every serious consumer AV solves this the same way
// (Kaspersky Rescue Disk, ESET SysRescue, Avira Rescue): REBOOT into a small,
// trusted environment, mount the real root read-only-ish, and scan it from the
// outside where the malware is not running.
//
// HyprNova does not ship a full distribution; it PREPARES the host for an
// operator-supplied rescue ISO:
//
//   * copies the ISO to /boot/hyprnova/rescue.iso,
//   * generates a GRUB loopback entry that boots it,
//   * generates /boot/hyprnova/clean.sh — the script the rescue environment
//     runs (or the operator runs from the rescue shell) to scan the real root
//     with fresh signatures and write a machine-readable report back into it,
//   * on the next normal boot, the agent ingests that report and turns it into
//     findings/events, closing the loop.
//
// Every step that changes the boot chain is privileged, default-dry-run, and
// fully previewable. Nothing here runs automatically: "arm" and "boot" are
// separate operator actions.

#pragma once

#include "core/config.hpp"
#include "core/json.hpp"

#include <string>
#include <vector>

namespace hyprnova::remediation {

class RescueBoot {
public:
    explicit RescueBoot(const core::RescueConfig& cfg) noexcept : cfg_(cfg) {}

    struct Status {
        bool enabled{false};
        bool iso_found{false};
        std::string iso_resolved;       // where the configured ISO actually is
        bool iso_staged{false};         // copied into boot_dir
        bool grub_entry_present{false};
        bool clean_script_present{false};
        bool prepared{false};           // staged && entry && script all present
        bool report_pending{false};     // a rescue run left a report to ingest
        std::vector<std::string> blockers;
        std::string preview;            // grub entry + clean.sh (always generated)
    };

    /// Validate + (when `write`) stage the ISO and write the GRUB entry and the
    /// clean script. `write == false` is the dry run: same checks, same preview,
    /// zero bytes touched. Blocking but fast (one file copy); run on the pool.
    [[nodiscard]] Status prepare(bool write) const noexcept;

    /// Read-only status probe (what the CLI/GUI shows by default).
    [[nodiscard]] Status status() const noexcept;

    /// Point GRUB at the rescue entry for the next boot and reboot. Requires
    /// root, a prepared host, and grub-reboot. `boot_once` uses grub-reboot so
    /// the machine comes back into the normal system on the NEXT restart even
    /// if the operator walks away.
    [[nodiscard]] bool boot(bool boot_once, std::string& err) const noexcept;

    /// The GRUB menu entry snippet (generated; stable across calls).
    [[nodiscard]] std::string grub_snippet() const noexcept;

    /// The clean script the rescue environment runs (generated).
    [[nodiscard]] std::string clean_script() const noexcept;

    /// Where the rescue run's report lands in the REAL root.
    [[nodiscard]] std::string report_path() const noexcept;

private:
    core::RescueConfig cfg_;
};

}  // namespace hyprnova::remediation
