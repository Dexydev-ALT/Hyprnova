// SPDX-License-Identifier: Apache-2.0
// HyprNova :: the Shredder (Module 10).
//
// Irreversible deletion is the most dangerous thing in the product, so the
// design is defensive in every dimension:
//
//   * PROTECTED PREFIXES: no path under /bin /boot /etc /usr /lib /sbin /proc
//     /sys /dev /run, HyprNova's own state, or the quarantine store can ever
//     be planned. The check is on canonical prefixes, not string equality.
//   * SYMLINKS ARE NOT FOLLOWED. A symlink target is unlinked as a link; the
//     referent outside the selection is untouched and reported.
//   * DRY RUN BY DEFAULT. plan() is read-only and produces the exact list the
//     execute step would process (paths, types, sizes) -- the operator reviews
//     THAT list, not a guess.
//   * TWO METHODS, HONESTLY DESCRIBED: standard unlink (data may remain
//     recoverable) and best-effort single-pass overwrite + unlink (no guarantee
//     on journaling/COW/SSD/snapshots -- the report says so, every time).
//   * AUDIT WITHOUT CONTENTS: the journal records paths, sizes, method and
//     outcome -- never file data.
//   * The AI analyst can RECOMMEND shredding; the endpoint refuses any request
//     that does not carry the operator's explicit confirmation flag, and the
//     GUI/CLI require a two-step confirm.

#pragma once

#include "core/config.hpp"
#include "core/json.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace hyprnova::remediation {

class Shredder {
public:
    enum class Method : std::uint8_t { Standard = 0, Overwrite };

    struct Item {
        std::string path;
        std::string type;          // file | dir | symlink | other
        std::uint64_t bytes{0};
        std::string note;          // e.g. "symlink -> /etc/passwd (link removed only)"
        // Identity captured at PLAN time (the path was verified to be a regular
        // file then). execute() re-checks it through an O_NOFOLLOW fd before
        // any overwrite: a path swapped for a symlink (or replaced outright)
        // after planning is refused, not followed — external finding.
        std::uint64_t dev{0};
        std::uint64_t ino{0};
    };

    struct Plan {
        bool ok{false};
        std::string error;
        std::vector<Item> items;
        std::size_t files{0}, dirs{0}, links{0};
        std::uint64_t total_bytes{0};
        std::vector<std::string> refusals;   // requested paths that are protected
        std::string method_note;             // the honest limitations paragraph
        bool overwrite{false};               // Method::Overwrite was requested
    };

    struct Outcome {
        bool ok{false};
        std::size_t files_removed{0}, dirs_removed{0}, links_removed{0};
        std::uint64_t bytes_overwritten{0};
        std::vector<std::string> errors;     // per-path failures
        std::string audit_line;              // what was journalled
    };

    explicit Shredder(const core::AgentConfig& cfg) noexcept : cfg_(cfg) {}

    /// Read-only plan. Refuses protected paths, expands directories (capped),
    /// classifies symlinks without following them.
    [[nodiscard]] Plan plan(const std::vector<std::string>& paths,
                            Method method) const noexcept;

    /// Execute a plan. `confirmed` must be true (the operator's explicit
    /// step); false makes this a no-op that returns an error. Journalled.
    [[nodiscard]] Outcome execute(const Plan& plan, bool confirmed) const noexcept;

    [[nodiscard]] static std::string_view method_note(Method m) noexcept;

    /// True when `path` is under any protected prefix (static: fixture-tested).
    [[nodiscard]] static bool protected_path(const std::string& path) noexcept;

private:
    core::AgentConfig cfg_;
};

}  // namespace hyprnova::remediation
