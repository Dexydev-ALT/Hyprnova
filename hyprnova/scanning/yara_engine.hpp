// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 3a — Signature Matching Engine
//
// Two backends behind one interface:
//
//   YaraLite (built in)  Parses a useful subset of YARA rule syntax -- strings
//                        (text, hex with wildcards/nibbles/jumps), and the
//                        condition operators `any of`, `all of`, `N of`, `#s > n`,
//                        `filesize < N`, `at`, `in`, `not`, `and`, `or`, `uint16(0)`
//                        -- and evaluates it against an mmap'd span. Compiled once
//                        into an Aho-Corasick automaton over the literal patterns
//                        so a scan of a 10 MB binary against 5,000 string patterns
//                        costs one pass, not 5,000.
//   LibYara (optional)   Real yr_rules_scan_mem when libyara is present at
//                        configure time (HYPRNOVA_HAVE_LIBYARA).
//
// The point of shipping YaraLite is not to replace YARA. It is that a security
// product whose *only* detection engine is a third-party shared object has
// outsourced its availability to a supply chain. YaraLite keeps detection running
// when libyara is absent, blocked by lockdown, or fails to load.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/fd.hpp"
#include "core/hash.hpp"

namespace hyprnova::scanning {

// ---------------------------------------------------------------------------
// Rule model
// ---------------------------------------------------------------------------

enum class PatternKind : std::uint8_t { Text, Hex, Regex };

struct Pattern {
    std::string identifier;        // $a, $magic, ...
    PatternKind kind{PatternKind::Text};
    std::string literal;           // for Text: the exact bytes
    std::vector<std::optional<std::uint8_t>> hex;  // for Hex: nullopt == wildcard byte
    bool nocase{false};
    bool wide{false};              // UTF-16LE
    bool fullword{false};
    std::size_t min_occurrences{1};
};

struct Rule {
    std::string identifier;
    std::vector<std::string> tags;
    bool is_private{false};
    std::string meta_author;
    std::string meta_description;
    std::string meta_family;
    std::string meta_reference;
    core::Severity severity{core::Severity::High};
    std::vector<Pattern> patterns;
    std::string condition;         // kept verbatim for the evaluator
    /// Precomputed thresholds from the condition, so evaluation is O(matches).
    std::size_t required_matches{1};
    bool require_all{false};
    std::optional<std::uint64_t> max_filesize;
    std::optional<std::uint16_t> magic_u16_at_0;
};

struct Match {
    std::string rule;
    std::vector<std::string> tags;
    std::string family;
    std::string description;
    core::Severity severity{core::Severity::High};
    std::vector<std::string> matched_patterns;
    std::size_t occurrence_count{0};
    std::size_t offset{0};
};

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct ParseIssue {
    std::size_t line{0};
    std::string message;
};

/// Parses YARA-subset rule files. Reports issues per rule and continues: one
/// malformed rule must never disable the whole rule set.
[[nodiscard]] std::vector<Rule> parse_rules(std::string_view source,
                                            std::vector<ParseIssue>* issues = nullptr) noexcept;

[[nodiscard]] inline std::vector<Rule> parse_rule_file(std::string_view path,
                                                       std::vector<ParseIssue>* issues = nullptr) noexcept {
    std::string src;
    if (core::fsx::read_file(path, src, 32 << 20) < 0) {
        if (issues) issues->push_back({0, "cannot read " + std::string(path)});
        return {};
    }
    return parse_rules(src, issues);
}

// ---------------------------------------------------------------------------
// Aho-Corasick automaton over literal patterns
// ---------------------------------------------------------------------------

class AhoCorasick {
public:
    AhoCorasick() = default;

    /// Add a literal. Returns the pattern index.
    std::size_t add(std::string_view literal, bool nocase = false);
    /// Build failure links. Must be called after all adds and before any scan.
    void build() noexcept;

    struct Hit {
        std::size_t pattern;
        std::size_t offset;  // offset of the FIRST byte of the match
    };

    /// One pass over `data`, invoking `cb` for every hit. Streaming-friendly:
    /// the automaton can be kept warm across chunks via `state`.
    template <typename Fn>
    void scan(std::span<const std::byte> data, Fn&& cb, std::size_t* state = nullptr) const {
        // NOTE: the root node is node 0, so `root_ == 0` is the normal state and
        // must NOT be treated as "not initialised" -- doing so silently disabled
        // every scan. The only precondition is build().
        if (!built_ || goto_.empty()) return;
        std::size_t s = state ? *state : root_;
        if (s >= goto_.size()) s = root_;
        for (std::size_t i = 0; i < data.size(); ++i) {
            const std::uint8_t c = std::to_integer<std::uint8_t>(data[i]);
            s = transition(s, c);
            // build() merged every suffix link's outputs into each node, so this
            // is a single visit per position rather than a failure-link walk.
            for (const std::size_t pat : output_[s]) {
                const std::size_t len = literal_len_[pat];
                cb(Hit{pat, i + 1 >= len ? i + 1 - len : 0});
            }
        }
        if (state) *state = s;
    }

    [[nodiscard]] std::size_t pattern_count() const noexcept { return literal_len_.size(); }
    [[nodiscard]] std::size_t node_count() const noexcept { return goto_.size(); }
    [[nodiscard]] bool built() const noexcept { return built_; }

private:
    std::size_t transition(std::size_t node, std::uint8_t c) const noexcept;

    /// goto_[node][byte] -> next node, or 0 when absent (filled by build()).
    std::vector<std::array<std::uint32_t, 256>> goto_;
    std::vector<std::uint32_t> fail_;
    std::vector<std::vector<std::uint32_t>> output_;
    std::vector<std::uint16_t> literal_len_;
    std::size_t root_{0};
    bool built_{false};
};

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

enum class Backend : std::uint8_t { YaraLite = 0, LibYara = 1 };

class SignatureEngine {
public:
    SignatureEngine();
    ~SignatureEngine();

    SignatureEngine(const SignatureEngine&) = delete;
    SignatureEngine& operator=(const SignatureEngine&) = delete;

    /// Load every configured rule file. Returns the total number of usable rules.
    std::size_t load(const core::ScanConfig& cfg, std::vector<ParseIssue>* issues = nullptr);
    std::size_t add_rules(std::vector<Rule> rules);

    /// Scan one buffer. Non-owning; the caller keeps the mmap alive.
    [[nodiscard]] std::vector<Match> scan(std::span<const std::byte> data,
                                          std::string_view path = {}) const noexcept;

    /// Scan a file by path (mmaps internally).
    [[nodiscard]] std::vector<Match> scan_file(std::string_view path) const noexcept;

    /// Scan the printable strings extracted from a frozen process's memory
    /// regions. This is step 2 of the escalation pipeline and needs no file.
    [[nodiscard]] std::vector<Match> scan_strings(const std::vector<std::string>& strings,
                                                  std::string_view label) const noexcept;

    [[nodiscard]] std::size_t rule_count() const noexcept { return rules_.size(); }
    [[nodiscard]] std::size_t pattern_count() const noexcept { return ac_.pattern_count(); }
    [[nodiscard]] Backend backend() const noexcept { return backend_; }
    [[nodiscard]] const std::vector<ParseIssue>& load_issues() const noexcept { return issues_; }
    [[nodiscard]] bool libyara_available() const noexcept;

private:
    void rebuild_automaton() noexcept;
    [[nodiscard]] bool evaluate_condition(const Rule& r, std::span<const std::byte> data,
                                          const std::vector<AhoCorasick::Hit>& hits) const noexcept;

    std::vector<Rule> rules_;
    /// rule index -> (pattern index within rule -> automaton pattern id)
    std::vector<std::vector<std::size_t>> rule_to_ac_;
    AhoCorasick ac_;
    /// True when any rule carries a nocase TEXT pattern: scan() then also runs
    /// the automaton over a fully lowercased copy of the buffer so mixed-case
    /// haystacks can still emit the hits the case-insensitive validator needs
    /// (external finding: original/lower/upper needle variants alone miss
    /// arbitrary mixed case).
    bool fold_scan_{false};
    std::vector<ParseIssue> issues_;
    Backend backend_{Backend::YaraLite};
    struct Impl;
    std::unique_ptr<Impl> impl_;  // libyara handles, when compiled in
};

/// A first-party rule set compiled into the binary so the agent detects the
/// behaviours it was built to catch even with zero rule files on disk.
[[nodiscard]] std::vector<Rule> builtin_rules() noexcept;

}  // namespace hyprnova::scanning
