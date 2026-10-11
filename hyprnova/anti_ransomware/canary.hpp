// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 2a — Anti-Ransomware Canary Files
//
// Ransomware enumerates a directory and encrypts in sorted order. A canary is a
// bait file that sorts first, costs nothing to write, and whose *first touch* by
// a non-allowlisted process is the earliest possible signal that an encryption
// pass has begun -- typically hundreds to thousands of files before the victim
// data is reached.
//
// Each canary carries an HMAC-SHA256 trailer under a key held only by the daemon.
// That distinguishes three states with very different meanings:
//   1. untouched              -> baseline
//   2. modified, MAC valid    -> something rewrote it through our own path
//   3. modified, MAC invalid  -> TAMPERING: an external writer, i.e. an encryptor
//   4. deleted                -> the encryptor already swept this directory

#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/hash.hpp"
#include "core/json.hpp"
#include "core/sensor.hpp"

namespace hyprnova::anti_ransomware {

/// On-disk canary envelope. Fixed layout so verification never needs a parser.
struct CanaryRecord {
    static constexpr std::string_view kMagic = "SENTCAN1";
    static constexpr std::size_t kMacLen = 32;

    std::string path;
    std::string root;                 // the directory group it belongs to
    std::uint64_t serial{0};          // generation counter
    std::string body;                 // the decoy payload (low-entropy, looks like text)
    core::hash::Sha256::Digest mac{}; // HMAC over magic||serial||path||body
    core::SysClock::time_point created{};
    bool hidden{false};               // dot-prefixed variant

    [[nodiscard]] std::string serialise() const;
    /// Returns nullopt if the bytes are not a valid envelope.
    [[nodiscard]] static std::optional<CanaryRecord> parse(std::string_view bytes,
                                                           std::string path = {}) noexcept;
};

/// Generates and verifies the decoy payload. The body is deliberately LOW
/// entropy and structurally plausible (CSV-ish rows) so that an entropy-based
/// detector sees the transition to high entropy clearly when it is encrypted.
class CanaryGenerator {
public:
    explicit CanaryGenerator(std::string key_path);

    /// Load or create the HMAC key. 32 bytes from /dev/urandom, mode 0600, owned
    /// by the daemon. Returns false if the key cannot be protected -- in which
    /// case canaries are unsigned and the module reports itself degraded rather
    /// than pretending to be tamper-evident.
    [[nodiscard]] bool ensure_key() noexcept;
    [[nodiscard]] bool key_signed() const noexcept { return key_signed_; }
    [[nodiscard]] const std::string& key_path() const noexcept { return key_path_; }

    /// Produce `n` canary records for one root directory. Names are chosen so a
    /// directory-sorted encryptor reaches them first.
    [[nodiscard]] std::vector<CanaryRecord> generate(std::string_view root, std::size_t n,
                                                     const core::CanaryConfig& cfg) noexcept;

    /// Sign a record body in place.
    void sign(CanaryRecord& rec) const noexcept;
    /// Verify. `tampered` is set true when the envelope parses but the MAC fails.
    [[nodiscard]] bool verify(const CanaryRecord& rec, bool* tampered) const noexcept;

    /// Recompute the MAC for the current on-disk bytes. Used after a legitimate
    /// re-plant; never called implicitly.
    [[nodiscard]] bool resign_file(std::string_view path) noexcept;

private:
    [[nodiscard]] std::string body_for(std::string_view root, std::size_t serial,
                                       std::string_view ext) const noexcept;

    std::string key_path_;
    std::string key_;
    bool key_signed_{false};
};

enum class CanaryVerdict : std::uint8_t {
    Ok = 0,
    Missing,      // deleted or moved away
    Modified,     // content changed, MAC still valid (our own re-plant)
    Tampered,     // MAC invalid: an external writer touched it
    Unreadable,   // permission problem
    Malformed,    // not a valid envelope: overwritten wholesale
};

constexpr std::string_view verdict_name(CanaryVerdict v) noexcept {
    switch (v) {
        case CanaryVerdict::Ok: return "ok";
        case CanaryVerdict::Missing: return "missing";
        case CanaryVerdict::Modified: return "modified";
        case CanaryVerdict::Tampered: return "TAMPERED";
        case CanaryVerdict::Unreadable: return "unreadable";
        case CanaryVerdict::Malformed: return "malformed";
    }
    return "unknown";
}

struct CanaryCheckResult {
    CanaryRecord expected;
    CanaryVerdict verdict{CanaryVerdict::Ok};
    std::size_t on_disk_size{0};
    double on_disk_entropy{0.0};   // high entropy + tampered == encrypted canary
    core::SysClock::time_point checked_at{};
    std::string detail;
};

class CanarySensor final : public core::ISensor {
public:
    CanarySensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool);

    /// Plant canaries everywhere the config asks. Idempotent: existing valid
    /// canaries are left alone so their MAC/serial stay stable.
    [[nodiscard]] bool plant_all() noexcept;

    /// Walk every planted canary and verify it. Cheap enough to run every 30 s.
    [[nodiscard]] std::vector<CanaryCheckResult> check_all() noexcept;

    /// Remove every canary we planted (used on uninstall; never automatic).
    std::size_t remove_all() noexcept;

    [[nodiscard]] const std::vector<CanaryRecord>& planted() const noexcept { return planted_; }
    [[nodiscard]] std::size_t planted_count() const noexcept { return planted_.size(); }
    [[nodiscard]] std::size_t healthy_count() const noexcept { return healthy_; }
    [[nodiscard]] std::size_t tampered_count() const noexcept { return tampered_; }
    [[nodiscard]] const CanaryGenerator& generator() const noexcept { return gen_; }

    /// Resolve a path to the canary it belongs to, if any. Used by the file
    /// monitor to classify an inotify/fanotify event in O(1).
    [[nodiscard]] const CanaryRecord* find(std::string_view path) const noexcept;

    /// Record a live filesystem event against a canary and evaluate it.
    void on_filesystem_event(pid_t pid, std::string_view path, core::EventKind kind, bool is_write);

    /// Note that THIS sensor is about to read `path` (the periodic integrity
    /// check). The file monitor consults self_read_recent() before reporting an
    /// IN_ACCESS on a canary, so our own verification reads do not raise
    /// "canary accessed" events every integrity_check_interval. Without this,
    /// degraded (inotify-only) mode reports the agent reading its own decoys as
    /// ransomware enumeration -- noise that trains the operator to ignore the
    /// real thing.
    void note_self_read(std::string_view path) noexcept;
    /// True if note_self_read() was called for `path` within the last few
    /// seconds. The window is generous because the inotify event is processed
    /// asynchronously on the file monitor's thread, after the read returns.
    [[nodiscard]] bool self_read_recent(std::string_view path) const noexcept;

protected:
    bool on_start() override;
    [[nodiscard]] bool enabled(const core::AgentConfig& c) const noexcept override;
    void on_stop() override;
    [[nodiscard]] bool wants_thread() const noexcept override { return true; }
    void loop(std::stop_token st) override;

private:
    static constexpr std::chrono::seconds kSelfReadWindow{5};
    mutable std::mutex self_read_mu_;
    std::unordered_map<std::string, core::SteadyClock::time_point> self_reads_;

    void persist_state() noexcept;
    bool load_state() noexcept;
    void report(const CanaryCheckResult& r) noexcept;

    CanaryGenerator gen_;
    std::vector<CanaryRecord> planted_;
    mutable std::shared_mutex mu_;
    std::size_t healthy_{0};
    std::size_t tampered_{0};
    std::size_t missing_{0};
    /// Paths already alerted on, so a sustained encryption pass does not flood
    /// the bus with one event per canary per second.
    mutable std::mutex alert_mu_;
    std::unordered_map<std::string, core::SysClock::time_point> alerted_;
    core::SysClock::time_point last_check_{};
};

}  // namespace hyprnova::anti_ransomware
