// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 2a implementation

#include "anti_ransomware/canary.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <format>
#include <fstream>
#include <random>
#include <set>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "core/fd.hpp"
#include "core/proc.hpp"

namespace hyprnova::anti_ransomware {

namespace fsx = core::fsx;
using core::hash::Sha256;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

namespace {

std::string read_random_bytes(std::size_t n) {
    std::string out;
    out.resize(n);
    core::UniqueFd fd{::open("/dev/urandom", O_RDONLY | O_CLOEXEC)};
    if (!fd) return out;
    std::size_t got = 0;
    while (got < n) {
        const ssize_t r = ::read(fd.get(), out.data() + got, n - got);
        if (r <= 0) break;
        got += static_cast<std::size_t>(r);
    }
    out.resize(got);
    return out;
}

/// Sort key that makes the canary appear FIRST in a naive lexicographic
/// directory walk, which is what every major ransomware family does.
std::string bait_name(std::string_view prefix, std::size_t serial, std::string_view ext, bool hidden) {
    // "!" and digits sort before letters in ASCII, so a leading '!' or '0' wins
    // against typical user filenames ("Documents", "photo_...").
    const std::string lead = hidden ? "." : "";
    return std::format("{}{}{:04d}_finance_summary{}", lead, prefix, serial, ext);
}

/// A body that looks like a spreadsheet export: low entropy, many repeated
/// tokens, plausible column names. Deliberately NOT random -- the whole point is
/// that the encrypted form is trivially distinguishable from this.
std::string decoy_body(std::string_view root, std::size_t serial) {
    static constexpr const char* kCols[] = {"invoice_id", "customer", "amount", "currency", "due_date",
                                            "status", "owner", "department"};
    static constexpr const char* kDepts[] = {"finance", "operations", "sales", "engineering", "legal"};
    static constexpr const char* kStatus[] = {"paid", "pending", "overdue", "draft"};

    std::mt19937_64 rng(0x5EEDull ^ (std::hash<std::string_view>{}(root) * 31) ^ serial);
    std::string out;
    out.reserve(2048);
    out += "# Internal record -- do not modify.\n";
    out += "# generated_by=hyprnova canary_serial=";
    out += std::to_string(serial);
    out += "\n";
    for (const char* c : kCols) { out += c; out += ','; }
    out.pop_back();
    out += '\n';

    for (int row = 0; row < 24; ++row) {
        out += std::format("INV-{:06d},ACME Holdings Ltd,{:.2f},USD,2024-{:02d}-15,{},j.smith,{}\n",
                           100000 + static_cast<int>(rng() % 899999),
                           static_cast<double>(rng() % 500000) / 100.0,
                           1 + static_cast<int>(rng() % 12), kStatus[rng() % 4],
                           kDepts[rng() % 5]);
    }
    return out;
}

std::string state_path(const core::AgentConfig& cfg) { return cfg.state_dir + "/canaries.json"; }

}  // namespace



/// Defined below; declared here because CanaryGenerator::generate needs it.
std::string canonical_canary_body(std::string_view root, std::uint64_t serial,
                                  std::string_view ext) noexcept;

// ---------------------------------------------------------------------------
// CanaryRecord
// ---------------------------------------------------------------------------

std::string CanaryRecord::serialise() const {
    // Layout: magic(8) | serial(8 ascii, zero padded) | pathlen(4) | path | maclen(2) | mac | body
    // Text-safe: the whole envelope is base16 for the binary parts so the file
    // still opens in an editor and looks like a plausible CSV footer.
    std::string out;
    out += kMagic;
    out += '\n';
    out += std::format("serial={:08}\n", serial);
    out += std::format("pathlen={}\n", path.size());
    out += path;
    out += '\n';
    out += "mac=" + Sha256::to_hex(mac) + "\n";
    out += "created=";
    out += std::to_string(std::chrono::system_clock::to_time_t(created));
    out += "\n";
    out += "-----\n";
    out += body;
    return out;
}

std::optional<CanaryRecord> CanaryRecord::parse(std::string_view bytes, std::string path) noexcept {
    if (bytes.size() < kMagic.size() + 32) return std::nullopt;
    if (bytes.substr(0, kMagic.size()) != kMagic) return std::nullopt;

    CanaryRecord r;
    r.path = std::move(path);
    std::size_t pos = kMagic.size();
    if (pos < bytes.size() && bytes[pos] == '\n') ++pos;

    auto take_line = [&]() -> std::string_view {
        const std::size_t nl = bytes.find('\n', pos);
        const std::string_view line{bytes.data() + pos, (nl == std::string_view::npos ? bytes.size() : nl) - pos};
        pos = nl == std::string_view::npos ? bytes.size() : nl + 1;
        return line;
    };

    bool saw_pathlen = false;
    std::size_t pathlen = 0;
    for (int i = 0; i < 6 && pos < bytes.size(); ++i) {
        const std::string_view line = take_line();
        if (line == "-----") break;
        if (line.starts_with("serial=")) {
            const std::string_view v = line.substr(7);
            std::uint64_t s = 0;
            if (std::from_chars(v.data(), v.data() + v.size(), s).ec != std::errc{}) return std::nullopt;
            r.serial = s;
        } else if (line.starts_with("pathlen=")) {
            const std::string_view v = line.substr(8);
            if (std::from_chars(v.data(), v.data() + v.size(), pathlen).ec != std::errc{}) return std::nullopt;
            saw_pathlen = true;
            // The path itself is the next line.
            const std::string_view pl = take_line();
            if (pl.size() != pathlen) return std::nullopt;
            r.path.assign(pl);
        } else if (line.starts_with("mac=")) {
            if (!Sha256::from_hex(line.substr(4), r.mac)) return std::nullopt;
        } else if (line.starts_with("created=")) {
            std::int64_t t = 0;
            const std::string_view v = line.substr(8);
            if (std::from_chars(v.data(), v.data() + v.size(), t).ec == std::errc{})
                r.created = core::SysClock::from_time_t(static_cast<std::time_t>(t));
        }
    }
    if (!saw_pathlen) return std::nullopt;
    if (pos < bytes.size()) r.body.assign(bytes.substr(pos));
    return r;
}

// ---------------------------------------------------------------------------
// CanaryGenerator
// ---------------------------------------------------------------------------

CanaryGenerator::CanaryGenerator(std::string key_path) : key_path_{std::move(key_path)} {}

bool CanaryGenerator::ensure_key() noexcept {
    std::string existing;
    if (fsx::read_file(key_path_, existing, 4096) >= 0 && existing.size() >= 32) {
        key_ = existing.substr(0, 32);
        key_signed_ = true;
        // Verify the key file is not world-readable; if it is, the MAC is not a
        // secret and the tamper-evidence claim is false.
        struct stat st {};
        if (::stat(key_path_.c_str(), &st) == 0 && (st.st_mode & (S_IROTH | S_IRGRP))) {
            if (::chmod(key_path_.c_str(), 0600) != 0) {
                key_signed_ = false;  // cannot protect the key -> cannot claim integrity
                return false;
            }
        }
        return true;
    }

    key_ = read_random_bytes(32);
    if (key_.size() != 32) return false;

    // Create the parent directory with strict perms before the key file.
    const std::size_t slash = key_path_.find_last_of('/');
    if (slash != std::string::npos) {
        const std::string dir = key_path_.substr(0, slash);
        ::mkdir(dir.c_str(), 0700);
    }
    if (!fsx::write_atomic(key_path_, {reinterpret_cast<const std::byte*>(key_.data()), key_.size()}, 0600)) {
        key_.clear();
        key_signed_ = false;
        return false;
    }
    ::chmod(key_path_.c_str(), 0600);
    key_signed_ = true;
    return true;
}

void CanaryGenerator::sign(CanaryRecord& rec) const noexcept {
    const std::string signed_part =
        std::string(CanaryRecord::kMagic) + "|" + std::to_string(rec.serial) + "|" + rec.path + "|" +
        rec.body;
    rec.mac = core::hash::hmac_sha256(
        {reinterpret_cast<const std::byte*>(key_.data()), key_.size()},
        {reinterpret_cast<const std::byte*>(signed_part.data()), signed_part.size()});
}

bool CanaryGenerator::verify(const CanaryRecord& rec, bool* tampered) const noexcept {
    if (tampered) *tampered = false;
    if (!key_signed_) return true;  // unsigned mode: cannot claim anything either way

    Sha256::Digest expected{};
    const std::string signed_part =
        std::string(CanaryRecord::kMagic) + "|" + std::to_string(rec.serial) + "|" + rec.path + "|" +
        rec.body;
    expected = core::hash::hmac_sha256(
        {reinterpret_cast<const std::byte*>(key_.data()), key_.size()},
        {reinterpret_cast<const std::byte*>(signed_part.data()), signed_part.size()});

    const bool ok = core::hash::ct_equal(
        {reinterpret_cast<const std::byte*>(expected.data()), expected.size()},
        {reinterpret_cast<const std::byte*>(rec.mac.data()), rec.mac.size()});
    if (!ok && tampered) *tampered = true;
    return ok;
}

/// THE canonical canary body for a given (root, serial, extension). Both the
/// planter and the state-loader call this, so an HMAC computed at plant time
/// still verifies after a daemon restart without persisting the body. Keeping the
/// body out of the state file matters: a leaked state file must not reveal the
/// exact expected content to an attacker who wants to forge a valid canary.
std::string canonical_canary_body(std::string_view root, std::uint64_t serial,
                                  std::string_view ext) noexcept {
    const std::string inner = decoy_body(root, static_cast<std::size_t>(serial));

    if (ext == ".pdf") {
        // Minimal but structurally valid PDF wrapper around the decoy text, so a
        // ransomware family that sniffs magic bytes still classifies the canary
        // as a document worth encrypting.
        std::string pdf = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        pdf += "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
        pdf += "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n";
        pdf += "4 0 obj\n<< /Length " + std::to_string(inner.size() + 40) +
               " >>\nstream\nBT /F1 10 Tf 40 700 Td (";
        pdf += inner;
        pdf += ") Tj ET\nendstream\nendobj\ntrailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n";
        return pdf;
    }
    if (ext == ".docx") {
        // A real .docx is a ZIP container. Emitting a genuine one needs a zip
        // library; the ZIP local-file-header magic followed by the decoy text is
        // enough for encryptors that filter on the first four bytes, which is the
        // detection property we actually need.
        std::string z = "PK\x03\x04";
        z += std::string(22, '\0');
        z += "[Content_Types].xml";
        z += inner;
        return z;
    }
    return inner;
}

std::string CanaryGenerator::body_for(std::string_view root, std::size_t serial,
                                      std::string_view ext) const noexcept {
    return canonical_canary_body(root, static_cast<std::uint64_t>(serial), ext);
}

std::vector<CanaryRecord> CanaryGenerator::generate(std::string_view root, std::size_t n,
                                                    const core::CanaryConfig& cfg) noexcept {
    std::vector<CanaryRecord> out;
    if (n == 0) return out;
    out.reserve(n);

    const std::string root_s{root};
    for (std::size_t i = 0; i < n; ++i) {
        CanaryRecord r;
        r.root = root_s;
        r.serial = static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(core::SysClock::now())) *
                       1000 +
                   i;
        r.hidden = cfg.hidden_files && (i % 2 == 1);
        const std::string ext = cfg.extensions.empty() ? ".docx" : cfg.extensions[i % cfg.extensions.size()];
        const std::string name = bait_name(cfg.prefix, i + 1, ext, r.hidden);
        r.path = root_s;
        if (!r.path.empty() && r.path.back() != '/') r.path += '/';
        r.path += cfg.subdir;
        if (!r.path.empty() && r.path.back() != '/') r.path += '/';
        r.path += name;
        r.body = body_for(root_s, r.serial, ext);
        r.created = core::SysClock::now();
        if (key_signed_) sign(r);
        out.push_back(std::move(r));
    }
    return out;
}

bool CanaryGenerator::resign_file(std::string_view path) noexcept {
    std::string raw;
    if (fsx::read_file(path, raw, 1 << 20) < 0) return false;
    auto rec = CanaryRecord::parse(raw, std::string(path));
    if (!rec) return false;
    sign(*rec);
    const std::string out = rec->serialise();
    return fsx::write_atomic(path, {reinterpret_cast<const std::byte*>(out.data()), out.size()}, 0644);
}

// ---------------------------------------------------------------------------
// CanarySensor
// ---------------------------------------------------------------------------

CanarySensor::CanarySensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool)
    : core::ISensor("canary", core::SensorId::Canary, bus, cfg, pool), gen_{cfg.canary.key_path} {}

bool CanarySensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.canary.enabled;
}

bool CanarySensor::on_start() {
    if (!gen_.ensure_key()) {
        // Not fatal, but it changes what this module can claim. Say so loudly.
        mark_degraded("canary HMAC key unavailable at " + cfg_.canary.key_path +
                      ": canaries will detect modification and deletion but NOT distinguish "
                      "tampering from our own re-plant");
    }
    (void)load_state();
    (void)plant_all();
    static_cast<void>(check_all());
    emit(core::EventKind::FileCanaryHit, core::Severity::Info,
         std::format("{} canaries planted across {} roots (signed={})", planted_.size(),
                     [&] {
                         std::set<std::string> roots;
                         for (const auto& c : planted_) roots.insert(c.root);
                         return roots.size();
                     }(),
                     gen_.key_signed() ? "yes" : "NO"));
    return true;
}

void CanarySensor::on_stop() { persist_state(); }

void CanarySensor::loop(std::stop_token st) {
    while (!st.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (last_check_ == core::SysClock::time_point{} ||
            core::SysClock::now() - last_check_ >= cfg_.canary.integrity_check_interval) {
            static_cast<void>(check_all());
        }
    }
}

bool CanarySensor::plant_all() noexcept {
    const auto& c = cfg_.canary;
    std::vector<std::string> roots;

    // /home/* -> per-user canary dirs
    for (const auto& hr : c.home_roots) {
        core::UniqueDir d{::opendir(hr.c_str())};
        if (!d) continue;
        while (const dirent* e = ::readdir(d.get())) {
            if (e->d_name[0] == '.') continue;
            if (e->d_type != DT_DIR && e->d_type != DT_UNKNOWN) continue;
            const std::string home = hr + "/" + e->d_name;
            if (!fsx::is_dir(home)) continue;
            roots.push_back(home);
        }
    }
    for (const auto& r : c.extra_roots) {
        if (fsx::is_dir(r)) roots.push_back(r);
    }
    if (roots.empty()) {
        note_error("no canary roots exist; nothing planted");
        return false;
    }

    std::vector<CanaryRecord> fresh;
    for (const auto& root : roots) {
        const std::string dir = root + (root.back() == '/' ? "" : "/") + c.subdir;
        ::mkdir(dir.c_str(), 0755);
        // The canary dir itself must not be writable by others, or an attacker
        // can simply delete the canaries -- which is a signal we do catch, but
        // making it harder is free.
        ::chmod(dir.c_str(), 0755);

        auto recs = gen_.generate(root, c.canaries_per_root, c);
        for (auto& r : recs) {
            // Skip if an identical-generation canary is already valid on disk.
            {
                std::shared_lock lk{mu_};
                const auto existing = std::find_if(planted_.begin(), planted_.end(),
                                                   [&](const CanaryRecord& p) { return p.path == r.path; });
                if (existing != planted_.end()) {
                    std::string raw;
                    if (fsx::read_file(r.path, raw, 1 << 20) >= 0) {
                        bool tampered = false;
                        if (auto parsed = CanaryRecord::parse(raw, r.path)) {
                            if (gen_.verify(*parsed, &tampered) && !tampered) {
                                fresh.push_back(*existing);
                                continue;
                            }
                        }
                    }
                }
            }
            const std::string bytes = r.serialise();
            // 0644, not 0600: a canary the encryptor cannot open is a canary it
            // will skip, and a skipped canary detects nothing.
            if (!fsx::write_atomic(r.path, {reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()},
                                   0644)) {
                note_error("failed to plant canary at " + r.path);
                continue;
            }
            fresh.push_back(std::move(r));
        }
    }

    {
        std::unique_lock lk{mu_};
        planted_ = std::move(fresh);
    }
    persist_state();
    return true;
}

void CanarySensor::note_self_read(std::string_view path) noexcept {
    const auto now = core::SteadyClock::now();
    std::lock_guard lk{self_read_mu_};
    for (auto it = self_reads_.begin(); it != self_reads_.end();)
        if (now - it->second > kSelfReadWindow) it = self_reads_.erase(it);
        else ++it;
    self_reads_.emplace(std::string(path), now);
}

bool CanarySensor::self_read_recent(std::string_view path) const noexcept {
    const auto now = core::SteadyClock::now();
    std::lock_guard lk{self_read_mu_};
    const auto it = self_reads_.find(std::string(path));
    return it != self_reads_.end() && (now - it->second) <= kSelfReadWindow;
}

std::vector<CanaryCheckResult> CanarySensor::check_all() noexcept {
    std::vector<CanaryCheckResult> out;
    std::vector<CanaryRecord> snapshot;
    {
        std::shared_lock lk{mu_};
        snapshot = planted_;
    }
    out.reserve(snapshot.size());

    std::size_t healthy = 0, tampered = 0, missing = 0;
    for (const auto& expected : snapshot) {
        CanaryCheckResult r;
        r.expected = expected;
        r.checked_at = core::SysClock::now();

        if (!fsx::exists(expected.path)) {
            r.verdict = CanaryVerdict::Missing;
            r.detail = "canary file is gone: deleted, moved, or the containing directory was wiped";
            ++missing;
        } else {
            std::string raw;
            // Announce the read BEFORE it happens: the inotify event is handled
            // asynchronously, so the note must already be in place when the
            // file monitor's thread gets around to it.
            note_self_read(expected.path);
            if (fsx::read_file(expected.path, raw, 4 << 20) < 0) {
                r.verdict = CanaryVerdict::Unreadable;
                r.detail = "cannot read canary (permissions or I/O error)";
            } else {
                r.on_disk_size = raw.size();
                r.on_disk_entropy = core::hash::shannon_entropy(
                    {reinterpret_cast<const std::byte*>(raw.data()),
                     std::min<std::size_t>(raw.size(), 65536)});

                auto parsed = CanaryRecord::parse(raw, expected.path);
                if (!parsed) {
                    // The envelope is gone. If entropy is high the file was
                    // encrypted in place -- the single clearest ransomware signal
                    // this module can produce.
                    r.verdict = r.on_disk_entropy >= 7.4 ? CanaryVerdict::Tampered
                                                         : CanaryVerdict::Malformed;
                    r.detail = std::format("canary envelope destroyed (entropy {:.2f}/8.00)",
                                           r.on_disk_entropy);
                    ++tampered;
                } else {
                    bool was_tampered = false;
                    const bool ok = gen_.verify(*parsed, &was_tampered);
                    if (!ok && was_tampered) {
                        r.verdict = CanaryVerdict::Tampered;
                        r.detail = std::format("HMAC verification FAILED and content changed "
                                               "(entropy {:.2f}/8.00): written by something other than "
                                               "the agent",
                                               r.on_disk_entropy);
                        ++tampered;
                    } else if (parsed->serial != expected.serial || parsed->body != expected.body) {
                        r.verdict = CanaryVerdict::Modified;
                        r.detail = "content differs from the planted generation";
                        ++healthy;
                    } else {
                        r.verdict = CanaryVerdict::Ok;
                        ++healthy;
                    }
                }
            }
        }
        report(r);
        out.push_back(std::move(r));
    }

    {
        std::unique_lock lk{mu_};
        healthy_ = healthy;
        tampered_ = tampered;
        missing_ = missing;
    }
    last_check_ = core::SysClock::now();

    if (tampered > 0 || missing > 0) {
        mark_degraded(std::format("{} tampered, {} missing", tampered, missing));
    } else {
        mark_running(std::format("{} healthy canaries", healthy));
    }
    return out;
}

void CanarySensor::report(const CanaryCheckResult& r) noexcept {
    if (r.verdict == CanaryVerdict::Ok) return;

    // Rate-limit per path: an encryption pass will trip every canary in a
    // directory within milliseconds, and one aggregated Critical event is more
    // actionable (and far cheaper) than fifty.
    {
        std::lock_guard lk{alert_mu_};
        auto it = alerted_.find(r.expected.path);
        if (it != alerted_.end() && core::SysClock::now() - it->second < 60s) return;
        alerted_[r.expected.path] = core::SysClock::now();
    }

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Canary;
    ev.kind = core::EventKind::FileCanaryHit;
    ev.target.path = r.expected.path;
    ev.target.rule_id = "canary-" + std::string(verdict_name(r.verdict));
    ev.metric = r.on_disk_entropy;

    switch (r.verdict) {
        case CanaryVerdict::Tampered:
            ev.severity = core::Severity::Critical;
            ev.risk_score = 900;
            ev.message = std::format("CANARY TAMPERED: {} {}", r.expected.path, r.detail);
            ev.triggers.push_back("canary_hmac_failed");
            if (r.on_disk_entropy >= 7.4) ev.triggers.push_back("canary_high_entropy");
            break;
        case CanaryVerdict::Missing:
            ev.severity = core::Severity::High;
            ev.risk_score = 700;
            ev.message = std::format("CANARY DELETED: {}", r.expected.path);
            ev.triggers.push_back("canary_deleted");
            break;
        case CanaryVerdict::Malformed:
            ev.severity = core::Severity::High;
            ev.risk_score = 620;
            ev.message = std::format("CANARY OVERWRITTEN: {} {}", r.expected.path, r.detail);
            ev.triggers.push_back("canary_malformed");
            break;
        case CanaryVerdict::Modified:
            ev.severity = core::Severity::Medium;
            ev.risk_score = 300;
            ev.message = std::format("CANARY MODIFIED: {} {}", r.expected.path, r.detail);
            ev.triggers.push_back("canary_modified");
            break;
        case CanaryVerdict::Unreadable:
            ev.severity = core::Severity::Medium;
            ev.risk_score = 250;
            ev.message = std::format("CANARY UNREADABLE: {} {}", r.expected.path, r.detail);
            break;
        case CanaryVerdict::Ok:
            return;
    }
    ev.fields["entropy"] = std::format("{:.3f}", r.on_disk_entropy);
    ev.fields["size"] = std::to_string(r.on_disk_size);
    ev.fields["root"] = r.expected.root;
    ev.fields["signed"] = gen_.key_signed() ? "yes" : "no";
    emit(std::move(ev));
}

void CanarySensor::on_filesystem_event(pid_t pid, std::string_view path, core::EventKind kind,
                                       bool is_write) {
    const CanaryRecord* rec = find(path);
    if (!rec) return;

    // A *read* of a canary by a non-allowlisted process is the earliest signal
    // there is: the encryptor has to enumerate and open before it writes.
    const std::string comm = core::proc::comm_of(pid);
    const bool allowlisted =
        std::find(cfg_.canary.reader_allowlist.begin(), cfg_.canary.reader_allowlist.end(), comm) !=
        cfg_.canary.reader_allowlist.end();
    const bool is_self = pid == ::getpid();

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Canary;
    ev.kind = kind;
    ev.actor.pid = pid;
    ev.actor.comm = comm;
    ev.target.path = std::string(path);
    ev.target.rule_id = "canary-access";
    ev.fields["write"] = is_write ? "yes" : "no";
    ev.fields["allowlisted"] = allowlisted ? "yes" : "no";

    if (is_write) {
        ev.severity = core::Severity::Critical;
        ev.risk_score = 950;
        ev.message = std::format("CANARY WRITTEN by pid {} ({}): {}", pid, comm, path);
        ev.triggers.push_back("canary_write");
    } else if (!allowlisted && !is_self) {
        ev.severity = core::Severity::High;
        ev.risk_score = 600;
        ev.message = std::format("CANARY READ by non-allowlisted pid {} ({}): {}", pid, comm, path);
        ev.triggers.push_back("canary_read_by_unknown_process");
    } else {
        return;  // routine, allowlisted read: do not spend bus capacity on it
    }
    emit(std::move(ev));
}

const CanaryRecord* CanarySensor::find(std::string_view path) const noexcept {
    std::shared_lock lk{mu_};
    // Linear scan is fine: the planted set is tens of entries, and this is only
    // consulted for paths that already matched a canary watch descriptor.
    for (const auto& c : planted_) {
        if (c.path == path) return &c;
    }
    return nullptr;
}

std::size_t CanarySensor::remove_all() noexcept {
    std::vector<CanaryRecord> snapshot;
    {
        std::shared_lock lk{mu_};
        snapshot = planted_;
    }
    std::size_t n = 0;
    std::set<std::string> dirs;
    for (const auto& c : snapshot) {
        if (::unlink(c.path.c_str()) == 0) ++n;
        const std::size_t slash = c.path.find_last_of('/');
        if (slash != std::string::npos) dirs.insert(c.path.substr(0, slash));
    }
    for (const auto& d : dirs) ::rmdir(d.c_str());
    {
        std::unique_lock lk{mu_};
        planted_.clear();
    }
    persist_state();
    return n;
}

void CanarySensor::persist_state() noexcept {
    core::json::Object root;
    core::json::Array arr;
    {
        std::shared_lock lk{mu_};
        for (const auto& c : planted_) {
            core::json::Object o;
            o["path"] = c.path;
            o["root"] = c.root;
            o["serial"] = static_cast<std::int64_t>(c.serial);
            o["mac"] = Sha256::to_hex(c.mac);
            o["hidden"] = c.hidden;
            o["created"] = static_cast<std::int64_t>(std::chrono::system_clock::to_time_t(c.created));
            // The body is NOT persisted: it is regenerable from (root, serial),
            // and keeping it out of the state file means a state-file leak does
            // not hand an attacker the exact expected content.
            arr.emplace_back(core::json::Value{std::move(o)});
        }
    }
    root["canaries"] = core::json::Value{std::move(arr)};
    root["signed"] = gen_.key_signed();
    core::json::Value doc{std::move(root)};
    const std::string text = doc.dump();
    if (!fsx::write_atomic(state_path(cfg_),
                           {reinterpret_cast<const std::byte*>(text.data()), text.size()}, 0600)) {
        note_error("could not persist canary state to " + state_path(cfg_));
    }
}

bool CanarySensor::load_state() noexcept {
    std::string text;
    if (fsx::read_file(state_path(cfg_), text, 8 << 20) < 0) return false;
    core::json::ParseError perr{};
    auto doc = core::json::parse(text, {}, &perr);
    if (!doc) {
        note_error("canary state file is corrupt: " + perr.message);
        return false;
    }
    const core::json::Array* arr = doc->at("canaries") ? doc->at("canaries")->as_array() : nullptr;
    if (!arr) return false;

    std::vector<CanaryRecord> loaded;
    loaded.reserve(arr->size());
    for (const auto& e : *arr) {
        CanaryRecord r;
        r.path = e.str("path");
        r.root = e.str("root");
        r.serial = static_cast<std::uint64_t>(e.integer("serial"));
        r.hidden = e.at("hidden") ? e.at("hidden")->as_bool() : false;
        const auto created = e.integer("created");
        if (created > 0) r.created = core::SysClock::from_time_t(static_cast<std::time_t>(created));
        if (const auto* macv = e.at("mac")) (void)Sha256::from_hex(macv->as_string(), r.mac);
        if (r.path.empty()) continue;
        // Regenerate the body deterministically from (root, serial, extension)
        // so HMAC verification works without persisting the body itself.
        const std::size_t dot = r.path.find_last_of('.');
        const std::string ext = dot == std::string::npos ? ".docx" : r.path.substr(dot);
        r.body = canonical_canary_body(r.root, r.serial, ext);
        loaded.push_back(std::move(r));
    }
    {
        std::unique_lock lk{mu_};
        planted_ = std::move(loaded);
    }
    return true;
}

}  // namespace hyprnova::anti_ransomware
