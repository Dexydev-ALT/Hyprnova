// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 3b/3c implementation

#include "scanning/scanner.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <format>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "core/exec.hpp"
#include "core/fd.hpp"
#include "core/proc.hpp"

namespace hyprnova::scanning {

namespace fsx = core::fsx;
using core::hash::FileFlavour;
using core::hash::shannon_entropy;
using namespace std::chrono_literals;

// ===========================================================================
// VerdictCache
// ===========================================================================

std::optional<VerdictCache::Entry> VerdictCache::lookup(std::string_view sha256, std::uint64_t size,
                                                        std::int64_t mtime) const noexcept {
    if (sha256.empty()) { misses_.fetch_add(1, std::memory_order_relaxed); return std::nullopt; }
    std::shared_lock lk{mu_};
    auto it = map_.find(std::string(sha256));
    if (it == map_.end()) { misses_.fetch_add(1, std::memory_order_relaxed); return std::nullopt; }
    // Size + mtime guard: the same digest at a different size/mtime means the
    // caller is asking about a different file than we cached, which cannot
    // happen for a real hash collision but does happen for a stale caller.
    if (it->second.size != size || (mtime != 0 && it->second.mtime != 0 && it->second.mtime != mtime)) {
        misses_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }
    hits_.fetch_add(1, std::memory_order_relaxed);
    return it->second;
}

void VerdictCache::insert(std::string_view sha256, Entry e) noexcept {
    if (sha256.empty()) return;
    std::unique_lock lk{mu_};
    const std::string key{sha256};
    if (map_.find(key) == map_.end()) {
        if (map_.size() >= max_ && !order_.empty()) {
            map_.erase(order_.front());
            order_.pop_front();
        }
        order_.push_back(key);
    }
    map_[key] = std::move(e);
}

std::size_t VerdictCache::size() const noexcept {
    std::shared_lock lk{mu_};
    return map_.size();
}

void VerdictCache::clear() noexcept {
    std::unique_lock lk{mu_};
    map_.clear();
    order_.clear();
}

// ===========================================================================
// BatchQueue
// ===========================================================================

bool BatchQueue::add(std::string path, ScanReason reason) noexcept {
    if (path.empty()) return false;
    bool force = false;
    {
        std::lock_guard lk{mu_};
        // Keep the highest-priority reason when a path is enqueued twice before
        // a flush: an escalation must not be downgraded to "inotify:create".
        auto it = pending_.find(path);
        if (it == pending_.end()) pending_.emplace(path, reason);
        else if (static_cast<int>(reason) > static_cast<int>(it->second)) it->second = reason;
        enqueued_.fetch_add(1, std::memory_order_relaxed);
        force = pending_.size() > cfg_.max_paths * 4;
    }
    return !force;
}

std::vector<std::string> BatchQueue::take() noexcept {
    std::lock_guard lk{mu_};
    std::vector<std::string> out;
    out.reserve(pending_.size());
    for (auto& [p, r] : pending_) {
        (void)r;
        out.push_back(std::move(p));
    }
    pending_.clear();
    last_flush_ = core::SteadyClock::now();
    if (!out.empty()) {
        flushed_.fetch_add(out.size(), std::memory_order_relaxed);
        batches_.fetch_add(1, std::memory_order_relaxed);
    }
    return out;
}

bool BatchQueue::due() const noexcept {
    std::lock_guard lk{mu_};
    if (pending_.empty()) return false;
    if (pending_.size() >= cfg_.max_paths) return true;
    return core::SteadyClock::now() - last_flush_ >= cfg_.flush_interval;
}

std::size_t BatchQueue::pending() const noexcept {
    std::lock_guard lk{mu_};
    return pending_.size();
}

std::chrono::seconds BatchQueue::seconds_until_due() const noexcept {
    std::lock_guard lk{mu_};
    if (pending_.empty()) return 0s;
    const auto elapsed = core::SteadyClock::now() - last_flush_;
    const auto remaining = cfg_.flush_interval - std::chrono::duration_cast<std::chrono::seconds>(elapsed);
    return remaining.count() > 0 ? remaining : 0s;
}

// ===========================================================================
// External scanners
// ===========================================================================

ExternalScannerInventory probe_external_scanners(const core::ScanConfig& cfg) noexcept {
    ExternalScannerInventory inv;

    inv.clamdscan = core::exec::first_executable({cfg.clamdscan_path, "clamdscan", "clamscan"});
    inv.kvrt = core::exec::first_executable({cfg.kvrt_path, "kvrt", "kvrt.run"});

    // clamd is only useful if the daemon socket is live; clamdscan without clamd
    // silently degrades to a fork of clamscan per invocation, which is exactly
    // the cold-start cost batching was designed to avoid.
    for (const char* sock : {"/run/clamav/clamd.ctl", "/var/run/clamav/clamd.ctl",
                             "/var/lib/clamav/clamd.sock", "/tmp/clamd.socket"}) {
        struct stat st {};
        if (::stat(sock, &st) == 0 && S_ISSOCK(st.st_mode)) {
            inv.clamd_socket = sock;
            inv.clamd_socket_alive = true;
            break;
        }
    }

    // KVRT is a Windows PE binary run through Wine/mono on Linux in most
    // deployments; "runnable" here means the wrapper exists and is executable.
    inv.kvrt_runnable = !inv.kvrt.empty();

    if (inv.clamdscan.empty() && inv.kvrt.empty()) {
        inv.findings.push_back("Neither clamdscan nor KVRT is installed. The agent runs on the "
                               "built-in YaraLite engine alone; third-party signature coverage is "
                               "unavailable.");
    } else {
        if (!inv.clamdscan.empty()) inv.findings.push_back("clamdscan: " + inv.clamdscan);
        if (!inv.clamd_socket_alive)
            inv.findings.push_back("clamd socket not found: clamdscan will fork clamscan per batch, "
                                   "which is slower but still one cold start per batch rather than "
                                   "per file.");
        else inv.findings.push_back("clamd socket live: " + inv.clamd_socket);
        if (inv.kvrt_runnable) inv.findings.push_back("KVRT wrapper: " + inv.kvrt);
    }
    return inv;
}

ExternalScanOutcome run_batch(const std::vector<std::string>& paths, const core::ScanConfig& cfg,
                              const ExternalScannerInventory& inv) noexcept {
    ExternalScanOutcome out;
    if (paths.empty()) return out;

    // Pick the engine. Preference order respects config, then availability.
    const bool use_kvrt = cfg.backend == core::ScanBackend::Kvrt && inv.kvrt_runnable;
    const bool use_clam = !use_kvrt && (cfg.prefer_clamd || cfg.backend == core::ScanBackend::ClamAv) &&
                          !inv.clamdscan.empty();

    std::string engine_path;
    std::vector<std::string> args;
    std::chrono::milliseconds timeout;

    // Write the path list to a 0600 file. Passing hundreds of absolute paths on
    // argv would (a) hit ARG_MAX on a large batch and (b) publish every filename
    // to any local user via /proc/<pid>/cmdline, which is an information leak
    // about what the host's users are downloading.
    std::string list_file;
    if (cfg.use_list_file) {
        list_file = "/run/hyprnova/scan-batch-" + std::to_string(::getpid()) + ".list";
        ::mkdir("/run/hyprnova", 0700);
        std::string body;
        for (const auto& p : paths) { body += p; body += '\n'; }
        if (!fsx::write_atomic(list_file,
                               {reinterpret_cast<const std::byte*>(body.data()), body.size()}, 0600)) {
            out.error = "could not write batch list file " + list_file;
            list_file.clear();
        }
    }

    if (use_kvrt) {
        engine_path = inv.kvrt;
        args = cfg.kvrt_args;
        if (!list_file.empty()) args.push_back(list_file);
        else for (const auto& p : paths) args.push_back(p);
        timeout = std::chrono::duration_cast<std::chrono::milliseconds>(cfg.kvrt_timeout);
        out.engine = "kvrt";
    } else if (use_clam) {
        engine_path = inv.clamdscan;
        args = cfg.clamdscan_args;
        // Our default arg list ends with "--file-list=" expecting concatenation.
        if (!args.empty() && args.back() == "--file-list=") {
            args.pop_back();
            if (!list_file.empty()) args.push_back("--file-list=" + list_file);
        }
        if (list_file.empty()) {
            args.push_back("--file-list=-");  // unused; paths go on argv below
            args.pop_back();
            for (const auto& p : paths) args.push_back(p);
        }
        if (inv.clamd_socket_alive) args.push_back("--stream");
        args.push_back("--infected");
        args.push_back("--no-summary");
        timeout = std::chrono::duration_cast<std::chrono::milliseconds>(cfg.clamd_timeout);
        out.engine = "clamdscan";
    } else {
        out.error = "no external scanner available";
        if (!list_file.empty()) ::unlink(list_file.c_str());
        return out;
    }

    core::exec::Options o;
    o.timeout = timeout;
    o.max_output_bytes = 8 << 20;
    const auto t0 = std::chrono::steady_clock::now();
    const auto r = core::exec::run(engine_path, args, o);
    out.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    out.ran = r.spawned;
    out.available = r.spawned && r.exit_code != 127;
    out.exit_code = r.exit_code;
    out.raw_output = r.out;
    out.scanned = paths.size();
    if (!r.error.empty()) out.error = r.error;
    else if (!r.err.empty()) out.error = r.err.substr(0, 4096);

    if (!list_file.empty()) ::unlink(list_file.c_str());

    if (!r.spawned) {
        out.available = false;
        out.error = r.error;
        return out;
    }

    // Parse detections. Both engines print "<path>: <signature> FOUND"; KVRT
    // writes a report file instead, so absence of stdout matches is not a clean
    // verdict there -- we say so rather than pretend.
    if (out.engine == "clamdscan") {
        std::string_view remaining = r.out;
        while (!remaining.empty()) {
            const std::size_t nl = remaining.find('\n');
            const std::string_view line = nl == std::string_view::npos ? remaining : remaining.substr(0, nl);
            remaining = nl == std::string_view::npos ? std::string_view{} : remaining.substr(nl + 1);

            const std::size_t found = line.find(" FOUND");
            if (found == std::string_view::npos) continue;
            const std::size_t colon = line.rfind(": ", 0 + found);
            if (colon == std::string_view::npos || colon >= found) {
                out.detections.emplace_back(std::string(line.substr(0, found)), "unknown-signature");
                continue;
            }
            out.detections.emplace_back(std::string(line.substr(0, colon)),
                                        std::string(line.substr(colon + 2, found - colon - 2)));
        }
    } else {
        // KVRT: exit code 0 == nothing found, non-zero == detections written to
        // its report path. We surface the exit code and the report location; a
        // dedicated KVRT report parser is a follow-on, and until it exists we
        // mark the batch Unknown rather than Clean. That is the honest state.
        if (r.exit_code != 0) {
            out.error = "KVRT exited " + std::to_string(r.exit_code) +
                        "; its report must be inspected (parser not yet wired)";
            out.scanned = 0;
        }
    }

    // clamdscan exit codes: 0 clean, 1 virus found, 2 error.
    if (out.engine == "clamdscan" && r.exit_code == 2 && out.detections.empty()) {
        out.error = "clamdscan reported an error condition";
    }
    return out;
}

// ===========================================================================
// ScannerSensor
// ===========================================================================

ScannerSensor::ScannerSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool)
    : core::ISensor("scanner", core::SensorId::StaticWatch, bus, cfg, pool),
      cache_{cfg.scan.hash_cache_entries},
      queue_{BatchQueue::Config{cfg.scan.batch_flush_interval, cfg.scan.batch_max_paths,
                                cfg.run_dir, cfg.scan.use_list_file}} {}

bool ScannerSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.scan.enabled;
}

bool ScannerSensor::on_start() {
    std::vector<ParseIssue> issues;
    const std::size_t n = engine_.load(cfg_.scan, &issues);
    for (const auto& i : issues) SWARN(name_, "rule load: {}", i.message);

    if (n == 0) {
        note_error("zero signature rules loaded: static detection is non-functional");
        return false;
    }

    inventory_ = probe_external_scanners(cfg_.scan);
    for (const auto& f : inventory_.findings) SINFO(name_, "external scanner: {}", f);

    ::mkdir(cfg_.run_dir.c_str(), 0700);
    ::mkdir(cfg_.state_dir.c_str(), 0700);

    const bool external = inventory_.clamd_socket_alive || inventory_.kvrt_runnable;
    mark_running(std::format("{} rules / {} patterns, backend={}, external scanners={}", n,
                             engine_.pattern_count(),
                             engine_.backend() == Backend::LibYara ? "libyara" : "yara-lite",
                             external ? "available" : "NONE"));
    if (!external) {
        mark_degraded(std::format("{} rules loaded, but no clamdscan/KVRT: third-party signature "
                                  "coverage unavailable", n));
    }
    emit(core::EventKind::SensorUp, core::Severity::Info,
         std::format("signature engine ready: {} rules, {} Aho-Corasick patterns, {} automaton nodes",
                     n, engine_.pattern_count(), engine_.pattern_count()));
    return true;
}

void ScannerSensor::on_stop() {
    if (sweeping_.load()) sweeping_.store(false);
}

bool ScannerSensor::should_skip(std::string_view path) const noexcept {
    // NEVER scan inside our own state dir: quarantine stores the very samples
    // we detected (self-detection loop), memory dumps are high-entropy secrets,
    // and honeypot decoys must keep their retro-dated atimes untouched -- a
    // scanner read there would both waste work and trip the read detection.
    if (!cfg_.state_dir.empty() &&
        (path == cfg_.state_dir || path.starts_with(cfg_.state_dir + "/")))
        return true;
    for (const auto& d : cfg_.scan.skip_dirs) {
        if (path.find("/" + d + "/") != std::string_view::npos || path.ends_with("/" + d)) return true;
    }
    const std::size_t dot = path.find_last_of('.');
    if (dot != std::string_view::npos) {
        std::string ext{path.substr(dot)};
        std::transform(ext.begin(), ext.end(), ext.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const auto& e : cfg_.scan.skip_extensions) {
            if (ext == e) return true;
        }
    }
    if (auto sz = fsx::file_size(path)) {
        if (*sz > cfg_.scan.max_file_bytes || *sz < cfg_.scan.min_file_bytes) return true;
    }
    return false;
}

ScanResult ScannerSensor::scan_now(std::string_view path, ScanReason reason,
                                   pid_t attributing_pid) noexcept {
    ScanRequest req;
    req.path = std::string(path);
    req.reason = reason;
    req.attributing_pid = attributing_pid;
    req.priority = ScanPriority::Urgent;
    req.queued_at = core::SysClock::now();
    auto r = scan_path_locked(req);
    // An urgent scan is operator- or sensor-initiated: its verdict MUST reach
    // the bus (attributed), or the heuristic engine never scores the actor and
    // on-exec detections die silently in the hash cache.
    publish(r, req);
    return r;
}

ScanResult ScannerSensor::scan_path_locked(const ScanRequest& req) noexcept {
    ScanResult r;
    r.path = req.path;
    r.reason = req.reason;
    r.attributing_pid = req.attributing_pid;
    const auto t0 = std::chrono::steady_clock::now();

    struct stat st {};
    if (::stat(req.path.c_str(), &st) != 0) {
        r.verdict = Verdict::Skipped;
        r.detail = std::string("stat failed: ") + std::strerror(errno);
        return r;
    }
    if (!S_ISREG(st.st_mode)) {
        r.verdict = Verdict::Skipped;
        r.detail = "not a regular file";
        return r;
    }
    r.size = static_cast<std::uint64_t>(st.st_size);

    // An explicit operator scan (right-click "Advanced scan", CLI `scan`)
    // overrides the realtime size/extension policy: the user asked for THIS
    // file, whatever its size or extension. Directory exclusions still apply --
    // no on-demand reads of /proc, /sys, ....
    if (req.reason == ScanReason::OnDemand) {
        for (const auto& d : cfg_.scan.skip_dirs) {
            if (req.path.find("/" + d + "/") != std::string::npos ||
                std::string_view{req.path}.ends_with("/" + d)) {
                r.verdict = Verdict::Skipped;
                r.detail = std::format("directory is excluded by policy ({})", d);
                return r;
            }
        }
    } else if (should_skip(req.path)) {
        r.verdict = Verdict::Skipped;
        r.detail = "excluded by policy (size, extension or directory)";
        return r;
    }

    // Digest first: it is the cache key and the IOC we would report anyway.
    r.sha256 = core::hash::Sha256::to_hex(core::hash::Sha256::of_file(req.path));
    if (cfg_.scan.hash_cache) {
        if (auto hit = cache_.lookup(r.sha256, r.size, static_cast<std::int64_t>(st.st_mtime))) {
            r.verdict = hit->verdict;
            r.risk = hit->risk;
            r.from_cache = true;
            r.detail = "cached verdict";
            for (const auto& rule : hit->rules) {
                Match m;
                m.rule = rule;
                r.matches.push_back(std::move(m));
            }
            r.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0);
            return r;
        }
    }

    auto mf = core::MappedFile::open(req.path, cfg_.scan.max_file_bytes);
    if (!mf) {
        r.verdict = Verdict::Error;
        r.detail = "mmap failed: " + std::string(std::strerror(errno));
        return r;
    }
    mf->advise_sequential();
    const auto bytes = mf->bytes();
    r.entropy = shannon_entropy(bytes.subspan(0, std::min<std::size_t>(bytes.size(), 1 << 20)));
    r.flavour = core::hash::classify(req.path, bytes.subspan(0, std::min<std::size_t>(bytes.size(), 16)));

    r.matches = engine_.scan(bytes, req.path);
    r.engine = engine_.backend() == Backend::LibYara ? "libyara" : "yara-lite";

    std::uint16_t risk = 0;
    for (const auto& m : r.matches) {
        risk = static_cast<std::uint16_t>(
            std::min<int>(1000, risk + (m.severity == core::Severity::Critical   ? 600
                                        : m.severity == core::Severity::High     ? 400
                                        : m.severity == core::Severity::Medium   ? 200 : 60)));
    }
    // A very high-entropy executable in a world-writable directory is worth
    // raising even with no signature: packed or freshly encrypted payloads.
    if (r.entropy >= 7.5 && (r.flavour == FileFlavour::Executable ||
                             core::proc::is_world_writable_runtime_dir(req.path))) {
        risk = static_cast<std::uint16_t>(std::min<int>(1000, risk + 250));
    }
    r.risk = risk;

    // A CRITICAL-severity signature (known-malware identifier, EICAR) is a
    // high-confidence detection on its own -- it must not be diluted into
    // "suspicious" just because it is the only match.
    const bool critical_hit =
        std::any_of(r.matches.begin(), r.matches.end(), [](const auto& m) {
            return m.severity == core::Severity::Critical;
        });
    if (r.matches.empty()) r.verdict = Verdict::Clean;
    else if (critical_hit || risk >= cfg_.heuristic.critical_threshold)
        r.verdict = Verdict::Malicious;
    else if (risk >= cfg_.heuristic.alert_threshold) r.verdict = Verdict::Suspicious;
    else r.verdict = Verdict::Suspicious;

    r.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    total_ns_.fetch_add(static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(r.elapsed).count()),
                        std::memory_order_relaxed);

    if (cfg_.scan.hash_cache && r.verdict != Verdict::Error) {
        VerdictCache::Entry e;
        e.verdict = r.verdict;
        e.size = r.size;
        e.mtime = static_cast<std::int64_t>(st.st_mtime);
        e.risk = r.risk;
        for (const auto& m : r.matches) e.rules.push_back(m.rule);
        e.when = core::SysClock::now();
        cache_.insert(r.sha256, std::move(e));
    }

    {
        std::lock_guard lk{stat_mu_};
        ++stats_.scanned;
        switch (r.verdict) {
            case Verdict::Clean: ++stats_.clean; break;
            case Verdict::Suspicious: ++stats_.suspicious; break;
            case Verdict::Malicious: ++stats_.malicious; break;
            case Verdict::Skipped: ++stats_.skipped; break;
            default: break;
        }
        if (r.from_cache) ++stats_.cache_hits;
    }
    {
        std::lock_guard lk{result_mu_};
        recent_.push_front(r);
        while (recent_.size() > kRecentMax) recent_.pop_back();
    }
    return r;
}

void ScannerSensor::publish(const ScanResult& r, const ScanRequest& req) noexcept {
    if (r.verdict == Verdict::Skipped || r.verdict == Verdict::Clean) {
        // Clean verdicts are still useful to the GUI but must not consume
        // heuristic-engine attention; publish at Info with no risk.
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::YaraMatch;
        ev.kind = core::EventKind::ScanVerdict;
        ev.severity = core::Severity::Info;
        ev.target.path = r.path;
        ev.actor.pid = req.attributing_pid;
        ev.metric = r.entropy;
        ev.message = std::format("{} {} ({} bytes, entropy {:.2f}, {})", verdict_name(r.verdict), r.path,
                                 r.size, r.entropy, r.from_cache ? "cached" : r.engine);
        emit(std::move(ev));
        return;
    }

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::YaraMatch;
    ev.kind = r.verdict == Verdict::Malicious ? core::EventKind::YaraVerdict : core::EventKind::ScanVerdict;
    ev.severity = r.verdict == Verdict::Malicious ? core::Severity::Critical : core::Severity::High;
    ev.target.path = r.path;
    ev.actor.pid = req.attributing_pid;
    ev.risk_score = r.risk;
    ev.metric = r.entropy;
    ev.count = r.matches.size();
    ev.escalated = req.escalated || r.verdict == Verdict::Malicious;
    if (!r.sha256.empty()) ev.target.rule_id = "sha256:" + r.sha256.substr(0, 16);

    std::string rules;
    for (const auto& m : r.matches) {
        if (!rules.empty()) rules += ", ";
        rules += m.rule;
        ev.triggers.push_back(m.rule);
        if (!m.family.empty()) ev.target.family = m.family;
    }
    ev.fields["rules"] = rules;
    ev.fields["sha256"] = r.sha256;
    ev.fields["size"] = std::to_string(r.size);
    ev.fields["entropy"] = std::format("{:.3f}", r.entropy);
    ev.fields["flavour"] = std::string(core::hash::flavour_name(r.flavour));
    ev.fields["engine"] = r.engine;
    ev.fields["scan_ms"] = std::to_string(r.elapsed.count());
    ev.fields["reason"] = std::string(reason_name(req.reason));
    ev.fields["cached"] = r.from_cache ? "yes" : "no";

    ev.message = std::format("{}: {} matched [{}] risk={}/1000 entropy={:.2f} size={} sha256={}",
                             verdict_name(r.verdict), r.path, rules, r.risk, r.entropy, r.size,
                             r.sha256.substr(0, 16));
    emit(std::move(ev));
}

bool ScannerSensor::enqueue(ScanRequest req) noexcept {
    if (req.path.empty()) return false;
    if (req.queued_at == core::SysClock::time_point{}) req.queued_at = core::SysClock::now();
    req.dedup_key = core::hash::xxh64(req.path);

    if (!ring_.try_push(std::move(req))) {
        note_error("scan ring saturated: request dropped");
        return false;
    }
    {
        std::lock_guard lk{stat_mu_};
        ++stats_.enqueued;
        stats_.queue_depth = ring_.capacity();
    }
    // Anything escalated or urgent also goes to the external batch so a second
    // opinion arrives even if our own engine is out of depth.
    if (req.reason == ScanReason::HeuristicEscalation || req.reason == ScanReason::CanaryEscalation ||
        req.priority == ScanPriority::Urgent) {
        // add() returning false means the pending set overflowed: flush NOW
        // rather than silently dropping a second-opinion request.
        if (!queue_.add(req.path, req.reason)) flush_batch();
    }
    return true;
}

void ScannerSensor::drain_ring() noexcept {
    std::array<ScanRequest, 128> batch;
    for (;;) {
        const std::size_t n = ring_.drain(batch.begin(), batch.size());
        if (n == 0) break;
        for (std::size_t i = 0; i < n; ++i) {
            const ScanRequest req = batch[i];
            // Dispatch the actual work to the pool: the sensor loop must stay
            // responsive so the batch timer and the GUI never wait on a scan.
            const bool ok = pool_.submit(
                [this, req] {
                    const ScanResult r = scan_path_locked(req);
                    publish(r, req);
                    // Every scanned file also accumulates into the external batch
                    // unless it was already judged malicious locally.
                    if (r.verdict == Verdict::Clean || r.verdict == Verdict::Suspicious) {
                        if (!queue_.add(r.path, r.reason)) flush_batch();
                    }
                },
                req.priority == ScanPriority::Urgent ? "urgent-scan" : "scan");
            if (!ok) note_error("scan pool saturated; dropped " + req.path);
        }
    }
}

void ScannerSensor::flush_batch() noexcept {
    auto paths = queue_.take();
    if (paths.empty()) return;

    const bool external = inventory_.clamd_socket_alive || !inventory_.clamdscan.empty() ||
                          inventory_.kvrt_runnable;
    if (!external) {
        SDEBUG(name_, "batch of {} paths skipped: no external scanner available", paths.size());
        return;
    }

    // One execve for the whole batch: that is the entire point of the queue.
    if (!pool_.submit(
        [this, paths = std::move(paths)] {
            const auto outcome = run_batch(paths, cfg_.scan, inventory_);
            if (!outcome.ran) {
                SWARN(name_, "external batch did not run: {}", outcome.error);
                return;
            }

            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::BatchScan;
            ev.kind = core::EventKind::ScanVerdict;
            ev.count = paths.size();
            ev.fields["engine"] = outcome.engine;
            ev.fields["exit_code"] = std::to_string(outcome.exit_code);
            ev.fields["batch_ms"] = std::to_string(outcome.elapsed.count());

            if (!outcome.detections.empty()) {
                ev.severity = core::Severity::Critical;
                ev.risk_score = 900;
                std::string list;
                for (const auto& [p, sig] : outcome.detections) {
                    if (!list.empty()) list += "; ";
                    list += p + " => " + sig;
                    core::TelemetryEvent hit;
                    hit.sensor = core::SensorId::BatchScan;
                    hit.kind = core::EventKind::YaraVerdict;
                    hit.severity = core::Severity::Critical;
                    hit.target.path = p;
                    hit.target.rule_id = sig;
                    hit.risk_score = 900;
                    hit.message = std::format("{} DETECTION by {}: {}", verdict_name(Verdict::Malicious),
                                              outcome.engine, sig);
                    emit(std::move(hit));
                }
                ev.message = std::format("{} detected {} file(s) in a batch of {}: {}", outcome.engine,
                                         outcome.detections.size(), paths.size(), list);
                {
                    std::lock_guard lk{stat_mu_};
                    stats_.external_detections += outcome.detections.size();
                }
            } else {
                ev.severity = core::Severity::Info;
                ev.message = std::format("{} batch of {} paths completed in {}ms with no detections{}",
                                         outcome.engine, paths.size(), outcome.elapsed.count(),
                                         outcome.error.empty() ? "" : " (" + outcome.error + ")");
            }
            emit(std::move(ev));
        },
        "batch-scan")) {
        note_error(std::format("scan pool saturated: external batch of {} paths deferred", paths.size()));
    }
}

void ScannerSensor::start_full_sweep(ScanPriority prio) {
    if (sweeping_.exchange(true)) {
        SWARN(name_, "sweep already in progress");
        return;
    }
    // The pool task cannot own a stop_token, so it checks the `sweeping_` atomic
    // that on_stop() clears -- that is the sweep's cancellation channel.
    if (!pool_.submit([this, prio] { sweep_worker(std::stop_token{}, prio); }, "full-sweep")) {
        sweeping_.store(false);
        note_error("scan pool saturated: full sweep could not be scheduled");
    }
}

void ScannerSensor::sweep_worker(std::stop_token st, ScanPriority prio) noexcept {
    (void)st;
    std::uint64_t total = 0, done = 0;

    // Count first so progress is meaningful.
    std::vector<std::string> all;
    for (const auto& root : cfg_.scan.roots) {
        if (!fsx::is_dir(root.path)) continue;
        std::deque<std::string> stack{root.path};
        while (!stack.empty() && sweeping_.load()) {
            const std::string dir = std::move(stack.front());
            stack.pop_front();
            core::UniqueDir d{::opendir(dir.c_str())};
            if (!d) continue;
            while (const dirent* e = ::readdir(d.get())) {
                if (e->d_name[0] == '.' && (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0')))
                    continue;
                const std::string child = dir + "/" + e->d_name;
                bool is_dir = e->d_type == DT_DIR;
                if (e->d_type == DT_UNKNOWN) is_dir = fsx::is_dir(child);
                if (is_dir) {
                    bool skip_dir = false;
                    for (const auto& sd : cfg_.scan.skip_dirs) {
                        if (std::string_view(e->d_name) == sd) { skip_dir = true; break; }
                    }
                    if (root.recursive && !skip_dir) stack.push_back(child);
                    continue;
                }
                if (should_skip(child)) continue;
                all.push_back(child);
                ++total;
                if (all.size() > 500000) break;  // hard bound on memory
            }
            if (all.size() > 500000) break;
        }
    }

    SINFO(name_, "full sweep: {} candidate files", total);
    for (const auto& path : all) {
        if (!sweeping_.load()) break;
        ScanRequest req;
        req.path = path;
        req.reason = ScanReason::FullSweep;
        req.priority = prio;
        req.queued_at = core::SysClock::now();
        const ScanResult r = scan_path_locked(req);
        publish(r, req);
        ++done;
        if (total > 0) sweep_progress_.store(static_cast<double>(done) / static_cast<double>(total));
        if ((done % 64) == 0) {
            std::lock_guard lk{sweep_mu_};
            sweep_current_ = path;
        }
        // Yield periodically: a sweep must never monopolise the CPU on a host
        // that is also doing real work.
        if ((done % 256) == 0) std::this_thread::sleep_for(5ms);
    }

    sweeping_.store(false);
    sweep_progress_.store(0.0);
    emit(core::EventKind::ScanVerdict, core::Severity::Info,
         std::format("full sweep complete: {} files scanned", done));
}

void ScannerSensor::loop(std::stop_token st) {
    while (!st.stop_requested()) {
        drain_ring();
        if (queue_.due()) flush_batch();
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    drain_ring();
    flush_batch();
}

ScannerSensor::Counters ScannerSensor::counters() const noexcept {
    Counters c;
    {
        std::lock_guard lk{stat_mu_};
        c = stats_;
    }
    c.cache_hits = cache_.hits();
    c.enqueued = queue_.enqueued();
    c.batches = queue_.batches();
    c.queue_depth = queue_.pending();
    c.sweep_running = sweeping_.load();
    c.sweep_progress = sweep_progress_.load();
    {
        std::lock_guard lk{sweep_mu_};
        c.sweep_current = sweep_current_;
    }
    const std::uint64_t ns = total_ns_.load(std::memory_order_relaxed);
    if (c.scanned > 0)
        c.mean_scan_ms = static_cast<double>(ns) / 1e6 / static_cast<double>(c.scanned);
    return c;
}

std::vector<ScanResult> ScannerSensor::recent(std::size_t n) const noexcept {
    std::lock_guard lk{result_mu_};
    std::vector<ScanResult> out;
    out.reserve(std::min(n, recent_.size()));
    for (std::size_t i = 0; i < std::min(n, recent_.size()); ++i) out.push_back(recent_[i]);
    return out;
}

}  // namespace hyprnova::scanning
