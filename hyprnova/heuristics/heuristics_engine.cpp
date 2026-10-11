// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 5 implementation

#include <filesystem>

#include "heuristics/heuristics_engine.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <format>
#include <numeric>
#include <thread>

#include "core/fd.hpp"
#include "core/hash.hpp"
#include "core/proc.hpp"

namespace hyprnova::heuristics {

namespace fsx = core::fsx;
using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// ActorRisk
// ---------------------------------------------------------------------------

core::Severity ActorRisk::severity_for(double s, const core::HeuristicConfig& cfg) const noexcept {
    if (s >= cfg.auto_respond_threshold) return core::Severity::Critical;
    if (s >= cfg.critical_threshold) return core::Severity::High;
    if (s >= cfg.alert_threshold) return core::Severity::Medium;
    if (s >= cfg.alert_threshold / 2.0) return core::Severity::Low;
    return core::Severity::Info;
}

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

bool Baseline::knows_child(std::string_view parent, std::string_view child) const noexcept {
    auto it = parent_to_children.find(std::string(parent));
    if (it == parent_to_children.end()) return false;
    return it->second.count(std::string(child)) > 0;
}

bool Baseline::knows_exe(std::string_view exe) const noexcept {
    return exec_frequency.count(std::string(exe)) > 0;
}

bool Baseline::knows_exe_for_uid(uid_t uid, std::string_view exe) const noexcept {
    auto it = uid_to_exes.find(uid);
    if (it == uid_to_exes.end()) return false;
    return it->second.count(std::string(exe)) > 0;
}

namespace {

/// Minimal line-oriented serialiser. JSON would be nicer to read, but the
/// baseline can hold hundreds of thousands of (uid, exe) pairs and a flat
/// "kind\tkey\tvalue" format loads in one pass without building a DOM.
void put(std::string& out, std::string_view kind, std::string_view a, std::uint64_t b) {
    out += kind;
    out += '\t';
    out += a;
    out += '\t';
    out += std::to_string(b);
    out += '\n';
}

}  // namespace

std::string serialise_baseline(const Baseline& b) noexcept {
    std::string out;
    out.reserve(b.exec_frequency.size() * 48 + 256);
    out += "# hyprnova baseline v1\n";
    out += "meta\tlearning\t" + std::string(b.learning ? "1" : "0") + "\n";
    out += "meta\tobservations\t" + std::to_string(b.observations) + "\n";
    out += "meta\tstarted\t" + std::to_string(std::chrono::system_clock::to_time_t(b.learning_started)) + "\n";
    out += "meta\tends\t" + std::to_string(std::chrono::system_clock::to_time_t(b.learning_ends)) + "\n";

    for (const auto& [parent, kids] : b.parent_to_children) {
        for (const auto& k : kids) put(out, "pc", parent + ">" + k, 1);
    }
    for (const auto& [exe, n] : b.exec_frequency) put(out, "exe", exe, n);
    for (const auto& [uid, exes] : b.uid_to_exes) {
        for (const auto& e : exes) put(out, "uid", std::to_string(uid) + ">" + e, 1);
    }
    for (const auto& d : b.listening_daemons) put(out, "listen", d, 1);
    for (const auto& [c, n] : b.outbound_peers) put(out, "outbound", c, n);
    return out;
}

bool deserialise_baseline(std::string_view text, Baseline& out) noexcept {
    std::size_t pos = 0;
    std::size_t n = 0;
    while (pos < text.size()) {
        const std::size_t nl = text.find('\n', pos);
        const std::string_view line{text.data() + pos, (nl == std::string_view::npos ? text.size() : nl) - pos};
        pos = nl == std::string_view::npos ? text.size() : nl + 1;
        if (line.empty() || line[0] == '#') continue;

        const std::size_t t1 = line.find('\t');
        if (t1 == std::string_view::npos) continue;
        const std::string_view kind = line.substr(0, t1);
        const std::size_t t2 = line.find('\t', t1 + 1);
        if (t2 == std::string_view::npos) continue;
        const std::string_view key = line.substr(t1 + 1, t2 - t1 - 1);
        std::uint64_t val = 0;
        const std::string_view vs = line.substr(t2 + 1);
        if (std::from_chars(vs.data(), vs.data() + vs.size(), val).ec != std::errc{}) continue;

        if (kind == "meta") {
            if (key == "learning") out.learning = val != 0;
            else if (key == "observations") out.observations = val;
            else if (key == "started")
                out.learning_started = core::SysClock::from_time_t(static_cast<std::time_t>(val));
            else if (key == "ends")
                out.learning_ends = core::SysClock::from_time_t(static_cast<std::time_t>(val));
        } else if (kind == "pc") {
            const std::size_t gt = key.find('>');
            if (gt != std::string_view::npos)
                out.parent_to_children[std::string(key.substr(0, gt))].emplace(key.substr(gt + 1));
        } else if (kind == "exe") {
            out.exec_frequency[std::string(key)] = val;
        } else if (kind == "uid") {
            const std::size_t gt = key.find('>');
            if (gt != std::string_view::npos) {
                std::uint64_t uid = 0;
                if (std::from_chars(key.data(), key.data() + gt, uid).ec == std::errc{})
                    out.uid_to_exes[static_cast<uid_t>(uid)].emplace(key.substr(gt + 1));
            }
        } else if (kind == "listen") {
            out.listening_daemons.emplace(key);
        } else if (kind == "outbound") {
            out.outbound_peers[std::string(key)] = val;
        }
        ++n;
        if (n > 5'000'000) break;  // a corrupt or hostile file must not OOM us
    }
    return n > 0;
}

// ---------------------------------------------------------------------------
// BurstCounter
// ---------------------------------------------------------------------------

void BurstCounter::hit(std::string_view key, core::SteadyClock::time_point when) noexcept {
    const auto now = when == core::SteadyClock::time_point{} ? core::SteadyClock::now() : when;
    std::lock_guard lk{mu_};
    auto& dq = hits_[std::string(key)];
    dq.push_back(now);
    // Bound each key: a flood must not grow memory without limit.
    while (dq.size() > 1024) dq.pop_front();
    if (hits_.size() > 8192) {
        // Drop the oldest-touched keys.
        std::size_t removed = 0;
        for (auto it = hits_.begin(); it != hits_.end() && removed < 1024;) {
            if (it->second.empty() || it->second.back() < now - 3600s) { it = hits_.erase(it); ++removed; }
            else ++it;
        }
    }
}

std::size_t BurstCounter::count(std::string_view key, std::chrono::milliseconds window) const noexcept {
    const auto cutoff = core::SteadyClock::now() - window;
    std::lock_guard lk{mu_};
    auto it = hits_.find(std::string(key));
    if (it == hits_.end()) return 0;
    std::size_t n = 0;
    for (const auto& t : it->second) {
        if (t >= cutoff) ++n;
    }
    return n;
}

void BurstCounter::prune(std::chrono::seconds max_age) noexcept {
    const auto cutoff = core::SteadyClock::now() - max_age;
    std::lock_guard lk{mu_};
    for (auto it = hits_.begin(); it != hits_.end();) {
        auto& dq = it->second;
        while (!dq.empty() && dq.front() < cutoff) dq.pop_front();
        if (dq.empty()) it = hits_.erase(it);
        else ++it;
    }
}

std::size_t BurstCounter::keys() const noexcept {
    std::lock_guard lk{mu_};
    return hits_.size();
}

// ---------------------------------------------------------------------------
// HeuristicSensor
// ---------------------------------------------------------------------------

HeuristicSensor::HeuristicSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                                 core::ThreadPool& pool)
    : core::ISensor("heuristics", core::SensorId::Heuristic, bus, cfg, pool) {}

HeuristicSensor::~HeuristicSensor() {
    if (sub_id_ != 0) bus_.unsubscribe(sub_id_);
}

void HeuristicSensor::set_backend(std::shared_ptr<IEscalationBackend> b) { backend_ = std::move(b); }

void HeuristicSensor::load_app_profiles() noexcept {
    app_profiles_.clear();
    app_profiles_loaded_ = 0;
    const std::string& dir = cfg_.heuristic.profiles_dir;
    if (dir.empty()) return;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        SINFO(name_, "no app-profile directory at {}: every app uses the global policy", dir);
        return;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec)) continue;
        const auto& path = entry.path();
        if (path.extension().generic_string() != ".json") continue;
        std::string text;
        if (core::fsx::read_file(path.generic_string(), text, 1 << 20) < 0) {
            SWARN(name_, "app profile {} unreadable: skipped", path.generic_string());
            continue;
        }
        core::json::ParseError pe {};
        const auto doc = core::json::parse(text, {}, &pe);
        if (!doc || !doc->is_object()) {
            SWARN(name_, "app profile {} is not valid JSON: skipped", path.generic_string());
            continue;
        }
        AppProfile p;
        p.app = doc->str("app");
        if (p.app.empty()) {
            SWARN(name_, "app profile {} has no \"app\" field: skipped", path.generic_string());
            continue;
        }
        if (const auto* a = doc->at("allowed_children"))
            if (const auto* arr = a->as_array())
                for (const auto& v : *arr) p.allowed_children.emplace_back(v.as_string_copy());
        if (const auto* a = doc->at("forbidden_children"))
            if (const auto* arr = a->as_array())
                for (const auto& v : *arr) p.forbidden_children.emplace_back(v.as_string_copy());
        SINFO(name_, "app profile for '{}': {} allowed, {} forbidden children (from {})",
              p.app, p.allowed_children.size(), p.forbidden_children.size(), path.filename().string());
        app_profiles_[p.app] = std::move(p);
        ++app_profiles_loaded_;
    }
    if (app_profiles_loaded_ == 0)
        SINFO(name_, "no usable app profiles in {}; every app uses the global policy", dir);
}

bool HeuristicSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.heuristic.enabled;
}

bool HeuristicSensor::on_start() {
    load_app_profiles();
    if (!backend_) {
        SWARN(name_, "no escalation backend wired: steps 1-3 of the escalation pipeline are inert, "
                     "findings will still be published");
    }
    (void)load_baseline();

    if (baseline_.learning) {
        if (baseline_.learning_started == core::SysClock::time_point{})
            baseline_.learning_started = core::SysClock::now();
        if (baseline_.learning_ends == core::SysClock::time_point{})
            baseline_.learning_ends = baseline_.learning_started + cfg_.heuristic.baseline_learning_period;
    }

    // Subscribe AFTER our own state is ready: an event arriving mid-construction
    // would hit a half-initialised engine.
    sub_id_ = bus_.subscribe("heuristics", [this](const core::TelemetryEvent& ev) { on_event(ev); });

    running_.store(true);
    mark_running(std::format("learning={} observations={} backend={}", baseline_.learning ? "yes" : "no",
                             baseline_.observations, backend_ ? "wired" : "NONE"));
    emit(core::EventKind::SensorUp, core::Severity::Info,
         std::format("heuristic engine ready: alert>={} critical>={} auto-respond>{} (auto_respond={})",
                     cfg_.heuristic.alert_threshold, cfg_.heuristic.critical_threshold,
                     cfg_.heuristic.auto_respond_threshold, cfg_.heuristic.auto_respond ? "ENABLED" : "off"));
    if (baseline_.learning) {
        emit(core::EventKind::ConfigReload, core::Severity::Info,
             std::format("baseline LEARNING until {} ({}h window): findings are published at reduced "
                         "severity and no automatic action is taken",
                         std::chrono::system_clock::to_time_t(baseline_.learning_ends),
                         cfg_.heuristic.baseline_learning_period.count()));
    }
    return true;
}

void HeuristicSensor::on_stop() {
    running_.store(false);
    if (sub_id_ != 0) {
        bus_.unsubscribe(sub_id_);
        sub_id_ = 0;
    }
    (void)save_baseline();
}

void HeuristicSensor::loop(std::stop_token st) {
    auto last_decay = core::SteadyClock::now();
    auto last_prune = core::SteadyClock::now();
    auto last_save = core::SteadyClock::now();

    while (!st.stop_requested()) {
        std::this_thread::sleep_for(200ms);

        if (core::SteadyClock::now() - last_decay >= 1s) {
            decay_tick();
            last_decay = core::SteadyClock::now();
        }
        if (core::SteadyClock::now() - last_prune >= 60s) {
            prune();
            ssh_spawns_.prune(cfg_.heuristic.ssh_spawn_window * 10);
            auth_failures_.prune(3600s);
            exec_bursts_.prune(3600s);
            last_prune = core::SteadyClock::now();
        }
        if (core::SteadyClock::now() - last_save >= 300s) {
            (void)save_baseline();
            last_save = core::SteadyClock::now();
        }
        // End the learning phase exactly once.
        if (baseline_.learning && core::SysClock::now() >= baseline_.learning_ends) {
            {
                std::unique_lock lk{mu_};
                baseline_.learning = false;
            }
            (void)save_baseline();
            emit(core::EventKind::ConfigReload, core::Severity::Info,
                 std::format("baseline learning COMPLETE after {} observations: full severity and "
                             "automatic response are now enabled",
                             baseline_.observations));
            mark_running(std::format("baseline learned ({} observations)", baseline_.observations));
        }
    }
}

void HeuristicSensor::observe_baseline(const core::TelemetryEvent& ev) noexcept {
    if (!cfg_.heuristic.learn_baseline) return;
    if (!baseline_.learning) return;

    observations_.fetch_add(1, std::memory_order_relaxed);

    std::unique_lock lk{mu_};
    ++baseline_.observations;

    if (ev.actor.exe.empty() && ev.actor.comm.empty()) return;
    const std::string child = ev.actor.comm.empty() ? ev.actor.exe : ev.actor.comm;
    const std::size_t slash = child.find_last_of('/');
    const std::string child_base = slash == std::string::npos ? child : child.substr(slash + 1);

    if (!ev.actor.exe.empty()) ++baseline_.exec_frequency[ev.actor.exe];
    if (ev.actor.uid != 0xFFFFFFFF && !ev.actor.exe.empty())
        baseline_.uid_to_exes[ev.actor.uid].insert(ev.actor.exe);

    // Parent name: prefer the enriched ancestry, else the fields the sensor set.
    std::string parent;
    auto pit = ev.fields.find("parent");
    if (pit != ev.fields.end()) parent = pit->second;
    else if (ev.actor.ancestry.size() >= 2) parent = core::proc::comm_of(ev.actor.ancestry[ev.actor.ancestry.size() - 2]);
    if (!parent.empty() && !child_base.empty()) baseline_.parent_to_children[parent].insert(child_base);

    if (ev.kind == core::EventKind::NetListen && !child_base.empty())
        baseline_.listening_daemons.insert(child_base);
    if (ev.kind == core::EventKind::NetConnect && !ev.target.peer_ip.empty() && !child_base.empty())
        ++baseline_.outbound_peers[child_base];
}

LineageAnomaly HeuristicSensor::check_lineage(const core::TelemetryEvent& ev) const noexcept {
    LineageAnomaly la;
    if (ev.actor.comm.empty() && ev.actor.exe.empty()) return la;

    const std::string child_full = ev.actor.exe.empty() ? ev.actor.comm : ev.actor.exe;
    const std::size_t slash = child_full.find_last_of('/');
    const std::string child = slash == std::string::npos ? child_full : child_full.substr(slash + 1);

    std::string parent;
    auto pit = ev.fields.find("parent");
    if (pit != ev.fields.end()) parent = pit->second;
    else if (ev.actor.ancestry.size() >= 2)
        parent = core::proc::comm_of(ev.actor.ancestry[ev.actor.ancestry.size() - 2]);
    if (parent.empty()) return la;

    la.parent = parent;
    la.child = child;

    // (0) Trusted per-app profiles, honoured BEFORE the global policy. A profile
    // that another party wrote for this app may allow a pair the global list
    // forbids (nginx may legitimately spawn php-fpm even though a generic
    // policy says no), and may forbid additional pairs specific to that app.
    // Read-only after on_start, so no lock here on the hot path.
    const auto prof_it = app_profiles_.find(parent);
    const AppProfile* profile = prof_it != app_profiles_.end() ? &prof_it->second : nullptr;
    const bool allowed_by_profile =
        profile && std::any_of(profile->allowed_children.begin(), profile->allowed_children.end(),
                               [&](const std::string& a) {
                                   return child == a || child_full == a || child.find(a) == 0;
                               });
    if (allowed_by_profile) return la;   // trusted profile says this pair is fine

    // (1) Explicitly forbidden parent/child pairs: a shell under nginx is never
    // legitimate, whatever the baseline says.
    for (const auto& [p, forbidden] : cfg_.heuristic.forbidden_children) {
        if (parent.find(p) == std::string::npos) continue;
        for (const auto& f : forbidden) {
            if (child == f || child_full == f || child.find(f) == 0) {
                la.anomaly = true;
                la.severity = core::Severity::Critical;
                la.risk = 780;
                la.reason = std::format("forbidden child process: '{}' spawned '{}' ({} under a network "
                                        "daemon is a web-shell or RCE foothold)",
                                        parent, child, child);
                la.triggers = {"forbidden_child_process", "possible_web_shell"};
                return la;
            }
        }
    }

    // (1b) App-specific forbidden pairs from the profile, on top of the globals.
    if (profile) {
        for (const auto& f : profile->forbidden_children) {
            if (child == f || child_full == f || child.find(f) == 0) {
                la.anomaly = true;
                la.severity = core::Severity::Critical;
                la.risk = 780;
                la.reason = std::format(
                    "forbidden child process (per app profile for '{}'): '{}' spawned '{}'",
                    profile->app, parent, child);
                la.triggers = {"forbidden_child_process", "app_profile_violation"};
                return la;
            }
        }
    }

    // (2) Interactive tty spawned from a service daemon.
    const bool is_shell = std::any_of(cfg_.heuristic.shells.begin(), cfg_.heuristic.shells.end(),
                                      [&](const std::string& s) {
                                          return child == s || child_full == s ||
                                                 (s.find_last_of('/') != std::string::npos &&
                                                  child == s.substr(s.find_last_of('/') + 1));
                                      });
    const bool parent_is_daemon = std::any_of(cfg_.heuristic.web_daemons.begin(),
                                              cfg_.heuristic.web_daemons.end(),
                                              [&](const std::string& d) {
                                                  return parent.find(d) != std::string::npos;
                                              });
    if (is_shell && parent_is_daemon) {
        la.anomaly = true;
        la.severity = core::Severity::Critical;
        la.risk = 820;
        la.reason = std::format("INTERACTIVE SHELL spawned by network daemon '{}': {} -> {}", parent,
                                parent, child);
        la.triggers = {"tty_from_daemon", "interactive_shell_under_service"};
        return la;
    }
    const std::string tty = ev.fields.count("tty") ? ev.fields.at("tty") : std::string{};
    if (!tty.empty() && tty != "0" && parent_is_daemon) {
        la.anomaly = true;
        la.severity = core::Severity::High;
        la.risk = 620;
        la.reason = std::format("daemon '{}' acquired a controlling tty ({})", parent, tty);
        la.triggers = {"tty_from_daemon"};
        return la;
    }

    // (3) A child never seen from this parent before. Only meaningful once the
    // baseline has learned; before that everything is new and everything would
    // fire.
    if (!baseline_.learning && !baseline_.parent_to_children.empty() && !baseline_.knows_child(parent, child)) {
        la.anomaly = true;
        la.severity = core::Severity::Medium;
        la.risk = 260;
        la.reason = std::format("novel process lineage: '{}' has never spawned '{}' on this host during "
                                "the {}h learning window",
                                parent, child, cfg_.heuristic.baseline_learning_period.count());
        la.triggers = {"novel_lineage"};
    }
    return la;
}

void HeuristicSensor::detect_service_anomalies(const core::TelemetryEvent& ev) noexcept {
    if (!cfg_.heuristic.detect_ssh_anomaly) return;

    std::string parent;
    auto pit = ev.fields.find("parent");
    if (pit != ev.fields.end()) parent = pit->second;
    else if (ev.actor.ancestry.size() >= 2)
        parent = core::proc::comm_of(ev.actor.ancestry[ev.actor.ancestry.size() - 2]);
    if (parent.empty()) return;

    // Only track the daemons we were asked to watch.
    const bool watched = parent.find("sshd") != std::string::npos || parent == "systemd" ||
                         std::any_of(cfg_.heuristic.web_daemons.begin(), cfg_.heuristic.web_daemons.end(),
                                     [&](const std::string& d) { return parent.find(d) != std::string::npos; });
    if (!watched) return;

    const std::string child_full = ev.actor.exe.empty() ? ev.actor.comm : ev.actor.exe;
    const std::size_t slash = child_full.find_last_of('/');
    const std::string child = slash == std::string::npos ? child_full : child_full.substr(slash + 1);
    if (child.empty()) return;

    const bool is_ssh = parent.find("sshd") != std::string::npos;
    if (is_ssh) ssh_spawns_.hit("sshd");
    exec_bursts_.hit(parent + ">" + child);

    {
        std::lock_guard lk{svc_mu_};
        ServiceState& s = services_[parent];
        s.daemon = parent;
        ++s.child_count;
        if (std::find(s.children.begin(), s.children.end(), child) == s.children.end()) {
            s.children.push_back(child);
            if (s.children.size() > 64) s.children.erase(s.children.begin());
        }
        const auto window = std::chrono::duration_cast<std::chrono::minutes>(cfg_.heuristic.ssh_spawn_window);
        s.spawn_rate_per_min = ssh_spawns_.count("sshd", window);

        const bool shell = std::any_of(cfg_.heuristic.shells.begin(), cfg_.heuristic.shells.end(),
                                       [&](const std::string& sh) {
                                           return child == sh ||
                                                  (sh.find_last_of('/') != std::string::npos &&
                                                   child == sh.substr(sh.find_last_of('/') + 1));
                                       });
        if (shell) s.shell_spawned = true;
        if (shell && !is_ssh) s.anomalous_child = true;
    }

    // SSH spawn burst: many sshd children in a short window is either a
    // brute-force landing or a worm moving laterally. Both matter.
    if (is_ssh) {
        const auto window = std::chrono::duration_cast<std::chrono::milliseconds>(cfg_.heuristic.ssh_spawn_window);
        const std::size_t n = ssh_spawns_.count("sshd", window);
        if (n >= cfg_.heuristic.ssh_spawn_burst) {
            core::TelemetryEvent out;
            out.sensor = core::SensorId::Heuristic;
            out.kind = core::EventKind::SshSpawn;
            out.severity = core::Severity::High;
            out.risk_score = 560;
            out.count = n;
            out.actor.pid = ev.actor.pid;
            out.actor.comm = child;
            out.message = std::format("SSH spawn burst: {} sshd child processes in {}s (threshold {})",
                                      n, window.count() / 1000, cfg_.heuristic.ssh_spawn_burst);
            out.triggers = {"ssh_spawn_burst", "possible_lateral_movement"};
            emit(std::move(out));
            // Reset the burst so we emit once per burst, not once per spawn.
            ssh_spawns_.prune(1s);
        }
    }

    // An unexpected child of systemd: a service unit that spawns curl/wget/nc.
    if (parent == "systemd") {
        for (const auto& [p, forbidden] : cfg_.heuristic.forbidden_children) {
            if (p != "systemd") continue;
            for (const auto& f : forbidden) {
                if (child == f) {
                    core::TelemetryEvent out;
                    out.sensor = core::SensorId::Heuristic;
                    out.kind = core::EventKind::ProcAnomaly;
                    out.severity = core::Severity::High;
                    out.risk_score = 520;
                    out.actor.pid = ev.actor.pid;
                    out.actor.comm = child;
                    out.message = std::format("systemd spawned '{}' which is on the forbidden-children "
                                              "list: a transient unit or a hijacked service is reaching "
                                              "the network",
                                              child);
                    out.triggers = {"unexpected_child_of_systemd"};
                    emit(std::move(out));
                }
            }
        }
    }
}

void HeuristicSensor::apply_risk(ActorRisk& a, std::string_view trigger, std::uint16_t points,
                                 core::SensorId sensor, core::Severity sev,
                                 std::string_view evidence) noexcept {
    RiskFactor f;
    f.trigger = std::string(trigger);
    f.points = points;
    f.sensor = sensor;
    f.severity = sev;
    f.when = core::SysClock::now();
    f.evidence = std::string(evidence);

    // Independent corroboration is worth more than repetition. A trigger we have
    // already seen for this actor contributes 25% on repeats: the first canary
    // write is the signal, the four hundredth is the same signal.
    const bool novel = a.trigger_set.insert(f.trigger).second;
    const double contribution = novel ? static_cast<double>(points) : static_cast<double>(points) * 0.25;

    a.score = std::min(1000.0, a.score + contribution);
    a.peak_score = std::max(a.peak_score, a.score);
    a.factors.push_back(std::move(f));
    if (a.factors.size() > 40) a.factors.erase(a.factors.begin(), a.factors.begin() + 10);
    a.distinct_triggers = a.trigger_set.size();
    a.last_update = core::SysClock::now();
    a.severity = a.severity_for(a.score, cfg_.heuristic);
}

void HeuristicSensor::on_event(const core::TelemetryEvent& ev) noexcept {
    if (!running_.load(std::memory_order_relaxed)) return;

    // LOOP GUARD, and it is the load-bearing one. This sensor emits alert events
    // (publish_alert, the unattributed-alert copy below, the escalation-completed
    // event) that are themselves TelemetryEvents on the same bus. Without this
    // filter the sensor receives its own alert, sees risk >= alert_threshold with
    // the same actor, and emits another alert -- a self-sustaining loop that
    // amplifies one finding into a bus-saturating storm (observed: a single
    // ransomware simulation produced ~210k events/second from one entropy event
    // family, because each scan.entropy event at risk 480 spawned an alert which
    // spawned an alert which ...). The attributed path has the same shape:
    // publish_alert sets risk_score = the actor's whole score, and the actor path
    // below adds ev.risk_score back into that actor, so an alert would compound
    // its own score. A sensor must never score its own emissions.
    if (ev.sensor == core::SensorId::Heuristic) return;
    // Response echoes are not evidence. Remediation/Gui events repeat the
    // actor's CURRENT risk in their risk_score (the action taken because of
    // that risk); scoring them fed the score back into itself: alert ->
    // suspend -> response event -> rescore -> alert ..., hundreds of duplicate
    // suspends per second. Actions taken are audit trail, not findings.
    if (ev.sensor == core::SensorId::Remediation || ev.sensor == core::SensorId::Gui) {
        observe_baseline(ev);
        return;
    }

    // Learn from everything first, including events that produce no risk.
    observe_baseline(ev);

    // Purely informational lifecycle events never score.
    if (ev.severity == core::Severity::Info && ev.risk_score == 0 &&
        ev.kind != core::EventKind::ProcExec && ev.kind != core::EventKind::NetConnect) {
        return;
    }

    // Lineage checks need a pid; the GUI/agent-lifecycle events do not have one.
    const LineageAnomaly la = ev.actor.pid > 0 ? check_lineage(ev) : LineageAnomaly{};
    if (ev.actor.pid > 0 && (ev.kind == core::EventKind::ProcExec || ev.kind == core::EventKind::ProcFork))
        detect_service_anomalies(ev);

    if (ev.actor.pid <= 0) {
        // Unattributed findings (inotify-only write anomalies, boot integrity)
        // still deserve an alert; they just have no actor to score.
        if (ev.risk_score >= cfg_.heuristic.alert_threshold || la.anomaly) {
            core::TelemetryEvent alert = ev;
            alert.sensor = core::SensorId::Heuristic;
            alert.escalated = true;
            alert.severity = std::max(ev.severity, core::Severity::Medium);
            if (la.anomaly) {
                alert.risk_score = std::max<std::uint16_t>(alert.risk_score, la.risk);
                alert.triggers.insert(alert.triggers.end(), la.triggers.begin(), la.triggers.end());
                alert.message += " | lineage: " + la.reason;
            }
            alerts_.fetch_add(1, std::memory_order_relaxed);
            emit(std::move(alert));
        }
        return;
    }

    ActorRisk* target = nullptr;
    {
        std::unique_lock lk{mu_};
        ActorRisk& a = actors_[ev.actor.pid];
        if (a.pid == 0) {
            a.pid = ev.actor.pid;
            a.first_seen = core::SysClock::now();
            a.last_decay = core::SteadyClock::now();
            a.lineage = core::proc::lineage_string(ev.actor.pid, 8);
        }
        if (a.exe.empty()) a.exe = ev.actor.exe;
        if (a.comm.empty()) a.comm = ev.actor.comm;
        if (a.cmdline.empty()) a.cmdline = ev.actor.cmdline;
        if (a.uid == 0xFFFFFFFF) a.uid = ev.actor.uid;
        if (a.container_id.empty()) a.container_id = ev.actor.container_id;
        if (a.ancestry.empty()) a.ancestry = ev.actor.ancestry;
        ++a.event_count;

        // Carry the sensor's own risk contribution.
        if (ev.risk_score > 0) {
            const std::string trigger = ev.triggers.empty() ? std::string(core::kind_name(ev.kind))
                                                            : ev.triggers.front();
            apply_risk(a, trigger, ev.risk_score, ev.sensor, ev.severity, ev.message);
        }
        for (const auto& t : ev.triggers) apply_risk(a, t, 0, ev.sensor, ev.severity, ev.message);
        if (la.anomaly) apply_risk(a, la.triggers.empty() ? "lineage" : la.triggers.front(), la.risk,
                                   core::SensorId::Heuristic, la.severity, la.reason);

        // During learning, damp everything. A brand-new host has no normal, so
        // "abnormal" is meaningless until the baseline exists.
        if (baseline_.learning && cfg_.heuristic.suppress_actions_during_learning) {
            a.score *= 0.5;
        }
        target = &a;
    }

    if (!target) return;

    const bool should_alert = target->score >= cfg_.heuristic.alert_threshold;
    const bool should_escalate = target->score >= cfg_.heuristic.critical_threshold;

    if (should_alert) {
        publish_alert(*target);
        alerts_.fetch_add(1, std::memory_order_relaxed);
    }
    if (should_escalate && !target->suspended && !target->inspected) maybe_escalate(*target);
}

void HeuristicSensor::publish_alert(const ActorRisk& a) noexcept {
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Heuristic;
    ev.kind = core::EventKind::ProcAnomaly;
    ev.severity = a.severity_for(a.score, cfg_.heuristic);
    ev.actor.pid = a.pid;
    ev.actor.exe = a.exe;
    ev.actor.comm = a.comm;
    ev.actor.cmdline = a.cmdline;
    ev.actor.uid = a.uid;
    ev.actor.container_id = a.container_id;
    ev.actor.ancestry = a.ancestry;
    ev.risk_score = static_cast<std::uint16_t>(std::min<double>(a.score, 1000.0));
    ev.metric = a.score;
    ev.escalated = a.score >= cfg_.heuristic.critical_threshold;

    std::string triggers;
    for (const auto& t : a.trigger_set) {
        if (!triggers.empty()) triggers += ", ";
        triggers += t;
        ev.triggers.push_back(t);
    }
    ev.fields["triggers"] = triggers;
    ev.fields["distinct_triggers"] = std::to_string(a.distinct_triggers);
    ev.fields["event_count"] = std::to_string(a.event_count);
    ev.fields["lineage"] = a.lineage;
    ev.fields["peak_score"] = std::format("{:.1f}", a.peak_score);
    ev.fields["learning"] = baseline_.learning ? "yes" : "no";

    // The most recent high-severity factor is the headline.
    std::string headline;
    for (auto it = a.factors.rbegin(); it != a.factors.rend(); ++it) {
        if (it->severity >= core::Severity::High) { headline = it->evidence; break; }
    }
    if (headline.empty() && !a.factors.empty()) headline = a.factors.back().evidence;

    ev.message = std::format("RISK {}/1000 pid {} ({}) [{}] -- {}", static_cast<int>(a.score), a.pid,
                             a.comm.empty() ? "?" : a.comm, triggers, headline);
    emit(std::move(ev));
}

void HeuristicSensor::maybe_escalate(ActorRisk& a) noexcept {
    if (baseline_.learning && cfg_.heuristic.suppress_actions_during_learning) {
        SINFO(name_, "pid {} reached risk {:.0f} during baseline learning: escalating observation only",
              a.pid, a.score);
        return;
    }

    const pid_t pid = a.pid;
    const double risk = a.score;
    const std::string reason = std::format("accumulated risk {:.0f}/1000 across {} distinct triggers",
                                           risk, a.distinct_triggers);

    a.inspected = true;  // claim it now so we escalate once, not per event

    if (!pool_.submit(
            [this, pid, reason] {
                auto report = escalate(pid, reason);
                if (report.reached == EscalationStep::None) return;

                core::TelemetryEvent ev;
                ev.sensor = core::SensorId::Heuristic;
                ev.kind = core::EventKind::ProcAnomaly;
                ev.actor.pid = pid;
                ev.actor.exe = report.exe;
                ev.severity = report.final_severity;
                ev.risk_score = static_cast<std::uint16_t>(std::min<double>(report.risk, 1000.0));
                ev.escalated = true;
                ev.message = std::format("ESCALATION for pid {} ({}) reached step '{}': {}", pid,
                                         report.exe, step_name(report.reached),
                                         report.findings.empty() ? "no additional evidence"
                                                                 : report.findings.back());
                for (const auto& f : report.findings) ev.triggers.push_back("escalation:" + f);
                for (const auto& m : report.memory_matches) ev.fields["mem_match:" + m] = "1";
                ev.fields["lineage"] = report.lineage;
                ev.fields["wx_regions"] = std::to_string(report.wx_regions);
                ev.fields["regions_scanned"] = std::to_string(report.regions_scanned);
                ev.fields["suspended"] = report.suspended ? "yes" : "no";
                emit(std::move(ev));
            },
            "escalate")) {
        note_error("pool saturated: escalation for pid " + std::to_string(pid) + " deferred");
        a.inspected = false;
    }
}

EscalationReport HeuristicSensor::escalate(pid_t pid, std::string_view reason) noexcept {
    EscalationReport rep;
    rep.pid = pid;
    rep.started = core::SysClock::now();
    rep.lineage = core::proc::lineage_string(pid, 8);

    const core::proc::ProcessInfo pi = core::proc::read(pid);
    if (!pi.exists) {
        rep.findings.emplace_back("process no longer exists (exited before escalation completed)");
        rep.finished = core::SysClock::now();
        return rep;
    }
    rep.exe = pi.exe;
    rep.start_time_ticks = pi.start_time_ticks;  // identity anchor for every later signal

    {
        std::shared_lock lk{mu_};
        auto it = actors_.find(pid);
        if (it != actors_.end()) {
            rep.risk = it->second.score;
            rep.factors = it->second.factors;
        }
    }

    SINFO(name_, "escalating pid {} ({}): {}", pid, pi.exe, reason);

    // ---- Step 1: freeze. -------------------------------------------------
    // Freezing first is deliberate: every later step reads /proc/<pid>, and a
    // live process can change under us. Freezing also stops the damage while we
    // decide, and unlike SIGKILL it preserves the memory image for forensics.
    if (backend_ && cfg_.heuristic.auto_respond) {
        if (backend_->suspend(pid, reason, pi.start_time_ticks)) {
            rep.suspended = true;
            rep.reached = EscalationStep::Freeze;
            rep.findings.emplace_back("step 1: process frozen with SIGSTOP, memory image preserved");
        } else {
            rep.findings.emplace_back("step 1: suspension declined (protected process, dry-run, or "
                                      "already gone) -- continuing with live inspection");
        }
    } else {
        rep.findings.emplace_back(cfg_.heuristic.auto_respond
                                      ? "step 1: skipped, no escalation backend wired"
                                      : "step 1: skipped, auto_respond is disabled (observation only)");
    }

    // ---- Step 2: memory inspection. --------------------------------------
    const auto regions = core::proc::maps(pid, 4096);
    rep.regions_scanned = regions.size();
    std::vector<std::string> all_strings;
    all_strings.reserve(4096);

    for (const auto& r : regions) {
        if (r.writable_and_executable) {
            ++rep.wx_regions;
            // A region that is both writable and executable violates W^X and is
            // where JIT-less shellcode lives. Worth reporting on its own.
            rep.findings.emplace_back(std::format("step 2: W^X VIOLATION -- region {:x}-{:x} is both "
                                                  "writable and executable ({})",
                                                  r.start, r.end, r.path.empty() ? "anonymous" : r.path));
        }
        // Anonymous executable regions are where injected shellcode lives; named
        // executable regions are normal file mappings and are cheap to skip.
        const bool interesting = r.executable && (r.anon || r.writable_and_executable);
        if (!interesting) continue;

        auto strs = core::proc::strings_from_region(pid, r, 6, 1 << 20);
        if (strs.size() + all_strings.size() > 200000) break;
        for (auto& s : strs) all_strings.push_back(std::move(s));
    }

    if (!all_strings.empty() && backend_) {
        rep.memory_matches = backend_->match_strings(all_strings, pi.exe.empty() ? "pid" : pi.exe);
        if (!rep.memory_matches.empty()) {
            std::string j;
            for (const auto& m : rep.memory_matches) { if (!j.empty()) j += ", "; j += m; }
            rep.findings.emplace_back("step 2: signature match against process memory: " + j);
            rep.risk = std::min(1000.0, rep.risk + 400.0);
        }
    }
    rep.reached = rep.regions_scanned > 0 ? EscalationStep::MemoryInspect : rep.reached;
    if (rep.wx_regions > 0) rep.risk = std::min(1000.0, rep.risk + 250.0);

    // ---- Step 3: batch scan the lineage's executables. --------------------
    std::vector<std::string> to_scan;
    to_scan.push_back(pi.exe);
    if (pi.ppid > 1) {
        const auto parent = core::proc::read(pi.ppid);
        if (!parent.exe.empty()) to_scan.push_back(parent.exe);
    }
    // Children too: the dropper is often the parent and the payload the child.
    for (const pid_t candidate : core::proc::list_pids(true)) {
        const auto cpi = core::proc::read(candidate);
        if (cpi.ppid == pid && !cpi.exe.empty()) to_scan.push_back(cpi.exe);
        if (to_scan.size() > 8) break;
    }
    to_scan.erase(std::remove_if(to_scan.begin(), to_scan.end(),
                                 [](const std::string& s) { return s.empty(); }),
                  to_scan.end());
    std::sort(to_scan.begin(), to_scan.end());
    to_scan.erase(std::unique(to_scan.begin(), to_scan.end()), to_scan.end());
    rep.scanned_paths = to_scan;

    if (backend_ && !to_scan.empty()) {
        const auto detections = backend_->batch_scan(to_scan);
        if (!detections.empty()) {
            std::string j;
            for (const auto& d : detections) { if (!j.empty()) j += "; "; j += d; }
            rep.findings.emplace_back("step 3: external scanner detections on lineage binaries: " + j);
            rep.risk = std::min(1000.0, rep.risk + 500.0);
        } else {
            rep.findings.emplace_back(std::format("step 3: {} lineage binaries scanned, no external "
                                                  "detections", to_scan.size()));
        }
        rep.reached = EscalationStep::BatchScan;
    }

    // ---- Step 4: prompt the operator. ------------------------------------
    rep.final_severity = rep.risk >= cfg_.heuristic.auto_respond_threshold ? core::Severity::Critical
                         : rep.risk >= cfg_.heuristic.critical_threshold   ? core::Severity::High
                         : rep.risk >= cfg_.heuristic.alert_threshold      ? core::Severity::Medium
                                                                          : core::Severity::Low;
    if (rep.wx_regions > 0 && rep.final_severity < core::Severity::High)
        rep.final_severity = core::Severity::High;
    if (!rep.memory_matches.empty() && rep.final_severity < core::Severity::Critical)
        rep.final_severity = core::Severity::Critical;

    if (backend_) {
        backend_->prompt_user(rep);
        rep.reached = EscalationStep::PromptUser;
    }

    // If the process was frozen and the evidence did not hold up, release it.
    // Leaving a suspended innocent process is worse than the false positive.
    if (rep.suspended && backend_ && rep.final_severity < core::Severity::High &&
        cfg_.heuristic.auto_respond) {
        if (backend_->resume(pid)) {
            rep.resumed = true;
            rep.findings.emplace_back("step 4: evidence below the High threshold -- process RESUMED "
                                      "(SIGCONT). It was frozen for " +
                                      std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                         core::SysClock::now() - rep.started)
                                                         .count()) +
                                      "ms");
        }
    }

    rep.finished = core::SysClock::now();
    escalations_.fetch_add(1, std::memory_order_relaxed);

    {
        std::unique_lock lk{mu_};
        auto it = actors_.find(pid);
        if (it != actors_.end()) {
            it->second.suspended = rep.suspended && !rep.resumed;
            it->second.inspected = true;
            it->second.scanned = !rep.scanned_paths.empty();
            it->second.prompted = backend_ != nullptr;
            it->second.score = std::max(it->second.score, rep.risk);
        }
    }
    return rep;
}

void HeuristicSensor::decay_tick() noexcept {
    std::unique_lock lk{mu_};
    const auto now = core::SteadyClock::now();
    for (auto& [pid, a] : actors_) {
        (void)pid;
        if (a.score <= 0.0) { a.last_decay = now; continue; }
        const double dt = std::chrono::duration<double>(now - a.last_decay).count();
        if (dt <= 0.0) continue;
        // Exponential-ish decay toward zero. A sustained attacker keeps topping
        // the score up; a one-off benign burst fades in about decay_window.
        const double factor = std::exp(-cfg_.heuristic.risk_decay_per_second * dt /
                                       std::max(1.0, static_cast<double>(cfg_.heuristic.decay_window.count()) /
                                                         60.0));
        a.score *= factor;
        if (a.score < 1.0) {
            a.score = 0.0;
            a.trigger_set.clear();
            a.factors.clear();
        }
        a.last_decay = now;
        a.severity = a.severity_for(a.score, cfg_.heuristic);
    }
}

void HeuristicSensor::prune() noexcept {
    std::unique_lock lk{mu_};
    const auto cutoff = core::SysClock::now() - cfg_.heuristic.decay_window * 4;
    for (auto it = actors_.begin(); it != actors_.end();) {
        const bool quiet = it->second.last_update < cutoff && it->second.score < 1.0;
        const bool gone = !core::ProcessHandle{it->first}.alive();
        // Never drop a suspended actor: the GUI must keep showing it until an
        // operator resumes or kills it, or the process becomes invisible.
        if ((quiet || gone) && !it->second.suspended) it = actors_.erase(it);
        else ++it;
    }
    if (actors_.size() > 8192) {
        // Hard bound: keep the highest-scoring actors.
        std::vector<pid_t> by_score;
        by_score.reserve(actors_.size());
        for (const auto& [pid, a] : actors_) by_score.push_back(pid);
        std::sort(by_score.begin(), by_score.end(), [&](pid_t x, pid_t y) {
            return actors_[x].score > actors_[y].score;
        });
        for (std::size_t i = 4096; i < by_score.size(); ++i) {
            auto it = actors_.find(by_score[i]);
            if (it != actors_.end() && !it->second.suspended) actors_.erase(it);
        }
    }
}

std::vector<ActorRisk> HeuristicSensor::top_actors(std::size_t n) const noexcept {
    std::vector<ActorRisk> out;
    {
        std::shared_lock lk{mu_};
        out.reserve(actors_.size());
        for (const auto& [pid, a] : actors_) {
            (void)pid;
            out.push_back(a);
        }
    }
    std::sort(out.begin(), out.end(),
              [](const ActorRisk& a, const ActorRisk& b) { return a.score > b.score; });
    if (out.size() > n) out.resize(n);
    return out;
}

std::optional<ActorRisk> HeuristicSensor::actor(pid_t pid) const noexcept {
    std::shared_lock lk{mu_};
    auto it = actors_.find(pid);
    if (it == actors_.end()) return std::nullopt;
    return it->second;
}

std::vector<HeuristicSensor::ServiceState> HeuristicSensor::services() const noexcept {
    std::lock_guard lk{svc_mu_};
    std::vector<ServiceState> out;
    out.reserve(services_.size());
    for (const auto& [k, v] : services_) {
        (void)k;
        out.push_back(v);
    }
    std::sort(out.begin(), out.end(), [](const ServiceState& a, const ServiceState& b) {
        return a.child_count > b.child_count;
    });
    return out;
}

bool HeuristicSensor::learning() const noexcept {
    std::shared_lock lk{mu_};
    return baseline_.learning;
}

double HeuristicSensor::learning_progress() const noexcept {
    std::shared_lock lk{mu_};
    if (!baseline_.learning) return 1.0;
    if (baseline_.learning_ends <= baseline_.learning_started) return 0.0;
    const double total = std::chrono::duration<double>(baseline_.learning_ends - baseline_.learning_started).count();
    const double elapsed = std::chrono::duration<double>(core::SysClock::now() - baseline_.learning_started).count();
    return std::clamp(elapsed / total, 0.0, 1.0);
}

std::uint64_t HeuristicSensor::observations() const noexcept {
    return observations_.load(std::memory_order_relaxed);
}

void HeuristicSensor::dismiss(pid_t pid, std::string_view analyst_note) noexcept {
    {
        std::unique_lock lk{mu_};
        auto it = actors_.find(pid);
        if (it != actors_.end()) {
            it->second.score = 0.0;
            it->second.trigger_set.clear();
            it->second.factors.clear();
            it->second.resolved = true;
            it->second.severity = core::Severity::Info;
        }
    }
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Gui;
    ev.kind = core::EventKind::UserAction;
    ev.severity = core::Severity::Info;
    ev.actor.pid = pid;
    ev.message = std::format("operator dismissed risk for pid {}: {}", pid, analyst_note);
    ev.fields["note"] = std::string(analyst_note);
    emit(std::move(ev));
    SINFO(name_, "operator dismissed pid {} ({})", pid, analyst_note);
}

bool HeuristicSensor::save_baseline() const noexcept {
    std::shared_lock lk{mu_};
    const std::string text = serialise_baseline(baseline_);
    if (!fsx::write_atomic(cfg_.heuristic.baseline_path,
                           {reinterpret_cast<const std::byte*>(text.data()), text.size()}, 0600)) {
        return false;
    }
    return true;
}

bool HeuristicSensor::load_baseline() noexcept {
    std::string text;
    if (fsx::read_file(cfg_.heuristic.baseline_path, text, 64 << 20) < 0) {
        std::unique_lock lk{mu_};
        baseline_ = Baseline{};
        // A learning window opens only when the operator asked for one. The
        // learning flag gates RESPONSE damping (suppress_actions_during_
        // learning), so an unwanted window would silently disable containment.
        if (cfg_.heuristic.learn_baseline) {
            baseline_.learning = true;
            baseline_.learning_started = core::SysClock::now();
            baseline_.learning_ends = baseline_.learning_started + cfg_.heuristic.baseline_learning_period;
        }
        return false;
    }
    Baseline b;
    if (!deserialise_baseline(text, b)) {
        note_error("baseline file is corrupt; starting a fresh learning window");
        b = Baseline{};
        if (cfg_.heuristic.learn_baseline) {
            b.learning = true;
            b.learning_started = core::SysClock::now();
            b.learning_ends = b.learning_started + cfg_.heuristic.baseline_learning_period;
        }
    }
    // A baseline saved during a learning window must not reopen that window
    // after the operator turned learning off: the toggle is the current intent,
    // the file is history.
    if (!cfg_.heuristic.learn_baseline) b.learning = false;
    std::unique_lock lk{mu_};
    baseline_ = std::move(b);
    observations_.store(baseline_.observations, std::memory_order_relaxed);
    return true;
}

}  // namespace hyprnova::heuristics
