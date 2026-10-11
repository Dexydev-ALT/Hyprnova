// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4a implementation

#include "behavioral/falco_sensor.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <format>
#include <numeric>
#include <thread>
#include <unordered_map>
#include <unistd.h>

#include "core/proc.hpp"

namespace hyprnova::behavioral {

using namespace std::chrono_literals;

// ===========================================================================
// Falco
// ===========================================================================

namespace {

std::vector<std::string> split_ancestry(std::string_view s) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (pos < s.size()) {
        const std::size_t sep = s.find('>', pos);
        std::string_view tok = sep == std::string_view::npos ? s.substr(pos) : s.substr(pos, sep - pos);
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '-')) tok.remove_prefix(1);
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '-')) tok.remove_suffix(1);
        if (!tok.empty()) out.emplace_back(tok);
        if (sep == std::string_view::npos) break;
        pos = sep + 1;
    }
    return out;
}

pid_t parse_pid(std::string_view s) noexcept {
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p == s.data()) return 0;
    return static_cast<pid_t>(v);
}

/// Falco's `output` field is "human text (k=v k2=v2 ...)". The k=v tail is where
/// the machine-readable data lives, and it is present even when the rule text
/// changes -- so parse the tail rather than depending on the prose.
std::unordered_map<std::string, std::string> parse_output_fields(std::string_view output) {
    std::unordered_map<std::string, std::string> out;
    const std::size_t open = output.find('(');
    if (open == std::string_view::npos) return out;
    const std::size_t close = output.rfind(')');
    if (close == std::string_view::npos || close <= open) return out;

    const std::string_view body = output.substr(open + 1, close - open - 1);
    std::size_t pos = 0;
    while (pos < body.size()) {
        while (pos < body.size() && body[pos] == ' ') ++pos;
        const std::size_t eq = body.find('=', pos);
        if (eq == std::string_view::npos) break;
        std::string_view key = body.substr(pos, eq - pos);

        std::size_t vstart = eq + 1;
        std::size_t vend = vstart;
        if (vstart < body.size() && body[vstart] == '<') {
            // <...> delimited value (used when the value contains spaces)
            const std::size_t gt = body.find('>', vstart);
            if (gt == std::string_view::npos) break;
            vstart += 1;
            vend = gt;
            pos = gt + 1;
        } else {
            vend = body.find(' ', vstart);
            if (vend == std::string_view::npos) vend = body.size();
            pos = vend;
        }
        out.emplace(std::string(key), std::string(body.substr(vstart, vend - vstart)));
    }
    return out;
}

}  // namespace

FalcoAlert parse_falco_json(const core::json::Value& v) noexcept {
    FalcoAlert a;

    // Falco emits {"output": "...", "priority": "...", "rule": "...",
    //              "time": <ns or ISO>, "output_fields": {...}, "source": "..."}
    a.rule = v.str("rule");
    a.priority = v.str("priority");
    a.output = v.str("output");
    a.source = v.str("source", "syscall");

    if (const core::json::Value* t = v.at("time")) {
        if (t->is_int()) {
            const auto ns = t->as_int();
            a.ts = core::SysClock::time_point{std::chrono::nanoseconds(ns)};
        } else if (t->is_string()) {
            // ISO-8601 with nanoseconds; timegm on the leading 19 chars is
            // adequate for correlation to the second.
            const std::string s{t->as_string()};
            std::tm tm{};
            if (s.size() >= 19 &&
                std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                            &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
                tm.tm_year -= 1900;
                tm.tm_mon -= 1;
                const std::time_t epoch = ::timegm(&tm);
                a.ts = core::SysClock::from_time_t(epoch);
            }
        }
    }
    if (a.ts == core::SysClock::time_point{}) a.ts = core::SysClock::now();

    if (const core::json::Value* tags = v.at("tags")) {
        if (const core::json::Array* arr = tags->as_array()) {
            for (const auto& t : *arr) {
                if (t.is_string()) a.tags.emplace_back(t.as_string());
            }
        }
    }

    // output_fields is the authoritative machine-readable source.
    auto fields = parse_output_fields(a.output);
    if (const core::json::Value* of = v.at("output_fields")) {
        if (const core::json::Object* obj = of->as_object()) {
            for (const auto& [k, val] : *obj) {
                fields[k] = val.as_string_copy().empty() && val.is_int()
                                ? std::to_string(val.as_int())
                                : val.as_string_copy();
            }
        }
    }

    auto get = [&](std::initializer_list<const char*> keys) -> std::string {
        for (const char* k : keys) {
            auto it = fields.find(k);
            if (it != fields.end() && !it->second.empty()) return it->second;
        }
        return {};
    };

    a.proc_name = get({"proc.name", "proc.exename"});
    a.proc_exe = get({"proc.exepath", "proc.exe"});
    a.proc_cmdline = get({"proc.cmdline", "proc.args"});
    a.proc_pname = get({"proc.pname"});
    a.tid = parse_pid(get({"proc.tid", "proc.pid"}));
    a.pid = parse_pid(get({"proc.pid"}));
    if (a.pid == 0) a.pid = a.tid;
    a.ppid = parse_pid(get({"proc.ppid"}));
    a.uid = [&] {
        const std::string u = get({"user.uid", "proc.uid"});
        if (u.empty()) return static_cast<uid_t>(0xFFFFFFFF);
        return static_cast<uid_t>(parse_pid(u));
    }();
    a.user = get({"user.name", "user.uid"});
    a.container_id = get({"container.id", "k8s.pod.id"});
    a.container_name = get({"container.name", "k8s.pod.name"});
    a.container_image = get({"container.image", "k8s.pod.image"});
    a.in_container = !a.container_id.empty() && a.container_id != "host";
    a.fd_name = get({"fd.name", "fd.nameraw", "file.path"});
    a.k8s_namespace = get({"k8s.ns.name"});
    a.k8s_pod = get({"k8s.pod.name"});
    a.tty = get({"proc.tty"});
    a.cwd = get({"proc.cwd"});
    if (const std::string an = get({"proc.aname"}); !an.empty()) a.ancestry = split_ancestry(an);

    return a;
}

core::EventKind map_rule_to_kind(std::string_view rule, std::string_view output,
                                 const core::FalcoConfig& cfg) noexcept {
    // Explicit mapping first: an operator who knows their environment beats any
    // keyword heuristic.
    for (const auto& [r, k] : cfg.rule_map) {
        if (r == rule) return k;
    }

    // Case-insensitive substring fallback.
    std::string lower_rule{rule};
    std::transform(lower_rule.begin(), lower_rule.end(), lower_rule.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string lower_out{output};
    std::transform(lower_out.begin(), lower_out.end(), lower_out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    struct Kw { std::string_view needle; core::EventKind kind; };
    static constexpr Kw kKeywords[] = {
        {"shell", core::EventKind::TtyFromDaemon},
        {"tty", core::EventKind::TtyFromDaemon},
        {"terminal", core::EventKind::TtyFromDaemon},
        {"kernel module", core::EventKind::KernelModuleLoad},
        {"insmod", core::EventKind::KernelModuleLoad},
        {"modprobe", core::EventKind::KernelModuleLoad},
        {"privileged", core::EventKind::PrivEscalation},
        {"setuid", core::EventKind::PrivEscalation},
        {"sudo", core::EventKind::SudoAbuse},
        {"shadow", core::EventKind::ShadowAccess},
        {"credential", core::EventKind::ShadowAccess},
        {"sensitive file", core::EventKind::ShadowAccess},
        {"write below etc", core::EventKind::FileWrite},
        {"write below root", core::EventKind::FileWrite},
        {"delete", core::EventKind::FileDelete},
        {"rename", core::EventKind::FileRename},
        {"udp", core::EventKind::NetC2Suspect},
        {"network", core::EventKind::NetConnect},
        {"connection", core::EventKind::NetConnect},
        {"api server", core::EventKind::NetConnect},
        {"cron", core::EventKind::ProcAnomaly},
        {"drift", core::EventKind::ProcAnomaly},
        {"spawn", core::EventKind::ProcFork},
        {"exec", core::EventKind::ProcExec},
    };
    for (const auto& kw : kKeywords) {
        if (lower_rule.find(kw.needle) != std::string::npos) return kw.kind;
    }
    for (const auto& kw : kKeywords) {
        if (lower_out.find(kw.needle) != std::string::npos) return kw.kind;
    }
    return core::EventKind::ProcAnomaly;
}

FalcoSensor::FalcoSensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool)
    : core::ISensor("falco", core::SensorId::Falco, bus, cfg, pool) {}

bool FalcoSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.falco.enabled;
}

bool FalcoSensor::on_start() {
    UnixSocketSource::Options o;
    o.path = cfg_.falco.socket_path;
    if (!core::fsx::exists(o.path)) o.path = cfg_.falco.grpc_socket;
    o.reconnect_max = cfg_.falco.reconnect_backoff_max;
    o.max_line_bytes = cfg_.falco.max_line_bytes;

    src_ = std::make_unique<UnixSocketSource>(std::move(o));
    if (!core::fsx::exists(src_->path())) {
        mark_degraded("Falco socket not present at " + cfg_.falco.socket_path + " or " +
                      cfg_.falco.grpc_socket + "; the eBPF behavioural sensor is inactive. Install "
                      "falco and enable its gRPC/unix output to activate Module 4a.");
        // Not a failure: the agent must run without Falco, degraded but alive.
        return true;
    }
    if (!src_->connect_now()) {
        mark_degraded("Falco socket present but not connectable: " + src_->last_error());
        return true;
    }
    mark_running("connected to " + src_->path());
    return true;
}

void FalcoSensor::on_stop() {
    if (src_) src_->close();
}

void FalcoSensor::loop(std::stop_token st) {
    while (!st.stop_requested()) {
        if (src_) {
            src_->tick();
            if (src_->state() == UnixSocketSource::State::Connected) {
                src_->pump();
                while (auto v = src_->next()) ingest_value(*v);
            } else if (src_->state() == UnixSocketSource::State::Disconnected &&
                       state() == core::SensorState::Running) {
                mark_degraded("Falco socket lost: " + src_->last_error());
            }
        }
        std::this_thread::sleep_for(cfg_.falco.poll_timeout);
    }
}

void FalcoSensor::ingest(std::string_view line) noexcept {
    core::json::ParseError perr{};
    auto v = core::json::parse(line, {}, &perr);
    if (!v) {
        if (parse_errors_.fetch_add(1) == 0) {
            SWARN(name_, "first malformed Falco frame at offset {}: {}", perr.offset, perr.message);
        }
        return;
    }
    ingest_value(*v);
}

void FalcoSensor::ingest_value(const core::json::Value& v) noexcept {
    FalcoAlert a = parse_falco_json(v);
    alerts_.fetch_add(1, std::memory_order_relaxed);

    a.severity = severity_from_priority(a.priority);
    a.kind = map_rule_to_kind(a.rule, a.output, cfg_.falco);

    const bool interesting =
        std::find(cfg_.falco.interesting_priorities.begin(), cfg_.falco.interesting_priorities.end(),
                  a.priority) != cfg_.falco.interesting_priorities.end();
    if (!interesting) {
        filtered_.fetch_add(1, std::memory_order_relaxed);
        a.filtered = true;
    }

    // Always count per-rule frequency: the GUI's top-rules panel is more useful
    // when it reflects reality rather than only the filtered subset.
    {
        std::lock_guard lk{rule_mu_};
        RuleCount& rc = rules_[a.rule];
        rc.rule = a.rule;
        ++rc.count;
        rc.severity = std::max(rc.severity, a.severity);
        rc.last_output = a.output.substr(0, 512);
        rc.last_seen = a.ts;
        if (rules_.size() > 512) {
            // Bound the map: evict the least-recently-seen rule.
            auto oldest = std::min_element(rules_.begin(), rules_.end(),
                                           [](const auto& x, const auto& y) {
                                               return x.second.last_seen < y.second.last_seen;
                                           });
            if (oldest != rules_.end()) rules_.erase(oldest);
        }
    }

    if (!a.filtered) publish(a);
}

void FalcoSensor::publish(const FalcoAlert& a) noexcept {
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Falco;
    ev.kind = a.kind;
    ev.severity = a.severity;
    ev.ts = a.ts;
    ev.actor.pid = a.pid;
    ev.actor.ppid = a.ppid;
    ev.actor.uid = a.uid;
    ev.actor.comm = a.proc_name;
    ev.actor.exe = a.proc_exe;
    ev.actor.cmdline = a.proc_cmdline;
    ev.actor.cwd = a.cwd;
    ev.actor.container_id = a.container_id;
    ev.actor.in_container = a.in_container;
    ev.actor.ancestry = std::vector<pid_t>{};
    ev.target.path = a.fd_name;
    ev.target.rule_id = a.rule;
    ev.message = a.output;
    ev.risk_score = static_cast<std::uint16_t>(a.severity == core::Severity::Critical   ? 520
                                               : a.severity == core::Severity::High     ? 380
                                               : a.severity == core::Severity::Medium   ? 220 : 80);
    ev.fields["priority"] = a.priority;
    ev.fields["source"] = a.source;
    if (!a.container_name.empty()) ev.fields["container"] = a.container_name;
    if (!a.container_image.empty()) ev.fields["image"] = a.container_image;
    if (!a.k8s_namespace.empty()) ev.fields["k8s_ns"] = a.k8s_namespace;
    if (!a.k8s_pod.empty()) ev.fields["k8s_pod"] = a.k8s_pod;
    if (!a.user.empty()) ev.fields["user"] = a.user;
    if (!a.proc_pname.empty()) ev.fields["parent"] = a.proc_pname;
    if (!a.tty.empty()) ev.fields["tty"] = a.tty;
    for (const auto& t : a.tags) ev.triggers.push_back("falco:" + t);
    ev.triggers.push_back("falco:" + a.rule);

    // A shell spawned by a network-facing daemon is the single highest-value
    // Falco finding; raise it above its nominal priority.
    if ((a.rule.find("shell") != std::string::npos || a.rule.find("Terminal") != std::string::npos) &&
        !a.proc_pname.empty()) {
        for (const auto& d : cfg_.heuristic.web_daemons) {
            if (a.proc_pname.find(d) != std::string::npos) {
                ev.severity = core::Severity::Critical;
                ev.risk_score = 860;
                ev.triggers.push_back("shell_under_web_daemon");
                ev.message += " [interactive shell spawned by network daemon " + a.proc_pname + "]";
                break;
            }
        }
    }
    emit(std::move(ev));
}

std::vector<FalcoSensor::RuleCount> FalcoSensor::top_rules(std::size_t n) const noexcept {
    std::vector<RuleCount> out;
    {
        std::lock_guard lk{rule_mu_};
        out.reserve(rules_.size());
        for (const auto& [k, v] : rules_) out.push_back(v);
    }
    std::sort(out.begin(), out.end(),
              [](const RuleCount& a, const RuleCount& b) { return a.count > b.count; });
    if (out.size() > n) out.resize(n);
    return out;
}

// ===========================================================================
// Suricata EVE + beacon detection
// ===========================================================================

SuricataSensor::SuricataSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                               core::ThreadPool& pool)
    : core::ISensor("suricata", core::SensorId::Suricata, bus, cfg, pool) {}

bool SuricataSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.suricata.enabled;
}

bool SuricataSensor::on_start() {
    if (!cfg_.suricata.eve_socket.empty()) {
        UnixSocketSource::Options o;
        o.path = cfg_.suricata.eve_socket;
        // Suricata's unix socket protocol expects a JSON command frame; asking
        // for live alerts is what makes it emit anything at all.
        o.handshake = R"({"command":"pcap-file-number"},{"command":"alert-file"})";
        src_ = std::make_unique<UnixSocketSource>(std::move(o));
        if (!src_->connect_now()) {
            mark_degraded("Suricata unix socket not connectable: " + src_->last_error());
            src_.reset();
        }
    }

    if (!src_) {
        const int fd = ::open(cfg_.suricata.eve_path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            mark_degraded("Suricata EVE not available at " + cfg_.suricata.eve_path +
                          " and no eve_socket configured; network beacon detection is inactive");
            return true;  // degraded, not failed
        }
        eve_file_ = core::UniqueFd{fd};
        // Start at EOF: replaying an entire historical eve.json on startup would
        // produce a flood of stale alerts and mis-attribute them to now.
        const off_t end = ::lseek(fd, 0, SEEK_END);
        eve_offset_ = end > 0 ? static_cast<std::size_t>(end) : 0;
    }
    mark_running(src_ ? "unix socket" : "tailing " + cfg_.suricata.eve_path);
    return true;
}

void SuricataSensor::on_stop() {
    if (src_) src_->close();
}

void SuricataSensor::loop(std::stop_token st) {
    std::string buf;
    buf.resize(64 * 1024);

    while (!st.stop_requested()) {
        if (src_) {
            src_->tick();
            src_->pump();
            while (auto v = src_->next()) ingest_value(*v);
        } else if (eve_file_) {
            for (;;) {
                const ssize_t n = ::pread(eve_file_.get(), buf.data(), buf.size(),
                                          static_cast<off_t>(eve_offset_));
                if (n <= 0) break;
                eve_offset_ += static_cast<std::size_t>(n);
                nd_.feed(std::string_view{buf.data(), static_cast<std::size_t>(n)});
                while (auto v = nd_.next()) ingest_value(*v);
                if (static_cast<std::size_t>(n) < buf.size()) break;
            }
        }

        if (core::SteadyClock::now() - last_eval_ >= cfg_.suricata.beacon_window / 6) {
            evaluate_beacons();
            last_eval_ = core::SteadyClock::now();
        }
        std::this_thread::sleep_for(cfg_.suricata.poll_interval);
    }
}

void SuricataSensor::ingest_value(const core::json::Value& v) noexcept {
    const std::string type = v.str("event_type");
    if (type.empty()) return;

    if (type == "alert") {
        alerts_.fetch_add(1, std::memory_order_relaxed);
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::Suricata;
        ev.kind = core::EventKind::NetC2Suspect;
        const auto sev = v.integer("alert.severity", 3);
        ev.severity = severity_from_eve("alert", sev);
        ev.target.peer_ip = v.str("dest_ip");
        ev.target.peer_port = static_cast<std::uint16_t>(v.integer("dest_port"));
        ev.target.rule_id = std::to_string(v.integer("alert.signature_id"));
        ev.target.family = v.str("alert.category");
        ev.message = std::format("suricata: {} (sid {}, severity {}) {}:{} -> {}:{}",
                                 v.str("alert.signature"), v.integer("alert.signature_id"), sev,
                                 v.str("src_ip"), v.integer("src_port"), v.str("dest_ip"),
                                 v.integer("dest_port"));
        ev.risk_score = static_cast<std::uint16_t>(sev <= 1 ? 700 : sev == 2 ? 480 : 200);
        ev.fields["proto"] = v.str("proto");
        if (!v.str("app_proto").empty()) ev.fields["app_proto"] = v.str("app_proto");
        emit(std::move(ev));
        return;
    }

    if (type == "flow" || type == "http" || type == "dns" || type == "tls") {
        flows_.fetch_add(1, std::memory_order_relaxed);
        const std::string dest = v.str("dest_ip");
        if (dest.empty()) return;
        const std::string key = dest + ":" + std::to_string(v.integer("dest_port"));

        std::lock_guard lk{beacon_mu_};
        BeaconProfile& b = beacons_[key];
        if (b.peer.empty()) {
            b.peer = key;
            b.process = v.str("app_proto");
        }
        ++b.hits;
        b.bytes_out += static_cast<std::uint64_t>(v.integer("flow.toclient", 0) +
                                                  v.integer("http.length", 0));
        b.bytes_in += static_cast<std::uint64_t>(v.integer("flow.toserver", 0));

        // Timestamp -> interval series. EVE gives ISO-8601; second resolution is
        // plenty for beacon periodicity, which is usually tens of seconds.
        const std::string ts = v.str("timestamp");
        if (!ts.empty()) {
            std::tm tm{};
            if (ts.size() >= 19 &&
                std::sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                            &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
                tm.tm_year -= 1900;
                tm.tm_mon -= 1;
                const std::time_t epoch = ::timegm(&tm);
                static thread_local std::unordered_map<std::string, std::time_t> last_seen;
                auto it = last_seen.find(key);
                if (it != last_seen.end()) {
                    const double dt = std::difftime(epoch, it->second);
                    if (dt > 0.5 && dt < 86400.0) {
                        b.intervals_seconds.push_back(dt);
                        if (b.intervals_seconds.size() > 512)
                            b.intervals_seconds.erase(b.intervals_seconds.begin());
                    }
                }
                last_seen[key] = epoch;
                if (last_seen.size() > 4096) last_seen.clear();
            }
        }
        if (beacons_.size() > 8192) {
            // Bound memory: drop the profiles with the fewest hits.
            for (auto it = beacons_.begin(); it != beacons_.end();) {
                if (it->second.hits < 2) it = beacons_.erase(it);
                else ++it;
            }
        }
    }
}

void SuricataSensor::evaluate_beacons() noexcept {
    std::vector<BeaconProfile> snapshots;
    {
        std::lock_guard lk{beacon_mu_};
        snapshots.reserve(beacons_.size());
        for (auto& [k, b] : beacons_) {
            if (b.intervals_seconds.size() < cfg_.suricata.beacon_min_hits) continue;

            const auto& iv = b.intervals_seconds;
            const double mean = std::accumulate(iv.begin(), iv.end(), 0.0) / static_cast<double>(iv.size());
            double var = 0.0;
            for (const double x : iv) var += (x - mean) * (x - mean);
            var /= static_cast<double>(iv.size());
            const double stdev = std::sqrt(var);
            b.mean_interval = mean;
            b.jitter = mean > 0.0 ? stdev / mean : 1.0;

            // Score: low jitter is the signal. A human browsing produces jitter
            // near 1.0; a timer-driven implant produces jitter below 0.1.
            double score = 0.0;
            score += std::max(0.0, 1.0 - b.jitter / 0.35) * 0.65;
            if (iv.size() >= 12) score += 0.20;
            else if (iv.size() >= 6) score += 0.10;
            if (b.bytes_out < 4096 * iv.size()) score += 0.15;  // small, regular payloads
            b.score = std::clamp(score, 0.0, 1.0);
            b.beacon_like = b.score >= cfg_.suricata.c2_beacon_score_threshold;
            if (b.beacon_like) snapshots.push_back(b);
        }
    }

    for (const auto& b : snapshots) {
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::Suricata;
        ev.kind = core::EventKind::NetC2Suspect;
        ev.severity = b.score >= 0.85 ? core::Severity::Critical : core::Severity::High;
        ev.target.peer_ip = b.peer;
        ev.target.rule_id = "beacon-detection";
        ev.metric = b.score;
        ev.count = b.hits;
        ev.risk_score = static_cast<std::uint16_t>(b.score * 800.0);
        ev.message = std::format("possible C2 beaconing to {} : {} contacts, mean interval {:.1f}s, "
                                 "jitter {:.3f}, score {:.2f}",
                                 b.peer, b.hits, b.mean_interval, b.jitter, b.score);
        ev.triggers.push_back("network_beacon");
        ev.fields["mean_interval_s"] = std::format("{:.2f}", b.mean_interval);
        ev.fields["jitter"] = std::format("{:.4f}", b.jitter);
        ev.fields["bytes_out"] = std::to_string(b.bytes_out);
        ev.fields["bytes_in"] = std::to_string(b.bytes_in);
        emit(std::move(ev));
    }
}

std::vector<BeaconProfile> SuricataSensor::beacons(std::size_t n) const noexcept {
    std::vector<BeaconProfile> out;
    {
        std::lock_guard lk{beacon_mu_};
        out.reserve(beacons_.size());
        for (const auto& [k, b] : beacons_) {
            (void)k;
            out.push_back(b);
        }
    }
    std::sort(out.begin(), out.end(),
              [](const BeaconProfile& a, const BeaconProfile& b) { return a.score > b.score; });
    if (out.size() > n) out.resize(n);
    return out;
}

}  // namespace hyprnova::behavioral
