// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 4c implementation

#include "behavioral/osquery_sensor.hpp"

#include <algorithm>
#include <charconv>
#include <format>
#include <thread>

#include "core/exec.hpp"
#include "core/proc.hpp"

namespace hyprnova::behavioral {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Row classification
// ---------------------------------------------------------------------------

RowFinding classify_row(std::string_view query_name, const core::json::Value& row) noexcept {
    RowFinding f;
    const std::string path = row.str("path");
    const std::string name = row.str("name");
    const std::int64_t pid = row.integer("pid");

    if (query_name == "procs_in_tmp") {
        // A process whose executable lives in /tmp, /dev/shm or /var/tmp is the
        // single highest-precision cheap indicator available on Linux. Legitimate
        // reasons exist (some installers) but they are rare and enumerable.
        const bool suspicious = path.find("/tmp/") == 0 || path.find("/dev/shm/") == 0 ||
                                path.find("/var/tmp/") == 0 || path.find("/home/") == 0;
        f.report = suspicious;
        f.kind = core::EventKind::ProcAnomaly;
        f.severity = (path.find("/dev/shm/") == 0) ? core::Severity::Critical : core::Severity::High;
        f.risk = (path.find("/dev/shm/") == 0) ? 820 : 560;
        f.pid = static_cast<pid_t>(pid);
        f.path = path;
        f.message = std::format("process '{}' (pid {}) is executing from {}: uid={}",
                                name.empty() ? "?" : name, pid, path, row.integer("uid", -1));
        f.triggers = {"exec_from_writable_path"};
        if (path.find("/dev/shm/") == 0) f.triggers.push_back("exec_from_memory_filesystem");
        return f;
    }

    if (query_name == "listening_ports") {
        // Anything listening on 0.0.0.0 that is not an expected service is worth
        // surfacing; the GUI shows the full table, only high ports on all
        // interfaces get an event.
        const std::int64_t port = row.integer("port");
        const std::string addr = row.str("address");
        const bool all_interfaces = addr == "0.0.0.0" || addr == "::" || addr.empty();
        f.report = all_interfaces && port > 1024 && port != 0;
        f.kind = core::EventKind::NetListen;
        f.severity = core::Severity::Medium;
        f.risk = 260;
        f.pid = static_cast<pid_t>(pid);
        f.path = name;
        f.message = std::format("pid {} ({}) is listening on {}:{} (all interfaces, non-privileged port)",
                                pid, name.empty() ? "?" : name, addr.empty() ? "0.0.0.0" : addr, port);
        f.triggers = {"unexpected_listener"};
        return f;
    }

    if (query_name == "socket_to_process") {
        const std::string remote = row.str("remote_address");
        const std::int64_t rport = row.integer("remote_port");
        // Established outbound from a database or web daemon process is anomalous:
        // those should be listening, not dialling out.
        const bool db_or_web = name.find("mysql") == 0 || name.find("postgres") == 0 ||
                               name.find("redis") == 0 || name.find("mongo") == 0 ||
                               name == "nginx" || name == "apache2" || name == "httpd";
        f.report = !remote.empty() && db_or_web;
        f.kind = core::EventKind::NetC2Suspect;
        f.severity = core::Severity::High;
        f.risk = 540;
        f.pid = static_cast<pid_t>(pid);
        f.path = row.str("path");
        f.message = std::format("server daemon '{}' (pid {}) has an ESTABLISHED outbound connection to "
                                "{}:{}",
                                name, pid, remote, rport);
        f.triggers = {"outbound_from_server_daemon", "possible_c2"};
        return f;
    }

    if (query_name == "suid_binaries") {
        // SUID binaries outside the distro's expected set are how a local
        // privilege escalation survives reboots.
        const bool expected = path.find("/usr/bin/") == 0 || path.find("/bin/") == 0 ||
                              path.find("/usr/sbin/") == 0 || path.find("/sbin/") == 0 ||
                              path.find("/usr/lib/") == 0;
        f.report = !expected && !path.empty();
        f.kind = core::EventKind::ProcAnomaly;
        f.severity = core::Severity::High;
        f.risk = 580;
        f.path = path;
        f.message = std::format("SUID binary outside the standard system paths: {}", path);
        f.triggers = {"unexpected_suid_binary"};
        return f;
    }

    if (query_name == "kern_modules_unsigned") {
        const std::string status = row.str("status");
        f.report = status == "Live" || status == "live";
        f.kind = core::EventKind::KernelModuleLoad;
        f.severity = core::Severity::Info;  // informational inventory; drift is the signal
        f.risk = 40;
        f.path = name;
        f.message = std::format("kernel module '{}' live, size {} bytes", name, row.integer("size"));
        return f;
    }

    if (query_name == "crontab_entries") {
        const std::string command = row.str("command");
        // A cron entry that fetches and executes is persistence with a delivery
        // mechanism attached.
        const bool fetches = command.find("curl") != std::string::npos ||
                             command.find("wget") != std::string::npos ||
                             command.find("/tmp/") != std::string::npos ||
                             command.find("/dev/shm") != std::string::npos ||
                             command.find("base64") != std::string::npos ||
                             command.find("nc ") != std::string::npos;
        f.report = fetches;
        f.kind = core::EventKind::ProcAnomaly;
        f.severity = core::Severity::High;
        f.risk = 620;
        f.path = row.str("path");
        f.message = std::format("cron entry downloads or executes from a writable location: {}", command);
        f.triggers = {"cron_persistence", "download_and_execute"};
        return f;
    }

    if (query_name == "shell_history_grep") {
        f.report = true;
        f.kind = core::EventKind::ProcAnomaly;
        f.severity = core::Severity::Medium;
        f.risk = 300;
        f.path = row.str("history_file");
        f.message = std::format("suspicious command in {}'s shell history: {}",
                                row.str("username"), row.str("command"));
        f.triggers = {"suspicious_shell_history"};
        return f;
    }

    if (query_name == "startup_items") {
        const std::string sp = row.str("path");
        const bool writable = sp.find("/tmp") == 0 || sp.find("/home/") == 0 || sp.find("/dev/shm") == 0;
        f.report = writable;
        f.kind = core::EventKind::ProcAnomaly;
        f.severity = core::Severity::High;
        f.risk = 600;
        f.path = sp;
        f.message = std::format("startup item '{}' points into a user-writable path: {}",
                                row.str("name"), sp);
        f.triggers = {"startup_persistence_writable_path"};
        return f;
    }

    // Unknown query name: report nothing. Adding a query without a classifier is
    // a config-only change that produces data for the GUI but no alerts, which
    // is the safe default.
    f.report = false;
    return f;
}

// ---------------------------------------------------------------------------
// Sensor
// ---------------------------------------------------------------------------

OsquerySensor::OsquerySensor(core::EventBus& bus, const core::AgentConfig& cfg, core::ThreadPool& pool)
    : core::ISensor("osquery", core::SensorId::Osquery, bus, cfg, pool) {}

bool OsquerySensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.osquery.enabled;
}

bool OsquerySensor::on_start() {
    if (!cfg_.osquery.enabled) {
        mark_degraded("osquery sensor disabled by configuration");
        return true;
    }
    binary_ = core::exec::resolve(cfg_.osquery.osqueryi_path, false);
    if (binary_.empty()) binary_ = core::exec::find_in_system_path("osqueryi");
    if (binary_.empty()) {
        available_ = false;
        mark_degraded("osqueryi not found: state-based queries (processes in /tmp, socket ownership, "
                      "SUID inventory) are unavailable. Install osquery to activate Module 4c.");
        return true;  // degraded, not failed
    }
    available_ = true;

    // Probe once at startup so a broken osquery install is reported immediately
    // rather than after the first interval.
    const auto probe = run_query("self_check", "select 1 as ok;");
    if (!probe.ok) {
        mark_degraded("osqueryi present at " + binary_ + " but a probe query failed: " + probe.error);
        return true;
    }
    mark_running(binary_ + " (" + std::to_string(cfg_.osquery.queries.size()) + " queries)");
    run_all();
    return true;
}

QueryResult OsquerySensor::run_query(std::string_view name, std::string_view sql) noexcept {
    QueryResult r;
    r.name = std::string(name);
    r.sql = std::string(sql);
    r.ran_at = core::SysClock::now();

    if (!available_) {
        r.error = "osqueryi unavailable";
        return r;
    }

    core::exec::Options o;
    o.timeout = std::chrono::duration_cast<std::chrono::milliseconds>(cfg_.osquery.query_timeout);
    o.max_output_bytes = 16 << 20;
    // --json gives a stable, parseable shape; --header=false removes the column
    // banner. Running read-only queries as a separate process also means a
    // crashing osquery cannot take the agent with it.
    const auto res = core::exec::run(binary_, {"--json", "--header=false", std::string(sql)}, o);
    r.elapsed = res.elapsed;
    run_count_.fetch_add(1, std::memory_order_relaxed);

    if (!res.spawned) {
        r.error = res.error.empty() ? "failed to spawn osqueryi" : res.error;
        return r;
    }
    if (res.timed_out) {
        r.error = "query timed out after " + std::to_string(o.timeout.count()) + "ms";
        return r;
    }
    if (res.exit_code != 0) {
        r.error = "osqueryi exit " + std::to_string(res.exit_code) + ": " +
                  res.err.substr(0, std::min<std::size_t>(res.err.size(), 512));
        return r;
    }

    core::json::ParseError perr{};
    auto doc = core::json::parse(res.out, {}, &perr);
    if (!doc) {
        r.error = "osqueryi returned unparseable JSON at offset " + std::to_string(perr.offset) + ": " +
                  perr.message;
        return r;
    }
    if (const core::json::Array* arr = doc->as_array()) {
        for (const auto& row : *arr) r.rows.push_back(row);
    } else if (doc->is_object()) {
        r.rows.push_back(*doc);
    }
    rows_.fetch_add(r.rows.size(), std::memory_order_relaxed);
    r.ok = true;
    return r;
}

void OsquerySensor::run_all() noexcept {
    // Every query is dispatched to the pool so a slow osquery table (process_open_
    // sockets is notoriously expensive) cannot delay the next one, and so the
    // sensor thread stays responsive to shutdown.
    for (const auto& [name, sql] : cfg_.osquery.queries) {
        if (!pool_.submit(
                [this, name, sql] {
                    QueryResult r = run_query(name, sql);
                    if (!r.ok) {
                        SWARN(this->name_, "osquery query '{}' failed: {}", name, r.error);
                        return;
                    }
                    for (const auto& row : r.rows) {
                        const RowFinding f = classify_row(name, row);
                        if (!f.report) continue;

                        core::TelemetryEvent ev;
                        ev.sensor = core::SensorId::Osquery;
                        ev.kind = f.kind;
                        ev.severity = f.severity;
                        ev.risk_score = f.risk;
                        ev.actor.pid = f.pid;
                        ev.target.path = f.path;
                        ev.target.rule_id = "osquery:" + name;
                        ev.message = f.message;
                        ev.triggers = f.triggers;
                        ev.fields["query"] = name;
                        // Attach the whole row so the GUI can show the evidence
                        // rather than just our interpretation of it.
                        ev.fields["row"] = row.dump();
                        emit(std::move(ev));

                        Anomaly a;
                        a.query = name;
                        a.message = f.message;
                        a.severity = f.severity;
                        a.risk = f.risk;
                        a.when = core::SysClock::now();
                        std::lock_guard lk{mu_};
                        anomalies_.push_front(a);
                        while (anomalies_.size() > kMaxAnomalies) anomalies_.pop_back();
                    }

                    std::lock_guard lk{mu_};
                    auto it = std::find_if(results_.begin(), results_.end(),
                                           [&](const QueryResult& x) { return x.name == name; });
                    if (it != results_.end()) *it = std::move(r);
                    else results_.push_back(std::move(r));
                    if (results_.size() > 64) results_.erase(results_.begin());
                },
                "osquery")) {
            note_error("pool saturated; osquery query '" + name + "' deferred");
        }
    }
    last_run_ = core::SysClock::now();
}

void OsquerySensor::loop(std::stop_token st) {
    while (!st.stop_requested()) {
        for (int slice = 0; slice < 4 && !st.stop_requested(); ++slice)
            std::this_thread::sleep_for(250ms);  // interruptible (see the hardening sensors)
        if (!available_) continue;
        if (last_run_ != core::SysClock::time_point{} &&
            core::SysClock::now() - last_run_ >= cfg_.osquery.query_interval) {
            run_all();
        }
    }
}

std::vector<QueryResult> OsquerySensor::last_results() const noexcept {
    std::lock_guard lk{mu_};
    return results_;
}

std::vector<OsquerySensor::Anomaly> OsquerySensor::anomalies(std::size_t n) const noexcept {
    std::lock_guard lk{mu_};
    std::vector<Anomaly> out;
    out.reserve(std::min(n, anomalies_.size()));
    for (std::size_t i = 0; i < std::min(n, anomalies_.size()); ++i) out.push_back(anomalies_[i]);
    return out;
}

}  // namespace hyprnova::behavioral
