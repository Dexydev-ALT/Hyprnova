// SPDX-License-Identifier: Apache-2.0
// HyprNova :: hyprnova-cli — headless client for the agent's IPC socket
//
// A GUI is not always available: SSH-only hosts, containers, and the 3 a.m. page
// where the operator has no X11 forwarding. This speaks exactly the same protocol
// as the Qt dashboard, so anything the console can do, so can this.

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#include "core/brand.hpp"
#include "core/json.hpp"
#include "tools/toolbox.hpp"

namespace {

using hyprnova::core::json::Object;
using hyprnova::core::json::Value;

constexpr std::string_view kDefaultSocket = "/run/hyprnova/gui.sock";

/// json::Value::str() returns a string_view into the DOM. printf needs a
/// NUL-terminated buffer, so every field goes through S() rather than being
/// handed to %s directly -- a string_view is not a C string and the compiler will
/// happily let you pass one to a variadic %s.
[[nodiscard]] std::string S(const Value* v) noexcept {
    // Guarded: an array of mixed types must not make the CLI throw while printing
    // a table.
    return (v && v->is_string()) ? std::string(v->as_string()) : std::string();
}
[[nodiscard]] std::string S(const Value& v, std::string_view key) noexcept {
    const Value* c = v.at(key);
    return (c && c->is_string()) ? std::string(c->as_string()) : std::string();
}
[[nodiscard]] long long I(const Value& v, std::string_view key, long long dflt = 0) noexcept {
    return static_cast<long long>(v.integer(key, dflt));
}
[[nodiscard]] double D(const Value& v, std::string_view key) noexcept {
    const Value* c = v.at(key);
    return c && c->is_number() ? c->as_double() : 0.0;
}

void usage() {
    std::printf(
        "hyprnova-cli -- %.*s control tool (hyprnovad core)\n"
        "\n"
        "usage: hyprnova-cli [-s SOCKET] [--json] <command> [args]\n"
        "\n"
        "read-only:\n"
        "  status                       posture, capabilities, counters\n"
        "  sensors                      per-sensor health\n"
        "  events [N]                   last N events (default 25)\n"
        "  risk                         actors ranked by accumulated risk\n"
        "  processes [N]                live process table, newest first\n"
        "  network                      listeners, connections, beacons, blocks\n"
        "  decisions                    prompts awaiting an operator\n"
        "  scans                        scanning module state and recent verdicts\n"
        "  hardening                    boot trust, kernel hardening, MAC profile\n"
        "  canaries                     planted canaries and a live re-check\n"
        "  baseline                     what the heuristic engine has learned\n"
        "  auditd                       kernel audit subsystem state\n"
        "  osquery                      state-query results\n"
        "  remediation                  action journal, blocks, quarantine\n"
        "  config                       effective configuration summary\n"
        "  selftest                     re-run the agent self-test\n"
        "  watch [--every MS]           live sign of life: heartbeats, alerts, actions\n"
        "\n"
        "actions (require root on the agent socket, or the agent's own uid):\n"
        "  investigate PID              run the full escalation pipeline now\n"
        "  resume PID | suspend PID | isolate PID | release PID | kill PID\n"
        "  answer ID allow|suspend|quarantine|kill\n"
        "  dismiss PID                  clear an actor's accumulated risk\n"
        "  scan PATH                    scan one file, print the verdict\n"
        "  sweep                        start a full sweep of the scan roots\n"
        "  quarantine PATH\n"
        "  restore ID PATH\n"
        "  block IP [PORT] [TTL_SECONDS]\n"
        "  unblock ID\n"
        "  block-exe PID [TTL_SECONDS]\n"
        "  analysis-plan SHA256          analysis workflow for a sample hash\n"
        "  sandbox-cmd APP [ARGS...]     sandboxed argv for an untrusted binary\n"
        "  unblock-exe ID\n"
        "  harden KEY VALUE             write one sysctl\n"
        "  harden-all                   apply every hardening remediation\n"
        "  reload                       reload agent.json (equivalent to SIGHUP)\n"
        "  plant-canaries               (re)plant the canary files\n"
        "\n"
        "recovery (shadow copies; a snapshot is taken at every agent start):\n"
        "  snapshots                    list shadow copies, newest first\n"
        "  snapshot [REASON]            take one now (root)\n"
        "  verify-snapshot ID           re-hash every file against the manifest\n"
        "  restore-snapshot ID [DEST]   restore to original paths, or into DEST (root)\n"
        "\n"
        "settings (user-friendly toggles for every protection area):\n"
        "  settings                     show every feature switch with its state\n"
        "  set KEY on|off               flip a switch (saved + hot-reloaded)\n"
        "  adv-scan PATH                engine verdict + sha256 + VirusTotal in one\n"
        "  mem-inspect PID              inspect one process's memory (W^X, strings, rules)\n"
        "  mem-dump PID [--yes]         opt-in per-process dump (0600; may contain secrets)\n"
        "  carve PATH [--out DIR]       opt-in: extract + scan embedded artifacts (scan.carving_enabled)\n"
        "  triage PATH                  static triage report: hashes, entropy, signatures, embedded artifacts\n"
        "  mem-status                   memory-forensics capabilities and external tools\n"
        "  ai-ask \"QUESTION\"           ask the AI analyst (needs ai.api_key)\n"
        "  ai-review PID                AI second opinion on a suspended process\n"
        "  shred PATH... [--overwrite] [--yes]\n"
        "                               irreversible deletion; dry run unless --yes\n"
        "\n"
        "combined scans (one command, many engines; always includes the in-tree engine):\n"
        "  deep-scan [PROFILE] [PATH...]  PROFILE = quick | deep | kernel | audit\n"
        "                                 quick: engine + ClamAV over /home /tmp ...\n"
        "                                 deep:  quick + rkhunter + chkrootkit + AIDE\n"
        "                                 kernel: rkhunter + chkrootkit + taint + seccomp\n"
        "                                 audit: Lynis + systemd unit exposure\n"
        "  systemd-check                per-unit systemd sandboxing exposure\n"
        "\n"
        "rescue environment (reboot-scan for kernel-level rootkits; like rescue disks):\n"
        "  rescue-status                what is staged and what blocks it\n"
        "  rescue-prepare [--write]     stage ISO + GRUB entry + cleaner (dry run by default)\n"
        "  rescue-boot [--now]          reboot into the rescue entry (root; --now skips the ask)\n"
        "\n"
        "toolbox (ecosystem integrations; `toolbox` shows what is installed):\n"
        "  toolbox                      coverage matrix across %zu registered tools\n"
        "  tool-run NAME [ARGS...]      run a registered tool (rkhunter, lynis,\n"
        "                               chkrootkit, clamav, ...) -- root, opt-in\n"
        "  vt-lookup SHA256             VirusTotal hash lookup (needs an API key)\n"
        "\n",
        static_cast<int>(hyprnova::core::kProductName.size()), hyprnova::core::kProductName.data(),
        hyprnova::tools::Toolbox::registry().size());
}

[[nodiscard]] std::int64_t as_i64(std::string_view text) noexcept {
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
    (void)ptr;
    if (ec != std::errc{}) {
        // A CLI must not terminate with an uncaught exception because someone
        // typed `hyprnova-cli kill abc`.
        std::fprintf(stderr, "hyprnova-cli: '%s' is not a number\n", std::string(text).c_str());
        ::_exit(2);
    }
    return v;
}

[[nodiscard]] std::string request(const Object& req, std::string_view socket_path,
                                  std::string& err) noexcept {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        err = std::string("socket: ") + std::strerror(errno);
        return {};
    }
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        err = "socket path too long";
        ::close(fd);
        return {};
    }
    std::memcpy(addr.sun_path, socket_path.data(), socket_path.size());
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = std::format("cannot connect to {}: {} (is hyprnovad running, and are you authorised?)",
                          socket_path, std::strerror(errno));
        ::close(fd);
        return {};
    }

    const std::string frame = Value{req}.dump() + "\n";
    std::size_t sent = 0;
    while (sent < frame.size()) {
        const ssize_t n = ::send(fd, frame.data() + sent, frame.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) {
            err = std::string("send: ") + std::strerror(errno);
            ::close(fd);
            return {};
        }
        sent += static_cast<std::size_t>(n);
    }

    // Read lines until we get the REPLY to our request. The bridge broadcasts
    // push frames ({"event":"telemetry",...} for escalation prompts and
    // remediation completions, {"event":"agent.shutdown",...} at exit) to every
    // connected client at any moment, so the first line after our request is not
    // necessarily our reply: under load a push can land between the two. Reading
    // exactly one line and assuming it is the reply is how this CLI used to print
    // zeros for `status` whenever an escalation fired while a command ran.
    //
    // Replies carry "cmd"; pushes carry "event" and never "cmd". Parse each line
    // and skip pushes. Replies can be large (a full process table), so grow
    // rather than cap.
    auto is_push_frame = [](const std::string& line) {
        hyprnova::core::json::ParseError pe {};
        auto doc = hyprnova::core::json::parse(line, {}, &pe);
        if (!doc) return false;  // unparseable: let the caller report it
        return doc->at("event") != nullptr && doc->at("cmd") == nullptr;
    };

    std::string rx;
    char buf[16384];
    for (int pass = 0; pass < 8192; ++pass) {
        // Drain every complete line currently buffered.
        for (;;) {
            const std::size_t nl = rx.find('\n');
            if (nl == std::string::npos) break;
            std::string line = rx.substr(0, nl);
            rx.erase(0, nl + 1);
            if (line.empty()) continue;
            if (!is_push_frame(line)) {
                ::close(fd);
                return line;
            }
            // A push frame: discard it. The CLI is request/response; the live
            // feed is the GUI's.
        }
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n == 0) break;  // agent closed: nothing more is coming
        if (n < 0) {
            if (errno == EINTR) continue;
            err = std::string("recv: ") + std::strerror(errno);
            ::close(fd);
            return {};
        }
        rx.append(buf, static_cast<std::size_t>(n));
        if (rx.size() > 256 << 20) {
            err = "reply exceeded 256 MiB";
            ::close(fd);
            return {};
        }
    }
    ::close(fd);
    if (!rx.empty() && rx.back() == '\n') rx.pop_back();
    if (!rx.empty() && !is_push_frame(rx)) return rx;
    err = "agent closed the connection before replying";
    return {};
}

[[nodiscard]] std::string paint(std::string_view text, std::string_view colour, bool on) noexcept {
    if (!on || colour.empty()) return std::string(text);
    return std::string(colour) + std::string(text) + "\033[0m";
}

[[nodiscard]] std::string sev_colour(std::string_view sev, bool colour) noexcept {
    if (sev == "critical") return paint(sev, "\033[1;31m", colour);
    if (sev == "high") return paint(sev, "\033[31m", colour);
    if (sev == "medium") return paint(sev, "\033[33m", colour);
    if (sev == "low") return paint(sev, "\033[36m", colour);
    if (sev == "failed") return paint(sev, "\033[1;31m", colour);
    if (sev == "degraded") return paint(sev, "\033[33m", colour);
    if (sev == "running") return paint(sev, "\033[32m", colour);
    return std::string(sev);
}

/// Pad first, colour second. printf's field width counts the escape bytes, so
/// colouring before padding misaligns every column that follows.
[[nodiscard]] std::string pad_colour(std::string_view text, std::size_t width, bool colour) noexcept {
    std::string padded{text};
    while (padded.size() < width) padded += ' ';
    return sev_colour(padded, colour);
}

[[nodiscard]] std::string join(const Value* arr) noexcept {
    std::string out;
    if (!arr || !arr->is_array()) return out;
    for (const auto& v : *arr->as_array()) {
        if (!out.empty()) out += ",";
        out += S(&v);
    }
    return out;
}

[[nodiscard]] int connect_unix(std::string_view socket_path, std::string& err) noexcept {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        err = std::string("socket: ") + std::strerror(errno);
        return -1;
    }
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(addr.sun_path)) {
        err = "socket path too long";
        ::close(fd);
        return -1;
    }
    std::memcpy(addr.sun_path, socket_path.data(), socket_path.size());
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = std::format("cannot connect to {}: {} (is hyprnovad running, and are you authorised?)",
                          socket_path, std::strerror(errno));
        ::close(fd);
        return -1;
    }
    return fd;
}

[[nodiscard]] bool send_line(int fd, std::string_view line) noexcept {
    const std::string frame{line};
    std::size_t sent = 0;
    while (sent < frame.size()) {
        const ssize_t n = ::send(fd, frame.data() + sent, frame.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

/// One line of local time, HH:MM:SS.
[[nodiscard]] std::string now_clock() noexcept {
    const std::time_t t = std::time(nullptr);
    std::tm tm {};
    ::localtime_r(&t, &tm);
    return std::format("{:02d}:{:02d}:{:02d}", tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/// `hyprnova-cli watch`: the sign of life. Holds one connection, prints every
/// pushed frame the agent sends -- the heartbeat every agent.heartbeat_interval,
/// and any escalation or remediation action the moment it happens -- and, when
/// nothing is happening, polls the overview on a timer so an idle-but-alive
/// agent still produces a line. If hyprnovad restarts, watch reconnects and
/// keeps going, because a watch tool that dies with the agent is useless during
/// exactly the incident it exists for.
[[nodiscard]] int watch_loop(std::string_view socket_path, int poll_ms, bool colour) noexcept {
    std::printf("watching %.*s -- heartbeat every agent.heartbeat_interval, Ctrl-C to stop\n",
                static_cast<int>(socket_path.size()), socket_path.data());
    std::fflush(stdout);

    std::string rx;
    char buf[16384];
    for (;;) {
        std::string err;
        int fd = connect_unix(socket_path, err);
        if (fd < 0) {
            std::printf("%s -- %s; retrying in 1s\n", now_clock().c_str(), err.c_str());
            std::fflush(stdout);
            ::sleep(1);
            continue;
        }
        // The push feed is on by default (Client::wants_events defaults true), so
        // there is nothing to enable; the uid-gated `live` command only toggles it
        // for clients that want to poll instead. This command exists to RECEIVE.
        std::printf("%s -- connected; waiting for the agent's sign of life\n", now_clock().c_str());
        std::fflush(stdout);

        for (;;) {
            pollfd pfd { fd, POLLIN, 0 };
            const int pr = ::poll(&pfd, 1, poll_ms);
            if (pr < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (pr == 0) {
                // Idle: ask for the overview so the operator still gets a line.
                // The reply arrives as a {"cmd":"overview",...} frame and is
                // printed by the readable branch below.
                if (!send_line(fd, "{\"cmd\":\"overview\"}\n")) break;
                continue;
            }
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;  // agent closed or died: reconnect
            rx.append(buf, static_cast<std::size_t>(n));

            std::size_t pos = 0;
            for (;;) {
                const std::size_t nl = rx.find('\n', pos);
                if (nl == std::string::npos) break;
                std::string line = rx.substr(pos, nl - pos);
                pos = nl + 1;
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;

                hyprnova::core::json::ParseError pe {};
                auto doc = hyprnova::core::json::parse(line, {}, &pe);
                if (!doc) continue;

                if (doc->at("event")) {
                    // A pushed frame. "telemetry" carries one event; the heartbeat
                    // is the alive signal, everything else is something to read.
                    const Value* data = doc->at("data");
                    const std::string kind = data ? S(*data, "kind") : std::string();
                    const std::string sev = data ? S(*data, "severity") : std::string("info");
                    const std::string msg = data ? S(*data, "message") : std::string();
                    if (kind == "agent.heartbeat") {
                        // Compact one-liner: the alive marker plus the counters
                        // an operator actually watches.
                        const Value* f = data ? data->at("fields") : nullptr;
                        const std::string up = f ? S(*f, "uptime") : "?";
                        const std::string post = f ? S(*f, "posture") : "?";
                        const std::string pub = data ? std::to_string(data->integer("count", 0)) : "?";
                        std::printf("%s %s alive  uptime=%ss posture=%s/100 published=%s\n",
                                    now_clock().c_str(), paint("♥", "\033[32m", colour).c_str(),
                                    up.c_str(), post.c_str(), pub.c_str());
                    } else {
                        std::printf("%s %s %s %s\n", now_clock().c_str(),
                                    pad_colour(sev, 8, colour).c_str(),
                                    pad_colour(kind, 22, colour).c_str(), msg.c_str());
                    }
                    std::fflush(stdout);
                    continue;
                }

                // Otherwise it is the reply to our overview poll.
                const std::string rcmd = S(*doc, "cmd");
                if (rcmd == "overview" && doc->integer("ok", 0) != 0) {
                    const Value* d = doc->at("data");
                    if (d) {
                        std::printf("%s %s posture=%lld/%s uptime=%llds events=%lld dropped=%lld sensors=%lld degraded=%lld\n",
                                    now_clock().c_str(), paint("·", "\033[2m", colour).c_str(),
                                    I(*d, "posture_score"), S(*d, "posture_label").c_str(),
                                    I(*d, "uptime"), I(*d, "published"),
                                    I(*d, "dropped"), I(*d, "sensors"),
                                    I(*d, "degraded"));
                        std::fflush(stdout);
                    }
                } else if (doc->integer("ok", 1) == 0) {
                    std::printf("%s %s error: %s\n", now_clock().c_str(),
                                paint("!", "\033[31m", colour).c_str(), S(*doc, "error").c_str());
                    std::fflush(stdout);
                }
            }
            rx.erase(0, pos);
        }
        ::close(fd);
        std::printf("%s -- agent connection lost; reconnecting\n", now_clock().c_str());
        std::fflush(stdout);
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::string socket_path{kDefaultSocket};
    bool raw_json = false;
    std::vector<std::string> args;

    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "-s" || a == "--socket") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "-s needs a path\n");
                return 2;
            }
            socket_path = argv[++i];
        } else if (a == "--json") {
            raw_json = true;
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else {
            args.emplace_back(a);
        }
    }
    if (args.empty()) {
        usage();
        return 2;
    }

    const std::string cmd = args[0];

    // `watch` holds its own connection and never returns until interrupted.
    if (cmd == "watch") {
        int poll_ms = 10000;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--every" && i + 1 < args.size()) {
                poll_ms = static_cast<int>(as_i64(args[++i]));
                if (poll_ms < 500) poll_ms = 500;
            }
        }
        return watch_loop(socket_path, poll_ms, !raw_json);
    }

    Object req;

    if (cmd == "status") req["cmd"] = std::string("overview");
    else if (cmd == "sensors") req["cmd"] = std::string("sensors");
    else if (cmd == "events") {
        req["cmd"] = std::string("events");
        req["limit"] = args.size() > 1 ? as_i64(args[1]) : std::int64_t{25};
    } else if (cmd == "risk") {
        req["cmd"] = std::string("risk");
    } else if (cmd == "processes") {
        req["cmd"] = std::string("processes");
        req["limit"] = args.size() > 1 ? as_i64(args[1]) : std::int64_t{60};
    } else if (cmd == "network") req["cmd"] = std::string("network");
    else if (cmd == "decisions") req["cmd"] = std::string("decisions");
    else if (cmd == "scans") req["cmd"] = std::string("scans");
    else if (cmd == "hardening") req["cmd"] = std::string("hardening");
    else if (cmd == "canaries") req["cmd"] = std::string("canaries");
    else if (cmd == "baseline") req["cmd"] = std::string("baseline");
    else if (cmd == "auditd") req["cmd"] = std::string("auditd");
    else if (cmd == "osquery") req["cmd"] = std::string("osquery");
    else if (cmd == "remediation") req["cmd"] = std::string("remediation");
    else if (cmd == "config") req["cmd"] = std::string("config");
    else if (cmd == "selftest") req["cmd"] = std::string("selftest");
    else if (cmd == "sweep") req["cmd"] = std::string("sweep");
    else if (cmd == "reload") req["cmd"] = std::string("reload");
    else if (cmd == "harden-all" || cmd == "hardening-all") req["cmd"] = std::string("harden_apply_all");
    else if (cmd == "plant-canaries") req["cmd"] = std::string("plant_canaries");
    else if (cmd == "investigate") {
        if (args.size() < 2) { std::fprintf(stderr, "investigate needs a PID\n"); return 2; }
        req["cmd"] = std::string("investigate");
        req["pid"] = as_i64(args[1]);
        req["reason"] = std::string("operator investigation via hyprnova-cli");
    } else if (cmd == "resume" || cmd == "suspend" || cmd == "isolate" || cmd == "kill" ||
               cmd == "release") {
        if (args.size() < 2) { std::fprintf(stderr, "%s needs a PID\n", cmd.c_str()); return 2; }
        req["cmd"] = cmd;
        req["pid"] = as_i64(args[1]);
    } else if (cmd == "answer") {
        if (args.size() < 3) {
            std::fprintf(stderr, "answer needs ID and allow|suspend|quarantine|kill\n");
            return 2;
        }
        req["cmd"] = std::string("answer");
        req["id"] = as_i64(args[1]);
        req["answer"] = args[2];
    } else if (cmd == "dismiss") {
        if (args.size() < 2) { std::fprintf(stderr, "dismiss needs a PID\n"); return 2; }
        req["cmd"] = std::string("dismiss");
        req["pid"] = as_i64(args[1]);
    } else if (cmd == "scan") {
        if (args.size() < 2) { std::fprintf(stderr, "scan needs a PATH\n"); return 2; }
        req["cmd"] = std::string("scan");
        req["path"] = args[1];
    } else if (cmd == "quarantine") {
        if (args.size() < 2) { std::fprintf(stderr, "quarantine needs a PATH\n"); return 2; }
        req["cmd"] = std::string("quarantine");
        req["path"] = args[1];
    } else if (cmd == "restore") {
        if (args.size() < 3) { std::fprintf(stderr, "restore needs ID and PATH\n"); return 2; }
        req["cmd"] = std::string("restore");
        req["id"] = as_i64(args[1]);
        for (std::size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--force") req["force"] = 1;
            else req["to"] = args[i];
        }
    } else if (cmd == "block") {
        if (args.size() < 2) { std::fprintf(stderr, "block needs an IP\n"); return 2; }
        req["cmd"] = std::string("block");
        req["ip"] = args[1];
        if (args.size() > 2) req["port"] = as_i64(args[2]);
        if (args.size() > 3) req["ttl_seconds"] = as_i64(args[3]);
        req["reason"] = std::string("operator block via hyprnova-cli");
    } else if (cmd == "unblock") {
        if (args.size() < 2) { std::fprintf(stderr, "unblock needs a block ID\n"); return 2; }
        req["cmd"] = std::string("unblock");
        req["id"] = as_i64(args[1]);
    } else if (cmd == "analysis-plan") {
        if (args.size() < 2) { std::fprintf(stderr, "analysis-plan needs a SHA256\n"); return 2; }
        req["cmd"] = std::string("analysis-plan");
        req["sha256"] = args[1];
    } else if (cmd == "sandbox-cmd") {
        if (args.size() < 2) { std::fprintf(stderr, "sandbox-cmd needs an absolute APP path\n"); return 2; }
        req["cmd"] = std::string("sandbox-cmd");
        req["app"] = args[1];
        if (args.size() > 2) {
            std::string arr = "[";
            for (std::size_t i = 2; i < args.size(); ++i) {
                if (i > 2) arr += ",";
                std::string a;
                for (char c : args[i]) {
                    if (c == '"' || c == '\\') a += '\\';
                    if (c == '"') a += '"';
                    a += c;
                }
                arr += std::format("\"{}\" ", a);
            }
            arr += "]";
            req["args"] = hyprnova::core::json::parse(arr).value_or(hyprnova::core::json::Value{});
        }
    } else if (cmd == "block-exe") {
        if (args.size() < 2) { std::fprintf(stderr, "block-exe needs a PID\n"); return 2; }
        req["cmd"] = std::string("block-exe");
        req["pid"] = as_i64(args[1]);
        if (args.size() > 2) req["ttl_seconds"] = as_i64(args[2]);
        req["reason"] = std::string("operator exe block via hyprnova-cli");
    } else if (cmd == "unblock-exe") {
        if (args.size() < 2) { std::fprintf(stderr, "unblock-exe needs a block ID\n"); return 2; }
        req["cmd"] = std::string("unblock-exe");
        req["id"] = as_i64(args[1]);
    } else if (cmd == "snapshots") {
        req["cmd"] = std::string("snapshots");
    } else if (cmd == "snapshot") {
        req["cmd"] = std::string("snapshot");
        if (args.size() > 1) req["reason"] = args[1];
    } else if (cmd == "verify-snapshot") {
        if (args.size() < 2) { std::fprintf(stderr, "verify-snapshot needs an ID\n"); return 2; }
        req["cmd"] = std::string("verify_snapshot");
        req["id"] = args[1];
    } else if (cmd == "restore-snapshot") {
        if (args.size() < 2) { std::fprintf(stderr, "restore-snapshot needs an ID [DEST]\n"); return 2; }
        req["cmd"] = std::string("restore_shadow");
        req["id"] = args[1];
        if (args.size() > 2) req["to"] = args[2];
    } else if (cmd == "settings") {
        req["cmd"] = std::string("settings_get");
    } else if (cmd == "set") {
        if (args.size() < 3) { std::fprintf(stderr, "usage: set KEY on|off   (see `settings`)\n"); return 2; }
        req["cmd"] = std::string("settings_set");
        req["key"] = args[1];
        const std::string v = args[2];
        if (v != "on" && v != "off") { std::fprintf(stderr, "value must be on|off\n"); return 2; }
        req["value"] = v == "on" ? 1 : 0;
    } else if (cmd == "ai-ask") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: ai-ask \"QUESTION\"\n"); return 2; }
        req["cmd"] = std::string("ai_ask");
        std::string q = args[1];
        for (std::size_t i = 2; i < args.size(); ++i) { q += " "; q += args[i]; }
        req["question"] = q;
    } else if (cmd == "ai-review") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: ai-review PID\n"); return 2; }
        req["cmd"] = std::string("ai_review");
        req["pid"] = as_i64(args[1]);
    } else if (cmd == "shred") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: shred PATH... [--overwrite] [--yes]  (dry run unless --yes)\n"); return 2; }
        req["cmd"] = std::string("shred");
        hyprnova::core::json::Array ps;
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--yes") req["confirm"] = 1;
            else if (args[i] == "--overwrite") req["overwrite"] = 1;
            else ps.emplace_back(args[i]);
        }
        req["paths"] = hyprnova::core::json::Value{std::move(ps)};
    } else if (cmd == "mem-inspect") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: mem-inspect PID\n"); return 2; }
        req["cmd"] = std::string("mem_inspect");
        req["pid"] = as_i64(args[1]);
    } else if (cmd == "mem-dump") {
        bool confirm = false;
        std::string pid_arg;  // first non-flag token (flags may precede or follow it)
        for (std::size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "--yes") confirm = true;
            else if (pid_arg.empty()) pid_arg = args[i];
        }
        req["cmd"] = std::string("mem_dump");
        req["confirm"] = confirm ? 1 : 0;
        if (pid_arg.empty()) { std::fprintf(stderr, "usage: mem-dump PID [--yes]\n"); return 2; }
        req["pid"] = as_i64(pid_arg);  // destination is chosen by the agent (state_dir/memory, 0700)
    } else if (cmd == "mem-status") {
        req["cmd"] = std::string("mem_status");
    } else if (cmd == "carve") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: carve PATH [--out DIR]\n"); return 2; }
        req["cmd"] = std::string("carve");
        req["path"] = args[1];
        for (std::size_t i = 2; i + 1 < args.size(); ++i)
            if (args[i] == "--out") req["out"] = args[i + 1];
    } else if (cmd == "triage") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: triage PATH\n"); return 2; }
        req["cmd"] = std::string("triage");
        req["path"] = args[1];
    } else if (cmd == "adv-scan") {
        if (args.size() < 2) { std::fprintf(stderr, "usage: adv-scan PATH\n"); return 2; }
        req["cmd"] = std::string("advanced_scan");
        req["path"] = args[1];
    } else if (cmd == "deep-scan") {
        req["cmd"] = std::string("combined_scan");
        if (args.size() > 1 && hyprnova::tools::Toolbox::valid_profile(args[1]))
            req["profile"] = args[1];
        else
            req["profile"] = std::string("quick");
        if (args.size() > 2) {
            hyprnova::core::json::Array ps;
            for (std::size_t i = 2; i < args.size(); ++i) ps.emplace_back(args[i]);
            req["paths"] = hyprnova::core::json::Value{std::move(ps)};
        }
    } else if (cmd == "systemd-check") {
        req["cmd"] = std::string("systemd");
    } else if (cmd == "rescue-status") {
        req["cmd"] = std::string("rescue_status");
    } else if (cmd == "rescue-prepare") {
        req["cmd"] = std::string("rescue_prepare");
        req["write"] = (args.size() > 1 && args[1] == "--write") ? 1 : 0;
    } else if (cmd == "rescue-boot") {
        req["cmd"] = std::string("rescue_boot");
        req["boot_once"] = (args.size() > 1 && args[1] == "--now") ? 0 : 1;
    } else if (cmd == "toolbox") {
        req["cmd"] = std::string("toolbox");
    } else if (cmd == "tool-run") {
        if (args.size() < 2) {
            std::fprintf(stderr, "tool-run needs a NAME (see `hyprnova-cli toolbox`)\n");
            return 2;
        }
        req["cmd"] = std::string("tool_run");
        req["name"] = args[1];
        if (args.size() > 2) {
            hyprnova::core::json::Array a;
            for (std::size_t i = 2; i < args.size(); ++i) a.emplace_back(args[i]);
            req["args"] = hyprnova::core::json::Value{std::move(a)};
        }
    } else if (cmd == "vt-lookup") {
        if (args.size() < 2) { std::fprintf(stderr, "vt-lookup needs a SHA-256 hash\n"); return 2; }
        req["cmd"] = std::string("vt_lookup");
        req["hash"] = args[1];
    } else if (cmd == "harden") {
        if (args.size() < 3) { std::fprintf(stderr, "harden needs KEY and VALUE\n"); return 2; }
        req["cmd"] = std::string("harden");
        req["key"] = args[1];
        req["value"] = args[2];
    } else {
        std::fprintf(stderr, "unknown command '%s'\n\n", cmd.c_str());
        usage();
        return 2;
    }

    std::string err;
    const std::string reply_text = request(req, socket_path, err);
    if (!err.empty()) {
        std::fprintf(stderr, "hyprnova-cli: %s\n", err.c_str());
        return 1;
    }

    hyprnova::core::json::ParseError pe {};
    auto doc = hyprnova::core::json::parse(reply_text, {}, &pe);
    if (!doc) {
        std::fprintf(stderr, "hyprnova-cli: unparseable reply at offset %zu: %s\n%.*s\n", pe.offset,
                     pe.message.c_str(),
                     static_cast<int>(std::min<std::size_t>(reply_text.size(), 512)),
                     reply_text.c_str());
        return 1;
    }
    if (raw_json) {
        std::printf("%s\n", doc->dump().c_str());
        return doc->integer("ok", 1) != 0 ? 0 : 1;
    }
    if (doc->integer("ok", 1) == 0) {
        std::fprintf(stderr, "hyprnova-cli: %s\n", S(*doc, "error").c_str());
        return 1;
    }
    const Value* data = doc->at("data");
    if (!data) {
        std::printf("%s\n", doc->dump().c_str());
        return 0;
    }

    const bool colour = ::isatty(1) != 0;

    // ---- human-readable rendering, one block per command ----
    if (cmd == "status") {
        std::printf("%.*s %s   posture %lld/100 (%s)\n",
                    static_cast<int>(hyprnova::core::kProductName.size()), hyprnova::core::kProductName.data(),
                    S(*data, "version").c_str(),
                    I(*data, "posture_score"), S(*data, "posture_label").c_str());
        std::printf("  uptime        %lld s      pid %lld   euid %lld%s\n", I(*data, "uptime"),
                    I(*data, "pid"), I(*data, "euid"),
                    data->integer("container") ? "   (inside a container)" : "");
        std::printf("  events        published=%lld dispatched=%lld dropped=%lld\n",
                    I(*data, "published"), I(*data, "dispatched"), I(*data, "dropped"));
        std::printf("  sensors       %lld running, %lld degraded\n", I(*data, "sensors"),
                    I(*data, "degraded"));
        std::printf("  containment   decisions=%lld blocks=%lld suspended=%lld\n",
                    I(*data, "pending_decisions"), I(*data, "active_blocks"), I(*data, "suspended"));
        std::printf("  learning      %.0f%%\n", D(*data, "learning") * 100.0);
        std::printf("  mode          dry_run=%s auto_respond=%s\n",
                    data->integer("dry_run") ? "YES" : "no",
                    data->integer("auto_respond") ? "YES" : "no");
        if (const Value* caps = data->at("capabilities")) {
            std::printf("  capabilities  signal=%s cgroup=%s network=%s quarantine=%s notify=%s\n",
                        caps->integer("signal") ? "yes" : "NO", caps->integer("cgroup") ? "yes" : "NO",
                        caps->integer("network") ? "yes" : "NO",
                        caps->integer("quarantine") ? "yes" : "NO",
                        caps->integer("notify") ? "yes" : "NO");
            for (const auto& n : *caps->at("notes")->as_array())
                std::printf("    ! %s\n", S(&n).c_str());
        }
        return 0;
    }

    if (cmd == "sensors") {
        std::printf("%-18s %-10s %9s %8s %7s %6s  %s\n", "SENSOR", "STATE", "EMITTED", "DROPPED",
                    "ERRORS", "CPU%", "DETAIL");
        for (const auto& s : *data->at("sensors")->as_array()) {
            std::printf("%-18s %s %9lld %8lld %7lld %6.2f  %s\n", S(s, "name").c_str(),
                        pad_colour(S(s, "state"), 10, colour).c_str(), I(s, "emitted"),
                        I(s, "dropped"), I(s, "errors"), D(s, "cpu"), S(s, "detail").c_str());
        }
        return 0;
    }

    if (cmd == "events") {
        for (const auto& e : *data->at("events")->as_array()) {
            std::printf("[%s] %-9s %-22s %s\n", S(e, "sensor").c_str(),
                        sev_colour(S(e, "severity"), colour).c_str(), S(e, "kind").c_str(),
                        S(e, "message").c_str());
            if (I(e, "risk") > 0 && e.at("actor"))
                std::printf("      risk=%lld pid=%lld exe=%s\n", I(e, "risk"),
                            I(*e.at("actor"), "pid"), S(*e.at("actor"), "exe").c_str());
        }
        return 0;
    }

    if (cmd == "risk") {
        std::printf("%-7s %6s %-9s %-30s %s\n", "PID", "RISK", "SEVERITY", "EXE", "TRIGGERS");
        for (const auto& a : *data->at("actors")->as_array()) {
            std::printf("%-7lld %6.0f %s %-30.30s %s\n", I(a, "pid"), D(a, "score"),
                        pad_colour(S(a, "severity"), 9, colour).c_str(), S(a, "exe").c_str(),
                        join(a.at("triggers")).c_str());
        }
        std::printf("\nalerts=%lld escalations=%lld observations=%lld learning=%s (%.0f%%)\n",
                    I(*data, "alerts"), I(*data, "escalations"), I(*data, "observations"),
                    data->integer("learning") ? "yes" : "no", D(*data, "learning_progress") * 100.0);
        std::printf("thresholds: alert>=%lld critical>=%lld auto-respond>=%lld\n",
                    I(*data, "thresholds_alert"), I(*data, "thresholds_critical"),
                    I(*data, "thresholds_auto"));
        return 0;
    }

    if (cmd == "processes") {
        std::printf("%-7s %-7s %-5s %-6s %-15s %s\n", "PID", "PPID", "UID", "STATE", "COMM", "EXE");
        for (const auto& p : *data->at("processes")->as_array()) {
            const std::string flag = S(p, "flag");
            std::printf("%-7lld %-7lld %-5lld %-6s %-15.15s %s%s\n", I(p, "pid"), I(p, "ppid"),
                        I(p, "uid"), S(p, "state").c_str(), S(p, "comm").c_str(),
                        S(p, "exe").c_str(), flag.empty() ? "" : ("  <" + flag + ">").c_str());
        }
        if (const Value* caps = data->at("capabilities")) {
            std::printf("\nagent capabilities: root=%s ptrace=%s dac_read_search=%s net_admin=%s\n",
                        caps->integer("root") ? "yes" : "NO",
                        caps->integer("cap_sys_ptrace") ? "yes" : "NO",
                        caps->integer("cap_dac_read_search") ? "yes" : "NO",
                        caps->integer("cap_net_admin") ? "yes" : "NO");
        }
        return 0;
    }

    if (cmd == "decisions") {
        if (I(*data, "count") == 0) {
            std::printf("no decisions pending\n");
            return 0;
        }
        for (const auto& d : *data->at("decisions")->as_array()) {
            const Value* r = d.at("report");
            if (!r) continue;
            std::printf("DECISION #%lld  pid %lld  risk %.0f  severity %s  step %s\n", I(d, "id"),
                        I(*r, "pid"), D(*r, "risk"), sev_colour(S(*r, "severity"), colour).c_str(),
                        S(*r, "step").c_str());
            std::printf("  exe      %s\n", S(*r, "exe").c_str());
            std::printf("  lineage  %s\n", S(*r, "lineage").c_str());
            std::printf("  advice   %s\n", S(d, "recommendation").c_str());
            std::printf("  answer:  hyprnova-cli answer %lld allow|suspend|quarantine|kill\n",
                        I(d, "id"));
            for (const auto& f : *r->at("findings")->as_array())
                std::printf("    - %s\n", S(&f).c_str());
            std::printf("\n");
        }
        return 0;
    }

    if (cmd == "network") {
        std::printf("LISTENERS\n");
        for (const auto& l : *data->at("listeners")->as_array())
            std::printf("  %-6s %-45s pid %-7lld %s\n", S(l, "protocol").c_str(),
                        S(l, "local").c_str(), I(l, "pid"), S(l, "exe").c_str());
        std::printf("\nESTABLISHED\n");
        for (const auto& c : *data->at("connections")->as_array())
            std::printf("  %-45s -> %-45s %-12s pid %-7lld %s%s\n", S(c, "local").c_str(),
                        S(c, "remote").c_str(), S(c, "state").c_str(), I(c, "pid"),
                        S(c, "exe").c_str(),
                        c.integer("attributed") ? "" : "  (owner unidentified)");
        if (const Value* b = data->at("blocks")) {
            std::printf("\nAGENT BLOCKS\n");
            for (const auto& x : *b->as_array())
                std::printf("  #%-6lld %s:%lld  ttl %llds  %s\n", I(x, "id"), S(x, "ip").c_str(),
                            I(x, "port"), I(x, "ttl"), S(x, "reason").c_str());
        }
        if (const Value* be = data->at("beacons")) {
            std::printf("\nBEACON CANDIDATES\n");
            for (const auto& x : *be->as_array())
                std::printf("  %-30s hits=%-6lld mean=%.1fs jitter=%.2f score=%.2f %s\n",
                            S(x, "peer").c_str(), I(x, "hits"), D(x, "mean_interval"),
                            D(x, "jitter"), D(x, "score"),
                            x.integer("beacon_like") ? "<== BEACON-LIKE" : "");
        }
        return 0;
    }

    if (cmd == "investigate") {
        std::printf("pid %lld  %s\n  lineage  %s\n  risk     %.0f/1000  severity %s  step %s\n",
                    I(*data, "pid"), S(*data, "exe").c_str(), S(*data, "lineage").c_str(),
                    D(*data, "risk"), sev_colour(S(*data, "severity"), colour).c_str(),
                    S(*data, "step").c_str());
        std::printf("  memory   %lld regions scanned, %lld writable+executable (W^X violations)\n",
                    I(*data, "regions_scanned"), I(*data, "wx_regions"));
        std::printf("  frozen   %s%s   elapsed %lld ms\n",
                    data->integer("suspended") ? "yes" : "no",
                    data->integer("resumed") ? " (resumed: evidence did not hold up)" : "",
                    I(*data, "elapsed_ms"));
        std::printf("  findings:\n");
        for (const auto& f : *data->at("findings")->as_array())
            std::printf("    - %s\n", S(&f).c_str());
        for (const auto& m : *data->at("memory_matches")->as_array())
            std::printf("    ! memory signature: %s\n", S(&m).c_str());
        std::printf("  binaries scanned:\n");
        for (const auto& p : *data->at("scanned_paths")->as_array())
            std::printf("    %s\n", S(&p).c_str());
        return 0;
    }

    if (cmd == "selftest") {
        for (const auto& c : *data->at("checks")->as_array())
            std::printf("%s\n", S(&c).c_str());
        std::printf("%s\n", data->integer("passed") ? "SELF-TEST PASSED" : "SELF-TEST FAILED");
        return data->integer("passed") ? 0 : 1;
    }

    if (cmd == "scan") {
        std::printf("%s\n  verdict  %s   risk %lld   engine %s   %lld ms%s\n",
                    S(*data, "path").c_str(), S(*data, "verdict").c_str(), I(*data, "risk"),
                    S(*data, "engine").c_str(), I(*data, "elapsed_ms"),
                    data->integer("from_cache") ? " (cached)" : "");
        std::printf("  sha256   %s   %lld bytes   entropy %.2f   flavour %s\n",
                    S(*data, "sha256").c_str(), I(*data, "size"), D(*data, "entropy"),
                    S(*data, "flavour").c_str());
        for (const auto& m : *data->at("matches")->as_array())
            std::printf("  ! rule %s [%s] %s\n", S(m, "rule").c_str(), S(m, "family").c_str(),
                        S(m, "description").c_str());
        if (!S(*data, "detail").empty()) std::printf("  detail   %s\n", S(*data, "detail").c_str());
        return 0;
    }

    if (cmd == "snapshots") {
        const Value* arr = data->at("snapshots");
        if (!arr || !arr->is_array()) { std::printf("no shadow copies\n"); return 0; }
        std::printf("%-28s %-16s %8s %10s %8s  %s\n", "SNAPSHOT", "REASON", "FILES", "BYTES",
                    "SKIPPED", "MISSING ROOTS");
        for (const auto& e : *arr->as_array()) {
            std::string missing;
            if (const Value* m = e.at("missing"))
                if (m->is_array())
                    for (const auto& x : *m->as_array()) {
                        if (!missing.empty()) missing += ",";
                        missing += S(&x);
                    }
            std::string reason = S(e, "reason");
            if (reason.size() > 16) reason = reason.substr(0, 16);
            std::printf("%-28s %-16s %8lld %10lld %8lld  %s\n", S(e, "id").c_str(), reason.c_str(),
                        I(e, "files"), I(e, "bytes"), I(e, "skipped"), missing.c_str());
        }
        std::printf("\nstore: %s (keeping the newest %lld)\n", S(*data, "dir").c_str(),
                    I(*data, "keep"));
        return 0;
    }

    if (cmd == "verify-snapshot" || cmd == "snapshot" || cmd == "restore-snapshot") {
        const bool ok = data->integer("verified", data->integer("ok", 1)) != 0 &&
                        data->integer("failed", 0) == 0;
        std::printf("%s: %s\n", cmd.c_str(), S(*data, "detail").c_str());
        if (const Value* f = data->at("failures"))
            if (f->is_array())
                for (const auto& x : *f->as_array()) std::printf("  ! %s\n", S(&x).c_str());
        if (const std::string id = S(*data, "id"); !id.empty())
            std::printf("  id: %s\n", id.c_str());
        return ok ? 0 : 1;
    }

    if (cmd == "toolbox") {
        const Value* tools = data->at("tools");
        if (!tools || !tools->is_array()) { std::printf("toolbox unavailable\n"); return 1; }
        // summary line first
        if (const Value* s = data->at("summary")) {
            std::printf("%s: %lld of %lld tools present (%lld built-in, %lld runners ready)\n",
                        "ecosystem", I(*s, "installed"), I(*s, "total"), I(*s, "builtin"),
                        I(*s, "runners_ready"));
        }
        std::string last_cat;
        for (const auto& t : *tools->as_array()) {
            const std::string cat = S(t, "category");
            if (cat != last_cat) {
                std::printf("\n%s\n", cat.c_str());
                last_cat = cat;
            }
            const bool installed = t.integer("installed") != 0;
            const std::string note = S(t, "note");
            const std::string integ = S(t, "integration");
            const std::string where = S(t, "binary");
            const std::string tail = !installed ? std::string("not installed")
                                     : (note != integ ? note
                                                      : (where.empty() ? std::string("-") : where));
            std::printf("  [%s] %-30s %-22s %s\n", installed ? "+" : " ", S(t, "label").c_str(),
                        integ.c_str(), tail.c_str());
        }
        if (const Value* p = data->at("proc_security")) {
            std::printf("\nPROCESS TABLE (live /proc audit)\n");
            std::printf("  %lld processes: %lld seccomp-filtered, %lld classic, %lld UNFILTERED\n",
                        I(*p, "processes"), I(*p, "seccomp_filter"), I(*p, "seccomp_classic"),
                        I(*p, "seccomp_none"));
            if (const Value* u = p->at("unfiltered_root"); u && u->is_array() && !u->as_array()->empty()) {
                std::printf("  root processes without seccomp filtering (kernel-exploit surface):\n");
                for (const auto& x : *u->as_array())
                    std::printf("    pid %-8s %s\n", S(x, "pid").c_str(), S(x, "comm").c_str());
            }
        }
        if (const Value* pol = data->at("policy")) {
            std::printf("\npolicy: runners %s, virustotal %s, sample upload %s\n",
                        pol->integer("runners_enabled") ? "enabled" : "disabled",
                        pol->integer("virustotal_enabled") ? "enabled" : "disabled",
                        pol->integer("online_submission") ? "ENABLED" : "off (privacy gate)");
        }
        return 0;
    }

    if (cmd == "settings_get") {
        const Value* st = data->at("states");
        const Value* ds = data->at("descriptions");
        if (!st || !st->is_object()) { std::printf("settings unavailable\n"); return 1; }
        std::printf("%-24s %-4s %s\n", "FEATURE", "STATE", "WHAT IT DOES");
        for (const auto& [k, v] : *st->as_object()) {
            std::string desc;
            if (ds)
                if (const Value* d = ds->at(k)) desc = std::string(d->as_string());
            std::printf("%-24s %-4s %s\n", k.c_str(),
                        v.as_bool() ? "ON" : "off", desc.c_str());
        }
        std::string why;
        const bool ai_ready = data->integer("ai_ready") != 0;
        std::printf("\nai analyst: %s%s%s\n", ai_ready ? "ready" : "off",
                    (!ai_ready && data->at("ai_note") && !S(*data, "ai_note").empty())
                        ? " -- " : "",
                    ai_ready ? "" : S(*data, "ai_note").c_str());
        return 0;
    }

    if (cmd == "settings_set") {
        std::printf("%s is now %s (config saved, agents reloaded)\n",
                    S(*data, "key").c_str(), data->integer("value") ? "ON" : "off");
        return 0;
    }

    if (cmd == "settings" || cmd == "set") {
        const Value* st = data->at("states");
        if (!st || !st->is_object()) { std::printf("%s\n", data->dump().c_str()); return 0; }
        const Value* desc = data->at("descriptions");
        if (const std::string note = S(*data, "ai_note"); !note.empty())
            std::printf("note: %s\n\n", note.c_str());
        std::printf("%-24s %-4s  DESCRIPTION\n", "TOGGLE", "STATE");
        for (const auto& kv : *st->as_object()) {
            const std::string& k = kv.first;
            const Value& v = kv.second;
            const Value* d = desc ? desc->at(k) : nullptr;
            std::printf("%-24s %-4s  %s\n", k.c_str(), v.as_bool() ? "on" : "OFF",
                        d ? S(d).c_str() : "");
        }
        return 0;
    }

    if (cmd == "mem_status") {
        std::printf("%s\n", S(*data, "limits").c_str());
        std::printf("readable memory: %s\n", data->integer("readable") ? "yes" : "NO (permissions)");
        std::printf("external tools:\n");
        if (const Value* ts = data->at("tools"); ts && ts->is_array())
            for (const auto& t : *ts->as_array())
                std::printf("  %-12s %s  %s\n", S(t, "name").c_str(),
                            t.integer("available") ? "[present]" : "[absent]",
                            S(t, "detail").c_str());
        return 0;
    }

    if (cmd == "mem_inspect") {
        std::printf("pid %lld  exe %s\n", I(*data, "pid"), S(*data, "exe").c_str());
        std::printf("regions scanned: %lld   readable: %s\n", I(*data, "regions_scanned"),
                    data->integer("readable") ? "yes" : "NO");
        for (const auto& fx : *data->at("findings")->as_array())
            std::printf("  - %s\n", S(&fx).c_str());
        if (const std::string note = S(*data, "limit_note"); !note.empty())
            std::printf("  LIMIT: %s\n", note.c_str());
        std::printf("suspicious: %s\n", data->integer("suspicious") ? "YES" : "no");
        return data->integer("suspicious") ? 1 : 0;
    }

    if (cmd == "mem_dump") {
        if (const std::string cmd_err = S(*data, "error"); !cmd_err.empty()) {
            std::printf("! %s\n", cmd_err.c_str());
            return 1;
        }
        std::printf("dumped %lld bytes -> %s\n", I(*data, "bytes"), S(*data, "path").c_str());
        return 0;
    }

    if (cmd == "ai-ask" || cmd == "ai-review") {
        if (const std::string cmd_err = S(*data, "error"); !cmd_err.empty()) {
            std::printf("! %s\n", cmd_err.c_str());
            return 1;
        }
        std::printf("%s\n", S(*data, "answer").c_str());
        std::printf("\n[model %s, %lld ms -- advises only; you decide]\n",
                    S(*data, "model").c_str(), I(*data, "elapsed_ms"));
        return 0;
    }

    if (cmd == "shred") {
        if (!data->at("items") || !data->at("items")->is_array()) {
            std::printf("nothing to shred\n");
            for (const auto& r : *data->at("refusals")->as_array())
                std::printf("  refused: %s\n", S(&r).c_str());
            return 1;
        }
        std::printf("%s: %lld file(s), %lld dir(s), %lld link(s), %lld bytes %s\n",
                    data->integer("executed") ? "SHREDDED" : "DRY RUN",
                    I(*data, "files"), I(*data, "dirs"), I(*data, "links"),
                    I(*data, "total_bytes"),
                    data->integer("overwrite") ? "(overwrite pass)" : "(standard unlink)");
        for (const auto& it : *data->at("items")->as_array()) {
            std::printf("  %-6s %12lld  %s%s\n", S(it, "type").c_str(), I(it, "bytes"),
                        S(it, "path").c_str(),
                        S(it, "note").empty() ? "" : std::format("  {}", S(it, "note")).c_str());
        }
        for (const auto& r : *data->at("refusals")->as_array())
            std::printf("  REFUSED: %s\n", S(&r).c_str());
        std::printf("\n%s\n", S(*data, "method_note").c_str());
        if (!data->integer("executed"))
            std::printf("\nreview the list above, then add --yes to execute.\n");
        else if (const Value* errs = data->at("errors"); errs && errs->is_array() && !errs->as_array()->empty()) {
            for (const auto& e : *errs->as_array()) std::printf("  ! %s\n", S(&e).c_str());
            return 1;
        }
        return 0;
    }

    if (cmd == "adv-scan") {
        if (const std::string next = S(*data, "next_step"); !next.empty())
            std::printf("NEXT: %s\n", next.c_str());
        std::printf("%s\n  verdict %s  risk %lld  engine %s\n  sha256 %s\n",
                    S(*data, "path").c_str(), S(*data, "verdict").c_str(),
                    I(*data, "risk"), S(*data, "engine").c_str(),
                    S(*data, "sha256").c_str());
        if (const Value* rules = data->at("rules"); rules && rules->is_array())
            for (const auto& r : *rules->as_array()) std::printf("  rule: %s\n", S(&r).c_str());
        if (const std::string vs = S(*data, "vt_summary"); !vs.empty())
            std::printf("  virustotal: %s\n", vs.c_str());
        else if (const std::string ve = S(*data, "vt_error"); !ve.empty())
            std::printf("  virustotal: (%s)\n", ve.c_str());
        return data->integer("ok", 1) != 0 ? 0 : 1;
    }

    if (cmd == "deep-scan") {
        const bool ok = data->integer("ok", 0) != 0;
        const std::string v = S(*data, "verdict");
        std::printf("%s\n", S(*data, "summary").c_str());
        if (const Value* secs = data->at("sections"); secs && secs->is_array())
            for (const auto& sc : *secs->as_array()) {
                const bool ran = sc.integer("ran") != 0;
                std::printf("  %-10s %s  %s\n", S(sc, "tool").c_str(),
                            ran ? (sc.integer("ok") ? "[ok]" : "[err]") : "[skip]",
                            S(sc, "label").c_str());
                if (!ran && !S(sc, "note").empty())
                    std::printf("             (%s)\n", S(sc, "note").c_str());
                if (const Value* f = sc.at("findings"); f && f->is_array())
                    for (const auto& x : *f->as_array())
                        std::printf("    ! %s\n", S(&x).c_str());
            }
        std::printf("  (%lld ms)\n", I(*data, "elapsed_ms"));
        if (v == "INFECTED") return 2;
        return ok && v != "suspicious" ? 0 : 1;
    }

    if (cmd == "systemd-check") {
        const Value* units = data->at("units");
        if (!units || !units->is_array()) { std::printf("systemd-analyze unavailable\n"); return 1; }
        std::printf("%-42s %9s  %-8s\n", "UNIT", "EXPOSURE", "GRADE");
        int worst = 0;
        for (const auto& u : *units->as_array()) {
            const double e = D(u, "exposure");
            std::printf("%-42s %9.1f  %-8s %s\n", S(u, "unit").c_str(), e,
                        S(u, "grade").c_str(),
                        e >= 9.0 ? "UNSAFE" : e >= 7.0 ? "exposed" : "");
            if (e >= 9.0) ++worst;
        }
        std::printf("\n%d unit(s) at UNSAFE exposure -- suggestions per unit:\n", worst);
        for (const auto& u : *units->as_array()) {
            if (D(u, "exposure") < 9.0) continue;
            if (const Value* sg = u.at("suggestions"); sg && sg->is_array() && !sg->as_array()->empty()) {
                std::printf("  %s\n", S(u, "unit").c_str());
                for (const auto& x : *sg->as_array())
                    std::printf("    %s\n", S(&x).c_str());
            }
        }
        return worst > 0 ? 1 : 0;
    }

    if (cmd == "rescue-status" || cmd == "rescue-prepare") {
        const bool prepared = data->integer("prepared") != 0;
        std::printf("rescue environment: %s\n",
                    prepared ? "PREPARED (reboot-ready)" : "not prepared");
        const std::string iso_path = S(*data, "iso_path");
        std::printf("  iso: %s%s%s\n", data->integer("iso_found") ? "found" : "MISSING",
                    data->integer("iso_staged") ? ", staged to boot dir" : "",
                    iso_path.empty() ? "" : std::format(" ({})", iso_path).c_str());
        std::printf("  grub entry: %s   clean script: %s   report pending: %s\n",
                    data->integer("grub_entry_present") ? "written" : "-",
                    data->integer("clean_script_present") ? "written" : "-",
                    data->integer("report_pending") ? "YES (rescue run finished!)" : "no");
        if (const Value* b = data->at("blockers"); b && b->is_array() && !b->as_array()->empty()) {
            std::printf("  blockers:\n");
            for (const auto& x : *b->as_array()) std::printf("    - %s\n", S(&x).c_str());
        }
        if (const std::string pv = S(*data, "preview"); !pv.empty())
            std::printf("\n%s\n", pv.c_str());
        return prepared ? 0 : 1;
    }

    if (cmd == "rescue-boot") {
        std::printf("rebooting into the rescue environment...\n");
        return 0;
    }

    if (cmd == "tool-run" || cmd == "vt-lookup") {
        const bool ok = data->integer("ok", 0) != 0;
        if (const std::string errmsg = S(*data, "error"); !errmsg.empty()) {
            std::printf("! %s\n", errmsg.c_str());
            return 1;
        }
        std::printf("%s\n", S(*data, "summary").c_str());
        if (const Value* f = data->at("findings"); f && f->is_array())
            for (const auto& x : *f->as_array()) std::printf("  - %s\n", S(&x).c_str());
        if (const std::string bin = S(*data, "binary"); !bin.empty())
            std::printf("  (%s exited %lld)\n", bin.c_str(), I(*data, "exit_code"));
        return ok ? 0 : 1;
    }

    // Everything else: wide nested structures that the GUI renders graphically.
    // The CLI prints them as JSON rather than maintaining a second rendering that
    // can silently drift from the data.
    std::printf("%s\n", data->dump().c_str());
    return 0;
}
