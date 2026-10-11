// SPDX-License-Identifier: Apache-2.0
// HyprNova :: hyprnovad — the agent daemon entry point
//
// Deliberately thin. All policy lives in the modules; main() only parses argv,
// optionally drops into the foreground, and hands control to Agent::run().

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "agent/agent.hpp"
#include "core/brand.hpp"
#include "core/config.hpp"
#include "core/exec.hpp"
#include "core/log.hpp"
#include "core/proc.hpp"

namespace {

constexpr std::string_view kVersion = "1.0.0";

void usage(std::string_view prog) {
    std::printf(
        "hyprnova %s -- low-overhead Linux EDR agent\n"
        "\n"
        "usage: %s [options]\n"
        "\n"
        "  -c, --config PATH     configuration file (default /etc/hyprnova/agent.json)\n"
        "  -f, --foreground      do not daemonise; log to stderr\n"
        "  -v, --verbose         debug logging\n"
        "  -q, --quiet           warnings and errors only\n"
        "  -n, --dry-run         observe only: no signals, no firewall, no quarantine\n"
        "      --self-test       run the startup self-test and exit\n"
        "      --describe        print the effective configuration and exit\n"
        "      --dump-config     write a default configuration to stdout and exit\n"
        "      --version         print the version and exit\n"
        "  -h, --help            this message\n"
        "\n"
        "Signals: SIGHUP reloads configuration, SIGTERM/SIGINT shut down cleanly.\n"
        "A clean shutdown resumes every process the agent froze and flushes every\n"
        "nftables block it installed.\n",
        std::string(kVersion).c_str(), std::string(prog).c_str());
}

/// Raise the fd limit before any sensor opens one. fanotify + inotify + a UNIX
/// socket per producer + a pipe per subprocess adds up fast on a busy host, and
/// hitting EMFILE mid-incident means losing attribution exactly when it matters.
void raise_fd_limit() noexcept {
    rlimit lim {};
    if (::getrlimit(RLIMIT_NOFILE, &lim) != 0) return;
    const rlim_t want = 65536;
    if (lim.rlim_cur >= want) return;
    rlimit nl = lim;
    nl.rlim_cur = std::min<rlim_t>(want, lim.rlim_max == RLIM_INFINITY ? want : lim.rlim_max);
    if (::setrlimit(RLIMIT_NOFILE, &nl) != 0) {
        std::fprintf(stderr, "hyprnovad: could not raise RLIMIT_NOFILE to %llu: %s\n",
                     static_cast<unsigned long long>(nl.rlim_cur), std::strerror(errno));
        return;
    }
    SINFO("main", "RLIMIT_NOFILE raised to {} (was {})", static_cast<std::uint64_t>(nl.rlim_cur),
          static_cast<std::uint64_t>(lim.rlim_cur));
}

/// A core dump of a root EDR agent can contain other processes' memory that we
/// read during escalation. Disable them unless the operator asked otherwise.
void harden_self() noexcept {
    rlimit no_core {};
    no_core.rlim_cur = 0;
    no_core.rlim_max = 0;
    if (::setrlimit(RLIMIT_CORE, &no_core) != 0)
        SWARN("main", "could not disable core dumps: {}", std::strerror(errno));

    // Refuse to be ptraced: an attacker with a local uid who can attach to the
    // agent can read its config, its canary HMAC key and its decision state.
    // PR_SET_DUMPABLE=0 makes /proc/<pid>/mem root-only even for the same uid.
#ifdef PR_SET_DUMPABLE
    (void)::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

[[nodiscard]] bool daemonise() noexcept {
    const pid_t pid = ::fork();
    if (pid < 0) {
        std::fprintf(stderr, "hyprnovad: fork failed: %s\n", std::strerror(errno));
        return false;
    }
    if (pid > 0) ::_exit(0);   // parent exits; the child is reparented to init
    if (::setsid() < 0) return false;
    // Second fork so the daemon can never reacquire a controlling terminal.
    const pid_t pid2 = ::fork();
    if (pid2 < 0) return false;
    if (pid2 > 0) ::_exit(0);
    (void)::chdir("/");
    (void)::umask(0027);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path = "/etc/hyprnova/agent.json";
    bool foreground = false;
    bool verbose = false;
    bool quiet = false;
    bool dry_run = false;
    bool self_test_only = false;
    bool describe_only = false;
    bool dump_config = false;

    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        auto next = [&](std::string_view what) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "hyprnovad: %s requires an argument\n",
                             std::string(what).c_str());
                ::_exit(2);
            }
            return argv[++i];
        };
        if (a == "-c" || a == "--config") config_path = next("config path");
        else if (a == "-f" || a == "--foreground") foreground = true;
        else if (a == "-v" || a == "--verbose") verbose = true;
        else if (a == "-q" || a == "--quiet") quiet = true;
        else if (a == "-n" || a == "--dry-run") dry_run = true;
        else if (a == "--self-test") self_test_only = true;
        else if (a == "--describe") describe_only = true;
        else if (a == "--dump-config") dump_config = true;
        else if (a == "--version") {
            std::printf("%.*s (hyprnova core) %s\n",
                        static_cast<int>(hyprnova::core::kProductName.size()), hyprnova::core::kProductName.data(),
                        std::string(kVersion).c_str());
            return 0;
        }
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else {
            std::fprintf(stderr, "hyprnovad: unknown option '%s'\n", std::string(a).c_str());
            usage(argv[0]);
            return 2;
        }
    }

    if (dump_config) {
        // Emit a fully-populated default so an operator never has to guess a key
        // name; the file is the documentation.
        const auto cfg = hyprnova::core::default_config();
        std::printf("%s\n", hyprnova::core::to_json(cfg).dump().c_str());
        return 0;
    }

    if (describe_only) {
        hyprnova::Agent agent;
        if (!agent.init(config_path)) return 1;
        std::printf("%s\n", hyprnova::core::describe(agent.config()).c_str());
        return 0;
    }

    hyprnova::Agent agent;
    if (!agent.init(config_path)) {
        std::fprintf(stderr, "hyprnovad: initialisation failed; see the log above\n");
        return 1;
    }
    if (verbose) hyprnova::core::logger().set_level(hyprnova::core::LogLevel::Debug);
    if (quiet) hyprnova::core::logger().set_level(hyprnova::core::LogLevel::Warn);
    if (dry_run) {
        agent.force_dry_run();
        SWARN("main", "--dry-run on the command line: no containment action will be taken");
    }

    if (self_test_only) {
        const auto st = agent.self_test();
        for (const auto& c : st.checks) std::printf("%s\n", c.c_str());
        std::printf("%s (%zu checks)\n", st.passed ? "SELF-TEST PASSED" : "SELF-TEST FAILED",
                    st.checks.size());
        return st.passed ? 0 : 1;
    }

    raise_fd_limit();
    harden_self();

    if (!foreground) {
        // Under systemd the unit sets Type=notify or Type=simple and we should stay
        // in the foreground; daemonise only when started by hand or from an init
        // script that expects it.
        const bool under_systemd = ::getppid() == 1 || !std::string_view(::getenv("INVOCATION_ID") ? ::getenv("INVOCATION_ID") : "").empty();
        if (under_systemd) {
            SINFO("main", "started by an init system; staying in the foreground");
        } else if (!daemonise()) {
            std::fprintf(stderr, "hyprnovad: could not daemonise: %s\n", std::strerror(errno));
            return 1;
        }
    }

    if (!agent.start()) {
        std::fprintf(stderr, "hyprnovad: startup failed\n");
        return 1;
    }
    agent.run();     // returns after SIGTERM/SIGINT
    agent.stop();    // idempotent
    return 0;
}
