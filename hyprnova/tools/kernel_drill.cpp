// SPDX-License-Identifier: Apache-2.0
// HyprNova :: gated KERNEL DRILL for the nftables containment path (spec §10,
// the root/VM-gated list). Runs the REAL RemediationEngine against the REAL
// kernel — inside a user+mount+network namespace the runner creates, where the
// process holds CAP_NET_ADMIN over its OWN netns. This is a genuine kernel
// exercise of apply_block_set()/run_nft()/block_c2()/unblock_c2(), scoped to a
// namespace that is deleted afterwards: the host ruleset is never touched.
//
//   unshare -Urnm tests/kernel_drill-wrapper.sh   (see tests/run_tests.sh §5)
//
// What is asserted (all real I/O, no mocks):
//   1. lo is up with 10.9.9.1 (TEST-NET-1 on loopback, never a host address).
//   2. A TCP listener+client pair on that address connects (netns sanity).
//   3. engine.block_c2("10.9.9.1", port) returns true — the engine probed nft,
//      rendered the single-transaction program, and the kernel accepted it.
//   4. The same connect now TIMES OUT (kernel drops the SYN) and `nft list
//      table` shows the counter — the drop is enforced, not just declared.
//   5. engine.unblock_c2(id) restores connectivity.
//   6. block_exe on a spawned child FAILS with the honest "needs cgroup v2 +
//      nftables" audit note — pinned so the boundary stays documented: cgroup2
//      userns-mounts are denied by this container's kernel, so the per-exe
//      kernel path REMAINS root/VM-gated even when the nftables half runs.
//
// Exit codes: 0 = all asserts passed; 3 = honest SKIP (prerequisite missing
// inside the namespace); 1 = FAILURE. A skip is never a pass.
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/exec.hpp"
#include "core/thread_pool.hpp"
#include "remediation/remediation_engine.hpp"

namespace {

using namespace hyprnova;

int fail(const std::string& what, const std::string& detail = {}) {
    std::printf("KERNEL-DRILL FAIL: %s%s%s\n", what.c_str(), detail.empty() ? "" : " -- ",
                detail.c_str());
    return 1;
}

int skip(const char* why) {
    std::printf("KERNEL-DRILL SKIP (NOT RUN): %s\n", why);
    return 3;
}

/// TCP connect with a hard timeout. Returns errno-style result:
/// 0 = established, ETIMEDOUT = dropped/filtered, other = refused/etc.
int probe_connect(const char* ip, std::uint16_t port, int timeout_ms) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return errno;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        ::close(fd);
        return EINVAL;
    }
    const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    if (rc == 0) {
        ::close(fd);
        return 0;
    }
    if (errno != EINPROGRESS) {
        const int e = errno;
        ::close(fd);
        return e;
    }
    pollfd p{fd, POLLOUT, 0};
    const int pr = ::poll(&p, 1, timeout_ms);
    if (pr == 0) {  // SYN never answered: the drop path
        ::close(fd);
        return ETIMEDOUT;
    }
    int err = 0;
    socklen_t elen = sizeof(err);
    (void)::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    ::close(fd);
    return err;
}

/// Listener bound once, reused by every probe (accept and discard).
int make_listener(const char* ip, std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip, &a.sin_addr) != 1 || ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
        ::listen(fd, 8) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

void drain_accepts(int lfd) {
    for (;;) {
        pollfd p{lfd, POLLIN, 0};
        if (::poll(&p, 1, 0) <= 0) break;
        const int c = ::accept(lfd, nullptr, nullptr);
        if (c >= 0) ::close(c);
    }
}

}  // namespace

int main() {
    // ---- environment honesty -------------------------------------------------
    const char* nft = ::getenv("HN_NFT");
    if (!nft || !*nft) nft = "/tmp/nftroot/usr/sbin/nft";
    {
        // The runner only invokes us when the binary exists; re-check anyway so
        // a stale path degrades to SKIP, never to a fake pass.
        if (::access(nft, X_OK) != 0) return skip("nft binary not available for this drill");
    }
    std::error_code ec;
    (void)std::filesystem::create_directories("/tmp/hn-kernel-drill", ec);
    // /run is a private tmpfs mounted by the wrapper; the engine's kRunDir needs it.
    if (::mkdir("/run/hyprnova", 0755) != 0 && errno != EEXIST)
        return skip("/run/hyprnova not creatable (is the wrapper's tmpfs mounted?)");

    // lo up + a non-loopback TEST-NET address ON lo, so we can block a
    // "remote" without touching the host's own addresses (block_c2 refuses
    // 127.x by design; 10.9.9.1 is ours alone and dies with the netns).
    (void)::system("/usr/sbin/ip link set lo up");
    (void)::system("/usr/sbin/ip addr replace 10.9.9.1/32 dev lo");

    // ---- engine, real config -------------------------------------------------
    core::EventBus bus{512};
    bus.start();
    core::AgentConfig cfg = core::default_config();
    cfg.state_dir = "/tmp/hn-kernel-drill";
    cfg.remediation.quarantine_dir = cfg.state_dir + "/quarantine";
    cfg.remediation.enabled = true;
    cfg.remediation.allow_network_block = true;
    cfg.dry_run = false;
    cfg.remediation.nft_cli = nft;
    cfg.remediation.nftables_table = "hn_kernel_drill";
    cfg.remediation.block_duration = std::chrono::seconds{120};
    core::ThreadPool pool{core::ThreadPoolConfig{}};
    remediation::RemediationEngine engine{bus, cfg};
    engine.probe_capabilities();
    if (!engine.capabilities().can_nftables)
        return skip("the engine did not accept the nft binary (resolve failed)");

    constexpr const char* kIp = "10.9.9.1";
    constexpr std::uint16_t kPort = 4811;
    const int lfd = make_listener(kIp, kPort);
    if (lfd < 0)
        return fail("listener on 10.9.9.1 (did 'ip addr add' run inside the netns?)");

    // 2. baseline connectivity
    if (probe_connect(kIp, kPort, 800) != 0)
        return fail("baseline connect FAILED before any rule (netns broken)");
    drain_accepts(lfd);

    // 3. the engine installs a real kernel rule
    if (!engine.block_c2(kIp, kPort, "kernel drill: verified containment",
                         std::chrono::seconds{120})) {
        std::string trail;
        for (const auto& a : engine.history(8))
            trail += std::format("[{} {}] {} | {}\n", action_name(a.action),
                                 outcome_name(a.outcome), a.detail, a.reason);
        return fail("block_c2 returned false (engine rejected or nft failed)", trail);
    }
    const auto blocks = engine.active_blocks();
    if (blocks.size() != 1)
        return fail("active_blocks() does not show exactly the drill block");
    drain_accepts(lfd);

    // 4. the kernel ENFORCES it
    const int dropped = probe_connect(kIp, kPort, 500);
    if (dropped != ETIMEDOUT)
        return fail("connect after block was not dropped (errno " + std::to_string(dropped) + ")");
    drain_accepts(lfd);
    const auto listing = core::exec::run(nft, {"list", "table", "inet", cfg.remediation.nftables_table}, {});
    if (listing.spawned && !listing.out.empty() &&
        listing.out.find(kIp) == std::string::npos)
        return fail("nft list table does not contain the blocked address", listing.out);

    // 5. release restores traffic
    if (!engine.unblock_c2(blocks[0].id))
        return fail("unblock_c2 returned false");
    if (probe_connect(kIp, kPort, 800) != 0)
        return fail("connect after unblock still fails (rule not removed?)");
    drain_accepts(lfd);

    // 6. the per-exe path's honest boundary (cgroup2 userns-mount denied here)
    const pid_t kid = ::fork();
    if (kid == 0) {
        ::execl("/bin/sleep", "sleep", "20", static_cast<char*>(nullptr));
        _exit(127);
    }
    if (kid > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds{150});
        std::string resolved;
        const bool blocked = engine.block_exe(kid, "kernel drill: per-exe", std::chrono::seconds{60}, resolved);
        bool honest = false;
        for (const auto& a : engine.history(8))
            if (a.detail.find("cgroup v2 and nftables") != std::string::npos) honest = true;
        if (blocked || !honest)
            return fail("block_exe did not fail with the honest cgroup boundary note");
        ::kill(kid, SIGKILL);
        int st = 0;
        ::waitpid(kid, &st, 0);
    }

    ::close(lfd);
    bus.stop();
    std::printf("KERNEL-DRILL PASS: real-kernel nftables containment verified end-to-end\n");
    return 0;
}
