// SPDX-License-Identifier: Apache-2.0
// HyprNova :: GUI <-> daemon IPC bridge implementation
//
// Threading model, which is the part that matters for "no GUI frame drops":
//
//   * One jthread runs epoll over the listening socket plus every connected
//     client. Commands are answered on that thread; they are all snapshot reads of
//     already-computed state, so they are microseconds, not milliseconds.
//   * The event broadcaster runs on the EventBus dispatcher thread. It serialises
//     each event once and writes it to every client. Serialising once rather than
//     once-per-client is what keeps a 200 event/s host from costing 200xN work.
//   * Writes are non-blocking. A client that stops reading gets frames dropped and
//     is counted as "slow" -- it is never allowed to apply back-pressure to the
//     detection pipeline. A frozen dashboard is a GUI bug; a stalled sensor is an
//     incident.
//
// Authorisation is by SO_PEERCRED. The socket file itself is 0660 root:hyprnova,
// but file permissions alone are not the control: an unprivileged process that can
// connect must still be refused, because the socket carries state (process lists,
// file paths) that is itself sensitive.

#include "tools/analysis.hpp"
#include "gui/gui_bridge.hpp"

#include "ai/analyst.hpp"
#include "remediation/shadow_copy.hpp"
#include "remediation/shredder.hpp"

#include <fstream>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <format>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include "agent/agent.hpp"
#include "anti_ransomware/canary.hpp"
#include "anti_ransomware/file_monitor.hpp"
#include "anti_ransomware/honeypot.hpp"
#include "behavioral/audit_sensor.hpp"
#include "behavioral/falco_sensor.hpp"
#include "behavioral/osquery_sensor.hpp"
#include "core/exec.hpp"
#include "forensics/mem_inspect.hpp"
#include "core/log.hpp"
#include "core/proc.hpp"
#include "behavioral/socket_source.hpp"
#include "hardening/boot_auditor.hpp"
#include "hardening/kernel_hardening.hpp"
#include "hardening/mac_profile.hpp"
#include "scanning/carver.hpp"
#include "scanning/scanner.hpp"
#include "core/hash.hpp"

namespace hyprnova {

using namespace std::chrono_literals;
namespace fsx = core::fsx;
using core::json::Array;
using core::json::Object;
using core::json::Value;

namespace {

constexpr std::size_t kMaxClients = 8;
constexpr std::size_t kMaxLineBytes = 1 << 20;
constexpr std::size_t kMaxFrameBytes = 8 << 20;

[[nodiscard]] std::int64_t epoch(core::SysClock::time_point t) noexcept {
    return static_cast<std::int64_t>(core::SysClock::to_time_t(t));
}

[[nodiscard]] Value arr(const std::vector<std::string>& in) noexcept {
    Array a;
    a.reserve(in.size());
    for (const auto& s : in) a.emplace_back(s);
    return Value{std::move(a)};
}

[[nodiscard]] Value to_json(const core::TelemetryEvent& ev) noexcept {
    Object o;
    o["id"] = static_cast<std::int64_t>(ev.monotonic_id);
    o["ts"] = epoch(ev.ts);
    o["sensor"] = std::string(core::sensor_name(ev.sensor));
    o["kind"] = std::string(core::kind_name(ev.kind));
    o["severity"] = std::string(core::severity_name(ev.severity));
    o["severity_rank"] = static_cast<std::int64_t>(ev.severity);
    o["message"] = ev.message;
    o["risk"] = static_cast<std::int64_t>(ev.risk_score);
    o["metric"] = ev.metric;
    o["count"] = static_cast<std::int64_t>(ev.count);
    o["escalated"] = ev.escalated;
    o["triggers"] = arr(ev.triggers);

    Object a;
    a["pid"] = static_cast<std::int64_t>(ev.actor.pid);
    a["ppid"] = static_cast<std::int64_t>(ev.actor.ppid);
    a["uid"] = static_cast<std::int64_t>(ev.actor.uid);
    a["exe"] = ev.actor.exe;
    a["comm"] = ev.actor.comm;
    a["cmdline"] = ev.actor.cmdline;
    a["cwd"] = ev.actor.cwd;
    a["container"] = ev.actor.container_id;
    a["in_container"] = ev.actor.in_container;
    o["actor"] = Value{std::move(a)};

    Object t;
    t["path"] = ev.target.path;
    t["peer_ip"] = ev.target.peer_ip;
    t["peer_port"] = static_cast<std::int64_t>(ev.target.peer_port);
    t["local_port"] = static_cast<std::int64_t>(ev.target.local_port);
    t["rule_id"] = ev.target.rule_id;
    t["family"] = ev.target.family;
    o["target"] = Value{std::move(t)};

    Object f;
    for (const auto& [k, v] : ev.fields) f[k] = v;
    o["fields"] = Value{std::move(f)};
    return Value{std::move(o)};
}

[[nodiscard]] std::string lockdown_mode_name(hardening::LockdownMode m) noexcept {
    switch (m) {
        case hardening::LockdownMode::None: return "none";
        case hardening::LockdownMode::Integrity: return "integrity";
        case hardening::LockdownMode::Confidentiality: return "confidentiality";
        case hardening::LockdownMode::Unavailable: return "unavailable";
    }
    return "unknown";
}

[[nodiscard]] std::string canary_verdict_name(anti_ransomware::CanaryVerdict v) noexcept {
    switch (v) {
        case anti_ransomware::CanaryVerdict::Ok: return "ok";
        case anti_ransomware::CanaryVerdict::Missing: return "missing";
        case anti_ransomware::CanaryVerdict::Modified: return "modified";
        case anti_ransomware::CanaryVerdict::Tampered: return "tampered";
        case anti_ransomware::CanaryVerdict::Unreadable: return "unreadable";
        case anti_ransomware::CanaryVerdict::Malformed: return "malformed";
    }
    return "unknown";
}

[[nodiscard]] std::string socket_state_name(behavioral::UnixSocketSource::State s) noexcept {
    switch (s) {
        case behavioral::UnixSocketSource::State::Disconnected: return "disconnected";
        case behavioral::UnixSocketSource::State::Connecting: return "connecting";
        case behavioral::UnixSocketSource::State::Connected: return "connected";
        case behavioral::UnixSocketSource::State::Failed: return "failed";
        case behavioral::UnixSocketSource::State::Disabled: return "disabled";
    }
    return "unknown";
}

}  // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

GuiBridge::GuiBridge(Agent& agent, core::EventBus& bus, const core::AgentConfig& cfg)
    : agent_(agent), bus_(bus), cfg_(cfg), path_(cfg.gui.ipc_socket) {}

GuiBridge::~GuiBridge() { stop(); }

void GuiBridge::allow_uid(uid_t uid) noexcept {
    std::lock_guard lk{clients_mu_};
    if (std::find(allowed_uids_.begin(), allowed_uids_.end(), uid) == allowed_uids_.end())
        allowed_uids_.push_back(uid);
}

bool GuiBridge::auth_decision(uid_t uid, uid_t daemon_uid,
                              const std::optional<gid_t>& operator_gid,
                              bool in_group) noexcept {
    if (uid == 0) return true;           // root always
    if (uid == daemon_uid) return true;  // the daemon's own console/CLI
    if (operator_gid && in_group) return true;  // operator group member
    return false;
}

bool GuiBridge::os_user_in_group(uid_t uid, gid_t gid) noexcept {
    const ::passwd* pw = ::getpwuid(uid);
    if (!pw) return false;  // unknown uid: no membership to speak of
    if (pw->pw_gid == gid) return true;  // primary group
    // Supplementary groups. getgrouplist reports the needed size by failing;
    // start from a generous buffer so the common case is one call.
    std::vector<gid_t> gids(128, 0);
    int got = static_cast<int>(gids.size());
    if (::getgrouplist(pw->pw_name, pw->pw_gid, gids.data(), &got) < 0) {
        const int needed = got;
        if (needed <= 0) return false;
        gids.resize(static_cast<std::size_t>(needed), 0);
        got = needed;
        if (::getgrouplist(pw->pw_name, pw->pw_gid, gids.data(), &got) < 0) return false;
    }
    gids.resize(static_cast<std::size_t>(got > 0 ? got : 0));
    return std::find(gids.begin(), gids.end(), gid) != gids.end();
}

bool GuiBridge::group_member_cached(uid_t uid) const {
    {
        std::lock_guard lk{clients_mu_};
        const auto it = group_cache_.find(uid);
        if (it != group_cache_.end()) return it->second;
    }
    const bool member = os_user_in_group(uid, *ipc_group_gid_);
    std::lock_guard lk{clients_mu_};
    group_cache_.emplace(uid, member);
    return member;
}

bool GuiBridge::authorised(uid_t uid) noexcept {
    const uid_t self = ::geteuid();
    const bool in_grp = ipc_group_gid_ && group_member_cached(uid);
    if (auth_decision(uid, self, ipc_group_gid_, in_grp)) return true;
    // Explicit operator allow-list still wins (set up at construction time).
    std::lock_guard lk{clients_mu_};
    return std::find(allowed_uids_.begin(), allowed_uids_.end(), uid) != allowed_uids_.end();
}

bool GuiBridge::start() noexcept {
    if (running_.load()) return true;

    // Create the parent directory: on a fresh install /run/hyprnova may not exist
    // yet, and failing here would silently leave the operator with no console.
    const std::size_t slash = path_.find_last_of('/');
    if (slash != std::string::npos && slash > 0) (void)fsx::mkdir_p(path_.substr(0, slash), 0755);

    // Remove a stale socket left by a crashed daemon. bind() on an existing
    // pathname fails with EADDRINUSE even when nothing is listening.
    if (fsx::exists(path_)) {
        // Refuse to unlink something that is not a socket: if an attacker has
        // planted a symlink or a regular file there, deleting it is their win.
        struct stat st {};
        if (::lstat(path_.c_str(), &st) == 0 && S_ISSOCK(st.st_mode)) {
            (void)::unlink(path_.c_str());
        } else {
            last_error_ = path_ + " exists and is not a socket; refusing to remove it";
            return false;
        }
    }

    core::UniqueFd fd{::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0)};
    if (!fd) {
        last_error_ = std::string("socket(AF_UNIX): ") + std::strerror(errno);
        return false;
    }
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(addr.sun_path)) {
        last_error_ = "ipc_socket path exceeds the sun_path limit";
        return false;
    }
    std::memcpy(addr.sun_path, path_.c_str(), path_.size());

    if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        last_error_ = std::string("bind(") + path_ + "): " + std::strerror(errno);
        return false;
    }
    // Resolve the operator group ONCE. An absent group degrades honestly (log
    // line, same-uid auth continues) — it never fails the bridge, per the
    // degrade-not-fail rule.
    ipc_group_ = cfg_.gui.ipc_group;
    ipc_group_gid_.reset();
    {
        std::lock_guard lk{clients_mu_};
        group_cache_.clear();
    }
    if (!ipc_group_.empty()) {
        if (const ::group* g = ::getgrnam(ipc_group_.c_str())) {
            ipc_group_gid_ = g->gr_gid;
            SINFO("gui-bridge", "operator group {} (gid {}) may connect to {}", ipc_group_,
                  *ipc_group_gid_, path_);
        } else {
            SWARN("gui-bridge",
                  "operator group '{}' does not exist on this host: only root and uid {} "
                  "may connect (group auth off, same-uid auth on)",
                  ipc_group_, ::geteuid());
        }
    }

    // 0660 <root>:<operator group>. The group bit is what lets an unprivileged
    // operator console CONNECT; world access would expose process and path
    // inventory to every user. The chown needs root (an unprivileged dev run
    // keeps its own ownership; EPERM is expected, not an error).
    if (::chmod(path_.c_str(), 0660) != 0)
        SWARN("gui-bridge", "chmod 0660 {} failed: {}", path_, std::strerror(errno));
    const gid_t sock_gid = ipc_group_gid_ ? *ipc_group_gid_ : 0;
    if (::chown(path_.c_str(), 0, sock_gid) != 0 && errno != EPERM)
        SDEBUG("gui-bridge", "chown {} to group {} failed: {}", path_, sock_gid,
               std::strerror(errno));

    if (::listen(fd.get(), static_cast<int>(kMaxClients)) != 0) {
        last_error_ = std::string("listen: ") + std::strerror(errno);
        return false;
    }
    // Remember the filesystem node bind() created so stop() can unlink exactly
    // it (and not a successor's socket) at shutdown.
    struct stat st_own {};
    if (::stat(path_.c_str(), &st_own) == 0) {
        own_sock_ino_ = st_own.st_ino;
        own_sock_dev_ = st_own.st_dev;
    }
    listen_fd_ = std::move(fd);

    // Subscribe before the acceptor starts so a client that connects immediately
    // still receives live events.
    sub_id_ = bus_.subscribe("gui-bridge", [this](const core::TelemetryEvent& ev) { on_event(ev); });

    running_.store(true, std::memory_order_release);
    acceptor_ = std::jthread([this](std::stop_token st) { accept_loop(st); });
    return true;
}

void GuiBridge::stop() noexcept {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        if (sub_id_ != 0) {
            bus_.unsubscribe(sub_id_);
            sub_id_ = 0;
        }
        return;
    }
    // Tell every connected console why it is about to go dark. A GUI that simply
    // loses its socket shows a spinner forever; one that receives a shutdown frame
    // can say "agent stopped".
    Object bye;
    bye["event"] = std::string("agent.shutdown");
    bye["reason"] = std::string("hyprnovad is stopping");
    bye["resume_hint"] = std::string("frozen processes are being resumed and firewall blocks removed");
    broadcast(Value{std::move(bye)}.dump() + "\n");

    if (acceptor_.joinable()) acceptor_.request_stop();
    if (listen_fd_) {
        // Closing the listening fd makes the pending accept() fail, which is what
        // actually wakes the thread; request_stop alone would not.
        const int lfd = listen_fd_.release();
        ::shutdown(lfd, SHUT_RDWR);
        ::close(lfd);
    }
    if (acceptor_.joinable()) acceptor_.join();

    {
        std::lock_guard lk{clients_mu_};
        for (auto& [fd, c] : clients_) {
            ::shutdown(fd, SHUT_RDWR);
            c.fd.reset();
        }
        clients_.clear();
    }
    if (sub_id_ != 0) {
        bus_.unsubscribe(sub_id_);
        sub_id_ = 0;
    }
    // Unlink the socket path ONLY if it is still OUR socket. Two daemons sharing a
    // path (a systemd restart racing a slow shutdown, a manual start beside the
    // service) means the path may already belong to the newer process; blindly
    // unlinking it would delete the live daemon's socket and make every console
    // connection fail with ENOENT until the next restart. Compare the inode of the
    // path with the inode of the listening fd we are about to lose: if they differ,
    // the path is not ours and we leave it alone.
    if (!path_.empty()) {
        // Unlink ONLY the node our bind created: compare against the inode
        // recorded at start(). (fstat on a bound AF_UNIX socket returns the
        // sockfs pseudo-inode, which NEVER matches the filesystem node -- the
        // old fd-based comparison could not ever succeed.) If a newer daemon
        // has replaced the path in the meantime, the inodes differ and we
        // leave their socket alone.
        struct stat st_path {};
        if (own_sock_ino_ != 0 && ::stat(path_.c_str(), &st_path) == 0 &&
            S_ISSOCK(st_path.st_mode) && st_path.st_ino == own_sock_ino_ &&
            st_path.st_dev == own_sock_dev_) {
            (void)::unlink(path_.c_str());
        }
    }
}

std::size_t GuiBridge::clients() const noexcept {
    std::lock_guard lk{clients_mu_};
    return clients_.size();
}

std::string GuiBridge::last_error() const noexcept {
    std::lock_guard lk{clients_mu_};
    return last_error_;
}

// ---------------------------------------------------------------------------
// Acceptor / reader loop
// ---------------------------------------------------------------------------

void GuiBridge::accept_loop(std::stop_token st) noexcept {
    auto epoll = core::EpollSet::create();
    if (!epoll) {
        SWARN("gui-bridge", "epoll_create failed ({}): the GUI cannot connect", epoll.message());
        running_.store(false);
        return;
    }
    auto wake = core::WakeupEvent::create();
    if (!wake) SWARN("gui-bridge", "eventfd creation failed; shutdown may block up to 200ms");

    const int lfd = listen_fd_.get();
    if (!epoll->add(lfd, EPOLLIN, reinterpret_cast<void*>(static_cast<std::intptr_t>(-1)))) {
        SWARN("gui-bridge", "epoll_ctl(listen) failed: {}", std::strerror(errno));
        running_.store(false);
        return;
    }
    if (wake) {
        (void)epoll->add(wake->fd(), EPOLLIN, reinterpret_cast<void*>(static_cast<std::intptr_t>(-2)));
    }

    SINFO("gui-bridge", "listening on {} (max {} clients, frame limit {} KiB)", path_, kMaxClients,
          kMaxFrameBytes / 1024);

    while (!st.stop_requested() && running_.load(std::memory_order_acquire)) {
        const auto ready = epoll->wait(200);
        for (const auto& ev : ready) {
            const auto tag = reinterpret_cast<std::intptr_t>(ev.data.ptr);
            if (tag == -2) {
                if (wake) wake->drain();
                continue;
            }
            if (tag == -1) {
                // ---- accept ----
                for (int i = 0; i < 8; ++i) {   // bounded: a connect flood cannot starve reads
                    sockaddr_un peer {};
                    socklen_t plen = sizeof(peer);
                    const int cfd = ::accept4(lfd, reinterpret_cast<sockaddr*>(&peer), &plen,
                                              SOCK_CLOEXEC | SOCK_NONBLOCK);
                    if (cfd < 0) break;

                    // Peer credentials before anything else: an unauthorised peer
                    // must not learn even that the agent is running.
                    ucred cred {};
                    socklen_t clen = sizeof(cred);
                    if (::getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0 ||
                        !authorised(cred.uid)) {
                        SWARN("gui-bridge",
                              "refused connection from uid {} pid {}: not root, not this "
                              "daemon's uid, and not in the operator group",
                              cred.uid, cred.pid);
                        Object deny;
                        deny["ok"] = false;
                        deny["error"] = std::string("unauthorised: uid ") + std::to_string(cred.uid) +
                                      " is not permitted to query the agent";
                        const std::string frame = Value{std::move(deny)}.dump() + "\n";
                        (void)::send(cfd, frame.data(), frame.size(), MSG_NOSIGNAL);
                        ::close(cfd);
                        continue;
                    }

                    std::lock_guard lk{clients_mu_};
                    // Reap dead entries first. A client whose send failed is closed
                    // (c.fd == null) but stays in the map until the event loop sees
                    // it, and epoll auto-removes a closed fd so the loop NEVER sees
                    // it: the entry is a zombie. Worse, the fd number is then reused
                    // by the next accept, and emplace() on the existing key fails
                    // silently -- destroying the local Client and closing the
                    // brand-new connection. Every connection after the first zombie
                    // would be refused. Erasing the zombie here is safe: its fd is
                    // already closed (UniqueFd is null, so the erase does not
                    // double-close), and the live count below ignores the rest.
                    std::size_t live = 0;
                    for (auto it = clients_.begin(); it != clients_.end();) {
                        if (!it->second.fd) it = clients_.erase(it);
                        else { ++live; ++it; }
                    }
                    if (live >= kMaxClients) {
                        SWARN("gui-bridge", "client limit {} reached; refusing uid {}", kMaxClients,
                              cred.uid);
                        Object busy;
                        busy["ok"] = false;
                        busy["error"] = std::string("too many GUI clients (limit ") +
                                      std::to_string(kMaxClients) + ")";
                        const std::string frame = Value{std::move(busy)}.dump() + "\n";
                        (void)::send(cfd, frame.data(), frame.size(), MSG_NOSIGNAL);
                        ::close(cfd);
                        continue;
                    }
                    Client c;
                    c.fd = core::UniqueFd{cfd};
                    c.uid = cred.uid;
                    c.pid = cred.pid;
                    c.connected = core::SysClock::now();
                    (void)epoll->add(cfd, EPOLLIN, reinterpret_cast<void*>(static_cast<std::intptr_t>(cfd)));
                    const auto [it, inserted] = clients_.emplace(cfd, std::move(c));
                    if (!inserted) {
                        // Cannot happen after the reap above; guard anyway so a
                        // future refactor cannot reintroduce the silent-close bug.
                        SWARN("gui-bridge", "internal: client fd {} already tracked; refusing", cfd);
                        ::close(cfd);
                        continue;
                    }
                    SINFO("gui-bridge", "GUI connected: uid {} pid {} fd {} ({} client(s))", cred.uid,
                          cred.pid, cfd, live + 1);
                }
                continue;
            }

            // ---- client readable ----
            const int cfd = static_cast<int>(tag);
            Client* cp = nullptr;
            {
                std::lock_guard lk{clients_mu_};
                auto it = clients_.find(cfd);
                if (it != clients_.end()) cp = &it->second;
            }
            if (!cp) {
                (void)epoll->remove(cfd);
                continue;
            }
            on_readable(*cp);
            if (!cp->fd) {  // on_readable closed it
                (void)epoll->remove(cfd);
                std::lock_guard lk{clients_mu_};
                clients_.erase(cfd);
            }
        }
    }
    SINFO("gui-bridge", "accept loop exiting");
}

void GuiBridge::on_readable(Client& c) noexcept {
    char buf[8192];
    for (int pass = 0; pass < 16; ++pass) {
        if (!c.fd) return;  // closed mid-dispatch (e.g. the reply send failed)
        const ssize_t n = ::recv(c.fd.get(), buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            c.rx.append(buf, static_cast<std::size_t>(n));
            if (c.rx.size() > kMaxLineBytes) {
                // An unterminated line that large is a protocol violation or an
                // attempt to make us allocate. Drop the connection.
                SWARN("gui-bridge", "client uid {} exceeded the {} byte line limit; disconnecting",
                      c.uid, kMaxLineBytes);
                c.rx.clear();
                c.fd.reset();
                return;
            }
            // Split complete lines and dispatch each.
            std::size_t pos = 0;
            for (;;) {
                const std::size_t nl = c.rx.find('\n', pos);
                if (nl == std::string::npos) break;
                std::string_view line{c.rx.data() + pos, nl - pos};
                while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                    line.remove_suffix(1);
                pos = nl + 1;
                if (line.empty()) continue;
                if (!handle_line(c, line)) {
                    c.rx.clear();
                    c.fd.reset();
                    return;
                }
            }
            c.rx.erase(0, pos);
            continue;
        }
        if (n == 0) {  // orderly disconnect
            SINFO("gui-bridge", "GUI disconnected: uid {} pid {} ({} frames sent)", c.uid, c.pid,
                  c.frames);
            c.fd.reset();
            return;
        }
        if (core::would_block(errno)) return;
        if (errno == EINTR) continue;
        SWARN("gui-bridge", "recv from uid {} failed: {}; disconnecting", c.uid, std::strerror(errno));
        c.fd.reset();
        return;
    }
}

bool GuiBridge::handle_line(Client& c, std::string_view line) noexcept {
    core::json::ParseError pe {};
    auto req = core::json::parse(line, {}, &pe);
    if (!req || !req->is_object()) {
        Object err;
        err["ok"] = false;
        err["error"] = std::string("malformed JSON at offset ") + std::to_string(pe.offset) + ": " +
                     pe.message;
        send_to(c, Value{std::move(err)}.dump() + "\n");
        return true;  // keep the connection: a typo must not disconnect the console
    }
    const std::string cmd = req->str("cmd");
    if (cmd.empty()) {
        Object err;
        err["ok"] = false;
        err["error"] = std::string("missing \"cmd\" field");
        send_to(c, Value{std::move(err)}.dump() + "\n");
        return true;
    }

    Value reply;
    try {
        reply = dispatch(cmd, *req, c.uid);
    } catch (const std::exception& e) {
        // A throwing snapshot builder must not take down the bridge, and certainly
        // not the daemon: the GUI is the least privileged part of the system.
        SERROR("gui-bridge", "handler for '{}' threw: {}", cmd, e.what());
        Object err;
        err["ok"] = false;
        err["cmd"] = cmd;
        err["error"] = std::string("internal error: ") + e.what();
        reply = Value{std::move(err)};
    }
    commands_.fetch_add(1, std::memory_order_relaxed);
    send_to(c, reply.dump() + "\n");
    return true;
}

void GuiBridge::send_to(Client& c, std::string_view frame) noexcept {
    if (!c.fd) return;
    if (frame.size() > kMaxFrameBytes) {
        SWARN("gui-bridge", "refusing to send a {} byte frame to uid {} (limit {})", frame.size(), c.uid,
              kMaxFrameBytes);
        return;
    }
    std::size_t sent = 0;
    // Bounded retry: a non-blocking socket can short-write. We never block here,
    // because blocking would stall the bus dispatcher for every other client.
    for (int attempt = 0; attempt < 8 && sent < frame.size(); ++attempt) {
        const ssize_t n = ::send(c.fd.get(), frame.data() + sent, frame.size() - sent,
                                 MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (core::would_block(errno))) {
            // The client's receive buffer is full: it is not reading fast enough.
            // Drop rather than grow without bound -- a GUI that cannot keep up
            // must not become an OOM vector for a root daemon.
            SWARN("gui-bridge", "client uid {} is not draining its socket; dropping a {} byte frame",
                  c.uid, frame.size() - sent);
            ++c.frames;
            return;
        }
        if (n < 0 && errno == EINTR) continue;
        SWARN("gui-bridge", "send to uid {} failed: {}; disconnecting", c.uid, std::strerror(errno));
        c.fd.reset();
        return;
    }
    ++c.frames;
    frames_.fetch_add(1, std::memory_order_relaxed);
}

void GuiBridge::broadcast(std::string_view frame) noexcept {
    std::lock_guard lk{clients_mu_};
    for (auto it = clients_.begin(); it != clients_.end();) {
        Client& c = it->second;
        if (!c.fd) { it = clients_.erase(it); continue; }  // reap zombies promptly
        if (!c.wants_events) { ++it; continue; }
        send_to(c, frame);
        // send_to may have closed the fd on error; reap immediately so the entry
        // cannot collide with a reused fd number at the next accept.
        if (!c.fd) it = clients_.erase(it); else ++it;
    }
}

void GuiBridge::on_event(const core::TelemetryEvent& ev) noexcept {
    // Keep the history ring for clients that connect mid-flight.
    {
        std::lock_guard lk{hist_mu_};
        history_.push_back(ev);
        while (history_.size() > cfg_.gui.event_feed_max) history_.pop_front();
    }
    if (!running_.load(std::memory_order_relaxed)) return;
    {
        std::lock_guard lk{clients_mu_};
        if (clients_.empty()) return;  // no console attached: skip serialisation entirely
    }
    if (!cfg_.gui.show_kernel_events && ev.severity == core::Severity::Info &&
        ev.kind != core::EventKind::UserActionRequired && ev.kind != core::EventKind::RemediationApplied &&
        ev.kind != core::EventKind::Heartbeat) {
        return;  // the feed is for things an operator would act on -- and the
                 // heartbeat, which is the sign of life a watch console waits for
    }
    Object frame;
    frame["event"] = std::string("telemetry");
    frame["data"] = to_json(ev);
    broadcast(Value{std::move(frame)}.dump() + "\n");
}

void GuiBridge::prime_history(std::size_t n) noexcept {
    std::lock_guard lk{hist_mu_};
    while (history_.size() > n) history_.pop_front();
}

std::vector<core::TelemetryEvent> GuiBridge::history(std::size_t n) const noexcept {
    std::lock_guard lk{hist_mu_};
    std::vector<core::TelemetryEvent> out;
    const std::size_t take = std::min(n, history_.size());
    out.reserve(take);
    for (std::size_t i = history_.size() - take; i < history_.size(); ++i) out.push_back(history_[i]);
    return out;
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

Value GuiBridge::snapshot_overview() const noexcept {
    const auto st = agent_.stats();
    Object o;
    o["version"] = st.version;
    o["uptime"] = static_cast<std::int64_t>(st.uptime_seconds);
    o["pid"] = static_cast<std::int64_t>(::getpid());
    o["euid"] = static_cast<std::int64_t>(::geteuid());
    o["published"] = static_cast<std::int64_t>(st.events_published);
    o["dispatched"] = static_cast<std::int64_t>(st.events_dispatched);
    o["dropped"] = static_cast<std::int64_t>(st.events_dropped);
    o["sensors"] = static_cast<std::int64_t>(st.sensors_running);
    o["degraded"] = static_cast<std::int64_t>(st.sensors_degraded);
    o["pending_decisions"] = static_cast<std::int64_t>(st.pending_decisions);
    o["active_blocks"] = static_cast<std::int64_t>(st.active_blocks);
    o["suspended"] = static_cast<std::int64_t>(st.suspended_pids);
    o["learning"] = st.heuristic_learning_progress;
    o["dry_run"] = agent_.config().dry_run;
    o["auto_respond"] = agent_.config().heuristic.auto_respond;
    o["container"] = core::exec::inside_container();
    o["pool_queued"] = static_cast<std::int64_t>(agent_.pool().queued());
    o["pool_rejected"] = static_cast<std::int64_t>(agent_.pool().rejected());
    o["log_dropped"] = static_cast<std::int64_t>(core::logger().dropped());
    o["gui_clients"] = static_cast<std::int64_t>(this->clients());
    o["gui_frames"] = static_cast<std::int64_t>(frames_.load(std::memory_order_relaxed));

    const auto& caps = agent_.remediation().capabilities();
    Object c;
    c["signal"] = caps.can_signal;
    c["cgroup"] = caps.can_cgroup;
    c["network"] = caps.can_nftables;
    c["quarantine"] = caps.can_quarantine;
    c["notify"] = caps.can_notify;
    c["cgroup_root"] = caps.cgroup_root;
    c["nft_binary"] = caps.nft_binary;
    c["notes"] = arr(caps.notes);
    o["capabilities"] = Value{std::move(c)};

    // Headline posture: the single number the dashboard's big indicator shows.
    // Delegated to the Agent so the heartbeat event and this snapshot can never
    // disagree about the same host.
    o["posture_score"] = static_cast<std::int64_t>(agent_.posture_score());
    o["posture_label"] = agent_.posture_label();
    return Value{std::move(o)};
}

Value GuiBridge::snapshot_sensors() const noexcept {
    Array a;
    for (const auto& h : agent_.sensors().health_snapshot()) {
        Object o;
        o["name"] = h.name;
        o["state"] = std::string(core::state_name(h.state));
        o["detail"] = h.detail;
        o["emitted"] = static_cast<std::int64_t>(h.events_emitted);
        o["dropped"] = static_cast<std::int64_t>(h.events_dropped);
        o["errors"] = static_cast<std::int64_t>(h.errors);
        o["restarts"] = static_cast<std::int64_t>(h.restarts);
        o["cpu"] = h.cpu_percent;
        o["rss"] = static_cast<std::int64_t>(h.rss_bytes);
        o["last_activity"] = epoch(h.last_activity);
        o["started_at"] = epoch(h.started_at);
        o["caps_missing"] = arr(h.capabilities_missing);
        o["deps_missing"] = arr(h.optional_deps_missing);
        a.emplace_back(Value{std::move(o)});
    }
    Object bus;
    for (const auto& s : agent_.bus().stats()) {
        Object so;
        so["name"] = s.name;
        so["delivered"] = static_cast<std::int64_t>(s.delivered);
        so["slow"] = static_cast<std::int64_t>(s.slow);
        bus[s.name] = Value{std::move(so)};
    }
    Object root;
    root["sensors"] = Value{std::move(a)};
    root["bus"] = Value{std::move(bus)};
    root["count"] = static_cast<std::int64_t>(agent_.sensors().count());
    root["degraded"] = static_cast<std::int64_t>(agent_.sensors().degraded_count());
    root["failed"] = static_cast<std::int64_t>(agent_.sensors().failed_count());
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_events(std::size_t n) const noexcept {
    Array a;
    for (const auto& ev : history(n)) a.emplace_back(to_json(ev));
    Object o;
    o["events"] = Value{std::move(a)};
    o["count"] = static_cast<std::int64_t>(a.size());
    return Value{std::move(o)};
}

Value GuiBridge::snapshot_risk() const noexcept {
    auto& h = agent_.heuristics();
    Array a;
    for (const auto& actor : h.top_actors(64)) {
        Object o;
        o["pid"] = static_cast<std::int64_t>(actor.pid);
        o["exe"] = actor.exe;
        o["comm"] = actor.comm;
        o["cmdline"] = actor.cmdline;
        o["uid"] = static_cast<std::int64_t>(actor.uid);
        o["container"] = actor.container_id;
        o["lineage"] = actor.lineage;
        o["score"] = actor.score;
        o["peak"] = actor.peak_score;
        o["severity"] = std::string(core::severity_name(actor.severity));
        o["events"] = static_cast<std::int64_t>(actor.event_count);
        o["distinct_triggers"] = static_cast<std::int64_t>(actor.distinct_triggers);
        o["first_seen"] = epoch(actor.first_seen);
        o["last_update"] = epoch(actor.last_update);
        o["suspended"] = actor.suspended;
        o["inspected"] = actor.inspected;
        o["scanned"] = actor.scanned;
        o["prompted"] = actor.prompted;
        o["alive"] = core::ProcessHandle{actor.pid}.alive();

        Array tr;
        for (const auto& t : actor.trigger_set) tr.emplace_back(t);
        o["triggers"] = Value{std::move(tr)};

        Array fa;
        // Newest first: an analyst reads the most recent evidence first.
        for (auto it = actor.factors.rbegin(); it != actor.factors.rend(); ++it) {
            Object fo;
            fo["trigger"] = it->trigger;
            fo["points"] = static_cast<std::int64_t>(it->points);
            fo["sensor"] = std::string(core::sensor_name(it->sensor));
            fo["severity"] = std::string(core::severity_name(it->severity));
            fo["when"] = epoch(it->when);
            fo["evidence"] = it->evidence;
            fa.emplace_back(Value{std::move(fo)});
            if (fa.size() >= 24) break;
        }
        o["factors"] = Value{std::move(fa)};
        a.emplace_back(Value{std::move(o)});
    }

    Object root;
    root["actors"] = Value{std::move(a)};
    root["alerts"] = static_cast<std::int64_t>(h.alerts_raised());
    root["escalations"] = static_cast<std::int64_t>(h.escalations_run());
    root["observations"] = static_cast<std::int64_t>(h.observations());
    root["learning"] = h.learning();
    root["learning_progress"] = h.learning_progress();
    root["thresholds_alert"] = static_cast<std::int64_t>(agent_.config().heuristic.alert_threshold);
    root["thresholds_critical"] = static_cast<std::int64_t>(agent_.config().heuristic.critical_threshold);
    root["thresholds_auto"] = static_cast<std::int64_t>(agent_.config().heuristic.auto_respond_threshold);

    Array svc;
    for (const auto& s : h.services()) {
        Object so;
        so["daemon"] = s.daemon;
        so["children"] = static_cast<std::int64_t>(s.child_count);
        so["rate_per_min"] = static_cast<std::int64_t>(s.spawn_rate_per_min);
        so["shell_spawned"] = s.shell_spawned;
        so["anomalous_child"] = s.anomalous_child;
        so["child_names"] = arr(s.children);
        svc.emplace_back(Value{std::move(so)});
    }
    root["services"] = Value{std::move(svc)};
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_decisions() const noexcept {
    Array a;
    for (const auto& d : agent_.remediation().pending(32)) {
        Object o;
        o["id"] = static_cast<std::int64_t>(d.id);
        o["raised"] = epoch(d.raised);
        o["recommendation"] = d.recommendation;
        o["answered"] = d.answered;

        const auto& rp = d.report;
        Object r;
        r["pid"] = static_cast<std::int64_t>(rp.pid);
        r["exe"] = rp.exe;
        r["lineage"] = rp.lineage;
        r["risk"] = rp.risk;
        r["severity"] = std::string(core::severity_name(rp.final_severity));
        r["step"] = std::string(heuristics::step_name(rp.reached));
        r["suspended"] = rp.suspended;
        r["resumed"] = rp.resumed;
        r["regions_scanned"] = static_cast<std::int64_t>(rp.regions_scanned);
        r["wx_regions"] = static_cast<std::int64_t>(rp.wx_regions);
        r["findings"] = arr(rp.findings);
        r["memory_matches"] = arr(rp.memory_matches);
        r["scanned_paths"] = arr(rp.scanned_paths);
        r["started"] = epoch(rp.started);
        r["finished"] = epoch(rp.finished);
        o["report"] = Value{std::move(r)};

        Array fa;
        for (const auto& f : rp.factors) {
            Object fo;
            fo["trigger"] = f.trigger;
            fo["points"] = static_cast<std::int64_t>(f.points);
            fo["sensor"] = std::string(core::sensor_name(f.sensor));
            fo["evidence"] = f.evidence;
            fa.emplace_back(Value{std::move(fo)});
        }
        o["factors"] = Value{std::move(fa)};
        o["actions"] = arr({"allow", "suspend", "quarantine", "kill"});
        a.emplace_back(Value{std::move(o)});
    }
    Object root;
    const std::int64_t n_decisions = static_cast<std::int64_t>(a.size());
    root["decisions"] = Value{std::move(a)};
    root["count"] = n_decisions;  // computed BEFORE the move; a moved vector is empty
    root["auto_respond"] = agent_.config().heuristic.auto_respond;
    root["dry_run"] = agent_.config().dry_run;
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_remediation() const noexcept {
    auto& rm = agent_.remediation();
    Array a;
    for (const auto& r : rm.history(200)) {
        Object o;
        o["id"] = static_cast<std::int64_t>(r.id);
        o["action"] = std::string(remediation::action_name(r.action));
        o["outcome"] = std::string(remediation::outcome_name(r.outcome));
        o["pid"] = static_cast<std::int64_t>(r.pid);
        o["target"] = r.target;
        o["reason"] = r.reason;
        o["detail"] = r.detail;
        o["undo"] = r.undo_hint;
        o["severity"] = std::string(core::severity_name(r.severity));
        o["when"] = epoch(r.when);
        o["duration_ms"] = static_cast<std::int64_t>(r.duration.count());
        o["dry_run"] = r.dry_run;
        o["reversible"] = r.reversible;
        a.emplace_back(Value{std::move(o)});
    }
    Array bl;
    for (const auto& b : rm.active_blocks()) {
        Object o;
        o["id"] = static_cast<std::int64_t>(b.id);
        o["ip"] = b.remote_ip;
        o["port"] = static_cast<std::int64_t>(b.remote_port);
        o["reason"] = b.reason;
        o["installed"] = epoch(b.installed);
        o["ttl_seconds"] = static_cast<std::int64_t>(b.ttl.count());
        o["rule"] = b.rule_handle;
        bl.emplace_back(Value{std::move(o)});
    }
    Array q;
    for (const auto& [id, desc] : rm.quarantined()) {
        Object o;
        o["id"] = static_cast<std::int64_t>(id);
        o["desc"] = desc;
        q.emplace_back(Value{std::move(o)});
    }
    Object root;
    root["actions"] = Value{std::move(a)};
    root["blocks"] = Value{std::move(bl)};
    root["quarantine"] = Value{std::move(q)};
    Array sp;
    for (const pid_t p : rm.suspended_pids()) sp.emplace_back(static_cast<std::int64_t>(p));
    root["suspended_pids"] = Value{std::move(sp)};
    root["total_actions"] = static_cast<std::int64_t>(rm.total_actions());
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_scans() const noexcept {
    Object root;
    auto* sc = agent_.sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch);
    if (!sc) {
        root["enabled"] = false;
        root["note"] = std::string("the scanning module is disabled in configuration");
        return Value{std::move(root)};
    }
    const auto c = sc->counters();
    Object cnt;
    cnt["scanned"] = static_cast<std::int64_t>(c.scanned);
    cnt["clean"] = static_cast<std::int64_t>(c.clean);
    cnt["suspicious"] = static_cast<std::int64_t>(c.suspicious);
    cnt["malicious"] = static_cast<std::int64_t>(c.malicious);
    cnt["skipped"] = static_cast<std::int64_t>(c.skipped);
    cnt["cache_hits"] = static_cast<std::int64_t>(c.cache_hits);
    cnt["enqueued"] = static_cast<std::int64_t>(c.enqueued);
    cnt["batches"] = static_cast<std::int64_t>(c.batches);
    cnt["external_detections"] = static_cast<std::int64_t>(c.external_detections);
    cnt["mean_scan_ms"] = c.mean_scan_ms;
    cnt["queue_depth"] = static_cast<std::int64_t>(c.queue_depth);
    cnt["sweep_running"] = c.sweep_running;
    cnt["sweep_progress"] = c.sweep_progress;
    cnt["sweep_current"] = c.sweep_current;
    root["counters"] = Value{std::move(cnt)};
    root["enabled"] = true;
    root["rules"] = static_cast<std::int64_t>(sc->engine().rule_count());
    root["patterns"] = static_cast<std::int64_t>(sc->engine().pattern_count());
    root["backend"] = sc->engine().backend() == scanning::Backend::LibYara ? std::string("libyara")
                                                                           : std::string("yara-lite");
    root["libyara"] = sc->engine().libyara_available();

    const auto& inv = sc->inventory();
    Object e;
    e["clamdscan"] = inv.clamdscan;
    e["kvrt"] = inv.kvrt;
    e["clamd_socket"] = inv.clamd_socket;
    e["clamd_socket_alive"] = inv.clamd_socket_alive;
    e["kvrt_runnable"] = inv.kvrt_runnable;
    e["findings"] = arr(inv.findings);
    root["external"] = Value{std::move(e)};

    Array a;
    for (const auto& r : sc->recent(64)) {
        Object o;
        o["path"] = r.path;
        o["verdict"] = std::string(scanning::verdict_name(r.verdict));
        o["risk"] = static_cast<std::int64_t>(r.risk);
        o["sha256"] = r.sha256;
        o["size"] = static_cast<std::int64_t>(r.size);
        o["entropy"] = r.entropy;
        o["flavour"] = std::string(core::hash::flavour_name(r.flavour));
        o["engine"] = r.engine;
        o["elapsed_ms"] = static_cast<std::int64_t>(r.elapsed.count());
        o["detail"] = r.detail;
        o["from_cache"] = r.from_cache;
        o["pid"] = static_cast<std::int64_t>(r.attributing_pid);
        Array m;
        for (const auto& mm : r.matches) {
            Object mo;
            mo["rule"] = mm.rule;
            mo["family"] = mm.family;
            mo["description"] = mm.description;
            mo["severity"] = std::string(core::severity_name(mm.severity));
            mo["occurrences"] = static_cast<std::int64_t>(mm.occurrence_count);
            m.emplace_back(Value{std::move(mo)});
        }
        o["matches"] = Value{std::move(m)};
        a.emplace_back(Value{std::move(o)});
    }
    root["recent"] = Value{std::move(a)};
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_hardening() const noexcept {
    Object root;

    if (auto* b = agent_.sensor<hardening::BootAuditSensor>(core::SensorId::BootAudit)) {
        Object o;
        const auto& sb = b->secure_boot();
        Object s;
        s["uefi"] = sb.platform_supports_uefi;
        s["efivarfs"] = sb.efivarfs_mounted;
        s["enabled"] = sb.secure_boot_enabled;
        s["setup_mode"] = sb.setup_mode;
        s["manufacturer_keys_only"] = sb.manufacturer_keys_only;
        s["mok_list"] = sb.mok_list_present;
        s["sbctl"] = sb.sbctl_available;
        s["sbctl_status"] = sb.sbctl_status_raw;
        s["score"] = static_cast<std::int64_t>(sb.score);
        s["trustworthy"] = sb.trustworthy;
        s["findings"] = arr(sb.findings);
        s["missing_tools"] = arr(sb.missing_tools);
        o["secure_boot"] = Value{std::move(s)};

        const auto& k = b->kernel();
        Object ki;
        ki["release"] = k.release;
        ki["version"] = k.version;
        ki["hardened_flavour"] = k.is_hardened_flavour;
        ki["lts"] = k.is_lts;
        ki["tainted"] = k.tainted;
        ki["taint_flags"] = k.taint_flags;
        ki["taint_meanings"] = arr(k.taint_meanings);
        ki["module_sig_enforced"] = k.module_signature_enforced;
        ki["modules"] = static_cast<std::int64_t>(k.loaded_module_count);
        ki["modules_digest"] = k.loaded_modules_digest;
        ki["findings"] = arr(k.findings);
        o["kernel"] = Value{std::move(ki)};

        const auto& bl = b->bootloader();
        Object bo;
        bo["flavour"] = bl.flavour;
        bo["world_writable_config"] = bl.world_writable_config;
        bo["findings"] = arr(bl.findings);
        Array paths;
        for (const auto& p : bl.config_paths) paths.emplace_back(p);
        bo["config_paths"] = Value{std::move(paths)};
        o["bootloader"] = Value{std::move(bo)};

        Array ir;
        for (const auto& i : b->initramfs()) {
            Object io;
            io["path"] = i.path;
            io["exists"] = i.exists;
            io["size"] = static_cast<std::int64_t>(i.size);
            io["sha256"] = i.sha256;
            io["mtime"] = i.mtime_unix;
            io["changed"] = i.changed_since_baseline;
            io["baseline_sha256"] = i.baseline_sha256;
            io["findings"] = arr(i.findings);
            ir.emplace_back(Value{std::move(io)});
        }
        o["initramfs"] = Value{std::move(ir)};
        o["trust_score"] = static_cast<std::int64_t>(b->trust_score());
        root["boot"] = Value{std::move(o)};
    }

    if (auto* kh = agent_.sensor<hardening::KernelHardeningSensor>(core::SensorId::KernelHardening)) {
        const auto& rep = kh->report();
        Object o;
        o["score"] = static_cast<std::int64_t>(rep.score);
        o["compliant"] = static_cast<std::int64_t>(rep.compliant);
        o["drift"] = static_cast<std::int64_t>(rep.drift);
        o["missing"] = static_cast<std::int64_t>(rep.missing);
        o["unacceptable"] = static_cast<std::int64_t>(rep.unacceptable);
        o["worst_severity"] = std::string(core::severity_name(rep.worst_severity));
        o["checked_at"] = epoch(rep.checked_at);
        o["lockdown"] = lockdown_mode_name(rep.lockdown.mode);
        o["lockdown_compliant"] = rep.lockdown.compliant;
        o["lockdown_findings"] = arr(rep.lockdown.findings);

        const auto& as = rep.aslr;
        Object a;
        a["randomize_va_space"] = static_cast<std::int64_t>(as.randomize_va_space);
        a["ptrace_scope"] = static_cast<std::int64_t>(as.ptrace_scope);
        a["kptr_restrict"] = static_cast<std::int64_t>(as.kptr_restrict);
        a["dmesg_restrict"] = static_cast<std::int64_t>(as.dmesg_restrict);
        a["unprivileged_bpf_disabled"] = static_cast<std::int64_t>(as.unprivileged_bpf_disabled);
        a["perf_event_paranoid"] = static_cast<std::int64_t>(as.perf_event_paranoid);
        a["suid_dumpable"] = static_cast<std::int64_t>(as.suid_dumpable);
        a["protected_symlinks"] = static_cast<std::int64_t>(as.protected_symlinks);
        a["protected_hardlinks"] = static_cast<std::int64_t>(as.protected_hardlinks);
        a["score"] = static_cast<std::int64_t>(as.score);
        a["findings"] = arr(as.findings);
        o["aslr"] = Value{std::move(a)};

        Array sy;
        for (const auto& c : rep.sysctls) {
            Object co;
            co["name"] = c.sysctl_name;
            co["path"] = c.path;
            co["expected"] = c.expected;
            co["actual"] = c.actual;
            co["verdict"] = std::string(hardening::verdict_name(c.verdict));
            co["severity"] = std::string(core::severity_name(c.severity));
            co["rationale"] = c.rationale;
            co["remediation"] = c.remediation;
            sy.emplace_back(Value{std::move(co)});
        }
        o["sysctls"] = Value{std::move(sy)};
        root["kernel_hardening"] = Value{std::move(o)};
    }

    if (auto* mac = agent_.sensor<hardening::MacProfileSensor>(core::SensorId::MacProfile)) {
        const auto& rep = mac->report();
        Object o;
        o["score"] = static_cast<std::int64_t>(rep.score);
        o["confined"] = static_cast<std::int64_t>(rep.confined_count);
        o["unconfined"] = static_cast<std::int64_t>(rep.unconfined_count);
        o["complain"] = static_cast<std::int64_t>(rep.complain_count);
        o["worst_severity"] = std::string(core::severity_name(rep.worst_severity));
        o["checked_at"] = epoch(rep.checked_at);

        Object l;
        l["raw"] = rep.lsm.raw;
        l["apparmor"] = rep.lsm.apparmor;
        l["selinux"] = rep.lsm.selinux;
        l["bpf_lsm"] = rep.lsm.bpf_lsm;
        l["landlock"] = rep.lsm.landlock;
        l["findings"] = arr(rep.lsm.findings);
        Array act;
        for (const auto k : rep.lsm.active) act.emplace_back(std::string(hardening::lsm_name(k)));
        l["active"] = Value{std::move(act)};
        o["lsm"] = Value{std::move(l)};

        Object aa;
        aa["enabled"] = rep.apparmor.enabled;
        Array tp;
        for (const auto& t : rep.apparmor.trusted_profiles) tp.emplace_back(t);
        aa["trusted_profiles"] = Value{std::move(tp)};
        aa["profiles"] = static_cast<std::int64_t>(rep.apparmor.profiles_loaded);
        aa["enforce"] = static_cast<std::int64_t>(rep.apparmor.profiles_enforce);
        aa["complain"] = static_cast<std::int64_t>(rep.apparmor.profiles_complain);
        aa["kill"] = static_cast<std::int64_t>(rep.apparmor.profiles_kill);
        aa["findings"] = arr(rep.apparmor.findings);
        o["apparmor"] = Value{std::move(aa)};

        Object se;
        se["enabled"] = rep.selinux.enabled;
        se["enforcing"] = rep.selinux.enforcing;
        se["permissive"] = rep.selinux.permissive;
        se["policy"] = rep.selinux.policy_name;
        se["denials"] = rep.selinux.denials;
        se["findings"] = arr(rep.selinux.findings);
        o["selinux"] = Value{std::move(se)};

        Array d;
        for (const auto& dc : rep.daemons) {
            Object o2;
            o2["name"] = dc.name;
            o2["running"] = dc.running;
            o2["confined"] = dc.confined;
            o2["profile"] = dc.profile;
            o2["mode"] = std::string(hardening::mode_name(dc.mode));
            o2["selinux_context"] = dc.selinux_context;
            o2["network_reachable"] = dc.network_reachable;
            o2["complain"] = dc.complain;
            o2["severity"] = std::string(core::severity_name(dc.severity));
            o2["findings"] = arr(dc.findings);
            Array pids;
            for (const pid_t p : dc.pids) pids.emplace_back(static_cast<std::int64_t>(p));
            o2["pids"] = Value{std::move(pids)};
            Array ports;
            for (const auto p : dc.listen_ports) ports.emplace_back(static_cast<std::int64_t>(p));
            o2["ports"] = Value{std::move(ports)};
            d.emplace_back(Value{std::move(o2)});
        }
        o["daemons"] = Value{std::move(d)};
        root["mac"] = Value{std::move(o)};
    }
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_canaries() const noexcept {
    Object root;
    auto* cs = agent_.sensor<anti_ransomware::CanarySensor>(core::SensorId::Canary);
    if (!cs) {
        root["enabled"] = false;
        return Value{std::move(root)};
    }
    root["enabled"] = true;
    root["planted"] = static_cast<std::int64_t>(cs->planted_count());
    root["healthy"] = static_cast<std::int64_t>(cs->healthy_count());
    root["tampered"] = static_cast<std::int64_t>(cs->tampered_count());

    Array a;
    for (const auto& rec : cs->planted()) {
        Object o;
        o["path"] = rec.path;
        o["root"] = rec.root;
        o["serial"] = static_cast<std::int64_t>(rec.serial);
        o["hidden"] = rec.hidden;
        o["created"] = epoch(rec.created);
        o["bytes"] = static_cast<std::int64_t>(rec.body.size());
        a.emplace_back(Value{std::move(o)});
    }
    root["canaries"] = Value{std::move(a)};

    // Live verification on request: the GUI's "Check now" button re-reads every
    // canary from disk rather than trusting the cached verdicts.
    Array checks;
    for (const auto& c : cs->check_all()) {
        Object o;
        o["path"] = c.expected.path;
        o["verdict"] = canary_verdict_name(c.verdict);
        o["ok"] = c.verdict == anti_ransomware::CanaryVerdict::Ok;
        o["size"] = static_cast<std::int64_t>(c.on_disk_size);
        o["entropy"] = c.on_disk_entropy;
        o["checked_at"] = epoch(c.checked_at);
        o["detail"] = c.detail;
        checks.emplace_back(Value{std::move(o)});
    }
    root["check"] = Value{std::move(checks)};

    if (auto* fm = agent_.sensor<anti_ransomware::FileMonitorSensor>(core::SensorId::MassModify)) {
        Object f;
        f["fanotify"] = fm->fanotify_available();
        f["events_seen"] = static_cast<std::int64_t>(fm->events_seen());
        root["file_monitor"] = Value{std::move(f)};
    }

    // Honeypot decoys (row 11): config-shaped bait in the state dir, watched by
    // inotify. READ/MODIFIED/DELETED events surface in the normal event feed;
    // this section shows what is planted and where, so the operator can see the
    // trap layout at a glance. No bait bodies or hashes are exposed beyond the
    // tamper-baseline prefix.
    if (auto* hp = agent_.sensor<anti_ransomware::HoneypotSensor>("honeypot")) {
        Object h;
        h["planted"] = static_cast<std::int64_t>(hp->planted_count());
        Array ds;
        for (const auto& d : hp->planted()) {
            Object o;
            o["rel"] = d.rel;
            o["root"] = d.root;
            o["sha256_16"] = d.sha256.substr(0, 16);
            ds.emplace_back(Value{std::move(o)});
        }
        h["decoys"] = Value{std::move(ds)};
        root["honeypots"] = Value{std::move(h)};
    }
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_processes(std::size_t n) const noexcept {
    struct Row {
        core::proc::ProcessInfo pi;
        std::string lineage;
        bool suspicious{false};
    };
    std::vector<Row> rows;
    for (const pid_t pid : core::proc::list_pids(true)) {
        Row r;
        r.pi = core::proc::read(pid);
        if (!r.pi.exists) continue;
        r.suspicious = core::proc::runs_from_suspicious_path(r.pi.exe);
        rows.push_back(std::move(r));
        if (rows.size() >= 4096) break;   // bounded: a fork bomb must not OOM the GUI
    }
    // Newest first is what an incident responder wants: the process that just
    // started is the one that just did something.
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return a.pi.start_time_ticks > b.pi.start_time_ticks;
    });
    if (rows.size() > n) rows.resize(n);

    // Lineage is only resolved for the rows we are actually going to send: each
    // one walks /proc up to 8 levels, so doing it for 4096 pids would be the
    // single most expensive thing in the bridge.
    Array a;
    for (auto& r : rows) {
        r.lineage = core::proc::lineage_string(r.pi.pid, 6);
        Object o;
        o["pid"] = static_cast<std::int64_t>(r.pi.pid);
        o["ppid"] = static_cast<std::int64_t>(r.pi.ppid);
        o["tgid"] = static_cast<std::int64_t>(r.pi.tgid);
        o["comm"] = r.pi.comm;
        o["exe"] = r.pi.exe;
        o["cmdline"] = r.pi.cmdline;
        o["state"] = r.pi.state;
        o["uid"] = static_cast<std::int64_t>(r.pi.uid);
        o["euid"] = static_cast<std::int64_t>(r.pi.euid);
        o["threads"] = static_cast<std::int64_t>(r.pi.tgid == r.pi.pid ? 1 : 0);
        o["vsize"] = static_cast<std::int64_t>(r.pi.vsize);
        o["rss_bytes"] = static_cast<std::int64_t>(r.pi.rss_pages * 4096);
        o["deleted_exe"] = r.pi.deleted_exe;
        o["traced"] = r.pi.traced;
        o["suspicious_path"] = r.suspicious;
        o["container"] = r.pi.container_id;
        o["cwd"] = r.pi.cwd;
        o["cgroup"] = r.pi.cgroup;
        o["lineage"] = r.lineage;
        o["start_time"] = static_cast<std::int64_t>(r.pi.start_time_ticks);
        if (const auto age = core::proc::age_seconds(r.pi.pid)) o["age_seconds"] = *age;
        // The two flags an analyst scans a process list for.
        o["flag"] = r.pi.deleted_exe        ? std::string("deleted-exe")
                    : r.suspicious          ? std::string("writable-path")
                    : r.pi.traced           ? std::string("being-traced")
                                            : std::string();
        a.emplace_back(Value{std::move(o)});
    }
    Object root;
    root["processes"] = Value{std::move(a)};
    root["count"] = static_cast<std::int64_t>(a.size());
    const auto caps = core::proc::capabilities();
    Object c;
    c["root"] = caps.root;
    c["cap_sys_admin"] = caps.cap_sys_admin;
    c["cap_sys_ptrace"] = caps.cap_sys_ptrace;
    c["cap_dac_read_search"] = caps.cap_dac_read_search;
    c["cap_net_admin"] = caps.cap_net_admin;
    c["cap_audit_read"] = caps.cap_audit_read;
    c["missing"] = arr(caps.missing);
    root["capabilities"] = Value{std::move(c)};
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_baseline() const noexcept {
    const auto& b = agent_.heuristics().baseline();
    Object o;
    o["learning"] = b.learning;
    o["observations"] = static_cast<std::int64_t>(b.observations);
    o["started"] = epoch(b.learning_started);
    o["ends"] = epoch(b.learning_ends);
    o["distinct_exes"] = static_cast<std::int64_t>(b.exec_frequency.size());
    o["distinct_lineages"] = static_cast<std::int64_t>(b.parent_to_children.size());
    o["distinct_uids"] = static_cast<std::int64_t>(b.uid_to_exes.size());
    o["listening_daemons"] = static_cast<std::int64_t>(b.listening_daemons.size());
    o["path"] = agent_.config().heuristic.baseline_path;
    o["learning_window_hours"] =
        static_cast<std::int64_t>(agent_.config().heuristic.baseline_learning_period.count());

    // Show the most-observed executables: that is the operator's sanity check that
    // the baseline learned the right thing.
    std::vector<std::pair<std::string, std::uint64_t>> top(b.exec_frequency.begin(),
                                                           b.exec_frequency.end());
    std::sort(top.begin(), top.end(),
              [](const auto& x, const auto& y) { return x.second > y.second; });
    if (top.size() > 40) top.resize(40);
    Array a;
    for (const auto& [exe, n] : top) {
        Object e;
        e["exe"] = exe;
        e["count"] = static_cast<std::int64_t>(n);
        a.emplace_back(Value{std::move(e)});
    }
    o["top_executables"] = Value{std::move(a)};

    Array l;
    for (const auto& [parent, kids] : b.parent_to_children) {
        Object e;
        e["parent"] = parent;
        e["children"] = static_cast<std::int64_t>(kids.size());
        Array kn;
        std::size_t i = 0;
        for (const auto& k : kids) {
            kn.emplace_back(k);
            if (++i >= 24) break;
        }
        e["names"] = Value{std::move(kn)};
        l.emplace_back(Value{std::move(e)});
        if (l.size() >= 40) break;
    }
    o["lineages"] = Value{std::move(l)};
    o["app_profiles"] = static_cast<std::int64_t>(agent_.heuristics().app_profiles_loaded());
    o["app_profiles_dir"] = agent_.heuristics().app_profiles_dir();
    return Value{std::move(o)};
}

Value GuiBridge::snapshot_shadows() const noexcept {
    Object root;
    auto* sc = agent_.shadow();
    if (!sc) {
        root["enabled"] = false;
        root["note"] = std::string("shadow-copy engine unavailable");
        return Value{std::move(root)};
    }
    Array a;
    for (const auto& e : sc->list()) {
        Object o;
        o["id"] = e.meta.id;
        o["created"] = static_cast<std::int64_t>(e.meta.created);
        o["reason"] = e.meta.reason;
        o["files"] = static_cast<std::int64_t>(e.meta.files);
        o["bytes"] = static_cast<std::int64_t>(e.meta.bytes);
        o["skipped"] = static_cast<std::int64_t>(e.meta.skipped);
        o["dir"] = e.dir;
        Array roots;
        for (const auto& r : e.meta.roots) roots.emplace_back(r);
        o["roots"] = Value{std::move(roots)};
        Array miss;
        for (const auto& m : e.meta.missing) miss.emplace_back(m);
        o["missing"] = Value{std::move(miss)};
        a.emplace_back(Value{std::move(o)});
    }
    root["snapshots"] = Value{std::move(a)};
    root["enabled"] = agent_.config().shadow.enabled;
    root["keep"] = static_cast<std::int64_t>(agent_.config().shadow.keep);
    root["dir"] = sc->root_dir();
    return Value{std::move(root)};
}

Value GuiBridge::snapshot_network() const noexcept {
    Object root;
    Array blocks;
    for (const auto& b : agent_.remediation().active_blocks()) {
        Object o;
        o["id"] = static_cast<std::int64_t>(b.id);
        o["ip"] = b.remote_ip;
        o["port"] = static_cast<std::int64_t>(b.remote_port);
        o["reason"] = b.reason;
        o["installed"] = epoch(b.installed);
        o["ttl"] = static_cast<std::int64_t>(b.ttl.count());
        blocks.emplace_back(Value{std::move(o)});
    }
    root["blocks"] = Value{std::move(blocks)};

    // Per-exe containment (row 12): what whole executables are offline.
    Array exeb;
    for (const auto& b : agent_.remediation().active_exe_blocks()) {
        Object o;
        o["id"] = static_cast<std::int64_t>(b.id);
        o["exe"] = b.exe;
        o["cgroup"] = b.cgroup;
        o["tasks"] = static_cast<std::int64_t>(b.pids.size());
        o["reason"] = b.reason;
        o["installed"] = epoch(b.installed);
        o["ttl"] = static_cast<std::int64_t>(b.ttl.count());
        exeb.emplace_back(Value{std::move(o)});
    }
    root["exe_blocks"] = Value{std::move(exeb)};

    // Beacons, from Suricata's EVE feed.
    if (auto* su = agent_.sensor<behavioral::SuricataSensor>(core::SensorId::Suricata)) {
        Array a;
        for (const auto& bp : su->beacons(32)) {
            Object o;
            o["peer"] = bp.peer;
            o["process"] = bp.process;
            o["hits"] = static_cast<std::int64_t>(bp.hits);
            o["mean_interval"] = bp.mean_interval;
            o["jitter"] = bp.jitter;
            o["bytes_out"] = static_cast<std::int64_t>(bp.bytes_out);
            o["bytes_in"] = static_cast<std::int64_t>(bp.bytes_in);
            o["score"] = bp.score;
            o["beacon_like"] = bp.beacon_like;
            Array iv;
            std::size_t i = 0;
            for (const double d : bp.intervals_seconds) {
                iv.emplace_back(d);
                if (++i >= 32) break;
            }
            o["intervals"] = Value{std::move(iv)};
            a.emplace_back(Value{std::move(o)});
        }
        root["beacons"] = Value{std::move(a)};
        root["eve_alerts"] = static_cast<std::int64_t>(su->alerts_seen());
        root["eve_flows"] = static_cast<std::int64_t>(su->flows_seen());
    }

    // Falco rule histogram.
    if (auto* fa = agent_.sensor<behavioral::FalcoSensor>(core::SensorId::Falco)) {
        Array a;
        for (const auto& rc : fa->top_rules(24)) {
            Object o;
            o["rule"] = rc.rule;
            o["count"] = static_cast<std::int64_t>(rc.count);
            o["severity"] = std::string(core::severity_name(rc.severity));
            o["last"] = epoch(rc.last_seen);
            o["last_output"] = rc.last_output;
            a.emplace_back(Value{std::move(o)});
        }
        Object f;
        f["rules"] = Value{std::move(a)};
        f["alerts_seen"] = static_cast<std::int64_t>(fa->alerts_seen());
        f["alerts_filtered"] = static_cast<std::int64_t>(fa->alerts_filtered());
        f["socket"] = fa->source().path();
        f["socket_state"] = socket_state_name(fa->source().state());
        root["falco"] = Value{std::move(f)};
    }

    // Live connection table, parsed straight out of /proc/net rather than by
    // running `ss`: ss is a binary an attacker who has rooted the box can replace.
    // Live socket table, read from /proc/net and attributed by walking
    // /proc/<pid>/fd for socket inodes. One walk serves both panels.
    const auto all = core::proc::net_sockets(false, 512);
    Array conns;
    Array lis;
    for (const auto& c : all) {
        Object o;
        o["protocol"] = c.protocol;
        o["local"] = c.local_address + ":" + std::to_string(c.local_port);
        o["remote"] = c.remote_address + ":" + std::to_string(c.remote_port);
        o["state"] = c.state;
        o["pid"] = static_cast<std::int64_t>(c.pid);
        o["exe"] = c.exe;
        o["comm"] = c.comm;
        o["uid"] = static_cast<std::int64_t>(c.uid);
        o["inode"] = static_cast<std::int64_t>(c.inode);
        o["attributed"] = c.pid > 0;
        if (c.listening) lis.emplace_back(Value{o});
        else conns.emplace_back(Value{std::move(o)});
    }
    root["connections"] = Value{std::move(conns)};
    root["listeners"] = Value{std::move(lis)};
    return Value{std::move(root)};
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

Value GuiBridge::dispatch(std::string_view cmd, const Value& req, uid_t uid) noexcept {
    Object reply;
    reply["ok"] = true;
    reply["cmd"] = std::string(cmd);

    // Snapshots: read-only, cheap, no privilege required beyond being connected.
    if (cmd == "ping") {
        reply["data"] = std::string("pong");
        reply["server_time"] = epoch(core::SysClock::now());
        return Value{std::move(reply)};
    }
    if (cmd == "overview") { reply["data"] = snapshot_overview(); return Value{std::move(reply)}; }
    if (cmd == "sensors") { reply["data"] = snapshot_sensors(); return Value{std::move(reply)}; }
    if (cmd == "risk") { reply["data"] = snapshot_risk(); return Value{std::move(reply)}; }
    if (cmd == "decisions") { reply["data"] = snapshot_decisions(); return Value{std::move(reply)}; }
    if (cmd == "remediation") { reply["data"] = snapshot_remediation(); return Value{std::move(reply)}; }
    if (cmd == "scans") { reply["data"] = snapshot_scans(); return Value{std::move(reply)}; }
    if (cmd == "hardening") { reply["data"] = snapshot_hardening(); return Value{std::move(reply)}; }
    if (cmd == "canaries") { reply["data"] = snapshot_canaries(); return Value{std::move(reply)}; }
    if (cmd == "baseline") { reply["data"] = snapshot_baseline(); return Value{std::move(reply)}; }
    if (cmd == "network") { reply["data"] = snapshot_network(); return Value{std::move(reply)}; }

    if (cmd == "events") {
        const auto limit = static_cast<std::size_t>(std::clamp<std::int64_t>(req.integer("limit", 200), 1, 2000));
        reply["data"] = snapshot_events(limit);
        return Value{std::move(reply)};
    }
    if (cmd == "processes") {
        const auto limit = static_cast<std::size_t>(std::clamp<std::int64_t>(req.integer("limit", 200), 1, 2000));
        reply["data"] = snapshot_processes(limit);
        return Value{std::move(reply)};
    }
    if (cmd == "osquery") {
        auto* os = agent_.sensor<behavioral::OsquerySensor>(core::SensorId::Osquery);
        Object o;
        if (!os) {
            o["enabled"] = false;
        } else {
            o["enabled"] = true;
            o["available"] = os->available();
            o["binary"] = os->binary();
            o["queries_run"] = static_cast<std::int64_t>(os->queries_run());
            o["rows"] = static_cast<std::int64_t>(os->rows_returned());
            Array res;
            for (const auto& r : os->last_results()) {
                Object ro;
                ro["name"] = r.name;
                ro["ok"] = r.ok;
                ro["error"] = r.error;
                ro["rows"] = static_cast<std::int64_t>(r.rows.size());
                ro["elapsed_ms"] = static_cast<std::int64_t>(r.elapsed.count());
                ro["ran_at"] = epoch(r.ran_at);
                Array rr;
                std::size_t i = 0;
                for (const auto& row : r.rows) {
                    rr.emplace_back(row);
                    if (++i >= 100) break;  // cap: a full crontab table is not a GUI payload
                }
                ro["data"] = Value{std::move(rr)};
                res.emplace_back(Value{std::move(ro)});
            }
            o["results"] = Value{std::move(res)};
            Array an;
            for (const auto& a : os->anomalies(64)) {
                Object ao;
                ao["query"] = a.query;
                ao["message"] = a.message;
                ao["severity"] = std::string(core::severity_name(a.severity));
                ao["risk"] = static_cast<std::int64_t>(a.risk);
                ao["when"] = epoch(a.when);
                an.emplace_back(Value{std::move(ao)});
            }
            o["anomalies"] = Value{std::move(an)};
        }
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "auditd") {
        auto* au = agent_.sensor<behavioral::AuditSensor>(core::SensorId::Auditd);
        Object o;
        if (!au) {
            o["enabled"] = false;
        } else {
            const auto st = au->query_status();
            o["enabled"] = true;
            o["netlink"] = au->netlink_active();
            o["records"] = static_cast<std::int64_t>(au->records_seen());
            o["analysed"] = static_cast<std::int64_t>(au->events_analysed());
            o["kernel_lost"] = static_cast<std::int64_t>(au->kernel_lost());
            o["status_readable"] = st.readable;
            o["audit_enabled"] = static_cast<std::int64_t>(st.enabled);
            o["auditd_pid"] = static_cast<std::int64_t>(st.pid);
                o["backlog_limit"] = static_cast<std::int64_t>(st.backlog_limit);
            o["lost"] = static_cast<std::int64_t>(st.lost);
            o["findings"] = arr(st.findings);
        }
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "config") {
        // The config is not secret, but it does reveal the protected-pid list and
        // the detection thresholds, which is exactly what an attacker wants. Only
        // root gets the full text.
        Object o;
        o["path"] = agent_.config_path();
        o["describe"] = core::describe(agent_.config());
        o["full_access"] = uid == 0;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }

    if (cmd == "snapshots") {
        // Read-only: the list reveals where recovery data lives, which is useful
        // to an attacker planning deletion -- but the same attacker with socket
        // access can already see the filesystem. Listing stays available to any
        // authorised console so an unprivileged operator can see the lifeline.
        reply["data"] = snapshot_shadows();
        return Value{std::move(reply)};
    }
    if (cmd == "settings_get") {
        static const std::vector<std::pair<const char*, const char*>> kDesc = {
            {"realtime_protection", "real-time file monitoring, entropy and mass-modify detection"},
            {"canaries", "canary files and decoy directories (ransomware tripwires)"},
            {"heuristics", "behavioural correlation and actor risk scoring"},
            {"auto_respond", "act without asking on CRITICAL confidence"},
            {"learning", "baseline learning period (fewer alerts on known-good behaviour)"},
            {"realtime_scanning", "on-exec and on-demand signature scanning"},
            {"falco", "Falco runtime-rule sensor"},
            {"auditd", "kernel audit sensor"},
            {"osquery", "osquery state queries"},
            {"suricata", "Suricata EVE network sensor (C2 beacon scoring)"},
            {"response", "response engine: freeze, quarantine, network blocks"},
            {"shadow_copies", "shadow-copy snapshots and restore points"},
            {"external_runners", "allow launching external scanners"},
            {"virustotal", "VirusTotal hash lookups (needs an API key)"},
            {"sample_upload", "allow uploading samples to online sandboxes (privacy!)"},
            {"ai_analyst", "AI forensic assistant (Groq; advises only, never acts)"},
            {"dry_run", "observe-only mode: detect but never act"},
            {"kernel_events_in_gui", "show low-level kernel events in the feed"},
            {"rescue", "rescue-environment reboot scan (rootkit class)"},
        };
        Object o;
        for (const auto& st : agent_.feature_states())
            for (const auto& [k, d] : kDesc)
                if (k == st.key) { o[st.key] = st.on; (void)d; }
        Object d;
        for (const auto& [k, desc] : kDesc) d[k] = std::string(desc);
        Object all;
        all["states"] = Value{std::move(o)};
        all["descriptions"] = Value{std::move(d)};
        std::string why;
        all["ai_ready"] = agent_.ai() && agent_.ai()->ready(why);
        all["ai_note"] = why;
        reply["data"] = Value{std::move(all)};
        return Value{std::move(reply)};
    }
    if (cmd == "systemd") {
        // Read-only audit; per-unit detail for the two worst offenders.
        if (auto* tb = agent_.toolbox()) {
            const auto units = tb->systemd_security(2);
            hyprnova::core::json::Array arr;
            for (const auto& u : units) {
                hyprnova::core::json::Object o;
                o["unit"] = u.unit;
                o["exposure"] = u.exposure;
                o["grade"] = u.grade;
                o["suggestions"] =
                    hyprnova::core::json::Value{hyprnova::core::json::Array(
                        u.suggestions.begin(), u.suggestions.end())};
                arr.push_back(hyprnova::core::json::Value{std::move(o)});
            }
            hyprnova::core::json::Object d;
            d["units"] = hyprnova::core::json::Value{std::move(arr)};
            reply["data"] = hyprnova::core::json::Value{std::move(d)};
        } else {
            reply["ok"] = false;
            reply["error"] = std::string("toolbox not available");
        }
        return Value{std::move(reply)};
    }
    if (cmd == "rescue_status") {
        if (auto* rc = agent_.rescue()) {
            auto st = rc->status();
            if (const auto rep = tools::Toolbox::parse_rescue_report(
                    agent_.rescue()->report_path())) {
                st.report_pending = true;
            }
            Object o;
            o["enabled"] = st.enabled;
            o["iso_found"] = st.iso_found;
            o["iso_path"] = st.iso_resolved;
            o["iso_staged"] = st.iso_staged;
            o["grub_entry_present"] = st.grub_entry_present;
            o["clean_script_present"] = st.clean_script_present;
            o["prepared"] = st.prepared;
            o["report_pending"] = st.report_pending;
            o["blockers"] = Value{Array(st.blockers.begin(), st.blockers.end())};
            o["preview"] = st.preview;
            reply["data"] = Value{std::move(o)};
        } else {
            reply["ok"] = false;
            reply["error"] = std::string("rescue module unavailable");
        }
        return Value{std::move(reply)};
    }
    if (cmd == "toolbox") {
        // Read-only, like `snapshots`: the matrix tells an attacker exactly as
        // much as `which rkhunter` does, and an unprivileged operator needs the
        // truthful coverage view. Probe() is ~200 stat() calls, cheap enough to
        // stay always-fresh.
        if (auto* tb = agent_.toolbox()) {
            tb->probe();
            reply["data"] = tb->snapshot_json();
        } else {
            reply["ok"] = false;
            reply["error"] = std::string("toolbox not available");
        }
        return Value{std::move(reply)};
    }
    if (cmd == "verify_snapshot") {
        const std::string id = req.str("id");
        if (id.empty()) {
            reply["ok"] = false;
            reply["error"] = std::string("\"id\" is required");
            return Value{std::move(reply)};
        }
        std::string d;
        Object o;
        o["id"] = id;
        o["verified"] = agent_.shadow()->verify(id, d);
        o["detail"] = d;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }

    // ---- mutating commands ------------------------------------------------
    // Every one of these is re-authorised here rather than trusting the socket's
    // file mode: the agent is the policy enforcement point, not the filesystem.
    //
    // Privileged means uid 0 OR the agent's own effective uid. The second case
    // matters for deployments where the agent deliberately runs as a dedicated
    // account with capabilities (CAP_KILL, CAP_DAC_READ_SEARCH, ...) instead of
    // root: locking its own console out of every action would make that design
    // unusable. It grants nothing extra -- a peer with the agent's uid could
    // already do everything the agent can do at that uid, directly.
    const bool privileged = uid == 0 || uid == static_cast<uid_t>(::geteuid());
    auto refuse = [&](std::string_view why) {
        reply["ok"] = false;
        reply["error"] = std::string(why);
        return Value{std::move(reply)};
    };
    if (!privileged)
        return refuse("this command requires root on the agent socket (or the same uid the agent runs as)");

    if (cmd == "settings_set") {
        const std::string key = req.str("key");
        const bool on = req.integer("value", -1) == 1;
        if (key.empty()) return refuse("\"key\" is required");
        if (!agent_.set_feature(key, on)) {
            // Distinguish "unknown key" from "refused by validation".
            bool known = false;
            for (const auto& st : agent_.feature_states()) known |= st.key == key;
            return refuse(known ? std::format("toggle '{}' refused by validation "
                                              "(see the agent log)", key)
                                : std::format("unknown feature '{}'", key));
        }
        SINFO("gui-bridge", "operator toggled {} = {} (uid {})", key, on, uid);
        Object o;
        o["key"] = key;
        o["value"] = on;
        o["reloaded"] = true;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "shred") {
        auto* sh = agent_.shredder();
        if (!sh) return refuse("shredder unavailable");
        const bool confirmed = req.integer("confirm", 0) != 0;
        const bool overwrite = req.integer("overwrite", 0) != 0;
        std::vector<std::string> paths;
        if (const Value* a = req.at("paths"); a && a->is_array())
            for (const auto& x : *a->as_array())
                if (const auto p = x.as_string(); !p.empty()) paths.emplace_back(p);
        if (paths.empty()) return refuse("\"paths\" is required");
        const auto plan = sh->plan(paths, overwrite ? remediation::Shredder::Method::Overwrite
                                                    : remediation::Shredder::Method::Standard);
        Object o;
        o["confirmed"] = confirmed;
        o["overwrite"] = overwrite;
        o["refusals"] = Value{Array(plan.refusals.begin(), plan.refusals.end())};
        o["method_note"] = std::string(plan.method_note);
        o["files"] = static_cast<std::int64_t>(plan.files);
        o["dirs"] = static_cast<std::int64_t>(plan.dirs);
        o["links"] = static_cast<std::int64_t>(plan.links);
        o["total_bytes"] = static_cast<std::int64_t>(plan.total_bytes);
        Array items;
        for (const auto& it : plan.items) {
            Object io;
            io["path"] = it.path;
            io["type"] = it.type;
            io["bytes"] = static_cast<std::int64_t>(it.bytes);
            if (!it.note.empty()) io["note"] = it.note;
            items.push_back(Value{std::move(io)});
        }
        o["items"] = Value{std::move(items)};
        if (confirmed && plan.ok) {
            const auto out = sh->execute(plan, true);
            o["executed"] = true;
            o["ok"] = out.ok;
            o["files_removed"] = static_cast<std::int64_t>(out.files_removed);
            o["dirs_removed"] = static_cast<std::int64_t>(out.dirs_removed);
            o["links_removed"] = static_cast<std::int64_t>(out.links_removed);
            o["bytes_overwritten"] = static_cast<std::int64_t>(out.bytes_overwritten);
            o["errors"] = Value{Array(out.errors.begin(), out.errors.end())};
        } else {
            o["executed"] = false;
        }
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "ai_ask") {
        auto* an = agent_.ai();
        if (!an) return refuse("AI module unavailable");
        const std::string question = req.str("question");
        if (question.empty()) return refuse("\"question\" is required");
        // Evidence: posture + the most recent events (bounded). This is what
        // the model is allowed to see -- nothing else leaves the host.
        Object ev;
        ev["e1_posture"] = snapshot_overview();
        Array evs;
        std::int64_t id = 2;
        {
            std::lock_guard<std::mutex> lk(hist_mu_);
            for (const auto& e : history_) {
                if (evs.size() >= 40) break;
                Object eo;
                eo["id"] = std::format("e{}", id++);
                eo["ts"] = std::chrono::duration_cast<std::chrono::seconds>(
                               e.ts.time_since_epoch()).count();
                eo["sensor"] = std::string(core::sensor_name(e.sensor));
                eo["kind"] = std::string(core::kind_name(e.kind));
                eo["severity"] = std::string(core::severity_name(e.severity));
                eo["risk"] = static_cast<std::int64_t>(e.risk_score);
                eo["message"] = e.message;
                if (!e.actor.comm.empty()) eo["proc"] = e.actor.comm;
                if (!e.target.path.empty()) eo["path"] = e.target.path;
                evs.push_back(Value{std::move(eo)});
            }
        }
        ev["events"] = Value{std::move(evs)};
        const auto out = an->ask(question, Value{std::move(ev)});
        // Audit trail: the consult itself is evidence.
        {
            std::ofstream aj{agent_.config().state_dir + "/ai-consults.ndjson", std::ios::app};
            if (aj) {
                Object rec;
                rec["question"] = question;
                rec["ok"] = out.ok;
                rec["model"] = out.model;
                rec["elapsed_ms"] = static_cast<std::int64_t>(out.elapsed.count());
                aj << Value{std::move(rec)}.dump() << "\n";
            }
        }
        Object o;
        o["ok"] = out.ok;
        o["answer"] = out.answer;
        o["model"] = out.model;
        o["elapsed_ms"] = static_cast<std::int64_t>(out.elapsed.count());
        if (!out.error.empty()) o["error"] = out.error;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "ai_review") {
        auto* an = agent_.ai();
        if (!an) return refuse("AI module unavailable");
        const auto pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 0) return refuse("\"pid\" is required");
        // Evidence bundle: the actor's own data + everything the bus knows
        // about it + a fresh verdict of its executable from the in-tree engine.
        Object ev;
        Object actor{};
        if (const auto pi = core::proc::read(pid); pi.pid != 0) {
            actor["pid"] = static_cast<std::int64_t>(pid);
            actor["exe"] = pi.exe;
            actor["comm"] = pi.comm;
            actor["uid"] = static_cast<std::int64_t>(pi.uid);
            actor["ppid"] = static_cast<std::int64_t>(pi.ppid);
            actor["cmdline"] = pi.cmdline;
            actor["e2_exe_verdict"] = [&] {
                auto* sc = agent_.sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch);
                if (!sc || pi.exe.empty()) return std::string("not scanned");
                const auto r = sc->scan_now(pi.exe, scanning::ScanReason::OnDemand);
                return std::format("{} (risk {})", scanning::verdict_name(r.verdict), r.risk);
            }();
        }
        ev["subject"] = Value{std::move(actor)};
        Array evs;
        std::int64_t id = 10;
        {
            std::lock_guard<std::mutex> lk(hist_mu_);
            for (const auto& e : history_) {
                if (e.actor.pid != pid && evs.size() >= 30) continue;
                if (e.actor.pid != pid) continue;
                Object eo;
                eo["id"] = std::format("e{}", id++);
                eo["sensor"] = std::string(core::sensor_name(e.sensor));
                eo["kind"] = std::string(core::kind_name(e.kind));
                eo["severity"] = std::string(core::severity_name(e.severity));
                eo["risk"] = static_cast<std::int64_t>(e.risk_score);
                eo["message"] = e.message;
                evs.push_back(Value{std::move(eo)});
                if (evs.size() >= 30) break;
            }
        }
        ev["events_for_pid"] = Value{std::move(evs)};
        for (const auto& d : agent_.remediation().pending(16)) {
            if (d.report.pid == pid && !d.answered) {
                Object dobj;
                dobj["id"] = static_cast<std::int64_t>(d.id);
                dobj["recommendation"] = d.recommendation;
                dobj["risk"] = static_cast<std::int64_t>(d.report.risk);
                ev["e3_pending_decision"] = Value{std::move(dobj)};
                break;
            }
        }
        const auto out = an->ask(std::format(
            "Review process pid {} for the operator. Should it stay suspended, "
            "be quarantined, or be allowed? Recommend, do not decide.", pid),
            Value{std::move(ev)});
        Object o;
        o["ok"] = out.ok;
        o["answer"] = out.answer;
        o["model"] = out.model;
        o["elapsed_ms"] = static_cast<std::int64_t>(out.elapsed.count());
        if (!out.error.empty()) o["error"] = out.error;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "mem_status") {
        auto* mi = agent_.meminspector();
        Object o;
        o["limits"] = std::string(hyprnova::forensics::MemInspector::limits_text());
        // Honest readability probe: can we read our OWN /proc/self/mem map?
        o["readable"] = ::access("/proc/self/mem", R_OK) == 0 ? 1 : 0;
        Array tools;
        for (const auto& t : hyprnova::forensics::MemInspector::external_tools()) {
            Object to;
            to["name"] = t.name;
            to["available"] = t.available ? 1 : 0;
            to["detail"] = t.detail;
            tools.push_back(Value{std::move(to)});
        }
        o["tools"] = Value{std::move(tools)};
        (void)mi;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "mem_inspect") {
        const auto pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 1) return refuse("\"pid\" (>1) is required");
        auto* mi = agent_.meminspector();
        if (!mi) return refuse("memory-inspection module unavailable");
        const auto rep = mi->inspect(pid);
        SINFO("gui-bridge", "mem-inspect pid {}: {} region(s), {} W^X, {} match(es)", pid,
              rep.regions_scanned, rep.wx.size(), rep.matches.size());
        Object o;
        o["pid"] = static_cast<std::int64_t>(rep.pid);
        o["start_time_ticks"] = static_cast<std::int64_t>(rep.start_time_ticks);
        o["exe"] = rep.exe;
        o["readable"] = rep.readable ? 1 : 0;
        o["regions_scanned"] = static_cast<std::int64_t>(rep.regions_scanned);
        o["bytes_scanned"] = static_cast<std::int64_t>(rep.bytes_scanned);
        o["suspicious"] = rep.suspicious() ? 1 : 0;
        o["limit_note"] = rep.limit_note;
        o["findings"] = Value{Array(rep.findings.begin(), rep.findings.end())};
        o["matches"] = Value{Array(rep.matches.begin(), rep.matches.end())};
        Array wx;
        for (const auto& w : rep.wx) {
            Object wo;
            wo["start"] = static_cast<std::int64_t>(w.start);
            wo["end"] = static_cast<std::int64_t>(w.end);
            wo["path"] = w.path;
            wx.push_back(Value{std::move(wo)});
        }
        o["wx"] = Value{std::move(wx)};
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "mem_dump") {
        const auto pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 1) return refuse("\"pid\" (>1) is required");
        if (req.integer("confirm", 0) == 0)
            return refuse("memory dumps may contain credentials -- this is an opt-in, "
                          "explicitly confirmed action");
        auto* mi = agent_.meminspector();
        if (!mi) return refuse("memory-inspection module unavailable");
        constexpr std::uint64_t kMaxDumpBytes = 512ull << 20;  // hard bound
        const auto res = mi->dump(pid, kMaxDumpBytes);
        Object o;
        o["ok"] = res.ok ? 1 : 0;
        o["path"] = res.path;
        o["bytes"] = static_cast<std::int64_t>(res.bytes);
        o["error"] = res.error;
        SINFO("gui-bridge", "mem-dump pid {}: {} bytes ({})", pid, res.bytes,
              res.ok ? "ok" : res.error);
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "carve" || cmd == "triage") {
        // Opt-in carving + static triage. Both are READ-ONLY towards the
        // target; carve additionally writes extracted artifacts only when
        // scan.carving_enabled is true (the config IS the consent).
        const std::string path = req.str("path");
        if (path.empty()) return refuse("\"path\" is required");
        auto* sc = agent_.sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch);
        const core::CarveConfig carve_cfg = agent_.config().scan.carve;
        const std::string out_dir =
            req.str("out").empty()
                ? agent_.config().state_dir + "/" + carve_cfg.out_dir
                : req.str("out");
        scanning::Carver carver(carve_cfg);
        const scanning::SignatureEngine* engine = sc ? &sc->engine() : nullptr;
        const bool extract = cmd == "carve";
        const auto rep = extract ? carver.carve_file(path, out_dir, engine)
                                 : scanning::Carver::inventory(path);
        Object o;
        o["path"] = path;
        o["mode"] = extract ? "carve" : "inventory";
        o["ok"] = rep.error.empty();
        if (!rep.error.empty()) o["error"] = rep.error;
        o["source_bytes"] = static_cast<std::int64_t>(rep.source_bytes);
        o["out_dir"] = out_dir;
        // Static context next to the artifact list: what triage promises.
        o["sha256"] = core::hash::Sha256::to_hex(core::hash::Sha256::of_file(path));
        Array arts;
        for (const auto& a : rep.artifacts) {
            Object ao;
            ao["offset"] = static_cast<std::int64_t>(a.span.offset);
            ao["size"] = static_cast<std::int64_t>(a.span.size);
            ao["kind"] = std::string(scanning::artifact_kind_name(a.span.kind));
            ao["path"] = a.path;
            ao["note"] = a.note;
            ao["rules"] = Value{Array(a.rules.begin(), a.rules.end())};
            arts.push_back(Value{std::move(ao)});
        }
        o["artifacts"] = Value{std::move(arts)};
        o["suspicious"] = rep.suspicious();
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "advanced_scan") {
        // Right-click "Advanced scan": engine verdict + sha256 + VirusTotal
        // (key-gated) in ONE call, so the console needs no orchestration.
        const std::string path = req.str("path");
        if (path.empty()) return refuse("\"path\" is required");
        Object o;
        o["path"] = path;
        auto* sc = agent_.sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch);
        if (!sc) return refuse("the scanning module is disabled");
        const auto r = sc->scan_now(path, scanning::ScanReason::OnDemand);
        o["verdict"] = std::string(scanning::verdict_name(r.verdict));
        o["risk"] = static_cast<std::int64_t>(r.risk);
        o["sha256"] = r.sha256;
        o["engine"] = std::string("yara-lite");
        Array rules;
        for (const auto& m : r.matches) rules.push_back(Value{std::string(m.rule)});
        o["rules"] = Value{std::move(rules)};
        if (auto* tb = agent_.toolbox()) {
            const auto vt = tb->vt_lookup(r.sha256);
            o["vt_ok"] = vt.ok;
            o["vt_summary"] = vt.summary;
            if (!vt.error.empty()) o["vt_error"] = vt.error;
            o["vt_findings"] = Value{Array(vt.findings.begin(), vt.findings.end())};
            // The escalation ladder: high-confidence malicious from the crowd
            // -> suggest ANY.RUN for behavioural detonation (deep link only).
            if (vt.ok && vt.summary.find("MALICIOUS") != std::string::npos)
                o["next_step"] = std::format(
                    "high-confidence malicious -- detonate behaviourally at "
                    "https://any.run/submission/#{}/ (upload stays off unless "
                    "integrations.online_submission is true)", r.sha256);
            else if (vt.ok && vt.summary.find("no engine") != std::string::npos &&
                     (r.risk >= 400 || !r.matches.empty()))
                o["next_step"] = std::format(
                    "engine is suspicious but VT is clean -- submit to "
                    "https://hybrid-analysis.com or ANY.RUN (key-gated), or run "
                    "`hyprnova-cli deep-scan deep {}`", path);
            else if (r.verdict == scanning::Verdict::Malicious)
                o["next_step"] =
                    "high-confidence malicious on the local engine -- quarantine the "
                    "file and suspend any process that executed it (Threats page); "
                    "the VirusTotal cross-check activates once "
                    "integrations.virustotal_enabled and its api_key are set";
            else if (r.verdict == scanning::Verdict::Suspicious) {
                // Unsure = exactly what behavioural detonation is for: the file
                // is suspicious locally but unconfirmed. NEVER auto-upload;
                // the link is the operator's decision.
                std::string msg =
                    "suspicious but unconfirmed -- detonate safely at ";
                msg += r.sha256.empty()
                           ? std::string("https://any.run/")
                           : std::format("https://any.run/submission/{}/", r.sha256);
                msg += " (upload only if the file is yours to share), or scan the "
                       "folder with KVRT: `hyprnova-cli deep-scan deep " + path + "`";
                o["next_step"] = std::move(msg);
            }
        }
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "combined_scan") {
        auto* tb = agent_.toolbox();
        if (!tb) return refuse("toolbox not available");
        const std::string profile = req.str("profile");
        if (!tools::Toolbox::valid_profile(profile))
            return refuse("profile must be one of: quick, deep, kernel, audit");
        std::vector<std::string> paths;
        if (const Value* a = req.at("paths"); a && a->is_array())
            for (const auto& x : *a->as_array())
                if (const auto p = x.as_string(); !p.empty()) paths.emplace_back(p);
        // Blocking by design (like investigate/tool_run): this runs many engines
        // back to back. Sensors are unaffected; only this reply waits.
        const auto rep = tb->combined_scan(profile, paths);
        SINFO("gui-bridge", "combined scan '{}' (uid {}): {}", profile, uid, rep.summary);
        Object o;
        o["profile"] = rep.profile;
        o["target"] = rep.target;
        o["verdict"] = rep.verdict;
        o["total_findings"] = static_cast<std::int64_t>(rep.total_findings);
        o["malicious"] = static_cast<std::int64_t>(rep.malicious);
        o["summary"] = rep.summary;
        o["elapsed_ms"] = static_cast<std::int64_t>(rep.elapsed.count());
        o["ok"] = rep.ok;
        if (!rep.error.empty()) o["error"] = rep.error;
        hyprnova::core::json::Array secs;
        for (const auto& sec : rep.sections) {
            hyprnova::core::json::Object so;
            so["tool"] = sec.tool;
            so["label"] = sec.label;
            so["ran"] = sec.ran;
            so["ok"] = sec.ok;
            so["note"] = sec.note;
            so["findings"] =
                hyprnova::core::json::Value{hyprnova::core::json::Array(
                    sec.findings.begin(), sec.findings.end())};
            secs.push_back(hyprnova::core::json::Value{std::move(so)});
        }
        o["sections"] = hyprnova::core::json::Value{std::move(secs)};
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "rescue_prepare") {
        auto* rc = agent_.rescue();
        if (!rc) return refuse("rescue module unavailable");
        const bool write = req.integer("write", 0) != 0;
        auto st = rc->prepare(write);
        SINFO("gui-bridge", "rescue prepare (write={}, uid {}): {} blocker(s)", write, uid,
              st.blockers.size());
        Object o;
        o["write"] = write;
        o["prepared"] = st.prepared;
        o["iso_found"] = st.iso_found;
        o["iso_staged"] = st.iso_staged;
        o["grub_entry_present"] = st.grub_entry_present;
        o["clean_script_present"] = st.clean_script_present;
        o["blockers"] = Value{Array(st.blockers.begin(), st.blockers.end())};
        o["preview"] = st.preview;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "rescue_boot") {
        auto* rc = agent_.rescue();
        if (!rc) return refuse("rescue module unavailable");
        if (!agent_.config().rescue.enabled)
            return refuse("rescue.enabled is false in agent.json");
        std::string err;
        const bool once = req.integer("boot_once", 1) != 0;
        if (!rc->boot(once, err)) return refuse(err);
        Object o;
        o["rebooting"] = true;
        o["boot_once"] = once;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "tool_run") {
        const std::string name = req.str("name");
        if (name.empty()) return refuse("\"name\" is required");
        auto* tb = agent_.toolbox();
        if (!tb) return refuse("toolbox not available");
        std::vector<std::string> args;
        if (const Value* a = req.at("args"); a && a->is_array())
            for (const auto& x : *a->as_array())
                if (const auto s = x.as_string(); !s.empty()) args.emplace_back(s);
        // Blocking by design (like `investigate`): a scan runs minutes, the
        // console shows a spinner, the agent's sensors keep running -- only this
        // command's reply waits.
        const auto out = tb->run_tool(name, args);
        SINFO("gui-bridge", "tool run '{}' (uid {}): {}", name, uid,
              out.error.empty() ? out.summary : out.error);
        Object o;
        o["ok"] = out.ok;
        o["timed_out"] = out.timed_out;
        o["exit_code"] = static_cast<std::int64_t>(out.exit_code);
        o["tool"] = out.tool;
        o["binary"] = out.binary;
        o["args"] = Value{Array(out.args.begin(), out.args.end())};
        o["output"] = out.output;
        o["findings"] = Value{Array(out.findings.begin(), out.findings.end())};
        o["summary"] = out.summary;
        o["error"] = out.error;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "vt_lookup") {
        const std::string hash = req.str("hash");
        if (hash.empty()) return refuse("\"hash\" is required");
        auto* tb = agent_.toolbox();
        if (!tb) return refuse("toolbox not available");
        const auto out = tb->vt_lookup(hash);
        Object o;
        o["ok"] = out.ok;
        o["tool"] = out.tool;
        o["findings"] = Value{Array(out.findings.begin(), out.findings.end())};
        o["summary"] = out.summary;
        o["error"] = out.error;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "answer") {
        const auto id = static_cast<std::uint64_t>(req.integer("id", -1));
        const std::string answer = req.str("answer");
        if (id == 0 || answer.empty()) return refuse("\"id\" and \"answer\" are required");
        const auto taken = agent_.remediation().answer(id, answer, "gui:uid" + std::to_string(uid));
        Object o;
        o["decision"] = static_cast<std::int64_t>(id);
        o["answer"] = answer;
        o["action"] = std::string(remediation::action_name(taken));
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "investigate") {
        const pid_t pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 0) return refuse("\"pid\" is required");
        const std::string why = req.str("reason").empty() ? std::string("operator requested investigation from the GUI")
                                                          : req.str("reason");
        // Blocking by design: the GUI shows a progress dialog and the operator is
        // waiting for the answer. It runs on the bridge thread, not the bus.
        const auto rep = agent_.heuristics().escalate(pid, why);
        Object o;
        o["pid"] = static_cast<std::int64_t>(rep.pid);
        o["exe"] = rep.exe;
        o["lineage"] = rep.lineage;
        o["risk"] = rep.risk;
        o["severity"] = std::string(core::severity_name(rep.final_severity));
        o["step"] = std::string(heuristics::step_name(rep.reached));
        o["suspended"] = rep.suspended;
        o["resumed"] = rep.resumed;
        o["wx_regions"] = static_cast<std::int64_t>(rep.wx_regions);
        o["regions_scanned"] = static_cast<std::int64_t>(rep.regions_scanned);
        o["findings"] = arr(rep.findings);
        o["memory_matches"] = arr(rep.memory_matches);
        o["scanned_paths"] = arr(rep.scanned_paths);
        o["elapsed_ms"] = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(rep.finished - rep.started).count());
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "resume" || cmd == "suspend" || cmd == "kill" || cmd == "isolate" || cmd == "release") {
        const pid_t pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 0) return refuse("\"pid\" is required");
        const std::string why = "operator action from the GUI (uid " + std::to_string(uid) + ")";
        auto& rm = agent_.remediation();
        const bool ok = cmd == "resume"   ? rm.resume(pid)
                        : cmd == "suspend" ? rm.suspend(pid, why)
                        : cmd == "kill"    ? rm.kill(pid, why)
                        : cmd == "isolate" ? rm.isolate(pid, why)
                                           : rm.release(pid);
        Object o;
        o["pid"] = static_cast<std::int64_t>(pid);
        o["action"] = std::string(cmd);
        o["result"] = ok;
        if (const auto last = rm.last(cmd == "resume"   ? remediation::Action::Resume
                                      : cmd == "suspend" ? remediation::Action::Suspend
                                      : cmd == "kill"    ? remediation::Action::Kill
                                                         : remediation::Action::Isolate)) {
            o["outcome"] = std::string(remediation::outcome_name(last->outcome));
            o["detail"] = last->detail;
            o["undo"] = last->undo_hint;
        }
        reply["ok"] = ok;
        reply["data"] = Value{std::move(o)};
        if (!ok) reply["error"] = std::string("action refused or failed; see detail");
        return Value{std::move(reply)};
    }
    if (cmd == "quarantine") {
        const std::string path = req.str("path");
        if (path.empty()) return refuse("\"path\" is required");
        const std::string why = "operator quarantine from the GUI (uid " + std::to_string(uid) + ")";
        const bool ok = agent_.remediation().quarantine_file(path, why);
        Object o;
        o["path"] = path;
        o["result"] = ok;
        reply["ok"] = ok;
        reply["data"] = Value{std::move(o)};
        if (!ok) reply["error"] = std::string("quarantine refused or failed");
        return Value{std::move(reply)};
    }
    if (cmd == "restore") {
        const auto id = static_cast<std::uint64_t>(req.integer("id", -1));
        const std::string dest = req.str("to");
        if (id == 0 || dest.empty()) return refuse("\"id\" and \"to\" are required");
        const bool ok = agent_.remediation().restore_file(
            id, dest, req.integer("force", 0) != 0);
        reply["ok"] = ok;
        Object o;
        o["id"] = static_cast<std::int64_t>(id);
        o["to"] = dest;
        o["result"] = ok;
        reply["data"] = Value{std::move(o)};
        if (!ok) reply["error"] = std::string("restore failed; see the agent log");
        return Value{std::move(reply)};
    }
    if (cmd == "block") {
        const std::string ip = req.str("ip");
        if (ip.empty()) return refuse("\"ip\" is required");
        const auto port = static_cast<std::uint16_t>(std::clamp<std::int64_t>(req.integer("port", 0), 0, 65535));
        const auto ttl = std::chrono::seconds{req.integer("ttl_seconds", 0) > 0
                                                  ? req.integer("ttl_seconds", 0)
                                                  : std::chrono::duration_cast<std::chrono::seconds>(
                                                        agent_.config().remediation.block_duration)
                                                        .count()};
        const std::string why = req.str("reason").empty()
                                    ? "operator block from the GUI (uid " + std::to_string(uid) + ")"
                                    : req.str("reason");
        const bool ok = agent_.remediation().block_c2(ip, port, why, ttl);
        // CrowdSec federation: a C2 we consider worth blocking is worth
        // sharing. Push the ban into the local CrowdSec engine (best-effort;
        // absent cscli or a non-LAPI setup degrades to a log line, never an
        // error) so the community blocklist learns the same indicator.
        if (ok && agent_.config().integrations.crowdsec_enabled) {
            // cscli lives on the trusted path; run it the same hardened way the
            // toolbox does. 15s ceiling: this must never stall the bridge.
            std::string cscli;
            for (const char* p : {"/usr/bin/cscli", "/usr/local/bin/cscli"})
                if (core::fsx::exists(p)) { cscli = p; break; }
            if (!cscli.empty()) {
                core::exec::Options opts;
                opts.timeout = std::chrono::seconds{15};
                const auto res = core::exec::run(
                    cscli,
                    {"decisions", "add", "--ip", ip,
                     "--duration", std::format("{}s", ttl.count()),
                     "--reason", std::format("HyprNova C2 block: {}", why)},
                    opts);
                SINFO("gui-bridge", "crowdsec push of ban for {}: exit {}", ip, res.exit_code);
            }
        }
        reply["ok"] = ok;
        Object o;
        o["ip"] = ip;
        o["port"] = static_cast<std::int64_t>(port);
        o["ttl_seconds"] = static_cast<std::int64_t>(ttl.count());
        o["result"] = ok;
        reply["data"] = Value{std::move(o)};
        if (!ok) reply["error"] = std::string("block refused or failed (see capabilities)");
        return Value{std::move(reply)};
    }
    if (cmd == "unblock") {
        const auto id = static_cast<std::uint64_t>(req.integer("id", -1));
        if (id == 0) return refuse("\"id\" is required");
        const bool ok = agent_.remediation().unblock_c2(id);
        reply["ok"] = ok;
        Object o;
        o["id"] = static_cast<std::int64_t>(id);
        o["result"] = ok;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "analysis-plan") {
        std::string sha = req.str("sha256");
        std::transform(sha.begin(), sha.end(), sha.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        auto* tb = agent_.toolbox();
        tools::analysis::Probed probed;
        if (tb) {
            const auto snap = tb->snapshot_json();
            if (const auto* arr = snap.at("tools") ? snap.at("tools")->as_array() : nullptr) {
                for (const auto& t : *arr) {
                    const std::string name = t.str("name");
                    const bool installed =
                        t.at("installed") && t.at("installed")->is_bool() &&
                        t.at("installed")->as_bool(false);
                    if (name == "capa") probed.capa = installed;
                    else if (name == "ghidra") probed.ghidra = installed;
                    else if (name == "cutter") probed.cutter = installed;
                    else if (name == "cape") probed.cape = installed;
                    else if (name == "firejail") probed.firejail = installed;
                    else if (name == "bubblewrap") probed.bubblewrap = installed;
                    else if (name == "qemu") probed.qemu = installed;
                }
            }
        }
        const auto plan = tools::analysis::plan_for(sha, probed);
        reply["ok"] = true;
        reply["data"] = plan.to_json();
        return Value{std::move(reply)};
    }
    if (cmd == "sandbox-cmd") {
        const std::string app = req.str("app");
        std::vector<std::string> app_args;
        if (const auto* arr = req.at("args") ? req.at("args")->as_array() : nullptr)
            for (const auto& v : *arr) app_args.emplace_back(v.as_string_copy());
        tools::analysis::Probed probed;
        if (auto* tb = agent_.toolbox()) {
            const auto snap = tb->snapshot_json();
            if (const auto* arr = snap.at("tools") ? snap.at("tools")->as_array() : nullptr)
                for (const auto& t : *arr) {
                    const std::string name = t.str("name");
                    const bool installed =
                        t.at("installed") && t.at("installed")->is_bool() &&
                        t.at("installed")->as_bool(false);
                    if (name == "firejail") probed.firejail = installed;
                    else if (name == "bubblewrap") probed.bubblewrap = installed;
                }
        }
        tools::analysis::SandboxOptions opts;
        opts.no_network = req.at("no_network") ? req.at("no_network")->as_bool(true) : true;
        opts.private_tmp = req.at("private_tmp") ? req.at("private_tmp")->as_bool(true) : true;
        std::string err;
        auto argv = tools::analysis::sandbox_argv(probed, app, app_args, opts, err);
        if (!argv) return refuse(err);
        reply["ok"] = true;
        Object o;
        Array a;
        for (const auto& v : *argv) a.emplace_back(Value{v});
        o["argv"] = Value{std::move(a)};
        o["backend"] = probed.bubblewrap ? "bubblewrap" : "firejail";
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "block-exe") {
        const auto pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 0) return refuse("\"pid\" is required");
        const auto ttl = std::chrono::seconds{req.integer("ttl_seconds", 0) > 0
                                                  ? req.integer("ttl_seconds", 0)
                                                  : std::chrono::duration_cast<std::chrono::seconds>(
                                                        agent_.config().remediation.block_duration)
                                                        .count()};
        const std::string why = req.str("reason").empty()
                                    ? "operator exe block from the GUI (uid " + std::to_string(uid) + ")"
                                    : req.str("reason");
        std::string resolved;
        const bool ok = agent_.remediation().block_exe(pid, why, ttl, resolved);
        reply["ok"] = ok;
        Object o;
        o["pid"] = static_cast<std::int64_t>(pid);
        o["exe"] = resolved;
        o["result"] = ok;
        reply["data"] = Value{std::move(o)};
        if (!ok) reply["error"] = std::string(
            "exe block refused or failed (needs cgroup v2 + nftables; see capabilities)");
        return Value{std::move(reply)};
    }
    if (cmd == "unblock-exe") {
        const auto id = static_cast<std::uint64_t>(req.integer("id", -1));
        if (id == 0) return refuse("\"id\" is required");
        const bool ok = agent_.remediation().unblock_exe(id);
        reply["ok"] = ok;
        Object o;
        o["id"] = static_cast<std::int64_t>(id);
        o["result"] = ok;
        reply["data"] = Value{std::move(o)};
        if (!ok) reply["error"] = std::string("no active exe block with that id");
        return Value{std::move(reply)};
    }
    if (cmd == "harden") {
        const std::string key = req.str("key");
        const std::string value = req.str("value");
        if (key.empty() || value.empty()) return refuse("\"key\" and \"value\" are required");
        const bool ok = agent_.remediation().apply_sysctl(key, value,
                                                          "operator hardening from the GUI (uid " +
                                                              std::to_string(uid) + ")");
        reply["ok"] = ok;
        Object o;
        o["key"] = key;
        o["value"] = value;
        o["result"] = ok;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "harden_apply_all") {
        auto* kh = agent_.sensor<hardening::KernelHardeningSensor>(core::SensorId::KernelHardening);
        if (!kh) return refuse("the kernel hardening sensor is not running");
        const bool ok = kh->apply_remediation();
        kh->rescan();
        reply["ok"] = ok;
        Object o;
        o["result"] = ok;
        o["report"] = snapshot_hardening();
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "scan") {
        const std::string path = req.str("path");
        auto* sc = agent_.sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch);
        if (!sc) return refuse("the scanning module is disabled");
        if (path.empty()) return refuse("\"path\" is required");
        // Synchronous: the GUI shows a spinner for one file and wants the verdict.
        const auto r = sc->scan_now(path, scanning::ScanReason::OnDemand);
        Object o;
        o["path"] = r.path;
        o["verdict"] = std::string(scanning::verdict_name(r.verdict));
        o["risk"] = static_cast<std::int64_t>(r.risk);
        o["sha256"] = r.sha256;
        o["size"] = static_cast<std::int64_t>(r.size);
        o["entropy"] = r.entropy;
        o["flavour"] = std::string(core::hash::flavour_name(r.flavour));
        o["engine"] = r.engine;
        o["elapsed_ms"] = static_cast<std::int64_t>(r.elapsed.count());
        o["detail"] = r.detail;
        o["from_cache"] = r.from_cache;
        Array m;
        for (const auto& mm : r.matches) {
            Object mo;
            mo["rule"] = mm.rule;
            mo["family"] = mm.family;
            mo["description"] = mm.description;
            mo["severity"] = std::string(core::severity_name(mm.severity));
            m.emplace_back(Value{std::move(mo)});
        }
        o["matches"] = Value{std::move(m)};
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "sweep") {
        auto* sc = agent_.sensor<scanning::ScannerSensor>(core::SensorId::StaticWatch);
        if (!sc) return refuse("the scanning module is disabled");
        sc->start_full_sweep(scanning::ScanPriority::Normal);
        reply["data"] = std::string("full sweep started; progress is published as scan.progress events");
        return Value{std::move(reply)};
    }
    if (cmd == "plant_canaries") {
        auto* cs = agent_.sensor<anti_ransomware::CanarySensor>(core::SensorId::Canary);
        if (!cs) return refuse("the canary module is disabled");
        const bool ok = cs->plant_all();
        reply["ok"] = ok;
        reply["data"] = snapshot_canaries();
        return Value{std::move(reply)};
    }
    if (cmd == "rescan_hardening") {
        if (auto* kh = agent_.sensor<hardening::KernelHardeningSensor>(core::SensorId::KernelHardening))
            kh->rescan();
        if (auto* mac = agent_.sensor<hardening::MacProfileSensor>(core::SensorId::MacProfile))
            mac->rescan();
        if (auto* b = agent_.sensor<hardening::BootAuditSensor>(core::SensorId::BootAudit))
            b->run_full_audit();
        reply["data"] = snapshot_hardening();
        return Value{std::move(reply)};
    }
    if (cmd == "dismiss") {
        const pid_t pid = static_cast<pid_t>(req.integer("pid", 0));
        if (pid <= 0) return refuse("\"pid\" is required");
        agent_.heuristics().dismiss(pid, "dismissed from the GUI by uid " + std::to_string(uid));
        reply["data"] = std::string("risk cleared for pid " + std::to_string(pid));
        return Value{std::move(reply)};
    }
    if (cmd == "reload") {
        const bool ok = agent_.reload_config("gui:uid" + std::to_string(uid));
        reply["ok"] = ok;
        reply["data"] = snapshot_overview();
        if (!ok) reply["error"] = std::string("reload failed; the previous configuration is retained");
        return Value{std::move(reply)};
    }
    if (cmd == "selftest") {
        const auto st = agent_.self_test();
        Object o;
        o["passed"] = st.passed;
        o["checks"] = arr(st.checks);
        o["fatal"] = arr(st.fatal);
        reply["ok"] = st.passed;
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "live") {
        // Let a client opt out of the push feed (useful for a CLI that polls).
        const bool on = req.integer("on", 1) != 0;
        std::lock_guard lk{clients_mu_};
        for (auto& [fd, c] : clients_) {
            (void)fd;
            if (c.uid == uid) c.wants_events = on;
        }
        reply["data"] = on ? std::string("live feed enabled") : std::string("live feed disabled");
        return Value{std::move(reply)};
    }

    if (cmd == "snapshot") {
        // Taking a snapshot writes state: privileged callers only (see above).
        if (!privileged) return refuse("this command requires root on the agent socket");
        const std::string reason = req.str("reason").empty() ? std::string("operator request from the console")
                                                             : req.str("reason");
        std::string d;
        Object o;
        const std::string id = agent_.shadow()->take(reason, d);
        o["id"] = id;
        o["detail"] = d;
        reply["ok"] = !id.empty();
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }
    if (cmd == "restore_shadow") {
        // Restoring writes arbitrary host state. Privileged callers only: the
        // recovery path must be at least as privileged as the path that broke it.
        if (!privileged) return refuse("this command requires root on the agent socket");
        const std::string id = req.str("id");
        if (id.empty()) return refuse("\"id\" is required");
        const std::string to = req.str("to");
        std::string d;
        const auto rep = agent_.shadow()->restore(id, to, d);
        Object o;
        o["id"] = rep.id;
        o["ok"] = rep.ok;
        o["restored"] = static_cast<std::int64_t>(rep.restored);
        o["verified"] = static_cast<std::int64_t>(rep.verified);
        o["failed"] = static_cast<std::int64_t>(rep.failed);
        o["detail"] = rep.detail;
        Array fails;
        for (const auto& f : rep.failures) fails.emplace_back(f);
        o["failures"] = Value{std::move(fails)};
        reply["data"] = Value{std::move(o)};
        return Value{std::move(reply)};
    }

    reply["ok"] = false;
    reply["error"] = std::string("unknown command: ") + std::string(cmd);
    return Value{std::move(reply)};
}

}  // namespace hyprnova
