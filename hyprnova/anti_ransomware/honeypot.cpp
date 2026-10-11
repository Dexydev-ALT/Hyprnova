// SPDX-License-Identifier: Apache-2.0
#include "anti_ransomware/honeypot.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>

#include "core/fd.hpp"
#include "core/hash.hpp"

namespace fs = std::filesystem;

namespace hyprnova::anti_ransomware {

namespace {
constexpr std::string_view kMarker = "# hyprnova decoy -- no real secrets here\n";

std::string sha256_hex(std::string_view bytes) noexcept {
    return core::hash::Sha256::to_hex(core::hash::Sha256::once(bytes));
}

/// Read a honeypot file WITHOUT perturbing it: O_NOATIME so the sweep never
/// advances the atime, and no mtime/ctime side effects. Owner-only files opened
/// by their owner; the EPERM/EACCES fallback keeps the flow working elsewhere.
bool read_noatime(const std::string& path, std::string& out) noexcept {
    core::UniqueFd fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOATIME)};
    if (!fd && (errno == EPERM || errno == EACCES))
        fd = core::UniqueFd{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
    if (!fd) return false;
    out.clear();
    char buf[8192];
    for (;;) {
        const ssize_t r = ::read(fd.get(), buf, sizeof(buf));
        if (r < 0) return false;
        if (r == 0) break;
        out.append(buf, static_cast<std::size_t>(r));
        if (out.size() > (1 << 20)) break;
    }
    return true;
}
}  // namespace

HoneyVerdict honey_classify(bool existed_before, bool exists_now, bool hash_equal,
                            bool atime_advanced) noexcept {
    if (existed_before && !exists_now) return HoneyVerdict::Gone;
    if (!existed_before && !exists_now) return HoneyVerdict::Untouched;  // never planted
    if (!hash_equal) return HoneyVerdict::Modified;
    if (atime_advanced) return HoneyVerdict::Read;  // legacy atime path (see F12 note)
    return HoneyVerdict::Untouched;
}

std::vector<std::string> honey_profile_names() noexcept {
    return {"aws/credentials",
            "ssh/id_rsa",
            "ssh/id_rsa.pub",
            "env/.env",
            "kube/config",
            "npm/.npmrc",
            "gcp/service-account.json",
            "app/settings_secret.py"};
}

std::string honey_profile_body(std::string_view profile) noexcept {
    std::string out;
    if (profile == "aws/credentials") {
        out = "[default]\n"
              "aws_access_key_id = AKIAIOSFODNN7DECOY\n"
              "aws_secret_access_key = wJalrXUtnFEMI/decoy/ONLY/bPxRfiCYNOTAREALKEY\n"
              "region = us-east-1\n"
              "[profile staging]\n"
              "role_arn = arn:aws:iam::123456789012:role/deploy\n"
              "source_profile = default\n";
    } else if (profile == "ssh/id_rsa") {
        // Structurally a PEM key, cryptographically dead: fixed decoy material,
        // not a key pair anyone ever generated.
        out = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
              "b3BlbnNzaC1rZXktdjEAAAAABGh5cHJub3ZhZGVjb3ktbm90LWEta2V5LWh5cHJub3Zh\n"
              "ZGVjb3ktbm90LWEta2V5LWh5cHJub3ZhZGVjb3ktbm90LWEta2V5LWh5cHJub3ZhZGVj\n"
              "b3ktbm90LWEta2V5LWh5cHJub3ZhZGVjb3ktbm90LWEta2V5LWh5cHJub3ZhZGVjb3k=\n"
              "-----END OPENSSH PRIVATE KEY-----\n";
    } else if (profile == "ssh/id_rsa.pub") {
        out = "ssh-rsa AAAAB3NzaC1yc2E-decoy-not-a-real-key-hyprnova honeypot@hyprnova\n";
    } else if (profile == "env/.env") {
        out = "DATABASE_URL=postgres://app:decoy_not_a_password@127.0.0.1:5432/prod\n"
              "SECRET_KEY=django-insecure-decoy-key-never-use\n"
              "STRIPE_SECRET_KEY=sk_test_decoy_hyprnova\n"
              "JWT_SIGNING_SECRET=decoy-only-hyprnova\n";
    } else if (profile == "kube/config") {
        out = "apiVersion: v1\nkind: Config\nclusters:\n- name: prod\n  cluster:\n"
              "    server: https://k8s.example.invalid:6443\nusers:\n- name: deploy\n"
              "  user:\n    token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlY295In0.decDecoy\n"
              "contexts:\n- name: prod\n  context: {cluster: prod, user: deploy}\n";
    } else if (profile == "npm/.npmrc") {
        out = "registry=https://registry.npmjs.org/\n"
              "//registry.npmjs.org/:_authToken=npm_decoy_token_hyprnova\n";
    } else if (profile == "gcp/service-account.json") {
        out = "{\"type\":\"service_account\",\"project_id\":\"decoy-prod\","
              "\"private_key_id\":\"0000000000000000000000000000000000000000\","
              "\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nDECOY\\n-----END PRIVATE "
              "KEY-----\\n\",\"client_email\":\"deploy@decoy-prod.iam.gserviceaccount.com\"}\n";
    } else if (profile == "app/settings_secret.py") {
        out = "SECRET_KEY = 'django-decoy-secret-key-hyprnova'\n"
              "AWS_S3_BUCKET = 'decoy-prod-backups'\n"
              "SENDGRID_API_KEY = 'SG.decoy_decoy_decoy'\n";
    } else {
        return std::string(kMarker);
    }
    out += kMarker;
    return out;
}

std::vector<HoneyOpener> honey_find_openers(std::string_view path) noexcept {
    std::vector<HoneyOpener> out;
    DIR* procs = ::opendir("/proc");
    if (!procs) return out;
    while (const auto* de = ::readdir(procs)) {
        const std::string_view name = de->d_name;
        if (name.empty() || name[0] < '0' || name[0] > '9') continue;
        const pid_t pid = ::atoi(std::string(name).c_str());
        if (pid <= 0) continue;
        const std::string fddir = std::format("/proc/{}/fd", name);
        DIR* fds = ::opendir(fddir.c_str());
        if (!fds) continue;  // other user's process: invisible, honestly skipped
        while (const auto* fe = ::readdir(fds)) {
            if (fe->d_name[0] < '0' || fe->d_name[0] > '9') continue;
            char target[4096] = {};
            const ssize_t n = ::readlink((fddir + "/" + fe->d_name).c_str(), target,
                                         sizeof(target) - 1);
            if (n <= 0) continue;
            target[n] = '\0';
            if (path == target) {
                HoneyOpener o;
                o.pid = pid;
                std::string comm;
                if (core::fsx::read_file(std::format("/proc/{}/comm", name), comm, 256) > 0) {
                    while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r'))
                        comm.pop_back();
                }
                o.comm = std::move(comm);
                out.push_back(std::move(o));
            }
        }
        ::closedir(fds);
    }
    ::closedir(procs);
    std::sort(out.begin(), out.end(),
              [](const HoneyOpener& a, const HoneyOpener& b) { return a.pid < b.pid; });
    return out;
}

// ---------------------------------------------------------------------------
// Sensor
// ---------------------------------------------------------------------------

HoneypotSensor::HoneypotSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                               core::ThreadPool& pool)
    : core::ISensor("honeypot", core::SensorId::Canary, bus, cfg, pool) {
    root_ = cfg_.state_dir + "/honeypots";
}

bool HoneypotSensor::on_start() {
    if (!plant_all()) {
        mark_degraded("honeypot planting failed in " + root_ +
                      " -- decoys are absent, the module will report nothing");
        // Degraded, not dead: watches on whatever DID plant still work.
    }
    if (!arm_watches()) {
        mark_degraded("inotify unavailable for honeypot decoys: read/tamper/delete "
                      "detection degraded to the periodic hash sweep");
    }
    check_all();
    mark_running(std::to_string(planted_count_) + " decoy config(s) at " + root_ +
                 (ino_fd_ >= 0 ? " (event-driven)" : " (sweep-only)"));
    return true;  // absence of decoys is degraded, never fatal
}

bool HoneypotSensor::plant_all() noexcept {
    std::error_code ec;
    fs::create_directories(root_, ec);
    if (ec) {
        note_error("create " + root_);
        return false;
    }
    (void)fs::permissions(root_, fs::perms::owner_all, ec);

    planted_.clear();
    bool all_ok = true;
    for (const auto& rel : honey_profile_names()) {
        Honey h;
        h.rel = rel;
        h.abs = root_ + "/" + rel;
        const std::string body = honey_profile_body(rel);
        h.sha256 = sha256_hex(body);

        struct stat st {};
        bool fresh = true;
        if (::stat(h.abs.c_str(), &st) == 0) {
            // Existing file: keep it (stable bait). Content is verified against
            // OUR hash every sweep; a mismatch surfaces as Modified.
            fresh = false;
        } else {
            const auto slash = h.abs.find_last_of('/');
            if (slash != std::string::npos)
                (void)fs::create_directories(h.abs.substr(0, slash), ec);
        }
        if (fresh && !core::fsx::write_atomic(
                         h.abs, {reinterpret_cast<const std::byte*>(body.data()), body.size()},
                         0600)) {
            all_ok = false;
            note_error("plant " + h.abs);
            continue;
        }
        std::lock_guard lk{planted_mu_};
        planted_.push_back(std::move(h));
    }
    planted_count_ = planted_.size();
    return all_ok;
}

std::vector<HoneypotSensor::HoneyView> HoneypotSensor::planted() const noexcept {
    std::lock_guard lk{planted_mu_};
    std::vector<HoneyView> out;
    out.reserve(planted_.size());
    for (const auto& h : planted_)
        out.push_back(HoneyView{h.rel, root_, h.sha256});
    return out;
}

bool HoneypotSensor::arm_watches() noexcept {
    if (ino_fd_ >= 0) return true;
    const int fd = ::inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (fd < 0) return false;
    ino_fd_ = fd;
    for (auto& h : planted_) {
        const int wd = ::inotify_add_watch(
            fd, h.abs.c_str(), IN_ACCESS | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
        if (wd >= 0) h.wd = wd;
    }
    return true;
}

void HoneypotSensor::handle_event(const struct ::inotify_event* ev) noexcept {
    // Self-sweep suppression: our own hash verification opens every decoy with
    // O_NOATIME, but inotify still reports IN_ACCESS for it. Sweeps must never
    // look like attackers.
    if (self_sweep_.load(std::memory_order_acquire)) return;

    for (auto& h : planted_) {
        if (h.wd != ev->wd) continue;
        if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
            emit(core::EventKind::FileCanaryHit, core::Severity::High,
                 std::format("HONEYPOT DELETED: decoy '{}' is gone (anti-forensics or "
                             "cleanup sweep)",
                             h.rel));
        } else if (ev->mask & IN_MODIFY) {
            emit(core::EventKind::FileCanaryHit, core::Severity::Critical,
                 std::format("HONEYPOT MODIFIED: decoy '{}' content changed -- an external "
                             "writer touched agent bait",
                             h.rel));
        } else if (ev->mask & IN_ACCESS) {
            std::string actors;
            for (const auto& o : honey_find_openers(h.abs))
                actors += std::format(" {}({})", o.comm.empty() ? "?" : o.comm, o.pid);
            emit(core::EventKind::FileCanaryHit, core::Severity::High,
                 std::format("HONEYPOT READ: decoy '{}' was opened; nobody legitimate "
                             "reads decoy credentials. Open now:{}",
                             h.rel,
                             actors.empty()
                                 ? " (fd closed since; no /proc attribution)"
                                 : actors));
        }
        return;
    }
}

void HoneypotSensor::check_all() noexcept {
    self_sweep_.store(true, std::memory_order_release);
    for (const auto& h : planted_) {
        struct stat st {};
        const bool exists = ::stat(h.abs.c_str(), &st) == 0;
        bool hash_equal = true;
        if (exists) {
            std::string body;
            if (read_noatime(h.abs, body)) hash_equal = sha256_hex(body) == h.sha256;
        }
        // Atime is deliberately NOT consulted for reads: relatime coalesces
        // them and same-uid readers are unattributable (F12 lessons). Reads
        // come from the inotify watches instead; this sweep is the integrity
        // net for tamper/gone in case an event was missed.
        const auto v = honey_classify(true, exists, hash_equal, false);
        switch (v) {
            case HoneyVerdict::Untouched:
            case HoneyVerdict::Read:  // handled by the inotify path only
                break;
            case HoneyVerdict::Modified:
                emit(core::EventKind::FileCanaryHit, core::Severity::Critical,
                     std::format("HONEYPOT MODIFIED: decoy '{}' content changed -- an external "
                                 "writer touched agent bait",
                                 h.rel));
                break;
            case HoneyVerdict::Gone:
                emit(core::EventKind::FileCanaryHit, core::Severity::High,
                     std::format("HONEYPOT DELETED: decoy '{}' is gone (anti-forensics or "
                                 "cleanup sweep)",
                                 h.rel));
                break;
        }
    }
    // Discard everything the sweep queued (our own reads fire IN_ACCESS even
    // under O_NOATIME). Draining here, while the guard is still up, means a
    // sweep can never masquerade as an attacker read.
    if (ino_fd_ >= 0) {
        std::array<std::byte, 4096> sink{};
        while (::read(ino_fd_, sink.data(), sink.size()) > 0) {}
    }
    self_sweep_.store(false, std::memory_order_release);
}

void HoneypotSensor::loop(std::stop_token st) {
    const auto interval = cfg_.canary.integrity_check_interval;
    auto next_sweep = std::chrono::steady_clock::now() + interval;
    std::array<std::byte, 4096> buf{};

    while (!st.stop_requested()) {
        // Drain inotify promptly (100 ms slices) so reads/tampers fire fast.
        if (ino_fd_ >= 0) {
            pollfd pfd{};
            pfd.fd = ino_fd_;
            pfd.events = POLLIN;
            const int r = ::poll(&pfd, 1, 100);
            if (r > 0) {
                for (;;) {
                    const ssize_t n = ::read(ino_fd_, buf.data(), buf.size());
                    if (n <= 0) break;
                    const char* p = reinterpret_cast<const char*>(buf.data());
                    const char* const end = p + n;
                    while (p + sizeof(struct ::inotify_event) <= end) {
                        const auto* ev = reinterpret_cast<const struct ::inotify_event*>(p);
                        handle_event(ev);
                        if (ev->len == 0) break;
                        p += sizeof(struct ::inotify_event) + ev->len;
                    }
                }
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (std::chrono::steady_clock::now() >= next_sweep) {
            check_all();
            next_sweep += interval;
        }
    }
}

HoneypotSensor::~HoneypotSensor() {
    if (ino_fd_ >= 0) ::close(ino_fd_);
}

}  // namespace hyprnova::anti_ransomware
