// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 1a implementation

#include "hardening/boot_auditor.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <format>
#include <fstream>
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <thread>
#include <unistd.h>

#include "core/exec.hpp"
#include "core/fd.hpp"
#include "core/hash.hpp"
#include "core/proc.hpp"
#include "hardening/kernel_hardening.hpp"

namespace hyprnova::hardening {

namespace fsx = core::fsx;
using core::hash::Sha256;
using namespace std::chrono_literals;
using namespace std::string_view_literals;

namespace {

/// Split /proc/cmdline on whitespace, preserving quotes.
std::vector<std::string> tokenize(std::string_view s) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quote = false;
    for (const char c : s) {
        if (c == '"') { in_quote = !in_quote; cur.push_back(c); continue; }
        if (!in_quote && (c == ' ' || c == '\t' || c == '\n')) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
            continue;
        }
        cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::string sha256_of_path(std::string_view path) {
    const auto d = Sha256::of_file(path);
    return Sha256::to_hex(d);
}

/// Extract CN= subjects from a DER-ish EFI key payload. We do not link OpenSSL's
/// X509 parser: the PK/KEK/db payload is a WIN_CERTIFICATE_UEFI_GUID wrapping
/// raw DER, and a naive scan for the printable CN substring is enough to tell an
/// operator *which* keys are enrolled, which is the actual question.
std::vector<std::string> extract_subjects(std::string_view raw) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while ((pos = raw.find("CN=", pos)) != std::string_view::npos) {
        std::size_t end = pos + 3;
        while (end < raw.size() && static_cast<unsigned char>(raw[end]) >= 0x20 &&
               static_cast<unsigned char>(raw[end]) < 0x7f)
            ++end;
        if (end > pos + 3) out.emplace_back(raw.substr(pos + 3, end - pos - 3));
        pos = end;
    }
    return out;
}

bool looks_like_executable_path(std::string_view p) noexcept {
    return fsx::exists(p) && ::access(std::string(p).c_str(), X_OK) == 0;
}

std::string first_existing(const std::vector<std::string>& paths) {
    for (const auto& p : paths) {
        if (looks_like_executable_path(p)) return p;
    }
    return {};
}

/// Helper execution goes through core::exec::run: absolute path, execve, minimal
/// environment, no /bin/sh. See core/exec.hpp for why that matters.
struct ExecResult {
    bool ok{false};
    int exit_code{-1};
    std::string out;
    std::string err;
};

ExecResult run_capture(const std::string& path, const std::vector<std::string>& args,
                       std::chrono::milliseconds timeout = 10s) {
    core::exec::Options o;
    o.timeout = timeout;
    o.max_output_bytes = 1 << 20;
    const auto r = core::exec::run(path, args, o);
    return ExecResult{r.ok(), r.exit_code, r.out, r.err};
}

}  // namespace

// ---------------------------------------------------------------------------
// Secure Boot
// ---------------------------------------------------------------------------

SecureBootStatus audit_secure_boot(const core::BootIntegrityConfig& cfg) noexcept {
    SecureBootStatus st;

    // Is this a UEFI platform at all? BIOS-boot machines have no efivarfs and
    // that is a finding, not an error.
    st.platform_supports_uefi = fsx::is_dir("/sys/firmware/efi");
    if (!st.platform_supports_uefi) {
        st.findings.push_back("Platform booted in legacy/CSM BIOS mode: no UEFI Secure Boot possible. "
                              "Boot chain is unmeasured and unverified.");
        st.score = 0;
        return st;
    }

    st.efivarfs_mounted = fsx::is_dir("/sys/firmware/efi/efivars");
    if (!st.efivarfs_mounted) {
        st.findings.push_back("/sys/firmware/efi/efivars is not mounted: cannot read Secure Boot state.");
        st.score = 10;
        return st;
    }

    // The canonical variables.
    struct VarSpec {
        const char* file;
        const char* name;
        const char* guid;
        bool is_key_db;
    };
    static constexpr VarSpec kVars[] = {
        {"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", "SecureBoot", "EFI_GLOBAL", false},
        {"SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", "SetupMode", "EFI_GLOBAL", false},
        {"PK-8be4df61-93ca-11d2-aa0d-00e098032b8c", "PK", "EFI_GLOBAL", true},
        {"KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c", "KEK", "EFI_GLOBAL", true},
        {"db-d719b2cb-3d3a-4596-a3bc-dad00e67656f", "db", "EFI_IMAGE_SECURITY_DATABASE", true},
        {"dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f", "dbx", "EFI_IMAGE_SECURITY_DATABASE", true},
        {"MokList-605dab50-e046-4300-ab63-5e815b740e44", "MokList", "SHIM", true},
        {"MokListRT-605dab50-e046-4300-ab63-5e815b740e44", "MokListRT", "SHIM", true},
    };

    int score = 0;
    for (const auto& spec : kVars) {
        EfiVariable v;
        v.name = spec.name;
        v.guid = spec.guid;

        const std::string path = std::string(cfg.efi_var_paths.empty()
                                                 ? "/sys/firmware/efi/efivars"
                                                 : cfg.efi_var_paths.front()) +
                                 "/" + spec.file;

        std::string raw;
        const std::ptrdiff_t n = fsx::read_file(path, raw, 1 << 20);
        v.exists = fsx::exists(path);
        v.readable = n >= 0;

        if (v.readable && n >= 4) {
            // efivarfs prepends 4 bytes of EFI variable attributes.
            std::uint32_t attrs = 0;
            std::memcpy(&attrs, raw.data(), 4);
            v.size = static_cast<std::size_t>(n) - 4;
            const std::string_view payload{raw.data() + 4, v.size};
            v.sha256 = Sha256::to_hex(Sha256::once(
                {reinterpret_cast<const std::byte*>(payload.data()), payload.size()}));
            // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS == 0x20
            v.immutable = (attrs & 0x20u) != 0;
            if (spec.is_key_db) v.subjects = extract_subjects(payload);

            if (spec.name == "SecureBoot"sv) {
                st.secure_boot_var = std::to_string(static_cast<int>(static_cast<unsigned char>(payload[0])));
                st.secure_boot_enabled = !payload.empty() && static_cast<unsigned char>(payload[0]) == 1;
            } else if (spec.name == "SetupMode"sv) {
                st.setup_mode = !payload.empty() && static_cast<unsigned char>(payload[0]) == 1;
            } else if (spec.name == "MokList"sv && v.size > 0) {
                st.mok_list_present = true;
            }
        }
        st.variables.push_back(std::move(v));
    }

    if (st.secure_boot_enabled) score += 45;
    else st.findings.push_back("UEFI Secure Boot is DISABLED. Unsigned bootloaders and kernels can be "
                               "loaded; boot-chain integrity cannot be asserted.");

    if (st.setup_mode) {
        score -= 20;
        st.findings.push_back("Platform is in SETUP MODE: no Platform Key is enrolled, so Secure Boot "
                              "cannot enforce anything even if the flag is set.");
    } else {
        score += 15;
    }

    // dbx presence and size is the strongest cheap signal that revocations are live.
    for (const auto& v : st.variables) {
        if (v.name == "dbx") {
            if (!v.exists || v.size == 0) {
                score -= 15;
                st.findings.push_back("dbx (revocation database) is empty or absent: known-bad "
                                      "bootloaders/shims are NOT revoked.");
            } else if (v.size > 8192) {
                score += 10;  // a populated dbx means the firmware received updates
            }
        }
        if (v.name == "PK" && v.readable && v.subjects.size() == 1) {
            const auto& cn = v.subjects.front();
            // If the PK is still a Microsoft/OEM key the operator does not own
            // the root of trust; that is normal on consumer hardware but must be
            // stated explicitly in an enterprise report.
            if (cn.find("Microsoft") != std::string::npos || cn.find("OEM") != std::string::npos) {
                st.manufacturer_keys_only = true;
                st.findings.push_back("PK is vendor-owned (" + cn + "): the root of trust is the "
                                      "manufacturer, not this organisation. Custom kernel/module "
                                      "signing will require re-enrolment.");
                score -= 5;
            } else {
                score += 10;
            }
        }
        if (!v.readable && v.exists) {
            st.findings.push_back("EFI variable " + v.name + " exists but is unreadable (need root or "
                                  "the efivarfs is mounted read-only/immutable).");
        }
    }

    // sbctl gives a much richer picture when installed (Arch/Debian packaging).
    const std::string sbctl = first_existing(cfg.sbctl_paths);
    if (!sbctl.empty()) {
        st.sbctl_available = true;
        auto r = run_capture(sbctl, {"status"});
        if (r.ok || !r.out.empty()) {
            st.sbctl_status_raw = r.out;
            // sbctl prints "Secure Boot: enabled/disabled" and "Vendor Keys: ..."
            if (st.sbctl_status_raw.find("disabled") != std::string::npos &&
                !st.secure_boot_enabled) {
                st.findings.push_back("sbctl confirms Secure Boot is disabled.");
            }
            if (st.sbctl_status_raw.find("Secure Boot: enabled") != std::string::npos) score += 5;
        }
        // Also verify every boot entry's signature chain.
        auto rv = run_capture(sbctl, {"verify"});
        if (!rv.out.empty()) {
            for (const auto& tok : tokenize(rv.out)) {
                if (tok.find("FAILED") != std::string::npos || tok.find("not signed") != std::string::npos) {
                    st.findings.push_back("sbctl verify: " + rv.out.substr(0, 400));
                    score -= 25;
                    break;
                }
            }
        }
    } else {
        st.missing_tools.push_back("sbctl (recommended for key enrolment state)");
        st.findings.push_back("sbctl not installed: falling back to raw efivarfs inspection. Install "
                              "sbctl or efitools for authoritative key-enrolment reporting.");
    }

    st.score = std::clamp(score, 0, 100);
    st.trustworthy = st.secure_boot_enabled && !st.setup_mode && st.score >= 60;
    return st;
}

// ---------------------------------------------------------------------------
// Kernel command line
// ---------------------------------------------------------------------------

KernelCmdline audit_kernel_cmdline(const core::BootIntegrityConfig& cfg) noexcept {
    KernelCmdline c;
    std::string raw;
    if (fsx::read_file("/proc/cmdline", raw, 8192) < 0) {
        c.findings.push_back("/proc/cmdline unreadable: cannot audit boot parameters.");
        return c;
    }
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r')) raw.pop_back();
    c.raw = raw;
    c.tokens = tokenize(raw);

    for (const auto& t : c.tokens) {
        for (const auto& bad : cfg.forbidden_cmdline) {
            // Match either the whole token or a "key=" prefix of it.
            if (t == bad || (bad.ends_with("=") && t.starts_with(bad)) ||
                (!bad.empty() && t.starts_with(bad) && bad.find('=') == std::string::npos &&
                 t.size() > bad.size() && (t[bad.size()] == '=' || t[bad.size()] == ' '))) {
                c.forbidden_present.push_back(t);
            }
        }
        if (t.starts_with("init=")) c.init = std::string(t.substr(5));
        if (t.starts_with("root=")) c.root = std::string(t.substr(5));
        if (t.starts_with("lockdown=")) c.lockdown_param = std::string(t.substr(9));
        if (t == "systemd.debug_shell=1" || t == "systemd.debug_shell") c.debug_shell = true;
        if (t == "audit=0") c.audit_disabled = true;
        if (t.starts_with("lsm=") || t == "apparmor=0" || t == "selinux=0") c.lsm_overridden = true;
    }

    for (const auto& want : cfg.expected_cmdline) {
        const std::size_t eq = want.find('=');
        const std::string key = eq == std::string::npos ? want : want.substr(0, eq);
        bool present = false;
        for (const auto& t : c.tokens) {
            if (t == want) { present = true; break; }
            if (eq != std::string::npos && t.starts_with(key + "=")) { present = true; break; }
        }
        if (present) c.expected_present.push_back(want);
        else c.expected_missing.push_back(want);
    }

    if (!c.forbidden_present.empty()) {
        c.findings.push_back("Kernel command line contains parameters that weaken the platform: " +
                             [&] {
                                 std::string s;
                                 for (const auto& f : c.forbidden_present) { if (!s.empty()) s += ", "; s += f; }
                                 return s;
                             }());
    }
    if (!c.init.empty() && c.init != "/sbin/init" && c.init != "/lib/systemd/systemd" &&
        c.init != "/usr/lib/systemd/systemd") {
        c.findings.push_back("init= is overridden to '" + c.init + "'. This is the classic single-user / "
                             "emergency-shell boot trick used to obtain root without credentials.");
    }
    if (c.debug_shell) {
        c.findings.push_back("systemd.debug_shell is enabled: a root shell is available on tty9 without "
                             "authentication.");
    }
    if (c.audit_disabled) {
        c.findings.push_back("audit=0 disables the kernel audit subsystem: Module 4's auditd sensor is "
                             "structurally blind on this host.");
    }
    if (c.lsm_overridden) {
        c.findings.push_back("The LSM stack was overridden on the command line; MAC enforcement cannot "
                             "be assumed to match the on-disk policy.");
    }
    if (!c.expected_missing.empty()) {
        c.findings.push_back(std::format("Hardening parameters absent from the kernel command line ({}): {}",
                                         c.expected_missing.size(),
                                         [&] {
                                             std::string s;
                                             for (const auto& m : c.expected_missing) {
                                                 if (!s.empty()) s += " ";
                                                 s += m;
                                             }
                                             return s;
                                         }()));
    }
    return c;
}

// ---------------------------------------------------------------------------
// Kernel identity
// ---------------------------------------------------------------------------

KernelIdentity audit_kernel_identity() noexcept {
    KernelIdentity k;
    ::utsname u{};
    if (::uname(&u) == 0) {
        k.release = u.release;
        k.version = u.version;
    } else {
        k.release = fsx::read_trimmed("/proc/sys/kernel/osrelease");
    }

    const std::string& r = k.release;
    // Flavour detection: distro hardened kernels announce themselves in the release string.
    for (const char* marker : {"hardened", "-grsec", "grsecurity", "-ck", "zen", "lts", "-secure",
                               "kspp", "-aws", "-gcp"}) {
        if (r.find(marker) != std::string::npos) {
            if (std::string_view(marker) == "lts"sv) k.is_lts = true;
            else k.is_hardened_flavour = true;
        }
    }
    // A release string alone is not proof. Cross-check KSPP-aligned runtime knobs:
    // a genuinely hardened kernel exposes and enforces these.
    const auto bpf = read_sysctl("kernel.unprivileged_bpf_disabled");
    const auto va = read_sysctl("kernel.randomize_va_space");
    const auto init_alloc = read_sysctl("init_on_alloc");
    if ((bpf && *bpf == "1") && (va && *va == "2") && init_alloc && *init_alloc == "1") {
        k.is_hardened_flavour = true;
    }

    // Taint flags: out-of-tree (O), unsigned (E), proprietary (P) modules.
    std::string tainted_raw;
    if (fsx::read_file("/proc/sys/kernel/tainted", tainted_raw, 64) >= 0) {
        unsigned long long mask = 0;
        const auto* p = tainted_raw.c_str();
        if (std::from_chars(p, p + tainted_raw.size(), mask).ec == std::errc{} && mask != 0) {
            k.tainted = true;
            k.taint_flags = std::to_string(mask);
            struct Bit { unsigned long long v; const char* meaning; };
            static constexpr Bit kBits[] = {
                {1ull << 0, "proprietary module loaded (P)"},
                {1ull << 1, "module force-loaded"},
                {1ull << 2, "kernel running on an out-of-spec system"},
                {1ull << 3, "processor reported MCE"},
                {1ull << 4, "bad page reference/unexpected page flags"},
                {1ull << 5, "taint requested by userspace (e.g. a helper)"},
                {1ull << 6, "kernel died recently (OOPS or BUG)"},
                {1ull << 7, "ACPI table overridden by user"},
                {1ull << 8, "kernel issued warning"},
                {1ull << 9, "staging driver loaded"},
                {1ull << 10, "workaround for platform firmware bug applied"},
                {1ull << 11, "unsigned module loaded (E)"},
                {1ull << 12, "soft lockup occurred"},
                {1ull << 13, "kernel live-patched"},
                {1ull << 14, "auxiliary taint"},
                {1ull << 15, "out-of-tree module loaded (O)"},
                {1ull << 16, "unsigned module loaded from a locked-down kernel"},
            };
            for (const auto& b : kBits) {
                if (mask & b.v) k.taint_meanings.emplace_back(b.meaning);
            }
            k.findings.push_back("Kernel is TAINTED (mask " + k.taint_flags + "): " +
                                 [&] {
                                     std::string s;
                                     for (const auto& m : k.taint_meanings) { if (!s.empty()) s += "; "; s += m; }
                                     return s;
                                 }());
        }
    }

    // Module signature enforcement.
    const auto sig = read_sysctl("kernel.module.sig_enforce");
    k.module_signature_enforced = sig && (*sig == "1" || *sig == "Y");
    if (!k.module_signature_enforced) {
        k.findings.push_back("kernel.module.sig_enforce is off: any root process can insert an "
                             "arbitrary kernel module. LKM rootkits are trivially installable.");
    }

    // Loaded-module inventory digest for drift detection across reboots.
    std::string lsmod;
    if (fsx::read_file("/proc/modules", lsmod, 1 << 20) >= 0) {
        std::vector<std::string> names;
        std::size_t pos = 0;
        while (pos < lsmod.size()) {
            const std::size_t nl = lsmod.find('\n', pos);
            const std::string_view line{lsmod.data() + pos, (nl == std::string_view::npos ? lsmod.size() : nl) - pos};
            const std::size_t sp = line.find(' ');
            if (sp != std::string_view::npos) names.emplace_back(line.substr(0, sp));
            if (nl == std::string_view::npos) break;
            pos = nl + 1;
        }
        std::sort(names.begin(), names.end());
        std::string joined;
        for (const auto& n : names) { joined += n; joined += '\n'; }
        k.loaded_module_count = names.size();
        k.loaded_modules_digest = Sha256::to_hex(Sha256::once(joined));
    }

    if (!k.is_hardened_flavour) {
        k.findings.push_back("Kernel '" + k.release + "' does not identify as a hardened build and its "
                             "runtime knobs are not KSPP-aligned. Consider linux-hardened or enabling "
                             "init_on_alloc/init_on_free/slab_nomerge.");
    }
    return k;
}

// ---------------------------------------------------------------------------
// initramfs
// ---------------------------------------------------------------------------

InitramfsStatus audit_initramfs(const std::string& path, const std::string& baseline_sha256) noexcept {
    InitramfsStatus s;
    s.path = path;
    s.baseline_sha256 = baseline_sha256;
    if (!fsx::exists(path)) {
        s.findings.push_back("initramfs not found at " + path);
        return s;
    }
    s.exists = true;
    if (auto sz = fsx::file_size(path)) s.size = *sz;
    struct stat st {};
    if (::stat(path.c_str(), &st) == 0) s.mtime_unix = static_cast<std::int64_t>(st.st_mtime);
    s.sha256 = sha256_of_path(path);
    if (!baseline_sha256.empty() && baseline_sha256 != s.sha256) {
        s.changed_since_baseline = true;
        s.findings.push_back("initramfs digest CHANGED since the recorded baseline (" +
                             baseline_sha256.substr(0, 16) + "... -> " + s.sha256.substr(0, 16) +
                             "...). Early-boot payload was rebuilt or tampered with.");
    }
    if (s.exists && (st.st_mode & (S_IWOTH | S_IWGRP))) {
        s.findings.push_back("initramfs is group/world writable: any local user can replace the "
                             "early-boot payload and gain pre-init root.");
    }
    return s;
}

// ---------------------------------------------------------------------------
// Bootloader
// ---------------------------------------------------------------------------

BootloaderStatus audit_bootloader() noexcept {
    BootloaderStatus b;
    static constexpr const char* kCandidates[] = {
        "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/BOOT/grub.cfg",
        "/boot/efi/EFI/debian/grub.cfg", "/boot/efi/EFI/fedora/grub.cfg",
        "/boot/efi/EFI/arch/grub.cfg", "/boot/loader/loader.conf", "/etc/default/grub",
        "/boot/grub/custom.cfg", "/boot/grub/grubenv",
    };

    for (const char* c : kCandidates) {
        if (!fsx::exists(c)) continue;
        b.config_paths.emplace_back(c);
        if (std::string_view(c).find("loader.conf") != std::string_view::npos) b.flavour = "systemd-boot";
        else if (b.flavour.empty()) b.flavour = "grub2";

        b.digests.emplace_back(c, sha256_of_path(c));

        struct stat st {};
        if (::stat(c, &st) == 0 && (st.st_mode & (S_IWOTH | S_IWGRP))) {
            b.world_writable_config = true;
            b.findings.push_back(std::string("Bootloader config ") + c +
                                 " is group/world writable: an unprivileged local user can rewrite "
                                 "the boot path (e.g. add init=/bin/sh) and own the machine at next boot.");
        }
    }
    if (b.flavour.empty()) b.flavour = "unknown";

    // BLS entries (Fedora/RHEL/Arch systemd-boot).
    if (fsx::is_dir("/boot/loader/entries")) {
        core::UniqueDir d{::opendir("/boot/loader/entries")};
        if (d) {
            while (const dirent* e = ::readdir(d.get())) {
                if (e->d_name[0] == '.') continue;
                const std::string p = std::string("/boot/loader/entries/") + e->d_name;
                std::string content;
                if (fsx::read_file(p, content, 1 << 16) >= 0) {
                    if (content.find("init=/bin/sh") != std::string::npos ||
                        content.find("rd.break") != std::string::npos ||
                        content.find("single") != std::string::npos) {
                        b.findings.push_back("Boot loader entry " + p +
                                             " contains an emergency-shell parameter.");
                    }
                    b.digests.emplace_back(p, Sha256::to_hex(Sha256::once(content)));
                }
            }
        }
    }
    return b;
}

// ---------------------------------------------------------------------------
// Kernel modules
// ---------------------------------------------------------------------------

std::vector<ModuleIntegrity> audit_kernel_modules(std::size_t max_modules) noexcept {
    std::vector<ModuleIntegrity> out;
    std::string raw;
    if (fsx::read_file("/proc/modules", raw, 1 << 20) < 0) return out;

    ::utsname u{};
    ::uname(&u);
    const std::string tree_root = std::string("/lib/modules/") + u.release + "/kernel";

    std::size_t pos = 0;
    while (pos < raw.size() && out.size() < max_modules) {
        const std::size_t nl = raw.find('\n', pos);
        const std::string_view line{raw.data() + pos, (nl == std::string_view::npos ? raw.size() : nl) - pos};
        pos = nl == std::string::npos ? raw.size() : nl + 1;
        if (line.empty()) continue;

        ModuleIntegrity m;
        const auto toks = tokenize(line);
        if (toks.empty()) continue;
        m.name = toks[0];
        if (toks.size() > 1) {
            unsigned long long sz = 0;
            if (std::from_chars(toks[1].c_str(), toks[1].c_str() + toks[1].size(), sz).ec == std::errc{})
                m.size = sz;
        }
        m.live = true;

        // Resolve the on-disk path from /sys/module/<name>/sections/.text or the
        // module's srcversion + modinfo. Cheap approximation: look for the .ko.
        const std::string sysfs = "/sys/module/" + m.name;
        m.path = fsx::read_trimmed(sysfs + "/coresize").empty() ? "" : sysfs;
        if (fsx::exists(sysfs + "/taint")) {
            const std::string taint = fsx::read_trimmed(sysfs + "/taint");
            if (taint.find('O') != std::string::npos) m.in_tree = false;
            if (taint.find('E') != std::string::npos) m.signed_ = false;
            else m.signed_ = true;
            if (taint.empty()) m.signed_ = true;
        }
        // A module whose name has no in-tree counterpart under /lib/modules is
        // out-of-tree by construction.
        const std::string probe = tree_root + "/" + m.name;
        m.in_tree = m.in_tree || fsx::exists(probe) || fsx::exists(probe + ".ko") ||
                    fsx::exists(probe + ".ko.xz") || fsx::exists(probe + ".ko.zst");
        m.from_writable_path = !m.path.empty() && core::proc::is_world_writable_runtime_dir(m.path);
        out.push_back(std::move(m));
    }
    return out;
}

// ---------------------------------------------------------------------------
// BootAuditSensor
// ---------------------------------------------------------------------------

BootAuditSensor::BootAuditSensor(core::EventBus& bus, const core::AgentConfig& cfg,
                                 core::ThreadPool& pool)
    : core::ISensor("boot-audit", core::SensorId::BootAudit, bus, cfg, pool) {}

bool BootAuditSensor::enabled(const core::AgentConfig& c) const noexcept {
    return c.boot.enabled;
}

bool BootAuditSensor::on_start() {
    (void)load_baseline();
    if (!core::proc::capabilities().euid0) {
        mark_degraded("running unprivileged: efivarfs, /boot and initramfs digests may be unreadable");
    }
    run_full_audit();
    return true;
}

void BootAuditSensor::loop(std::stop_token st) {
    // Boot state changes only on reboot or when an operator rebuilds the
    // initramfs, so this sensor is deliberately quiet: one audit per rescan
    // interval, plus an immediate re-audit after a suspend/resume is out of
    // scope for a boot-chain check.
    while (!st.stop_requested()) {
        // Interruptible wait: one flat 5 s sleep made daemon shutdown lag up
        // to 15 s (three sensors joined sequentially). 250 ms slices keep the
        // same cadence but honour stop_request within a quarter second.
        for (int slice = 0; slice < 20 && !st.stop_requested(); ++slice)
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        const auto interval = cfg_.hardening.rescan_interval;
        if (last_audit_ == core::SysClock::time_point{}) continue;
        if (core::SysClock::now() - last_audit_ >= interval) run_full_audit();
    }
}

void BootAuditSensor::run_full_audit() {
    sb_ = audit_secure_boot(cfg_.boot);
    cmdline_ = audit_kernel_cmdline(cfg_.boot);
    kernel_ = audit_kernel_identity();
    bootloader_ = audit_bootloader();

    initramfs_.clear();
    std::string baseline_text;
    if (fsx::read_file(cfg_.boot.baseline_path, baseline_text, 1 << 20) >= 0) baseline_text_ = baseline_text;

    for (const auto& p : cfg_.boot.initramfs_paths) {
        std::string baseline_digest;
        // Look for a previously recorded digest for this path.
        const std::string marker = "initramfs:" + p + "=";
        const std::size_t at = baseline_text_.find(marker);
        if (at != std::string::npos) {
            const std::size_t s = at + marker.size();
            const std::size_t e = baseline_text_.find('\n', s);
            baseline_digest = baseline_text_.substr(s, (e == std::string::npos ? baseline_text_.size() : e) - s);
        }
        initramfs_.push_back(audit_initramfs(p, baseline_digest));
    }

    last_audit_ = core::SysClock::now();
    publish_findings();
}

int BootAuditSensor::trust_score() const noexcept {
    int score = sb_.score;
    // Penalty per unresolved finding; each is a real gap in the chain of trust.
    const auto findings = sb_.findings.size() + cmdline_.findings.size() + kernel_.findings.size() +
                          bootloader_.findings.size();
    score -= static_cast<int>(std::min<std::size_t>(findings * 3, 40));
    for (const auto& i : initramfs_) {
        if (i.changed_since_baseline) score -= 25;
    }
    if (kernel_.tainted) score -= 15;
    if (!kernel_.module_signature_enforced) score -= 15;
    if (bootloader_.world_writable_config) score -= 20;
    return std::clamp(score, 0, 100);
}

void BootAuditSensor::publish_findings() {
    const auto sev_for = [](std::string_view text) {
        if (text.find("DISABLED") != std::string_view::npos || text.find("init= is overridden") != std::string_view::npos ||
            text.find("writable") != std::string_view::npos || text.find("CHANGED") != std::string_view::npos ||
            text.find("emergency-shell") != std::string_view::npos)
            return core::Severity::High;
        if (text.find("SETUP MODE") != std::string_view::npos || text.find("dbx") != std::string_view::npos ||
            text.find("TAINTED") != std::string_view::npos || text.find("sig_enforce") != std::string_view::npos)
            return core::Severity::Medium;
        return core::Severity::Low;
    };

    auto publish_all = [&](const std::vector<std::string>& fs) {
        for (const auto& f : fs) {
            core::TelemetryEvent ev;
            ev.sensor = core::SensorId::BootAudit;
            ev.kind = core::EventKind::BootIntegrity;
            ev.severity = sev_for(f);
            ev.message = f;
            ev.risk_score = static_cast<std::uint16_t>(ev.severity == core::Severity::High ? 350 : 150);
            emit(std::move(ev));
        }
    };
    publish_all(sb_.findings);
    publish_all(cmdline_.findings);
    publish_all(kernel_.findings);
    publish_all(bootloader_.findings);
    for (const auto& i : initramfs_) publish_all(i.findings);

    core::TelemetryEvent summary;
    summary.sensor = core::SensorId::BootAudit;
    summary.kind = core::EventKind::BootIntegrity;
    summary.severity = trust_score() >= 80 ? core::Severity::Info
                       : trust_score() >= 55 ? core::Severity::Low
                       : trust_score() >= 30 ? core::Severity::Medium
                                             : core::Severity::High;
    summary.metric = static_cast<double>(trust_score());
    summary.message = std::format("boot trust score {}/100 | secure_boot={} setup_mode={} lockdown='{}' "
                                  "kernel={} tainted={} modules={} initramfs_changed={}",
                                  trust_score(), sb_.secure_boot_enabled ? "on" : "off",
                                  sb_.setup_mode ? "yes" : "no",
                                  cmdline_.lockdown_param.empty() ? "unset" : cmdline_.lockdown_param,
                                  kernel_.release, kernel_.tainted ? "yes" : "no",
                                  kernel_.loaded_module_count,
                                  std::any_of(initramfs_.begin(), initramfs_.end(),
                                              [](const InitramfsStatus& i) { return i.changed_since_baseline; })
                                      ? "YES"
                                      : "no");
    emit(std::move(summary));
}

bool BootAuditSensor::write_baseline() noexcept {
    std::string out;
    out += "# HyprNova boot-integrity baseline. Regenerated by an operator action only.\n";
    out += "# Any digest change after this point is a boot-chain integrity finding.\n";
    out += "generated_at=" + std::to_string(std::chrono::system_clock::to_time_t(core::SysClock::now())) + "\n";
    out += "kernel_release=" + kernel_.release + "\n";
    out += "kernel_modules_digest=" + kernel_.loaded_modules_digest + "\n";
    out += "secure_boot_score=" + std::to_string(sb_.score) + "\n";
    out += "cmdline_sha256=" + Sha256::to_hex(Sha256::once(cmdline_.raw)) + "\n";
    for (const auto& v : sb_.variables) {
        if (v.readable) out += "efivar:" + v.name + "=" + v.sha256 + "\n";
    }
    for (const auto& [p, d] : bootloader_.digests) out += "bootloader:" + p + "=" + d + "\n";
    for (const auto& i : initramfs_) {
        if (i.exists) out += "initramfs:" + i.path + "=" + i.sha256 + "\n";
    }
    if (!core::fsx::write_atomic(cfg_.boot.baseline_path,
                                 {reinterpret_cast<const std::byte*>(out.data()), out.size()}, 0600)) {
        note_error("failed to write boot baseline to " + cfg_.boot.baseline_path);
        return false;
    }
    baseline_text_ = out;
    SINFO(name_, "boot baseline written to {}", cfg_.boot.baseline_path);
    return true;
}

bool BootAuditSensor::load_baseline() noexcept {
    std::string text;
    if (fsx::read_file(cfg_.boot.baseline_path, text, 1 << 20) < 0) {
        SINFO(name_, "no boot baseline at {}; first run will record one on operator request",
              cfg_.boot.baseline_path);
        return false;
    }
    baseline_text_ = std::move(text);
    return true;
}

}  // namespace hyprnova::hardening
