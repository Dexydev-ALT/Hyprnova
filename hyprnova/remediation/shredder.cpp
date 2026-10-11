// SPDX-License-Identifier: Apache-2.0
// HyprNova :: the Shredder (implementation).

#include "remediation/shredder.hpp"

#include "core/fd.hpp"
#include "core/log.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <system_error>

namespace hyprnova::remediation {

namespace fs = std::filesystem;

namespace {

constexpr std::string_view kProtected[] = {
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
    "/sbin", "/sys", "/usr", "/var/lib/hyprnova",
};

constexpr std::size_t kMaxItems = 50'000;

bool under_prefix(const std::string& path, std::string_view prefix) noexcept {
    // "/" protects only the root entry itself; every other prefix requires the
    // path to be inside it ("/etc2" is NOT "/etc").
    if (prefix == "/") return path == "/";
    if (path.size() < prefix.size()) return false;
    if (path.compare(0, prefix.size(), prefix) != 0) return false;
    // "/etc2" must not match "/etc": the next char must be '/' or end.
    return path.size() == prefix.size() || path[prefix.size()] == '/';
}

}  // namespace

bool Shredder::protected_path(const std::string& path) noexcept {
    std::error_code ec;
    std::string canonical = fs::weakly_canonical(fs::path{path}, ec).string();
    if (ec || canonical.empty()) canonical = path;
    for (const auto p : kProtected)
        if (under_prefix(canonical, p)) return true;
    return false;
}

std::string_view Shredder::method_note(Method m) noexcept {
    switch (m) {
        case Method::Standard:
            return "standard unlink: the directory entries are removed; the "
                   "underlying data MAY remain recoverable until overwritten. "
                   "On SSD/flash, TRIM usually reclaims it eventually -- but no "
                   "guarantee is possible.";
        case Method::Overwrite:
            return "best-effort single-pass overwrite + unlink: every regular "
                   "file's contents are overwritten in place before removal. "
                   "This is NOT a guarantee on journaling filesystems (ext4), "
                   "copy-on-write (btrfs/zfs), SSDs, or systems with "
                   "snapshots. For strong erasure use full-disk encryption and "
                   "destroy the keys, or device-level sanitize (blkdiscard / "
                   "NVMe format).";
    }
    return "";
}

Shredder::Plan Shredder::plan(const std::vector<std::string>& paths,
                              Method method) const noexcept {
    Plan p;
    p.method_note = method_note(method);
    p.overwrite = method == Method::Overwrite;
    std::error_code ec;

    for (const auto& raw : paths) {
        if (raw.empty()) continue;
        if (protected_path(raw)) {
            p.refusals.push_back(std::format("{} is a protected system path", raw));
            continue;
        }
        const fs::path target{raw};
        if (!fs::exists(fs::symlink_status(target, ec))) {
            p.refusals.push_back(std::format("{}: no such file or directory", raw));
            continue;
        }
        const auto status = fs::symlink_status(target, ec);
        if (ec) {
            p.refusals.push_back(std::format("{}: {}", raw, ec.message()));
            continue;
        }
        if (fs::is_symlink(status)) {
            Item it;
            it.path = raw;
            it.type = "symlink";
            it.note = std::format("symlink -> {} (the link is removed; the "
                                  "target is untouched)",
                                  fs::read_symlink(target, ec).string());
            p.items.push_back(std::move(it));
            ++p.links;
            continue;
        }
        if (fs::is_regular_file(status)) {
            Item it;
            it.path = raw;
            it.type = "file";
            it.bytes = static_cast<std::uint64_t>(fs::file_size(target, ec));
            p.items.push_back(std::move(it));
            ++p.files;
            p.total_bytes += p.items.back().bytes;
            continue;
        }
        if (fs::is_directory(status)) {
            ++p.dirs;
            // Depth-first collect of the CONTENTS; the directory itself is
            // removed last. Symlinks inside are recorded as links.
            for (auto it = fs::recursive_directory_iterator(
                     target, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (p.items.size() >= kMaxItems) {
                    p.refusals.push_back(std::format(
                        "{}: tree exceeds {} entries; shred in parts", raw, kMaxItems));
                    break;
                }
                auto st = fs::symlink_status(it->path(), ec);
                if (ec) continue;
                Item item;
                item.path = it->path().string();
                if (fs::is_symlink(st)) {
                    item.type = "symlink";
                    ++p.links;
                } else if (it->is_regular_file(ec)) {
                    item.type = "file";
                    item.bytes = static_cast<std::uint64_t>(it->file_size(ec));
                    ++p.files;
                    p.total_bytes += item.bytes;
                } else if (it->is_directory(ec)) {
                    item.type = "dir";
                    ++p.dirs;
                } else {
                    item.type = "other";
                }
                p.items.push_back(std::move(item));
            }
            Item root_item;
            root_item.path = raw;
            root_item.type = "dir";
            p.items.push_back(std::move(root_item));
            continue;
        }
        p.refusals.push_back(std::format("{}: not a regular file or directory", raw));
    }

    p.ok = !p.items.empty();
    if (p.items.empty() && p.refusals.empty())
        p.error = "nothing to shred";
    return p;
}

Shredder::Outcome Shredder::execute(const Plan& plan, bool confirmed) const noexcept {
    Outcome o;
    if (!confirmed) {
        o.errors.push_back("refused: execution requires the operator's explicit "
                           "confirmation (dry-run plans are read-only)");
        return o;
    }
    if (!plan.ok) {
        o.errors.push_back("refused: empty plan");
        return o;
    }

    // Remove leaves first, roots last. Plan order interleaves (a directory is
    // recorded when entered, before its contents), so derive the safe order:
    // files and symlinks first, then directories deepest-first. A parent is
    // only ever removed after everything under it is gone.
    std::error_code ec;
    std::vector<const Item*> order;  // plan items are few (cap 50k); pointers stay valid
    for (const auto& item : plan.items) order.push_back(&item);
    std::stable_sort(order.begin(), order.end(), [](const Item* a, const Item* b) {
        const bool da = a->type == "dir", db = b->type == "dir";
        if (da != db) return !da;  // non-dirs before dirs
        if (!da) return false;     // keep relative order among non-dirs
        const auto depth = [](std::string_view p) {
            return static_cast<int>(std::count(p.begin(), p.end(), '/'));
        };
        return depth(a->path) > depth(b->path);  // deeper directories first
    });
    for (const auto* pitem : order) {
        const auto& item = *pitem;
        const fs::path p{item.path};
        if (item.type == "file") {
            // Best-effort overwrite pass when requested.
            if (plan.overwrite) {
                std::error_code sec;
                const auto size = fs::file_size(p, sec);
                if (!sec && size > 0) {
                    std::ofstream f{p, std::ios::binary | std::ios::in | std::ios::out};
                    if (f) {
                        static std::array<char, 64 * 1024> zero{};
                        std::uint64_t left = size;
                        while (left > 0) {
                            const auto chunk = std::min<std::uint64_t>(left, zero.size());
                            f.write(zero.data(), static_cast<std::streamsize>(chunk));
                            if (!f) break;
                            left -= chunk;
                        }
                        f.flush();
                        o.bytes_overwritten += size - left;
                    } else {
                        o.errors.push_back(std::format("{}: overwrite failed (open)", item.path));
                    }
                }
            }
            if (fs::remove(p, ec)) {
                ++o.files_removed;
            } else {
                o.errors.push_back(std::format("{}: {}", item.path, ec.message()));
                ec.clear();
            }
        } else if (item.type == "symlink") {
            if (fs::remove(p, ec)) ++o.links_removed;
            else {
                o.errors.push_back(std::format("{}: {}", item.path, ec.message()));
                ec.clear();
            }
        } else if (item.type == "dir") {
            if (fs::remove(p, ec)) ++o.dirs_removed;
            else {
                // Non-empty => children failed above; report once.
                o.errors.push_back(std::format("{}: {}", item.path, ec.message()));
                ec.clear();
            }
        }
    }

    o.ok = o.errors.empty();
    o.audit_line = std::format(
        "shred: files={} dirs={} links={} bytes_overwritten={} errors={} "
        "(method: {})",
        o.files_removed, o.dirs_removed, o.links_removed, o.bytes_overwritten,
        o.errors.size(),
        plan.overwrite ? "overwrite" : "standard");
    // Audit record: paths count and sizes, never contents.
    SINFO("shredder", "{}", o.audit_line);
    return o;
}

}  // namespace hyprnova::remediation
