// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 6 — shadow copy implementation
//
// See shadow_copy.hpp for the semantics. Implementation notes that matter:
//
//   * std::filesystem is used for walking and removal, wrapped in try/catch:
//     this code runs once per start and once per operator command, never in a
//     hot path, and the filesystem API throws. Every throw is converted to a
//     false return with a reason; the engine never propagates an exception.
//   * Hashes are computed over the bytes as they are read for the copy, so a
//     file is read exactly once per snapshot.
//   * The manifest is the trust anchor for restore: restore re-hashes what it
//     reads out of the snapshot and refuses on mismatch, so a corrupted or
//     tampered snapshot cannot silently write bad data back to the host.

#include "remediation/shadow_copy.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/config.hpp"
#include "core/fd.hpp"
#include "core/hash.hpp"
#include "core/json.hpp"
#include "core/log.hpp"

namespace hyprnova::remediation {

namespace fs = std::filesystem;
using core::json::Array;
using core::json::Object;
using core::json::Value;

namespace {

constexpr std::size_t kMaxDepth = 16;
constexpr std::uint64_t kMaxFileBytes = 64ull << 20;   // per file
constexpr const char* kManifestName = "manifest.json";
constexpr const char* kMetaName = "meta.json";

[[nodiscard]] std::string utc_stamp(std::time_t t) noexcept {
    std::tm tm {};
    ::gmtime_r(&t, &tm);
    return std::format("{:04d}{:02d}{:02d}T{:02d}{:02d}{:02d}Z", tm.tm_year + 1900, tm.tm_mon + 1,
                       tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

[[nodiscard]] std::string rel_to_root(const fs::path& root, const fs::path& p) noexcept {
    std::error_code ec;
    const auto rel = fs::relative(p, root, ec);
    if (ec) return {};
    const std::string s = rel.generic_string();
    // A relative path that climbs out of the root is not a relative path.
    if (s.empty() || s == ".." || s.starts_with("../")) return {};
    return s;
}

/// Copy one regular file into the snapshot, hashing as we go. Returns false on
/// any I/O problem; the caller records a skip. `truncated_out` is set when the
/// copy stopped at a limit (the source grew past the caps mid-copy); the bytes
/// actually copied still land in `size_out` so the caller's accounting stays
/// exact.
[[nodiscard]] bool copy_file_hashed(const fs::path& src, const fs::path& dst,
                                    const std::uint64_t budget, std::string& sha_out,
                                    std::uint64_t& size_out, bool& truncated_out) noexcept {
    try {
        std::error_code ec;
        const auto sz = fs::file_size(src, ec);
        if (ec || sz > kMaxFileBytes || sz > budget) return false;

        fs::create_directories(dst.parent_path(), ec);
        if (ec) return false;

        // O_NOFOLLOW: a symlink swapped in mid-walk must not redirect the copy.
        const int in = ::open(src.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (in < 0) return false;
        core::UniqueFd in_fd{in};

        const int out = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (out < 0) return false;
        core::UniqueFd out_fd{out};

        core::hash::Sha256 sha;
        std::string buf(1 << 16, '\0');
        std::uint64_t total = 0;
        for (;;) {
            const std::uint64_t room = copy_room(total, kMaxFileBytes, budget);
            if (room == 0) {
                truncated_out = total > 0;
                break;
            }
            const ssize_t n = ::read(in_fd.get(), buf.data(),
                                     static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), room)));
            if (n < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            if (n == 0) break;
            sha.update({reinterpret_cast<const std::byte*>(buf.data()), static_cast<std::size_t>(n)});
            std::size_t off = 0;
            while (off < static_cast<std::size_t>(n)) {
                const ssize_t w = ::write(out_fd.get(), buf.data() + off, static_cast<std::size_t>(n) - off);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    return false;
                }
                off += static_cast<std::size_t>(w);
            }
            total += static_cast<std::uint64_t>(n);
        }
        // Preserve the mode of the original, minus anything world-writable: a
        // snapshot must not be a privilege-escalation copy of a 0666 file.
        struct stat st {};
        if (::fstat(in_fd.get(), &st) == 0) (void)::fchmod(out_fd.get(), st.st_mode & 0777);
        sha_out = core::hash::Sha256::to_hex(sha.final());
        size_out = total;
        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace

ShadowCopyEngine::ShadowCopyEngine(const core::AgentConfig& cfg) noexcept : cfg_(cfg) {
    root_ = (fs::path{cfg.state_dir} / "shadow").generic_string();
}

std::string ShadowCopyEngine::snapshot_dir_for(std::string_view id) const noexcept {
    // The id is a directory name we produced (timestamp-pid). Refuse anything
    // that could traverse: restore/verify take an operator-supplied id.
    if (id.empty() || id.size() > 128) return {};
    if (id.find('/') != std::string_view::npos || id.find("..") != std::string_view::npos) return {};
    return (fs::path{root_} / std::string{id}).generic_string();
}

bool ShadowCopyEngine::load_meta(const std::string& dir, ShadowMeta& out) const noexcept {
    try {
        std::string text;
        if (core::fsx::read_file((fs::path{dir} / kMetaName).generic_string(), text, 1 << 20) < 0)
            return false;
        core::json::ParseError pe {};
        const auto doc = core::json::parse(text, {}, &pe);
        if (!doc) return false;
        out.id = doc->str("id");
        out.created = static_cast<std::time_t>(doc->integer("created", 0));
        out.reason = doc->str("reason");
        out.files = static_cast<std::uint64_t>(doc->integer("files", 0));
        out.bytes = static_cast<std::uint64_t>(doc->integer("bytes", 0));
        out.skipped = static_cast<std::uint64_t>(doc->integer("skipped", 0));
        if (const auto* a = doc->at("roots"))
            if (const auto* arr = a->as_array())
                for (const auto& v : *arr) out.roots.emplace_back(v.as_string_copy());
        if (const auto* m = doc->at("missing"))
            if (const auto* arr = m->as_array())
                for (const auto& v : *arr) out.missing.emplace_back(v.as_string_copy());
        return !out.id.empty();
    } catch (...) {
        return false;
    }
}

std::string ShadowCopyEngine::take(std::string_view reason, std::string& detail) noexcept {
    if (!cfg_.shadow.enabled) {
        detail = "shadow copies are disabled in configuration";
        return {};
    }
    try {
        const std::time_t now = core::SysClock::to_time_t(core::SysClock::now());
        const std::string id = std::format("{}-{}", utc_stamp(now), ::getpid());
        const fs::path snap = fs::path{root_} / id;
        std::error_code ec;
        fs::create_directories(snap, ec);
        if (ec) {
            detail = std::format("cannot create snapshot dir {}: {}", snap.string(), ec.message());
            return {};
        }

        Object manifest;
        manifest["version"] = std::int64_t{1};
        manifest["created"] = static_cast<std::int64_t>(now);
        manifest["reason"] = std::string{reason};
        Array roots_arr;
        Array files_arr;
        std::uint64_t total_bytes = 0;
        std::uint64_t total_files = 0;
        std::uint64_t skipped = 0;
        std::vector<std::string> missing;

        // The agent's own state directory is ALWAYS part of a snapshot (the canary
        // key, baselines and journal are the hardest things to reconstruct), and
        // the shadow store itself and the quarantine are always excluded: a
        // snapshot must not contain snapshots, and quarantined malware samples
        // must not be copied into a recovery set.
        std::vector<std::string> roots = cfg_.shadow.roots;
        if (std::find(roots.begin(), roots.end(), cfg_.state_dir) == roots.end())
            roots.emplace_back(cfg_.state_dir);
        const std::string exclude_a = root_;
        const std::string exclude_b = cfg_.remediation.quarantine_dir;
        // Honeypot decoys are agent bait, not recoverable user data: they are
        // regenerated (hash-verified) at every start, and snapshotting them
        // would make the shadow engine READ the bait with plain reads -- which
        // the honeypot's own watches see exactly like an attacker opening
        // decoy credentials. (Root cause of the startup ghost-read race.)
        const std::string exclude_c =
            (fs::path{cfg_.state_dir} / "honeypots").generic_string();

        for (std::size_t ri = 0; ri < roots.size(); ++ri) {
            const fs::path root{roots[ri]};
            roots_arr.emplace_back(root.generic_string());
            std::error_code rec;
            if (!fs::exists(root, rec) || !fs::is_directory(root, rec)) {
                missing.emplace_back(root.generic_string());
                continue;
            }
            const fs::path dst_root = snap / std::to_string(ri);
            fs::create_directories(dst_root, rec);

            // Iterative walk with an explicit depth cap: a recursive lambda over
            // a hostile tree (deep nesting, symlink loops) must not blow the
            // stack. Symlinks are recorded as symlinks, never followed.
            std::vector<std::pair<fs::path, int>> stack{{root, 0}};
            while (!stack.empty() && total_files < cfg_.shadow.max_files &&
                   total_bytes < cfg_.shadow.max_snapshot_bytes) {
                const auto [dir, depth] = stack.back();
                stack.pop_back();
                fs::directory_iterator it{dir, fs::directory_options::skip_permission_denied, rec};
                if (rec) {
                    ++skipped;
                    continue;
                }
                for (const auto& entry : it) {
                    if (total_files >= cfg_.shadow.max_files ||
                        total_bytes >= cfg_.shadow.max_snapshot_bytes)
                        break;
                    std::error_code sec;
                    const auto& p = entry.path();
                    const std::string rel = rel_to_root(root, p);
                    if (rel.empty()) {
                        ++skipped;
                        continue;
                    }
                    if (entry.is_symlink(sec)) {
                        // Preserve the link itself, never what it points at.
                        const auto target = fs::read_symlink(p, sec);
                        if (sec) {
                            ++skipped;
                            continue;
                        }
                        const fs::path dst = dst_root / rel;
                        fs::create_directories(dst.parent_path(), sec);
                        fs::create_symlink(target, dst, sec);
                        if (sec) {
                            ++skipped;
                            continue;
                        }
                        Object fo;
                        fo["path"] = p.generic_string();
                        fo["rel"] = rel;
                        fo["root"] = static_cast<std::int64_t>(ri);
                        fo["kind"] = std::string{"symlink"};
                        fo["target"] = target.generic_string();
                        files_arr.emplace_back(Value{std::move(fo)});
                        ++total_files;
                        continue;
                    }
                    if (entry.is_directory(sec)) {
                        const std::string abs = p.generic_string();
                        if (abs == exclude_a || abs == exclude_b || abs == exclude_c)
                            continue;  // never recurse into ourselves / into the bait
                        if (depth < static_cast<int>(kMaxDepth)) stack.emplace_back(p, depth + 1);
                        else ++skipped;
                        continue;
                    }
                    if (!entry.is_regular_file(sec)) {
                        ++skipped;   // socket, fifo, device: never copied
                        continue;
                    }
                    std::string sha;
                    std::uint64_t sz = 0;
                    bool truncated = false;
                    const fs::path dst = dst_root / rel;
                    if (!copy_file_hashed(p, dst, cfg_.shadow.max_snapshot_bytes - total_bytes,
                                          sha, sz, truncated)) {
                        ++skipped;
                        continue;
                    }
                    if (truncated) ++skipped;  // counted as a limit-skip too (honest totals)
                    Object fo;
                    fo["path"] = p.generic_string();
                    fo["rel"] = rel;
                    fo["root"] = static_cast<std::int64_t>(ri);
                    fo["kind"] = std::string{"file"};
                    fo["sha256"] = sha;
                    fo["size"] = static_cast<std::int64_t>(sz);
                    if (truncated) {
                        fo["truncated"] = 1;
                        fo["note"] = std::string(
                            "source grew past the per-file/snapshot cap mid-copy; "
                            "snapshot copy stopped at the cap");
                    }
                    struct stat st {};
                    if (::stat(p.c_str(), &st) == 0)
                        fo["mode"] = static_cast<std::int64_t>(st.st_mode & 0777);
                    files_arr.emplace_back(Value{std::move(fo)});
                    total_bytes += sz;
                    ++total_files;
                }
            }
        }

        manifest["files"] = Value{std::move(files_arr)};
        manifest["total_bytes"] = static_cast<std::int64_t>(total_bytes);
        {
            const std::string mtext = Value{std::move(manifest)}.dump();
            if (!core::fsx::write_atomic((snap / kManifestName).generic_string(),
                                         {reinterpret_cast<const std::byte*>(mtext.data()), mtext.size()},
                                         0600)) {
                detail = "could not write manifest";
                return {};
            }
        }

        Object meta;
        meta["id"] = id;
        meta["created"] = static_cast<std::int64_t>(now);
        meta["reason"] = std::string{reason};
        meta["files"] = static_cast<std::int64_t>(total_files);
        meta["bytes"] = static_cast<std::int64_t>(total_bytes);
        meta["skipped"] = static_cast<std::int64_t>(skipped);
        meta["roots"] = Value{std::move(roots_arr)};
        {
            Array miss;
            for (const auto& m : missing) miss.emplace_back(m);
            meta["missing"] = Value{std::move(miss)};
        }
        {
            const std::string mtext = Value{std::move(meta)}.dump();
            if (!core::fsx::write_atomic((snap / kMetaName).generic_string(),
                                         {reinterpret_cast<const std::byte*>(mtext.data()), mtext.size()},
                                         0600)) {
                detail = "could not write meta";
                return {};
            }
        }

        const std::size_t pruned = prune();
        SINFO("shadow", "snapshot {} taken: {} files, {} bytes, {} skipped, {} pruned (reason: {})",
              id, total_files, total_bytes, skipped, pruned, reason);
        detail = std::format("{} files, {} bytes", total_files, total_bytes);
        return id;
    } catch (const std::exception& e) {
        detail = std::string{"snapshot failed: "} + e.what();
        return {};
    } catch (...) {
        detail = "snapshot failed: unknown error";
        return {};
    }
}

std::vector<ShadowEntry> ShadowCopyEngine::list() const noexcept {
    std::vector<ShadowEntry> out;
    try {
        std::error_code ec;
        if (!fs::is_directory(root_, ec)) return out;
        for (const auto& entry : fs::directory_iterator{root_, ec}) {
            if (!entry.is_directory(ec)) continue;
            ShadowMeta m;
            const std::string dir = entry.path().generic_string();
            m.id = entry.path().filename().generic_string();
            if (!load_meta(dir, m)) continue;
            out.push_back({std::move(m), dir});
        }
    } catch (...) {
    }
    // Newest first: the id is <UTC stamp>-<pid>, so lexicographic == chronological.
    std::sort(out.begin(), out.end(), [](const ShadowEntry& a, const ShadowEntry& b) {
        return a.meta.id > b.meta.id;
    });
    return out;
}

std::size_t ShadowCopyEngine::prune() noexcept {
    if (cfg_.shadow.keep == 0) return 0;
    const auto entries = list();
    if (entries.size() <= cfg_.shadow.keep) return 0;
    std::size_t removed = 0;
    try {
        // entries is newest-first; delete everything past the retention count.
        for (std::size_t i = cfg_.shadow.keep; i < entries.size(); ++i) {
            std::error_code ec;
            fs::remove_all(entries[i].dir, ec);
            if (!ec) ++removed;
        }
    } catch (...) {
    }
    if (removed > 0) SINFO("shadow", "retention: removed {} old snapshot(s), keeping {}", removed, cfg_.shadow.keep);
    return removed;
}

bool ShadowCopyEngine::verify(std::string_view id, std::string& detail) const noexcept {
    const std::string dir = snapshot_dir_for(id);
    if (dir.empty()) {
        detail = "invalid snapshot id";
        return false;
    }
    try {
        std::string text;
        if (core::fsx::read_file((fs::path{dir} / kManifestName).generic_string(), text, 64 << 20) < 0) {
            detail = "no manifest in snapshot";
            return false;
        }
        core::json::ParseError pe {};
        const auto doc = core::json::parse(text, {}, &pe);
        if (!doc) {
            detail = "manifest does not parse";
            return false;
        }
        const auto* files = doc->at("files");
        if (!files || !files->is_array()) {
            detail = "manifest has no files array";
            return false;
        }
        std::uint64_t checked = 0, bad = 0;
        for (const auto& f : *files->as_array()) {
            if (f.str("kind") != "file") continue;
            const std::string rel = f.str("rel");
            const std::int64_t ri = f.integer("root", -1);
            const std::string want = f.str("sha256");
            if (rel.empty() || ri < 0 || want.empty()) {
                ++bad;
                continue;
            }
            const fs::path src = fs::path{dir} / std::to_string(ri) / rel;
            std::string content;
            if (core::fsx::read_file(src.generic_string(), content, kMaxFileBytes) < 0) {
                ++bad;
                continue;
            }
            const std::string got = core::hash::Sha256::to_hex(core::hash::Sha256::once(
                {reinterpret_cast<const std::byte*>(content.data()), content.size()}));
            ++checked;
            if (got != want) ++bad;
        }
        detail = std::format("{} files verified, {} mismatched", checked, bad);
        return bad == 0;
    } catch (const std::exception& e) {
        detail = std::string{"verify failed: "} + e.what();
        return false;
    } catch (...) {
        detail = "verify failed: unknown error";
        return false;
    }
}

ShadowRestoreReport ShadowCopyEngine::restore(std::string_view id, std::string_view dest,
                                             std::string& detail) noexcept {
    ShadowRestoreReport rep;
    rep.id = std::string{id};
    const std::string dir = snapshot_dir_for(id);
    if (dir.empty()) {
        detail = "invalid snapshot id";
        return rep;
    }
    try {
        std::string text;
        if (core::fsx::read_file((fs::path{dir} / kManifestName).generic_string(), text, 64 << 20) < 0) {
            detail = "no manifest in snapshot";
            return rep;
        }
        core::json::ParseError pe {};
        const auto doc = core::json::parse(text, {}, &pe);
        const auto* files = doc ? doc->at("files") : nullptr;
        if (!files || !files->is_array()) {
            detail = "manifest has no files array";
            return rep;
        }

        const bool to_dest = !dest.empty();
        for (const auto& f : *files->as_array()) {
            const std::string kind = f.str("kind");
            const std::string rel = f.str("rel");
            const std::int64_t ri = f.integer("root", -1);
            if (rel.empty() || ri < 0) {
                ++rep.failed;
                continue;
            }
            // Resolve the destination: original absolute path, or dest/<root>/<rel>.
            fs::path target;
            if (to_dest) {
                target = fs::path{dest} / std::to_string(ri) / rel;
            } else {
                const std::string orig = f.str("path");
                if (orig.empty() || orig.starts_with("..") || orig.find("..") != std::string::npos) {
                    // A manifest entry with a traversal-shaped original path is
                    // not restored to an absolute location, ever.
                    ++rep.failed;
                    if (rep.failures.size() < 8)
                        rep.failures.emplace_back("refusing traversal-shaped path: " + orig);
                    continue;
                }
                target = fs::path{orig};
            }
            // The relative part must never climb out of its destination root.
            if (rel == ".." || rel.starts_with("../")) {
                ++rep.failed;
                continue;
            }

            if (kind == "symlink") {
                const std::string link_target = f.str("target");
                std::error_code ec;
                fs::create_directories(target.parent_path(), ec);
                fs::remove(target, ec);
                fs::create_symlink(link_target, target, ec);
                if (ec) {
                    ++rep.failed;
                    if (rep.failures.size() < 8) rep.failures.emplace_back(target.generic_string());
                    continue;
                }
                ++rep.restored;
                continue;
            }
            if (kind != "file") {
                ++rep.failed;
                continue;
            }

            // Hash-verify the snapshot copy BEFORE writing anything back.
            const fs::path src = fs::path{dir} / std::to_string(ri) / rel;
            std::string content;
            if (core::fsx::read_file(src.generic_string(), content, kMaxFileBytes) < 0) {
                ++rep.failed;
                if (rep.failures.size() < 8)
                    rep.failures.emplace_back("unreadable in snapshot: " + rel);
                continue;
            }
            const std::string got = core::hash::Sha256::to_hex(core::hash::Sha256::once(
                {reinterpret_cast<const std::byte*>(content.data()), content.size()}));
            const std::string want = f.str("sha256");
            ++rep.verified;
            if (got != want) {
                ++rep.failed;
                if (rep.failures.size() < 8)
                    rep.failures.emplace_back("hash mismatch, not restored: " + rel);
                continue;
            }

            std::error_code ec;
            fs::create_directories(target.parent_path(), ec);
            const mode_t mode = static_cast<mode_t>(f.integer("mode", 0600)) & 0777;
            if (!core::fsx::write_atomic(target.generic_string(),
                                         {reinterpret_cast<const std::byte*>(content.data()), content.size()},
                                         mode == 0 ? 0600 : mode)) {
                ++rep.failed;
                if (rep.failures.size() < 8)
                    rep.failures.emplace_back("write failed: " + target.generic_string());
                continue;
            }
            ++rep.restored;
        }

        rep.ok = rep.failed == 0;
        rep.detail = std::format("{} restored, {} verified, {} failed", rep.restored, rep.verified,
                                 rep.failed);
        detail = rep.detail;
        SINFO("shadow", "restore {}: {} (to {})", id, rep.detail, to_dest ? std::string{dest} : "original paths");
        return rep;
    } catch (const std::exception& e) {
        detail = std::string{"restore failed: "} + e.what();
        return rep;
    } catch (...) {
        detail = "restore failed: unknown error";
        return rep;
    }
}

}  // namespace hyprnova::remediation
