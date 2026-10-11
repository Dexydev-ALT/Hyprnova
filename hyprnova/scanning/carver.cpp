// SPDX-License-Identifier: Apache-2.0
#include "scanning/carver.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "core/fd.hpp"
#include "core/hash.hpp"
#include "core/log.hpp"
#include "scanning/yara_engine.hpp"

#include <filesystem>

namespace fs = std::filesystem;

namespace hyprnova::scanning {

namespace {

using Bytes = std::span<const std::byte>;

constexpr std::array<std::uint8_t, 4> kElf = {0x7f, 'E', 'L', 'F'};
constexpr std::array<std::uint8_t, 2> kMz = {'M', 'Z'};
constexpr std::array<std::uint8_t, 4> kZip = {'P', 'K', 0x03, 0x04};
constexpr std::array<std::uint8_t, 4> kZipEocd = {'P', 'K', 0x05, 0x06};
constexpr std::array<std::uint8_t, 3> kJpeg = {0xff, 0xd8, 0xff};
constexpr std::array<std::uint8_t, 2> kJpegEnd = {0xff, 0xd9};
constexpr std::array<std::uint8_t, 8> kPng = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
constexpr std::array<std::uint8_t, 2> kGzip = {0x1f, 0x8b};

bool starts_with(const Bytes data, std::size_t off, const auto& magic) noexcept {
    if (off + magic.size() > data.size()) return false;
    return std::memcmp(data.data() + off, magic.data(), magic.size()) == 0;
}

/// Extent for formats with a trailer: first occurrence of `end` at/after `off`.
std::uint64_t extent_to(const Bytes data, std::size_t off, const auto& end_magic,
                        std::uint64_t cap) noexcept {
    const std::size_t min_end = off + end_magic.size();
    if (data.size() < min_end) return 0;
    const std::size_t last = data.size() - end_magic.size();
    for (std::size_t i = off; i <= last; ++i) {
        if (starts_with(data, i, end_magic)) {
            const std::uint64_t size = static_cast<std::uint64_t>(i) + end_magic.size() - off;
            return std::min(size, cap);
        }
        // JPEG sanity: an EOI more than cap bytes in is a false trailer; stop.
        if (i - off > static_cast<std::size_t>(cap)) break;
    }
    return 0;  // truncated artifact; caller applies the cap as a best effort
}

/// PE extent: e_lfanew at off+0x3c points to "PE\0\0"; size is unknown without
/// section parsing, so cap at the next artifact or the configured cap.
}  // namespace

std::vector<ArtifactSpan> Carver::find_artifacts(Bytes data) noexcept {
    std::vector<ArtifactSpan> out;
    if (data.size() < 8) return out;

    std::size_t i = 0;
    while (i + 4 <= data.size()) {
        std::optional<ArtifactSpan> hit;
        if (starts_with(data, i, kElf)) {
            hit = ArtifactSpan{i, 0, ArtifactKind::Elf};
        } else if (starts_with(data, i, kMz)) {
            // "MZ" alone is weak (text can start with MZ); require the
            // e_lfanew pointer + PE signature to be plausible.
            if (i + 0x40 <= data.size()) {
                std::uint32_t lfanew = 0;
                std::memcpy(&lfanew, data.data() + i + 0x3c, 4);
                if (lfanew >= 0x40 && lfanew < 0x100000 && i + lfanew + 4 <= data.size() &&
                    std::memcmp(data.data() + i + lfanew, "PE\0\0", 4) == 0)
                    hit = ArtifactSpan{i, 0, ArtifactKind::Pe};
            }
        } else if (starts_with(data, i, kZip)) {
            hit = ArtifactSpan{i, 0, ArtifactKind::Zip};
        } else if (starts_with(data, i, kJpeg)) {
            hit = ArtifactSpan{i, 0, ArtifactKind::Jpeg};
        } else if (starts_with(data, i, kPng)) {
            hit = ArtifactSpan{i, 0, ArtifactKind::Png};
        } else if (starts_with(data, i, kGzip)) {
            hit = ArtifactSpan{i, 0, ArtifactKind::Gzip};
        }

        if (hit) {
            switch (hit->kind) {
                case ArtifactKind::Jpeg:
                    hit->size = extent_to(data, i, kJpegEnd, 64ull << 20);
                    break;
                case ArtifactKind::Png: {
                    // IEND chunk: 00 00 00 00 'I' 'E' 'N' 'D' ae 42 60 82
                    std::size_t p = i;
                    while (p + 12 <= data.size()) {
                        if (std::memcmp(data.data() + p, "IEND", 4) == 0) {
                            hit->size = std::min<std::uint64_t>(p + 12 - i, 64ull << 20);
                            break;
                        }
                        ++p;
                    }
                    break;
                }
                case ArtifactKind::Zip: {
                    // EOCD: PK\x05\x06 + 18 fixed bytes + comment. The comment
                    // LENGTH is read from the EOCD itself (2 bytes LE at +20);
                    // assuming the 65535 maximum here used to over-count the
                    // extent past the buffer -- a heap overread (F9).
                    std::size_t p = i;
                    while (p + 22 <= data.size()) {
                        if (starts_with(data, p, kZipEocd)) {
                            std::uint16_t comment = 0;
                            std::memcpy(&comment, data.data() + p + 20, 2);
                            const std::uint64_t end =
                                std::min<std::uint64_t>(p + 22 + comment, data.size());
                            hit->size = end - i;
                            break;
                        }
                        ++p;
                    }
                    break;
                }
                case ArtifactKind::Elf:
                case ArtifactKind::Pe:
                case ArtifactKind::Gzip:
                    hit->size = 0;  // resolved below / capped
                    break;
            }
            if (out.empty() || hit->offset > out.back().offset) out.push_back(*hit);
        }
        ++i;
    }

    // Resolve unknown extents: next artifact start (or EOF), capped later.
    for (std::size_t n = 0; n < out.size(); ++n) {
        if (out[n].size == 0) {
            const std::uint64_t end = n + 1 < out.size()
                                          ? out[n + 1].offset
                                          : static_cast<std::uint64_t>(data.size());
            out[n].size = end > out[n].offset ? end - out[n].offset : 0;
        }
    }
    // Hard clamp (F9 regression guard): an extent can never run past the
    // buffer, whatever the trailer arithmetic above did.
    for (auto& a : out) {
        if (a.offset >= data.size()) a.size = 0;
        else a.size = std::min<std::uint64_t>(a.size, data.size() - a.offset);
    }
    // Merge trivial overlaps (a JPEG inside an ELF region etc.): keep both but
    // shrink the earlier one so extraction never duplicates bytes.
    for (std::size_t n = 0; n + 1 < out.size(); ++n) {
        const std::uint64_t next_start = out[n + 1].offset;
        if (out[n].offset + out[n].size > next_start)
            out[n].size = next_start > out[n].offset ? next_start - out[n].offset : 0;
    }
    return out;
}

CarveReport Carver::inventory(std::string_view path) noexcept {
    CarveReport rep;
    rep.source = std::string(path);
    std::string blob;
    if (core::fsx::read_file(path, blob, 512ull << 20) < 0) {
        rep.error = std::format("unreadable: {}", path);
        return rep;
    }
    rep.source_bytes = blob.size();
    const auto spans = find_artifacts(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(blob.data()), blob.size()));
    rep.artifacts.reserve(spans.size());
    for (const auto& sp : spans) {
        CarvedArtifact a;
        a.span = sp;
        a.note = std::format("{} bytes embedded {}", sp.size, artifact_kind_name(sp.kind));
        rep.artifacts.push_back(std::move(a));
    }
    return rep;
}

CarveReport Carver::carve_file(std::string_view path, std::string_view out_dir,
                               const SignatureEngine* engine) const noexcept {
    CarveReport rep;
    // The opt-in gate is the config: refusing here is the feature boundary.
    if (!cfg_.enabled) {
        rep.error = "carving is disabled (scan.carving_enabled=false): enable it explicitly "
                    "to extract and scan embedded artifacts";
        return rep;
    }
    rep = inventory(path);
    if (!rep.error.empty()) return rep;

    std::string blob;
    if (core::fsx::read_file(path, blob, 512ull << 20) < 0) {
        rep.error = std::format("unreadable on second open: {}", path);
        return rep;
    }
    if (rep.artifacts.size() > cfg_.max_artifacts) {
        rep.artifacts.resize(cfg_.max_artifacts);
        rep.artifacts.back().note += " [truncated inventory: carve_max_artifacts reached]";
    }
    if (rep.artifacts.empty()) return rep;

    std::error_code ec;
    fs::create_directories(out_dir, ec);
    if (ec) {
        rep.error = std::format("cannot create carve dir {}: {}", out_dir, ec.message());
        return rep;
    }
    (void)fs::permissions(out_dir, fs::perms::owner_all, ec);

    const Bytes view(reinterpret_cast<const std::byte*>(blob.data()), blob.size());
    for (auto& a : rep.artifacts) {
        if (a.span.size == 0 || a.span.size > cfg_.max_artifact_bytes) {
            a.note += std::format(" [not extracted: {} bytes exceeds carve_max_artifact_bytes]",
                                  a.span.size);
            continue;
        }
        const auto* begin = blob.data() + a.span.offset;
        const std::uint64_t avail = blob.size() - a.span.offset;
        const std::uint64_t take = std::min<std::uint64_t>(a.span.size, avail);
        std::span<const std::byte> bytes(view.data() + a.span.offset, take);

        const auto dig = core::hash::Sha256::once(bytes);
        const std::string hex = core::hash::Sha256::to_hex(dig);

        const std::string dest =
            std::format("{}/{}-{}.{}", out_dir, hex.substr(0, 16), a.span.offset,
                        artifact_kind_name(a.span.kind));
        if (!core::fsx::write_atomic(dest,
                                     {reinterpret_cast<const std::byte*>(begin),
                                      static_cast<std::size_t>(take)},
                                     0600)) {
            a.note += " [extraction failed (write_atomic); nothing written]";
            continue;
        }
        a.path = dest;
        if (engine) {
            // Data, not code: the extracted bytes are scanned like any file.
            for (const auto& m : engine->scan_file(dest)) a.rules.push_back(m.rule);
        }
    }
    return rep;
}

}  // namespace hyprnova::scanning
