// SPDX-License-Identifier: Apache-2.0
// HyprNova :: File carving (spec §5E, strictly opt-in)
//
// Malware increasingly arrives INSIDE something innocent: an installer with a
// packed ELF appended, a "photo" that is a JPEG with a second payload after
// EOI, a ZIP inside a document. The carver inventories embedded artifacts by
// header/footer signatures and -- only when the operator asks -- extracts them
// for signature scanning.
//
// Opt-in by design: carving reads whole files and writes derived copies. The
// feature is OFF in the default config; `hyprnova-cli carve PATH` is an
// explicit operator action, and `triage` uses the inventory half (read-only)
// only. Nothing here executes the artifacts; they are data, scanned as data.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "core/config.hpp"

namespace hyprnova::scanning {

class SignatureEngine;

enum class ArtifactKind : std::uint8_t {
    Elf,
    Pe,
    Zip,
    Jpeg,
    Png,
    Gzip,
};

constexpr std::string_view artifact_kind_name(ArtifactKind k) noexcept {
    switch (k) {
        case ArtifactKind::Elf: return "elf";
        case ArtifactKind::Pe: return "pe";
        case ArtifactKind::Zip: return "zip";
        case ArtifactKind::Jpeg: return "jpeg";
        case ArtifactKind::Png: return "png";
        case ArtifactKind::Gzip: return "gzip";
    }
    return "unknown";
}

/// One embedded artifact found by signature (offset + best-known extent).
struct ArtifactSpan {
    std::uint64_t offset{0};
    std::uint64_t size{0};       // 0 = unknown extent (streamed format), capped later
    ArtifactKind kind{ArtifactKind::Elf};
};

struct CarvedArtifact {
    ArtifactSpan span;
    std::string path;            // empty when inventory-only
    std::vector<std::string> rules;  // signature hits in the extracted bytes
    std::string note;
};

struct CarveReport {
    std::string source;
    std::uint64_t source_bytes{0};
    std::vector<CarvedArtifact> artifacts;
    std::string error;           // non-empty => the operation did not happen
    [[nodiscard]] bool suspicious() const noexcept {
        for (const auto& a : artifacts)
            if (!a.rules.empty()) return true;
        return false;
    }
};

class Carver {
public:
    explicit Carver(const core::CarveConfig& cfg) noexcept : cfg_(cfg) {}

    /// PURE: find artifact spans in a buffer. No I/O, deterministic, unit-test
    /// floor for everything else. Spans are non-overlapping, offset-ordered.
    [[nodiscard]] static std::vector<ArtifactSpan> find_artifacts(
        std::span<const std::byte> data) noexcept;

    /// Opt-in workflow: extract artifacts from `path` into `out_dir` (created
    /// 0700, files 0600, names keyed by sha256 of the extracted bytes) and,
    /// when `engine` is given, signature-scan each extraction. Refuses when
    /// the feature is disabled in config -- the refusal IS the opt-in gate.
    [[nodiscard]] CarveReport carve_file(std::string_view path, std::string_view out_dir,
                                         const SignatureEngine* engine) const noexcept;

    /// Inventory-only (no writes): what `triage` shows. Honours the same caps.
    [[nodiscard]] static CarveReport inventory(std::string_view path) noexcept;

    [[nodiscard]] const core::CarveConfig& config() const noexcept { return cfg_; }

private:
    core::CarveConfig cfg_;
};

/// How many bytes of a CARVED span are actually present in the re-read blob.
/// Inventory offsets come from one read; the file may shrink before the carve
/// re-opens it. Returns 0 and sets ok=false when the span starts past the end
/// (the old code underflowed `size - offset` here and hashed out of bounds);
/// otherwise clamps to what is there and sets ok=true. Exposed for the
/// stale-offset regression cases.
[[nodiscard]] inline std::uint64_t carve_take(std::uint64_t span_offset, std::uint64_t span_size,
                                              std::uint64_t blob_size, bool& ok) noexcept {
    if (span_offset >= blob_size) { ok = false; return 0; }
    ok = true;
    return std::min<std::uint64_t>(span_size, blob_size - span_offset);
}

}  // namespace hyprnova::scanning
