// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/hash.hpp
// Cryptographic + fast hashing used by canary signing, scan de-duplication and
// the boot integrity baseline.
//
// SHA-256 is implemented in-tree (public-domain derivation) so the daemon has no
// hard dependency on libcrypto at rest; if OpenSSL EVP is detected at configure
// time, HYPRNOVA_HAVE_OPENSSL routes through it for hardware acceleration.
// XXH64 is used for the *hot* path (per-event identity keys) where collision
// resistance is not required but speed is.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace hyprnova::core::hash {

using Bytes = std::span<const std::byte>;

// ---------------------------------------------------------------------------
// XXH64 — event identity / de-dup keys
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint64_t xxh64(Bytes data, std::uint64_t seed = 0) noexcept;
[[nodiscard]] inline std::uint64_t xxh64(std::string_view s, std::uint64_t seed = 0) noexcept {
    return xxh64({reinterpret_cast<const std::byte*>(s.data()), s.size()}, seed);
}

// ---------------------------------------------------------------------------
// SHA-256 — canary signatures, IOC digests, boot baseline
// ---------------------------------------------------------------------------

class Sha256 {
public:
    static constexpr std::size_t kDigestLen = 32;
    using Digest = std::array<std::uint8_t, kDigestLen>;

    Sha256() noexcept { reset(); }

    void reset() noexcept;
    void update(Bytes data) noexcept;
    void update(std::string_view s) noexcept {
        update({reinterpret_cast<const std::byte*>(s.data()), s.size()});
    }
    [[nodiscard]] Digest final() noexcept;

    [[nodiscard]] static Digest once(Bytes data) noexcept;
    [[nodiscard]] static Digest once(std::string_view s) noexcept {
        return once({reinterpret_cast<const std::byte*>(s.data()), s.size()});
    }

    /// Incremental hashing of a large file via mmap'd span chunks.
    [[nodiscard]] static Digest of_file(std::string_view path) noexcept;

    [[nodiscard]] static std::string to_hex(const Digest& d) noexcept;
    [[nodiscard]] static bool from_hex(std::string_view hex, Digest& out) noexcept;

private:
    void transform(const std::uint8_t* block) noexcept;
    void pad_and_finish(Digest& out) noexcept;

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buf_{};
    std::uint64_t bitlen_{0};
    std::size_t buflen_{0};
};

// ---------------------------------------------------------------------------
// HMAC-SHA256 + Ed25519-style signed canary envelope
// ---------------------------------------------------------------------------

/// Canary files are signed with HMAC-SHA256 under a key held only by the daemon
/// (mode 0600, /var/lib/hyprnova/canary.key). A canary that fails verification
/// has been *tampered with*, which is a distinct and higher-severity signal than
/// a canary that was merely read.
[[nodiscard]] Sha256::Digest hmac_sha256(Bytes key, Bytes message) noexcept;

/// Constant-time comparison. Never use == on MACs.
[[nodiscard]] bool ct_equal(Bytes a, Bytes b) noexcept;

// ---------------------------------------------------------------------------
// Shannon entropy — the anti-ransomware workhorse
// ---------------------------------------------------------------------------

/// H = -sum(p * log2(p)) over the byte histogram. 0.0 for empty input,
/// ~8.0 for uniformly random (encrypted/compressed) data.
[[nodiscard]] double shannon_entropy(Bytes data) noexcept;

[[nodiscard]] inline double shannon_entropy(std::string_view s) noexcept {
    return shannon_entropy({reinterpret_cast<const std::byte*>(s.data()), s.size()});
}

/// Chunk-wise entropy profile: returns the max and mean entropy over fixed
/// windows. Ransomware encrypts in blocks, so a file whose *tail* entropy jumps
/// while the head stays low is a far better signal than whole-file entropy.
struct EntropyProfile {
    double mean{0.0};
    double max{0.0};
    double head{0.0};   // first window
    double tail{0.0};   // last window
    double delta{0.0};  // tail - head
    std::size_t windows{0};
    std::size_t bytes{0};
};

[[nodiscard]] EntropyProfile entropy_profile(Bytes data, std::size_t window = 4096) noexcept;

/// Cheap magic-byte classification used to decide whether a write target is a
/// "structured personal file" (.docx/.pdf/.cpp/...) worth protecting.
enum class FileFlavour : std::uint8_t {
    Unknown = 0,
    Document,   // docx, odt, pdf, rtf
    Image,      // png, jpg
    Archive,    // zip, gz, tar
    Executable, // ELF
    Source,     // cpp, h, py, js
    Data,       // csv, json, sqlite
    Media,      // mp4, mp3
};

[[nodiscard]] FileFlavour classify(std::string_view path, Bytes head) noexcept;

[[nodiscard]] constexpr std::string_view flavour_name(FileFlavour f) noexcept {
    switch (f) {
        case FileFlavour::Document: return "document";
        case FileFlavour::Image: return "image";
        case FileFlavour::Archive: return "archive";
        case FileFlavour::Executable: return "executable";
        case FileFlavour::Source: return "source";
        case FileFlavour::Data: return "data";
        case FileFlavour::Media: return "media";
        case FileFlavour::Unknown: return "unknown";
    }
    return "unknown";
}

/// True when this flavour is one ransomware actually targets.
[[nodiscard]] constexpr bool is_ransomware_target(FileFlavour f) noexcept {
    return f == FileFlavour::Document || f == FileFlavour::Source || f == FileFlavour::Image ||
           f == FileFlavour::Data || f == FileFlavour::Media;
}

}  // namespace hyprnova::core::hash
