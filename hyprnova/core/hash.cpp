// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/hash.cpp

#include "core/hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>

#include "core/fd.hpp"

namespace hyprnova::core::hash {

// ===========================================================================
// XXH64 (public-domain derivation of the reference algorithm)
// ===========================================================================

namespace {

constexpr std::uint64_t kP1 = 0x9E3779B185EBCA87ULL;
constexpr std::uint64_t kP2 = 0xC2B2AE3D27D4EB4FULL;
constexpr std::uint64_t kP3 = 0x165667B19E3779F9ULL;
constexpr std::uint64_t kP4 = 0x85EBCA77C2B2AE63ULL;
constexpr std::uint64_t kP5 = 0x27D4EB2F165667C5ULL;

inline std::uint64_t read64(const std::byte* p) noexcept {
    std::uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}
inline std::uint32_t read32(const std::byte* p) noexcept {
    std::uint32_t v;
    std::memcpy(&v, p, 4);
    return v;
}

inline std::uint64_t round64(std::uint64_t acc, std::uint64_t in) noexcept {
    acc += in * kP2;
    acc = std::rotl(acc, 31);
    acc *= kP1;
    return acc;
}
inline std::uint64_t merge64(std::uint64_t acc, std::uint64_t v) noexcept {
    v = round64(0, v);
    acc ^= v;
    acc = acc * kP1 + kP4;
    return acc;
}

}  // namespace

std::uint64_t xxh64(Bytes data, std::uint64_t seed) noexcept {
    const auto* p = data.data();
    std::size_t len = data.size();
    std::uint64_t h;

    if (len >= 32) {
        const auto* const limit = p + len - 32;
        std::uint64_t v1 = seed + kP1 + kP2;
        std::uint64_t v2 = seed + kP2;
        std::uint64_t v3 = seed + 0;
        std::uint64_t v4 = seed - kP1;
        do {
            v1 = round64(v1, read64(p)); p += 8;
            v2 = round64(v2, read64(p)); p += 8;
            v3 = round64(v3, read64(p)); p += 8;
            v4 = round64(v4, read64(p)); p += 8;
        } while (p <= limit);
        h = std::rotl(v1, 1) + std::rotl(v2, 7) + std::rotl(v3, 12) + std::rotl(v4, 18);
        h = merge64(h, v1); h = merge64(h, v2); h = merge64(h, v3); h = merge64(h, v4);
    } else {
        h = seed + kP5;
    }

    h += static_cast<std::uint64_t>(len);

    while (len >= 8) {
        h ^= round64(0, read64(p));
        h = std::rotl(h, 27) * kP1 + kP4;
        p += 8; len -= 8;
    }
    if (len >= 4) {
        h ^= static_cast<std::uint64_t>(read32(p)) * kP1;
        h = std::rotl(h, 23) * kP2 + kP3;
        p += 4; len -= 4;
    }
    while (len > 0) {
        h ^= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(*p)) * kP5;
        h = std::rotl(h, 11) * kP1;
        ++p; --len;
    }

    h ^= h >> 33; h *= kP2;
    h ^= h >> 29; h *= kP3;
    h ^= h >> 32;
    return h;
}

// ===========================================================================
// SHA-256
// ===========================================================================

namespace {

constexpr std::array<std::uint32_t, 64> kK = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

}  // namespace

void Sha256::reset() noexcept {
    state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
              0x5be0cd19};
    bitlen_ = 0;
    buflen_ = 0;
}

void Sha256::transform(const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<std::uint32_t>(block[i * 4 + 3]);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + S1 + ch + kK[i] + w[i];
        const std::uint32_t S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256::update(Bytes data) noexcept {
    const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t len = data.size();
    bitlen_ += static_cast<std::uint64_t>(len) * 8;

    while (len > 0) {
        const std::size_t take = std::min(len, buf_.size() - buflen_);
        std::memcpy(buf_.data() + buflen_, p, take);
        buflen_ += take;
        p += take;
        len -= take;
        if (buflen_ == 64) {
            transform(buf_.data());
            buflen_ = 0;
        }
    }
}

void Sha256::pad_and_finish(Digest& out) noexcept {
    const std::uint64_t bits = bitlen_;
    buf_[buflen_++] = 0x80;
    if (buflen_ > 56) {
        while (buflen_ < 64) buf_[buflen_++] = 0;
        transform(buf_.data());
        buflen_ = 0;
    }
    while (buflen_ < 56) buf_[buflen_++] = 0;
    for (std::size_t i = 8; i-- > 0;)
        buf_[buflen_++] = static_cast<std::uint8_t>(bits >> (i * 8));
    transform(buf_.data());

    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<std::uint8_t>(state_[i] >> 24);
        out[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
        out[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
        out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
    }
}

Sha256::Digest Sha256::final() noexcept {
    Digest d{};
    pad_and_finish(d);
    return d;
}

Sha256::Digest Sha256::once(Bytes data) noexcept {
    Sha256 h;
    h.update(data);
    return h.final();
}

Sha256::Digest Sha256::of_file(std::string_view path) noexcept {
    auto mf = MappedFile::open(path);
    if (!mf) return {};
    mf->advise_sequential();
    Bytes b = mf->bytes();

    // Chunked so a 4 GB container image does not need to be resident at once.
    Sha256 h;
    constexpr std::size_t kChunk = 4 << 20;
    for (std::size_t off = 0; off < b.size(); off += kChunk) {
        const std::size_t n = std::min(kChunk, b.size() - off);
        h.update(b.subspan(off, n));
    }
    return h.final();
}

std::string Sha256::to_hex(const Digest& d) noexcept {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(d.size() * 2);
    for (std::size_t i = 0; i < d.size(); ++i) {
        out[i * 2] = kHex[d[i] >> 4];
        out[i * 2 + 1] = kHex[d[i] & 0x0F];
    }
    return out;
}

bool Sha256::from_hex(std::string_view hex, Digest& out) noexcept {
    if (hex.size() != out.size() * 2) return false;
    auto nib = [](char c, std::uint8_t& v) -> bool {
        if (c >= '0' && c <= '9') { v = static_cast<std::uint8_t>(c - '0'); return true; }
        if (c >= 'a' && c <= 'f') { v = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
        if (c >= 'A' && c <= 'F') { v = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
        return false;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        std::uint8_t hi = 0, lo = 0;
        if (!nib(hex[i * 2], hi) || !nib(hex[i * 2 + 1], lo)) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

// ===========================================================================
// HMAC-SHA256
// ===========================================================================

Sha256::Digest hmac_sha256(Bytes key, Bytes message) noexcept {
    // HMAC block size == SHA-256 block size == 64 bytes (not the 32-byte digest).
    constexpr std::size_t kBlock = 64;
    std::array<std::uint8_t, kBlock> k{};
    if (key.size() > kBlock) {
        const auto d = Sha256::once(key);
        std::memcpy(k.data(), d.data(), d.size());
    } else {
        std::memcpy(k.data(), key.data(), key.size());
    }

    std::array<std::uint8_t, kBlock> ipad{}, opad{};
    ipad.fill(0x36);
    opad.fill(0x5c);
    for (std::size_t i = 0; i < kBlock; ++i) {
        ipad[i] = static_cast<std::uint8_t>(ipad[i] ^ k[i]);
        opad[i] = static_cast<std::uint8_t>(opad[i] ^ k[i]);
    }

    const auto as_bytes = [](const auto& a) noexcept {
        return Bytes{reinterpret_cast<const std::byte*>(a.data()), a.size()};
    };

    Sha256 inner;
    inner.update(as_bytes(ipad));
    inner.update(message);
    const auto ih = inner.final();

    Sha256 outer;
    outer.update(as_bytes(opad));
    outer.update(as_bytes(ih));
    return outer.final();
}

bool ct_equal(Bytes a, Bytes b) noexcept {
    if (a.size() != b.size()) return false;
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        acc = static_cast<std::uint8_t>(acc | (std::to_integer<std::uint8_t>(a[i]) ^
                                               std::to_integer<std::uint8_t>(b[i])));
    }
    return acc == 0;
}

// ===========================================================================
// Shannon entropy
// ===========================================================================

double shannon_entropy(Bytes data) noexcept {
    if (data.empty()) return 0.0;
    std::array<std::uint64_t, 256> hist{};
    for (const std::byte b : data) hist[std::to_integer<std::uint8_t>(b)]++;

    const double n = static_cast<double>(data.size());
    double h = 0.0;
    for (const std::uint64_t c : hist) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        h -= p * std::log2(p);
    }
    return h;
}

EntropyProfile entropy_profile(Bytes data, std::size_t window) noexcept {
    EntropyProfile prof{};
    prof.bytes = data.size();
    if (data.empty()) return prof;
    if (window == 0) window = 4096;
    if (window > data.size()) window = data.size();

    double sum = 0.0;
    double mx = 0.0;
    std::size_t idx = 0;
    for (std::size_t off = 0; off < data.size(); off += window, ++idx) {
        const std::size_t n = std::min(window, data.size() - off);
        const double e = shannon_entropy(data.subspan(off, n));
        sum += e;
        mx = std::max(mx, e);
        if (idx == 0) prof.head = e;
        prof.tail = e;
    }
    prof.windows = idx;
    prof.mean = idx ? sum / static_cast<double>(idx) : 0.0;
    prof.max = mx;
    prof.delta = prof.tail - prof.head;
    return prof;
}

// ===========================================================================
// Flavour classification
// ===========================================================================

namespace {

bool has_ext(std::string_view path, std::initializer_list<std::string_view> exts) noexcept {
    const std::size_t dot = path.find_last_of('.');
    const std::size_t slash = path.find_last_of('/');
    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash)) return false;
    std::string ext{path.substr(dot)};
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto e : exts) {
        if (ext == e) return true;
    }
    return false;
}

}  // namespace

FileFlavour classify(std::string_view path, Bytes head) noexcept {
    const auto* p = reinterpret_cast<const char*>(head.data());

    if (head.size() >= 4 && p[0] == 0x7F && p[1] == 'E' && p[2] == 'L' && p[3] == 'F')
        return FileFlavour::Executable;
    if (head.size() >= 5 && std::memcmp(p, "%PDF-", 5) == 0) return FileFlavour::Document;
    if (head.size() >= 4 && std::memcmp(p, "PK\x03\x04", 4) == 0) {
        // OOXML and ODF are ZIP containers; plain ZIP is an archive.
        if (has_ext(path, {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".apk"}))
            return FileFlavour::Document;
        return FileFlavour::Archive;
    }
    if (head.size() >= 8 && std::memcmp(p, "\x89PNG\r\n\x1a\n", 8) == 0) return FileFlavour::Image;
    if (head.size() >= 3 && std::memcmp(p, "\xff\xd8\xff", 3) == 0) return FileFlavour::Image;
    if (head.size() >= 2 && std::memcmp(p, "\x1f\x8b", 2) == 0) return FileFlavour::Archive;
    if (head.size() >= 16 && std::memcmp(p, "SQLite format 3", 15) == 0) return FileFlavour::Data;
    if (head.size() >= 12 && std::memcmp(p + 4, "ftyp", 4) == 0) return FileFlavour::Media;
    if (head.size() >= 3 && std::memcmp(p, "ID3", 3) == 0) return FileFlavour::Media;

    if (has_ext(path, {".docx", ".doc", ".odt", ".rtf", ".pdf", ".xlsx", ".pptx", ".tex"}))
        return FileFlavour::Document;
    if (has_ext(path, {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".rs", ".go", ".py", ".js",
                       ".ts", ".java", ".rb", ".php", ".sh", ".pl", ".lua", ".sql"}))
        return FileFlavour::Source;
    if (has_ext(path, {".csv", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".log"}))
        return FileFlavour::Data;
    if (has_ext(path, {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".webp", ".tif"}))
        return FileFlavour::Image;
    if (has_ext(path, {".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst"}))
        return FileFlavour::Archive;
    if (has_ext(path, {".mp4", ".mkv", ".avi", ".mov", ".mp3", ".flac", ".wav", ".ogg"}))
        return FileFlavour::Media;
    return FileFlavour::Unknown;
}

}  // namespace hyprnova::core::hash
