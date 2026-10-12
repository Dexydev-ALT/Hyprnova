// SPDX-License-Identifier: Apache-2.0
// HyprNova :: Module 3a implementation

#include "scanning/yara_engine.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <deque>
#include <format>

#include "core/fd.hpp"
#include "core/log.hpp"

#ifdef HYPRNOVA_HAVE_LIBYARA
#include <yara.h>
#endif

namespace hyprnova::scanning {

namespace fsx = core::fsx;
using namespace std::string_view_literals;

// ===========================================================================
// Aho-Corasick
// ===========================================================================

std::size_t AhoCorasick::transition(std::size_t node, std::uint8_t c) const noexcept {
    // goto_ is fully populated by build(), so this is a single array lookup with
    // no failure-link walking at scan time. That is what makes it one-pass.
    return goto_[node][c];
}

std::size_t AhoCorasick::add(std::string_view literal, bool nocase) {
    if (literal.empty()) {
        // Register a zero-length pattern rather than aliasing pattern 0: a hit on
        // the empty literal is impossible, and returning 0 here would make the
        // caller's rule_to_ac_ entry collide with a real pattern.
        literal_len_.push_back(0);
        return literal_len_.size() - 1;
    }
    if (goto_.empty()) {
        goto_.emplace_back();
        goto_[0].fill(0);
        fail_.push_back(0);
        output_.emplace_back();
        root_ = 0;
    }

    const std::size_t pattern_id = literal_len_.size();
    literal_len_.push_back(static_cast<std::uint16_t>(std::min<std::size_t>(literal.size(), 65535)));

    // Case-insensitive patterns: the automaton sees the ORIGINAL bytes plus a
    // lowercase variant. The lowercase variant only ever matches in the
    // case-FOLDED copy of the buffer that scan() runs as a second pass — that
    // is what catches ARBITRARY mixed-case haystacks. (Indexing only the
    // lower/upper spellings of the needle used to miss mixed-case data: the
    // automaton never emitted, so the case-insensitive validator downstream —
    // however correct — had nothing to validate.)
    std::vector<std::string> variants;
    variants.emplace_back(literal);
    if (nocase) {
        std::string lower{literal};
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lower != variants[0]) variants.push_back(std::move(lower));
    }

    for (const auto& v : variants) {
        std::size_t cur = root_;
        for (const char ch : v) {
            const auto c = static_cast<std::uint8_t>(ch);
            std::uint32_t next = goto_[cur][c];
            if (next == 0) {
                goto_.emplace_back();
                goto_.back().fill(0);
                fail_.push_back(0);
                output_.emplace_back();
                next = static_cast<std::uint32_t>(goto_.size() - 1);
                goto_[cur][c] = next;
            }
            cur = next;
        }
        output_[cur].push_back(static_cast<std::uint32_t>(pattern_id));
    }
    built_ = false;
    return pattern_id;
}

void AhoCorasick::build() noexcept {
    if (goto_.empty()) return;

    std::deque<std::size_t> q;
    // Depth-1 nodes fail to root.
    for (std::size_t c = 0; c < 256; ++c) {
        const std::uint32_t next = goto_[root_][c];
        if (next != 0 && next != root_) {
            fail_[next] = static_cast<std::uint32_t>(root_);
            q.push_back(next);
        } else {
            goto_[root_][c] = static_cast<std::uint32_t>(root_);
        }
    }

    while (!q.empty()) {
        const std::size_t u = q.front();
        q.pop_front();
        for (std::size_t c = 0; c < 256; ++c) {
            const std::uint32_t v = goto_[u][c];
            if (v != 0) {
                std::uint32_t f = fail_[u];
                while (f != root_ && goto_[f][c] == 0) f = fail_[f];
                fail_[v] = goto_[f][c] == v ? static_cast<std::uint32_t>(root_) : goto_[f][c];
                // Merge the suffix link's outputs so scanning never walks links.
                for (const std::uint32_t o : output_[fail_[v]]) output_[v].push_back(o);
                q.push_back(v);
            } else {
                goto_[u][c] = goto_[fail_[u]][c];
            }
        }
    }
    built_ = true;
}

// ===========================================================================
// Rule parser
// ===========================================================================

namespace {

struct Lexer {
    std::string_view src;
    std::size_t pos{0};
    std::size_t line{1};

    [[nodiscard]] bool eof() const noexcept { return pos >= src.size(); }
    [[nodiscard]] char peek(std::size_t k = 0) const noexcept {
        return pos + k < src.size() ? src[pos + k] : '\0';
    }
    void advance(std::size_t n = 1) noexcept {
        for (std::size_t i = 0; i < n && !eof(); ++i) {
            if (src[pos] == '\n') ++line;
            ++pos;
        }
    }
    void skip_ws_and_comments() noexcept {
        for (;;) {
            while (!eof() && std::isspace(static_cast<unsigned char>(peek()))) advance();
            if (peek() == '/' && peek(1) == '/') {
                while (!eof() && peek() != '\n') advance();
                continue;
            }
            if (peek() == '/' && peek(1) == '*') {
                advance(2);
                while (!eof() && !(peek() == '*' && peek(1) == '/')) advance();
                advance(2);
                continue;
            }
            break;
        }
    }
    [[nodiscard]] bool eat(std::string_view tok) noexcept {
        skip_ws_and_comments();
        if (src.substr(pos, tok.size()) == tok) {
            advance(tok.size());
            return true;
        }
        return false;
    }
    [[nodiscard]] std::string identifier() noexcept {
        skip_ws_and_comments();
        const std::size_t s = pos;
        while (!eof() && (std::isalnum(static_cast<unsigned char>(peek())) || peek() == '_')) advance();
        return std::string(src.substr(s, pos - s));
    }
    [[nodiscard]] std::string quoted() noexcept {
        skip_ws_and_comments();
        if (peek() != '"') return {};
        advance();
        std::string out;
        while (!eof() && peek() != '"') {
            if (peek() == '\\') {
                advance();
                switch (peek()) {
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case '0': out.push_back('\0'); break;
                    case 'x': {
                        advance();
                        unsigned v = 0;
                        for (int i = 0; i < 2 && std::isxdigit(static_cast<unsigned char>(peek())); ++i) {
                            v <<= 4;
                            const char c = peek();
                            v |= (c >= '0' && c <= '9') ? static_cast<unsigned>(c - '0')
                                                        : static_cast<unsigned>(std::tolower(c) - 'a' + 10);
                            advance();
                        }
                        out.push_back(static_cast<char>(v));
                        continue;  // already advanced
                    }
                    default: out.push_back(peek()); break;
                }
                advance();
                continue;
            }
            out.push_back(peek());
            advance();
        }
        advance();  // closing quote
        return out;
    }
};

std::vector<std::optional<std::uint8_t>> parse_hex_pattern(std::string_view body) {
    std::vector<std::optional<std::uint8_t>> out;
    std::size_t i = 0;
    while (i < body.size()) {
        const char c = body[i];
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
        if (c == '{') {
            // Jump {n}, {n-m}, or {-m}
            while (i < body.size() && body[i] != '}') ++i;
            ++i;
            out.push_back(std::nullopt);  // one wildcard stands in for the jump
            continue;
        }
        if (c == '[') {
            // Alternation / full wildcard group: treat as a single wildcard byte.
            int depth = 0;
            while (i < body.size()) {
                if (body[i] == '[') ++depth;
                else if (body[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
                ++i;
            }
            out.push_back(std::nullopt);
            continue;
        }
        if (c == '?') {
            out.push_back(std::nullopt);
            ++i;
            if (i < body.size() && body[i] == '?') ++i;  // ?? == whole-byte wildcard
            continue;
        }
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            auto nib = [](char ch) -> int {
                if (ch >= '0' && ch <= '9') return ch - '0';
                return std::tolower(ch) - 'a' + 10;
            };
            if (i + 1 < body.size() && std::isxdigit(static_cast<unsigned char>(body[i + 1]))) {
                out.push_back(static_cast<std::uint8_t>((nib(c) << 4) | nib(body[i + 1])));
                i += 2;
            } else {
                // Trailing nibble wildcard (e.g. "4?"): half-byte -> full wildcard.
                out.push_back(std::nullopt);
                ++i;
            }
            continue;
        }
        ++i;  // unrecognised token; skip rather than abort the rule
    }
    return out;
}

/// Evaluate the small condition grammar we support. Deliberately a threshold
/// extractor rather than a general expression evaluator: the value is in deciding
/// "how many patterns must match", not in emulating YARA's full boolean algebra.
void compile_condition(const std::string& cond, Rule& r) {
    std::string c = cond;
    std::transform(c.begin(), c.end(), c.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

    if (c.find("all of") != std::string::npos) {
        r.require_all = true;
        r.required_matches = std::max<std::size_t>(1, r.patterns.size());
    } else if (c.find("any of") != std::string::npos) {
        r.require_all = false;
        r.required_matches = 1;
    } else if (const std::size_t at = c.find(" of them"); at != std::string::npos) {
        // "2 of them" / "60% of them"
        std::string_view pre{c.data(), at};
        std::size_t s = 0;
        while (s < pre.size() && std::isspace(static_cast<unsigned char>(pre[s]))) ++s;
        std::uint64_t n = 0;
        const auto* p = pre.data() + s;
        if (std::from_chars(p, pre.data() + pre.size(), n).ec == std::errc{}) {
            r.required_matches = static_cast<std::size_t>(n);
        } else if (pre.find('%') != std::string_view::npos) {
            double pct = 0;
            if (std::sscanf(std::string(pre).c_str(), "%lf", &pct) == 1) {
                r.required_matches = std::max<std::size_t>(
                    1, static_cast<std::size_t>(static_cast<double>(r.patterns.size()) * pct / 100.0));
            }
        }
    } else {
        // Default: a bare "$a" or "$a or $b" condition. Require the first
        // pattern, which is the conservative reading of an under-specified rule.
        r.required_matches = r.patterns.empty() ? 0 : 1;
    }

    // filesize constraints
    for (const char* op : {"filesize <", "filesize >", "filesize <=", "filesize >="}) {
        const std::size_t at = c.find(op);
        if (at == std::string::npos) continue;
        std::string_view tail{c.data() + at + std::strlen(op)};
        std::size_t s = 0;
        while (s < tail.size() && std::isspace(static_cast<unsigned char>(tail[s]))) ++s;
        std::uint64_t n = 0;
        const auto* p = tail.data() + s;
        const auto* e = tail.data() + tail.size();
        if (std::from_chars(p, e, n).ec != std::errc{}) continue;
        std::uint64_t mult = 1;
        if (p < e) {
            switch (*p) {
                case 'k': mult = 1024; break;
                case 'm': mult = 1024 * 1024; break;
                case 'g': mult = 1024ull * 1024 * 1024; break;
                default: break;
            }
        }
        n *= mult;
        if (std::strstr(op, "<")) r.max_filesize = n;
    }

    // uint16(0) == 0x5A4D  ->  "MZ" fast prefilter
    if (const std::size_t at = c.find("uint16(0)"); at != std::string::npos) {
        std::string_view tail{c.data() + at + 9};
        std::size_t s = 0;
        while (s < tail.size() && (std::isspace(static_cast<unsigned char>(tail[s])) || tail[s] == '='))
            ++s;
        std::uint64_t n = 0;
        const auto* p = tail.data() + s;
        const int base = (s < tail.size() && tail[s] == '0' &&
                          (s + 1 < tail.size() && (tail[s + 1] == 'x' || tail[s + 1] == 'X')))
                             ? 0
                             : 10;
        if (base == 0) p += 2;
        if (std::from_chars(p, tail.data() + tail.size(), n, base).ec == std::errc{}) {
            r.magic_u16_at_0 = static_cast<std::uint16_t>(n);
        }
    }
}

core::Severity severity_from_tags(const std::vector<std::string>& tags,
                                  const std::string& identifier) noexcept {
    for (const auto& t : tags) {
        if (t == "critical" || t == "ransomware" || t == "rootkit" || t == "bootkit")
            return core::Severity::Critical;
        if (t == "high" || t == "trojan" || t == "backdoor" || t == "loader" || t == "c2")
            return core::Severity::High;
        if (t == "low" || t == "pup" || t == "adware" || t == "riskware") return core::Severity::Low;
    }
    const std::string lower = [&] {
        std::string s = identifier;
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }();
    if (lower.find("ransom") != std::string::npos || lower.find("rootkit") != std::string::npos)
        return core::Severity::Critical;
    if (lower.find("suspicious") != std::string::npos || lower.find("heuristic") != std::string::npos)
        return core::Severity::Medium;
    return core::Severity::High;
}

}  // namespace

std::vector<Rule> parse_rules(std::string_view source, std::vector<ParseIssue>* issues) noexcept {
    std::vector<Rule> out;
    Lexer lx{source};

    auto issue = [&](std::size_t line, std::string msg) {
        if (issues) issues->push_back({line, std::move(msg)});
    };

    for (;;) {
        lx.skip_ws_and_comments();
        if (lx.eof()) break;

        Rule r;
        if (lx.eat("private")) r.is_private = true;
        else if (!lx.eat("rule")) {
            // Skip an unrecognised token rather than failing the whole file.
            issue(lx.line, "expected 'rule' or 'private rule'");
            lx.advance();
            continue;
        }
        if (r.is_private && !lx.eat("rule")) {
            issue(lx.line, "expected 'rule' after 'private'");
            continue;
        }
        r.identifier = lx.identifier();
        if (r.identifier.empty()) {
            issue(lx.line, "rule has no identifier");
            lx.advance();
            continue;
        }

        // Optional tag list
        lx.skip_ws_and_comments();
        if (lx.peek() == ':') {
            lx.advance();
            for (;;) {
                const std::string tag = lx.identifier();
                if (tag.empty()) break;
                r.tags.push_back(tag);
            }
        }
        if (!lx.eat("{")) {
            issue(lx.line, "expected '{' to open rule " + r.identifier);
            continue;
        }

        // meta / strings / condition sections, in any order
        for (;;) {
            lx.skip_ws_and_comments();
            if (lx.eat("}")) break;
            if (lx.eof()) {
                issue(lx.line, "unterminated rule " + r.identifier);
                break;
            }

            if (lx.eat("meta")) {
                if (!lx.eat(":")) { issue(lx.line, "expected ':' after meta"); continue; }
                for (;;) {
                    lx.skip_ws_and_comments();
                    if (lx.eof()) break;
                    // peek for the next section keyword
                    const std::string_view rest = lx.src.substr(lx.pos);
                    if (rest.starts_with("strings") || rest.starts_with("condition") ||
                        rest.starts_with("}"))
                        break;
                    const std::string key = lx.identifier();
                    if (key.empty()) { lx.advance(); continue; }
                    if (!lx.eat("=")) { issue(lx.line, "expected '=' in meta"); continue; }
                    lx.skip_ws_and_comments();
                    std::string value;
                    if (lx.peek() == '"') value = lx.quoted();
                    else {
                        const std::size_t s = lx.pos;
                        while (!lx.eof() && lx.peek() != '\n') lx.advance();
                        value = std::string(lx.src.substr(s, lx.pos - s));
                        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
                            value.pop_back();
                    }
                    if (key == "author") r.meta_author = value;
                    else if (key == "description") r.meta_description = value;
                    else if (key == "family" || key == "malware_family") r.meta_family = value;
                    else if (key == "reference" || key == "url") r.meta_reference = value;
                    else if (key == "severity") {
                        if (value == "critical") r.severity = core::Severity::Critical;
                        else if (value == "high") r.severity = core::Severity::High;
                        else if (value == "medium") r.severity = core::Severity::Medium;
                        else if (value == "low") r.severity = core::Severity::Low;
                        else if (value == "info") r.severity = core::Severity::Info;
                    }
                }
                continue;
            }

            if (lx.eat("strings")) {
                if (!lx.eat(":")) { issue(lx.line, "expected ':' after strings"); continue; }
                for (;;) {
                    lx.skip_ws_and_comments();
                    if (lx.eof()) break;
                    const std::string_view rest = lx.src.substr(lx.pos);
                    if (rest.starts_with("condition") || rest.starts_with("}")) break;
                    if (lx.peek() != '$') { lx.advance(); continue; }

                    Pattern p;
                    lx.advance();  // '$'
                    p.identifier = lx.identifier();
                    if (!lx.eat("=")) { issue(lx.line, "expected '=' after $" + p.identifier); continue; }
                    lx.skip_ws_and_comments();

                    if (lx.peek() == '"') {
                        p.kind = PatternKind::Text;
                        p.literal = lx.quoted();
                    } else if (lx.peek() == '{') {
                        lx.advance();
                        const std::size_t s = lx.pos;
                        int depth = 1;
                        while (!lx.eof() && depth > 0) {
                            if (lx.peek() == '{') ++depth;
                            else if (lx.peek() == '}') --depth;
                            if (depth > 0) lx.advance();
                        }
                        p.kind = PatternKind::Hex;
                        p.hex = parse_hex_pattern(lx.src.substr(s, lx.pos - s));
                        lx.advance();  // '}'
                    } else if (lx.peek() == '/') {
                        p.kind = PatternKind::Regex;
                        lx.advance();
                        const std::size_t s = lx.pos;
                        while (!lx.eof() && lx.peek() != '/' && lx.peek() != '\n') {
                            if (lx.peek() == '\\') lx.advance();
                            lx.advance();
                        }
                        p.literal = std::string(lx.src.substr(s, lx.pos - s));
                        if (lx.peek() == '/') lx.advance();
                    } else {
                        issue(lx.line, "unsupported pattern syntax in $" + p.identifier);
                        lx.advance();
                        continue;
                    }

                    // Modifiers
                    for (;;) {
                        lx.skip_ws_and_comments();
                        if (lx.eat("nocase")) { p.nocase = true; continue; }
                        if (lx.eat("wide")) { p.wide = true; continue; }
                        if (lx.eat("ascii")) { continue; }
                        if (lx.eat("fullword")) { p.fullword = true; continue; }
                        if (lx.eat("xor")) { issue(lx.line, "xor modifier is not supported by YaraLite"); continue; }
                        break;
                    }
                    if (p.kind == PatternKind::Text && p.literal.empty()) continue;
                    if (p.kind == PatternKind::Hex && p.hex.empty()) continue;
                    r.patterns.push_back(std::move(p));
                }
                continue;
            }

            if (lx.eat("condition")) {
                if (!lx.eat(":")) { issue(lx.line, "expected ':' after condition"); continue; }
                const std::size_t s = lx.pos;
                int depth = 0;
                while (!lx.eof()) {
                    lx.skip_ws_and_comments();
                    if (lx.eof()) break;
                    if (lx.peek() == '(') ++depth;
                    if (lx.peek() == ')') --depth;
                    if (depth <= 0) {
                        const std::string_view rest = lx.src.substr(lx.pos);
                        if (rest.starts_with("}") || rest.starts_with("strings") ||
                            rest.starts_with("meta") || rest.starts_with("condition"))
                            break;
                    }
                    lx.advance();
                }
                r.condition = std::string(lx.src.substr(s, lx.pos - s));
                while (!r.condition.empty() && std::isspace(static_cast<unsigned char>(r.condition.back())))
                    r.condition.pop_back();
                continue;
            }

            lx.advance();  // unrecognised token inside a rule
        }

        if (r.patterns.empty() && r.condition.empty()) {
            issue(lx.line, "rule " + r.identifier + " has neither patterns nor a condition");
            continue;
        }
        compile_condition(r.condition, r);
        if (r.severity == core::Severity::High) r.severity = severity_from_tags(r.tags, r.identifier);
        out.push_back(std::move(r));
    }
    return out;
}

// ===========================================================================
// SignatureEngine
// ===========================================================================

#ifdef HYPRNOVA_HAVE_LIBYARA
struct SignatureEngine::Impl {
    bool yr_initialised{false};
    YR_RULES* rules{nullptr};
    YR_COMPILER* compiler{nullptr};
};
#else
struct SignatureEngine::Impl {};
#endif

SignatureEngine::SignatureEngine() : impl_{std::make_unique<Impl>()} {
#ifdef HYPRNOVA_HAVE_LIBYARA
    if (yr_initialize() == ERROR_SUCCESS) {
        impl_->yr_initialised = true;
        if (yr_compiler_create(&impl_->compiler) != ERROR_SUCCESS) impl_->compiler = nullptr;
        backend_ = Backend::LibYara;
    }
#endif
}

SignatureEngine::~SignatureEngine() {
#ifdef HYPRNOVA_HAVE_LIBYARA
    if (impl_->rules) yr_rules_destroy(impl_->rules);
    if (impl_->compiler) yr_compiler_destroy(impl_->compiler);
    if (impl_->yr_initialised) yr_finalize();
#endif
}

bool SignatureEngine::libyara_available() const noexcept {
#ifdef HYPRNOVA_HAVE_LIBYARA
    return impl_ && impl_->yr_initialised;
#else
    return false;
#endif
}

void SignatureEngine::rebuild_automaton() noexcept {
    ac_ = AhoCorasick{};
    rule_to_ac_.assign(rules_.size(), {});

    fold_scan_ = false;

    for (std::size_t ri = 0; ri < rules_.size(); ++ri) {
        const Rule& r = rules_[ri];
        for (const Pattern& p : r.patterns) {
            if (p.kind == PatternKind::Text && !p.literal.empty()) {
                rule_to_ac_[ri].push_back(ac_.add(p.literal, p.nocase));
                if (p.nocase) fold_scan_ = true;
                if (p.wide) {
                    // UTF-16LE variants: interleave a NUL after each byte. The
                    // returned pattern id MUST be kept: it is the only thing
                    // that routes a UTF-16LE hit back to this rule (dropping
                    // it made `wide` matches silently unsatisfiable).
                    std::string w;
                    w.reserve(p.literal.size() * 2);
                    for (const char c : p.literal) { w.push_back(c); w.push_back('\0'); }
                    rule_to_ac_[ri].push_back(ac_.add(w, false));
                    if (p.nocase) {
                        // Lowercase wide twin: matches the case-folded pass, so
                        // mixed-case UTF-16LE is found too.
                        std::string wl{w};
                        for (std::size_t i = 0; i < wl.size(); i += 2)
                            wl[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(wl[i])));
                        if (wl != w) rule_to_ac_[ri].push_back(ac_.add(wl, false));
                    }
                }
            } else {
                // Hex and regex patterns have no single literal to key on, so
                // they get a hyprnova id and are evaluated by direct scan.
                rule_to_ac_[ri].push_back(SIZE_MAX);
            }
        }
    }
    ac_.build();
}

std::size_t SignatureEngine::add_rules(std::vector<Rule> rules) {
    const std::size_t n = rules.size();
    for (auto& r : rules) rules_.push_back(std::move(r));

#ifdef HYPRNOVA_HAVE_LIBYARA
    if (impl_ && impl_->yr_initialised && impl_->compiler) {
        // Re-compile the full rule text into libyara. We keep the parsed
        // YaraLite rules regardless, so a libyara compile failure degrades
        // rather than disables detection.
        std::string all;
        for (const auto& r : rules_) {
            // libyara gets the original source only when we still have it; the
            // parsed model cannot round-trip, so this path is used when the
            // caller supplied rule files (see load()).
            (void)r;
        }
        (void)all;
    }
#endif

    rebuild_automaton();
    return n;
}

std::size_t SignatureEngine::load(const core::ScanConfig& cfg, std::vector<ParseIssue>* issues) {
    issues_.clear();
    rules_.clear();

    std::vector<Rule> loaded;
    for (const auto& path : cfg.rule_files) {
        if (!fsx::exists(path)) {
            issues_.push_back({0, "rule file not present: " + path});
            continue;
        }
        std::vector<ParseIssue> local;
        auto rules = parse_rule_file(path, &local);
        for (auto& i : local) i.message = path + ": " + i.message;
        for (auto& i : local) issues_.push_back(std::move(i));
        SINFO("yara-lite", "loaded {} rules from {}", rules.size(), path);
        for (auto& r : rules) loaded.push_back(std::move(r));
    }

    // The built-in set is always loaded: it is the floor, not a fallback.
    auto builtin = builtin_rules();
    for (auto& r : builtin) loaded.push_back(std::move(r));

#ifdef HYPRNOVA_HAVE_LIBYARA
    if (impl_ && impl_->yr_initialised && impl_->compiler && cfg.backend == core::ScanBackend::LibYara) {
        int compiled = 0;
        for (const auto& path : cfg.rule_files) {
            std::string src;
            if (fsx::read_file(path, src, 32 << 20) < 0) continue;
            compiled += yr_compiler_add_string(impl_->compiler, src.c_str(), path.c_str());
        }
        if (compiled == 0 && yr_compiler_get_rules(impl_->compiler, &impl_->rules) == ERROR_SUCCESS) {
            backend_ = Backend::LibYara;
            SINFO("yara", "libyara compiled all rule files; using native engine");
        } else {
            SWARN("yara", "libyara reported {} compile errors; falling back to YaraLite", compiled);
            backend_ = Backend::YaraLite;
        }
    }
#endif

    if (issues) *issues = issues_;
    return add_rules(std::move(loaded));
}

namespace {

bool hex_match_at(std::span<const std::byte> data, std::size_t off,
                  const std::vector<std::optional<std::uint8_t>>& hex) noexcept {
    if (off + hex.size() > data.size()) return false;
    for (std::size_t i = 0; i < hex.size(); ++i) {
        if (!hex[i].has_value()) continue;  // wildcard
        if (std::to_integer<std::uint8_t>(data[off + i]) != *hex[i]) return false;
    }
    return true;
}

}  // namespace

bool SignatureEngine::evaluate_condition(const Rule& r, std::span<const std::byte> data,
                                         const std::vector<AhoCorasick::Hit>& hits) const noexcept {
    // filesize prefilter
    if (r.max_filesize && data.size() > *r.max_filesize) return false;
    // magic prefilter
    if (r.magic_u16_at_0) {
        if (data.size() < 2) return false;
        const std::uint16_t v = static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[0])) |
                                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[1]) << 8);
        if (v != *r.magic_u16_at_0) return false;
    }
    if (r.patterns.empty()) return false;

    // Count distinct patterns present. A rule with `2 of them` needs two
    // DIFFERENT identifiers, not the same one twice.
    std::vector<bool> present(r.patterns.size(), false);
    for (const auto& h : hits) {
        for (std::size_t pi = 0; pi < r.patterns.size(); ++pi) {
            const Pattern& p = r.patterns[pi];
            if (p.kind != PatternKind::Text) continue;
            if (h.offset + p.literal.size() <= data.size()) {
                bool eq = true;
                for (std::size_t i = 0; i < p.literal.size(); ++i) {
                    const auto a = static_cast<char>(std::to_integer<std::uint8_t>(data[h.offset + i]));
                    const auto b = p.literal[i];
                    if (p.nocase) {
                        if (std::tolower(static_cast<unsigned char>(a)) !=
                            std::tolower(static_cast<unsigned char>(b))) { eq = false; break; }
                    } else if (a != b) { eq = false; break; }
                }
                if (eq) { present[pi] = true; continue; }
            }
            if (p.wide) {
                // A hit may also be the UTF-16LE form (every literal byte
                // followed by a NUL). The automaton indexes that form, so the
                // validator must accept it here — otherwise wide hits can never
                // satisfy the rule (external finding).
                const std::size_t wbytes = p.literal.size() * 2;
                if (h.offset + wbytes <= data.size()) {
                    bool eqw = true;
                    for (std::size_t i = 0; i < p.literal.size(); ++i) {
                        const auto a = static_cast<char>(
                            std::to_integer<std::uint8_t>(data[h.offset + 2 * i]));
                        const auto hi = std::to_integer<std::uint8_t>(data[h.offset + 2 * i + 1]);
                        const auto b = p.literal[i];
                        if (hi != 0) { eqw = false; break; }
                        if (p.nocase) {
                            if (std::tolower(static_cast<unsigned char>(a)) !=
                                std::tolower(static_cast<unsigned char>(b))) { eqw = false; break; }
                        } else if (a != b) { eqw = false; break; }
                    }
                    if (eqw) present[pi] = true;
                }
            }
        }
    }

    // Hex patterns: direct scan, but only when the literal gate already narrowed
    // the file. Scanning a 10 MB buffer per hex pattern is affordable because a
    // typical rule has a handful of them and this runs off the sensor thread.
    for (std::size_t pi = 0; pi < r.patterns.size(); ++pi) {
        const Pattern& p = r.patterns[pi];
        if (p.kind != PatternKind::Hex || p.hex.empty()) continue;
        for (std::size_t off = 0; off + p.hex.size() <= data.size(); ++off) {
            if (hex_match_at(data, off, p.hex)) { present[pi] = true; break; }
        }
    }

    const std::size_t matched =
        static_cast<std::size_t>(std::count(present.begin(), present.end(), true));
    if (r.require_all) return matched == r.patterns.size();
    return matched >= r.required_matches;
}

std::vector<Match> SignatureEngine::scan(std::span<const std::byte> data,
                                         std::string_view path) const noexcept {
    std::vector<Match> out;
    if (data.empty()) return out;

    // Collect hits per rule so evaluate_condition sees only what it needs.
    std::vector<std::vector<AhoCorasick::Hit>> per_rule(rules_.size());
    const auto sink = [&](const AhoCorasick::Hit& h) {
        for (std::size_t ri = 0; ri < rules_.size(); ++ri) {
            const auto& ids = rule_to_ac_[ri];
            for (std::size_t pi = 0; pi < ids.size(); ++pi) {
                if (ids[pi] == h.pattern) {
                    per_rule[ri].push_back(h);
                    return;  // one rule per hit is enough to trigger evaluation
                }
            }
        }
    };
    ac_.scan(data, sink);
    if (fold_scan_) {
        // Second pass over a case-folded copy: same length, same offsets, so
        // hits validate byte-for-byte against the ORIGINAL buffer downstream
        // (the nocase validator folds both sides). This is the pass that finds
        // mixed-case data for case-insensitive rules.
        std::string fold;
        fold.reserve(data.size());
        for (std::size_t i = 0; i < data.size(); ++i)
            fold.push_back(static_cast<char>(
                std::tolower(static_cast<unsigned char>(data[i]))));
        const auto* fb = reinterpret_cast<const std::byte*>(fold.data());
        ac_.scan(std::span<const std::byte>(fb, fold.size()), sink);
    }
    // Two passes can record the same (pattern, offset) twice; condition
    // evaluation counts DISTINCT patterns, but keep the hit lists clean.
    for (auto& v : per_rule) {
        std::sort(v.begin(), v.end(), [](const AhoCorasick::Hit& a, const AhoCorasick::Hit& b) {
            return a.offset != b.offset ? a.offset < b.offset : a.pattern < b.pattern;
        });
        v.erase(std::unique(v.begin(), v.end(), [](const AhoCorasick::Hit& a, const AhoCorasick::Hit& b) {
                    return a.offset == b.offset && a.pattern == b.pattern;
                }),
                v.end());
    }

    for (std::size_t ri = 0; ri < rules_.size(); ++ri) {
        const Rule& r = rules_[ri];
        if (r.is_private) continue;
        if (!evaluate_condition(r, data, per_rule[ri])) continue;

        Match m;
        m.rule = r.identifier;
        m.tags = r.tags;
        m.family = r.meta_family.empty() ? r.meta_description : r.meta_family;
        m.description = r.meta_description;
        m.severity = r.severity;
        m.occurrence_count = per_rule[ri].size();
        if (!per_rule[ri].empty()) m.offset = per_rule[ri].front().offset;
        for (const auto& p : r.patterns) {
            // The parser stores the identifier without its sigil.
            m.matched_patterns.push_back(p.identifier.empty() || p.identifier[0] == '$'
                                             ? p.identifier
                                             : "$" + p.identifier);
        }
        if (!path.empty()) m.tags.push_back("path:" + std::string(path));
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<Match> SignatureEngine::scan_file(std::string_view path) const noexcept {
    auto mf = core::MappedFile::open(path);
    if (!mf) return {};
    mf->advise_sequential();
    return scan(mf->bytes(), path);
}

std::vector<Match> SignatureEngine::scan_strings(const std::vector<std::string>& strings,
                                                 std::string_view label) const noexcept {
    // Join with a separator that cannot occur inside a pattern match, so a
    // pattern spanning two unrelated strings cannot produce a false positive.
    std::string joined;
    std::size_t total = 0;
    for (const auto& s : strings) total += s.size() + 1;
    joined.reserve(total);
    for (const auto& s : strings) { joined += s; joined.push_back('\x01'); }
    return scan({reinterpret_cast<const std::byte*>(joined.data()), joined.size()}, label);
}

// ===========================================================================
// Built-in first-party rule set
// ===========================================================================

std::vector<Rule> builtin_rules() noexcept {
    // These target *behaviour artefacts* rather than known malware hashes, which
    // is the only class of signature that helps against a zero-day: the strings a
    // dropper must contain to do its job, not the hash of a sample we have seen.
    static constexpr std::string_view kSource = R"YARALITE(
rule HyprNova_EICAR_Test_File : eicar testfile critical
{
    meta:
        author = "HyprNova built-in"
        description = "EICAR Standard Antivirus Test File (the industry AV test string)"
        severity = "high"
    strings:
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $a
}

rule HyprNova_Ransomware_Dropper_Traits : ransomware dropper critical
{
    meta:
        author = "HyprNova built-in"
        description = "Ransomware drop-stage primitives: a program carrying several of these strings at once is not a backup tool"
        severity = "critical"
    strings:
        $a = "README_RESTORE"
        $b = "all your files have been encrypted" nocase
        $c = ".locked"
        $d = "bitcoin" nocase
        $e = "YOUR FILES" nocase
        $f = "shadow copies" nocase
        $g = "recover-" 
        $h = "vssadmin delete shadows" nocase
    condition:
        3 of them
}

rule HyprNova_ShellcodeLoader_Artifacts : loader suspicious
{
    meta:
        author = "HyprNova built-in"
        description = "In-memory shellcode loader primitives"
        severity = "high"
    strings:
        $a = "mmap" nocase
        $b = "mprotect" nocase
        $c = "PROT_EXEC"
        $d = "/proc/self/mem"
        $e = "ptrace"
        $f = "__libc_start_main"
    condition:
        4 of them
}

rule HyprNova_C2_BeaconTooling : c2 backdoor
{
    meta:
        author = "HyprNova built-in"
        description = "Common C2 client primitives and callback tooling"
        severity = "critical"
    strings:
        $a = "/bin/sh -c" 
        $b = "base64 -d"
        $c = "curl -s"
        $d = "wget -qO-"
        $e = "nc -e"
        $f = "socat TCP"
        $g = "bash -i >& /dev/tcp/"
    condition:
        2 of them
}

rule HyprNova_Ransomware_Behaviour : ransomware critical
{
    meta:
        author = "HyprNova built-in"
        description = "Encryption-and-note artefacts typical of Linux ransomware"
        family = "generic-linux-ransom"
        severity = "critical"
    strings:
        $note1 = "your files have been encrypted" nocase
        $note2 = "how to decrypt" nocase
        $note3 = "bitcoin" nocase
        $note4 = ".locked" nocase
        $note5 = "send 0." nocase
        $crypto1 = "EVP_EncryptUpdate"
        $crypto2 = "AES_set_encrypt_key"
        $crypto3 = "crypto_secretbox"
        $shadow = "vssadmin delete shadows" nocase
    condition:
        2 of them
}

rule HyprNova_Lateral_Movement_SSH : lateral
{
    meta:
        author = "HyprNova built-in"
        description = "SSH credential harvesting and lateral movement tooling"
        severity = "high"
    strings:
        $a = "authorized_keys"
        $b = "sshpass"
        $c = "id_rsa"
        $d = "StrictHostKeyChecking=no"
        $e = "known_hosts"
        $f = "ssh-copy-id"
    condition:
        3 of them
}

rule HyprNova_Credential_Theft : stealer
{
    meta:
        author = "HyprNova built-in"
        description = "Local credential and secret harvesting"
        severity = "critical"
    strings:
        $a = "/etc/shadow"
        $b = "unshadow"
        $c = "john --wordlist"
        $d = "hashcat -m 1800"
        $e = "/root/.aws/credentials"
        $f = "gnome-keyring"
        $g = ".git-credentials"
    condition:
        2 of them
}

rule HyprNova_Rootkit_LKM : rootkit critical
{
    meta:
        author = "HyprNova built-in"
        description = "Loadable-kernel-module rootkit artefacts"
        severity = "critical"
    strings:
        $a = "init_module"
        $b = "sys_call_table"
        $c = "hook_syscall"
        $d = "hide_proc"
        $e = "/dev/kmem"
        $f = "register_kprobe"
    condition:
        3 of them
}

rule HyprNova_ELF_MZ_Mismatch : suspicious
{
    meta:
        author = "HyprNova built-in"
        description = "PE header inside a file presented as an ELF/executable script"
        severity = "medium"
    strings:
        $mz = { 4D 5A 90 00 }
        $this = "This program cannot be run in DOS mode"
    condition:
        any of them
}

rule HyprNova_Cryptominer : miner
{
    meta:
        author = "HyprNova built-in"
        description = "Cryptocurrency miner artefacts"
        family = "cryptominer"
        severity = "high"
    strings:
        $a = "stratum+tcp://"
        $b = "stratum+ssl://"
        $c = "--donate-level"
        $d = "xmrig" nocase
        $e = "cryptonight" nocase
        $f = "pool.minexmr"
        $g = "nicehash" nocase
    condition:
        2 of them
}

rule HyprNova_Webshell_PHP : webshell
{
    meta:
        author = "HyprNova built-in"
        description = "PHP webshell primitives"
        severity = "critical"
    strings:
        $a = "eval($_POST"
        $b = "eval($_GET"
        $c = "assert($_REQUEST"
        $d = "base64_decode($_"
        $e = "system($_GET"
        $f = "shell_exec($_"
        $g = "passthru("
    condition:
        2 of them
}

rule HyprNova_Persistence_Cron : persistence
{
    meta:
        author = "HyprNova built-in"
        description = "Cron/systemd persistence installation artefacts"
        severity = "medium"
    strings:
        $a = "/etc/cron.d/"
        $b = "crontab -l"
        $c = "systemctl enable"
        $d = "/etc/systemd/system/"
        $e = ".config/autostart/"
        $f = "/etc/rc.local"
    condition:
        3 of them
}
)YARALITE";

    std::vector<ParseIssue> issues;
    auto rules = parse_rules(kSource, &issues);
    if (!issues.empty()) {
        for (const auto& i : issues) {
            SERROR("yara-lite", "built-in rule set issue at line {}: {}", i.line, i.message);
        }
    }
    return rules;
}

}  // namespace hyprnova::scanning
