// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/json.cpp

#include "core/json.hpp"

#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace hyprnova::core::json {

// ---------------------------------------------------------------------------
// Value accessors
// ---------------------------------------------------------------------------

bool Value::as_bool(bool def) const noexcept {
    if (auto* b = std::get_if<bool>(&data_)) return *b;
    if (auto* i = std::get_if<std::int64_t>(&data_)) return *i != 0;
    if (auto* s = std::get_if<std::string>(&data_)) return !s->empty();
    return def;
}

std::int64_t Value::as_int(std::int64_t def) const noexcept {
    if (auto* i = std::get_if<std::int64_t>(&data_)) return *i;
    if (auto* d = std::get_if<double>(&data_)) return static_cast<std::int64_t>(*d);
    if (auto* b = std::get_if<bool>(&data_)) return *b ? 1 : 0;
    if (auto* s = std::get_if<std::string>(&data_)) {
        std::int64_t v = 0;
        const auto* first = s->data();
        const auto* last = s->data() + s->size();
        if (std::from_chars(first, last, v).ec == std::errc{}) return v;
    }
    return def;
}

double Value::as_double(double def) const noexcept {
    if (auto* d = std::get_if<double>(&data_)) return *d;
    if (auto* i = std::get_if<std::int64_t>(&data_)) return static_cast<double>(*i);
    return def;
}

std::string_view Value::as_string(std::string_view def) const noexcept {
    if (auto* s = std::get_if<std::string>(&data_)) return *s;
    return def;
}

std::string Value::as_string_copy() const { return std::string(as_string()); }

const Array* Value::as_array() const noexcept { return std::get_if<Array>(&data_); }
const Object* Value::as_object() const noexcept { return std::get_if<Object>(&data_); }
Array* Value::as_array_mut() { return std::get_if<Array>(&data_); }
Object* Value::as_object_mut() { return std::get_if<Object>(&data_); }

std::size_t Value::size() const noexcept {
    if (auto* a = as_array()) return a->size();
    if (auto* o = as_object()) return o->size();
    if (auto* s = std::get_if<std::string>(&data_)) return s->size();
    return 0;
}

const Value* Value::at(std::string_view path) const noexcept {
    const Value* cur = this;
    while (!path.empty() && cur != nullptr) {
        const std::size_t dot = path.find('.');
        const std::string_view key = dot == std::string_view::npos ? path : path.substr(0, dot);
        path = dot == std::string_view::npos ? std::string_view{} : path.substr(dot + 1);

        if (const Object* obj = cur->as_object()) {
            const auto it = obj->find(std::string(key));
            if (it == obj->end()) return nullptr;
            cur = &it->second;
            continue;
        }
        // A purely numeric segment indexes into an array, so dotted paths can
        // reach "dns.answers.0.data" and "http.headers.1.value" -- EVE and Falco
        // both nest arrays inside objects, and a caller that cannot address them
        // ends up hand-walking the DOM for every field.
        if (const Array* arr = cur->as_array()) {
            if (key.empty()) return nullptr;
            std::size_t idx = 0;
            for (const char c : key) {
                if (c < '0' || c > '9') return nullptr;
                idx = idx * 10 + static_cast<std::size_t>(c - '0');
                if (idx > 1'000'000) return nullptr;   // "00000000001" is not an index
            }
            if (idx >= arr->size()) return nullptr;
            cur = &(*arr)[idx];
            continue;
        }
        return nullptr;
    }
    return cur;
}

std::string Value::str(std::string_view path, std::string_view def) const noexcept {
    const Value* v = at(path);
    return v ? std::string(v->as_string(def)) : std::string(def);
}

std::int64_t Value::integer(std::string_view path, std::int64_t def) const noexcept {
    const Value* v = at(path);
    return v ? v->as_int(def) : def;
}

// ---------------------------------------------------------------------------
// Serialiser
// ---------------------------------------------------------------------------

namespace {

void dump_string(std::string_view s, std::string& out) {
    out.push_back('"');
    for (const char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char tmp[8];
                    std::snprintf(tmp, sizeof(tmp), "\\u%04x", static_cast<unsigned>(c));
                    out += tmp;
                } else {
                    out.push_back(c);
                }
        }
    }
    out.push_back('"');
}

}  // namespace

void Value::dump_to(const Value& v, std::string& out) {
    std::visit(
        [&](const auto& x) {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>) {
                out += "null";
            } else if constexpr (std::is_same_v<T, bool>) {
                out += x ? "true" : "false";
            } else if constexpr (std::is_same_v<T, std::int64_t>) {
                out += std::to_string(x);
            } else if constexpr (std::is_same_v<T, double>) {
                if (std::isfinite(x)) {
                    char tmp[32];
                    std::snprintf(tmp, sizeof(tmp), "%.17g", x);
                    out += tmp;
                } else {
                    out += "null";
                }
            } else if constexpr (std::is_same_v<T, std::string>) {
                dump_string(x, out);
            } else if constexpr (std::is_same_v<T, Array>) {
                out.push_back('[');
                bool first = true;
                for (const auto& e : x) {
                    if (!first) out.push_back(',');
                    first = false;
                    dump_to(e, out);
                }
                out.push_back(']');
            } else if constexpr (std::is_same_v<T, Object>) {
                out.push_back('{');
                bool first = true;
                for (const auto& [k, val] : x) {
                    if (!first) out.push_back(',');
                    first = false;
                    dump_string(k, out);
                    out.push_back(':');
                    dump_to(val, out);
                }
                out.push_back('}');
            }
        },
        v.data_);
}

std::string Value::dump() const {
    std::string out;
    out.reserve(128);
    dump_to(*this, out);
    return out;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

namespace {

class Parser {
public:
    Parser(std::string_view text, const ParseOptions& opts, ParseError* err)
        : s_{text}, opts_{opts}, err_{err} {}

    std::optional<Value> run() noexcept {
        skip_ws();
        auto v = parse_value(0);
        if (!v) return std::nullopt;
        skip_ws();
        if (!opts_.allow_trailing_garbage && pos_ != s_.size()) {
            return fail("trailing characters after JSON document");
        }
        return v;
    }

private:
    std::optional<Value> fail(std::string_view msg) noexcept {
        if (err_) {
            err_->offset = pos_;
            err_->message = std::string(msg);
        }
        return std::nullopt;
    }

    [[nodiscard]] bool budget() noexcept {
        if (++nodes_ > opts_.max_nodes) {
            fail("node budget exhausted");
            return false;
        }
        return true;
    }

    void skip_ws() noexcept {
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_;
            else break;
        }
    }

    [[nodiscard]] bool eat(char c) noexcept {
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    [[nodiscard]] bool literal(std::string_view lit) noexcept {
        if (s_.substr(pos_, lit.size()) == lit) {
            pos_ += lit.size();
            return true;
        }
        return false;
    }

    std::optional<Value> parse_value(int depth) noexcept {
        if (depth > static_cast<int>(opts_.max_depth)) return fail("max nesting depth exceeded");
        if (!budget()) return std::nullopt;
        skip_ws();
        if (pos_ >= s_.size()) return fail("unexpected end of input");

        switch (s_[pos_]) {
            case '{': return parse_object(depth);
            case '[': return parse_array(depth);
            case '"': {
                std::string out;
                if (!parse_string(out)) return std::nullopt;
                return Value{std::move(out)};
            }
            case 't':
                if (literal("true")) return Value{true};
                return fail("invalid literal");
            case 'f':
                if (literal("false")) return Value{false};
                return fail("invalid literal");
            case 'n':
                if (literal("null")) return Value{nullptr};
                return fail("invalid literal");
            default: return parse_number();
        }
    }

    std::optional<Value> parse_object(int depth) noexcept {
        Object obj;
        ++pos_;  // '{'
        skip_ws();
        if (eat('}')) return Value{std::move(obj)};
        for (;;) {
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != '"') return fail("expected string key");
            std::string key;
            if (!parse_string(key)) return std::nullopt;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') return fail("expected ':'");
            ++pos_;
            auto v = parse_value(depth + 1);
            if (!v) return std::nullopt;
            obj.emplace(std::move(key), std::move(*v));
            skip_ws();
            if (eat(',')) continue;
            if (eat('}')) break;
            return fail("expected ',' or '}'");
        }
        return Value{std::move(obj)};
    }

    std::optional<Value> parse_array(int depth) noexcept {
        Array arr;
        ++pos_;  // '['
        skip_ws();
        if (eat(']')) return Value{std::move(arr)};
        for (;;) {
            auto v = parse_value(depth + 1);
            if (!v) return std::nullopt;
            arr.push_back(std::move(*v));
            skip_ws();
            if (eat(',')) continue;
            if (eat(']')) break;
            return fail("expected ',' or ']'");
        }
        return Value{std::move(arr)};
    }

    bool parse_string(std::string& out) noexcept {
        ++pos_;  // opening quote
        out.clear();
        while (pos_ < s_.size()) {
            const char c = s_[pos_++];
            if (c == '"') return true;
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (pos_ >= s_.size()) break;
            const char e = s_[pos_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    if (pos_ + 4 > s_.size()) return false;
                    unsigned cp = 0;
                    if (!hex4(cp)) return false;
                    // Decode surrogate pairs (Falco proc args can contain them).
                    if (cp >= 0xD800 && cp <= 0xDBFF && pos_ + 6 <= s_.size() && s_[pos_] == '\\' &&
                        s_[pos_ + 1] == 'u') {
                        pos_ += 2;
                        unsigned lo = 0;
                        if (!hex4(lo)) return false;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    append_utf8(out, cp);
                    break;
                }
                default: return false;
            }
        }
        fail("unterminated string");
        return false;
    }

    bool hex4(unsigned& out) noexcept {
        out = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = s_[pos_++];
            out <<= 4;
            if (c >= '0' && c <= '9') out |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') out |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') out |= static_cast<unsigned>(c - 'A' + 10);
            else return false;
        }
        return true;
    }

    static void append_utf8(std::string& out, unsigned cp) noexcept {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    std::optional<Value> parse_number() noexcept {
        const std::size_t start = pos_;
        if (pos_ < s_.size() && (s_[pos_] == '-' || s_[pos_] == '+')) ++pos_;
        bool is_float = false;
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c >= '0' && c <= '9') { ++pos_; continue; }
            if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { is_float = true; ++pos_; continue; }
            break;
        }
        if (pos_ == start) return fail("invalid number");
        const std::string_view tok = s_.substr(start, pos_ - start);
        if (!is_float) {
            std::int64_t v = 0;
            const auto [p, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
            if (ec == std::errc{} && p == tok.data() + tok.size()) return Value{v};
        }
        // Fall back to strtod for fractional / exponent forms.
        std::string z{tok};
        char* end = nullptr;
        errno = 0;
        const double d = std::strtod(z.c_str(), &end);
        if (end != z.c_str() + z.size() || errno == ERANGE) return fail("malformed number");
        return Value{d};
    }

    std::string_view s_;
    ParseOptions opts_;
    ParseError* err_;
    std::size_t pos_{0};
    std::size_t nodes_{0};
};

}  // namespace

std::optional<Value> parse(std::string_view text, const ParseOptions& opts, ParseError* err) noexcept {
    Parser p{text, opts, err};
    return p.run();
}

// ---------------------------------------------------------------------------
// NdjsonReader
// ---------------------------------------------------------------------------

void NdjsonReader::feed(std::string_view chunk) {
    buf_.append(chunk);

    std::size_t consumed = 0;
    for (;;) {
        const std::size_t nl = buf_.find('\n', consumed);
        if (nl == std::string::npos) break;
        std::string_view line{buf_.data() + consumed, nl - consumed};
        consumed = nl + 1;

        // Strip trailing \r from CRLF producers.
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.remove_suffix(1);
        if (line.empty()) continue;

        if (line.size() > max_line_) {
            truncated_ = true;
            line = line.substr(0, max_line_);
        }
        ParseError perr{};
        ParseOptions opts{};
        opts.allow_trailing_garbage = false;
        if (auto v = parse(line, opts, &perr)) {
            ready_.push_back(std::move(*v));
        }
        // Malformed lines are skipped deliberately: a single bad frame from a
        // compromised Falco socket must not stall the whole sensor pipeline.
    }

    if (consumed > 0) buf_.erase(0, consumed);

    // Back-pressure on the buffer itself: if a peer floods us with newline-free
    // data, drop it rather than growing without bound.
    if (buf_.size() > max_line_) {
        truncated_ = true;
        buf_.clear();
    }
}

std::optional<Value> NdjsonReader::next() noexcept {
    if (ready_.empty()) return std::nullopt;
    Value v = std::move(ready_.front());
    ready_.erase(ready_.begin());
    return v;
}

}  // namespace hyprnova::core::json
