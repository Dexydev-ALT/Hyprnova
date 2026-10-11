// SPDX-License-Identifier: Apache-2.0
// HyprNova :: core/json.hpp
// Dependency-free JSON value + parser + serialiser.
//
// Why hand-rolled: the EDR sensor layer consumes three JSON dialects
// (Falco rule output, Suricata EVE, osquery --json) and the config file. Pulling
// nlohmann/json in as a vcpkg dependency for a setuid-root daemon widens the
// supply-chain attack surface for no functional gain. ~400 lines, no exceptions
// on malformed input, allocation-counted so a hostile stream cannot OOM us.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace hyprnova::core::json {

class Value;
using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

/// Recursive variant. Null / bool / double / int64 / string / array / object.
class Value {
public:
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;

    Value() noexcept = default;
    Value(std::nullptr_t) noexcept {}
    Value(bool b) noexcept : data_{b} {}
    Value(std::int64_t i) noexcept : data_{i} {}
    Value(int i) noexcept : data_{static_cast<std::int64_t>(i)} {}
    Value(double d) noexcept : data_{d} {}
    Value(std::string s) : data_{std::move(s)} {}
    Value(std::string_view s) : data_{std::string(s)} {}
    Value(const char* s) : data_{std::string(s)} {}
    Value(Array a) : data_{std::move(a)} {}
    Value(Object o) : data_{std::move(o)} {}

    [[nodiscard]] bool is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(data_); }
    [[nodiscard]] bool is_bool() const noexcept { return std::holds_alternative<bool>(data_); }
    [[nodiscard]] bool is_int() const noexcept { return std::holds_alternative<std::int64_t>(data_); }
    [[nodiscard]] bool is_number() const noexcept { return is_int() || std::holds_alternative<double>(data_); }
    [[nodiscard]] bool is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
    [[nodiscard]] bool is_array() const noexcept { return std::holds_alternative<Array>(data_); }
    [[nodiscard]] bool is_object() const noexcept { return std::holds_alternative<Object>(data_); }

    // Tolerant accessors: a missing/typed-wrong field yields the default rather
    // than throwing. Sensor streams are untrusted and frequently partial.
    [[nodiscard]] bool as_bool(bool def = false) const noexcept;
    [[nodiscard]] std::int64_t as_int(std::int64_t def = 0) const noexcept;
    [[nodiscard]] double as_double(double def = 0.0) const noexcept;
    [[nodiscard]] std::string_view as_string(std::string_view def = {}) const noexcept;
    [[nodiscard]] std::string as_string_copy() const;

    [[nodiscard]] const Array* as_array() const noexcept;
    [[nodiscard]] const Object* as_object() const noexcept;
    [[nodiscard]] Array* as_array_mut();
    [[nodiscard]] Object* as_object_mut();

    /// Object field lookup with dotted path support: at("output.fields.proc_name").
    [[nodiscard]] const Value* at(std::string_view path) const noexcept;

    /// Convenience used all over the sensor layer.
    [[nodiscard]] std::string str(std::string_view path, std::string_view def = {}) const noexcept;
    [[nodiscard]] std::int64_t integer(std::string_view path, std::int64_t def = 0) const noexcept;

    [[nodiscard]] std::size_t size() const noexcept;

    /// Serialise (compact). Never throws.
    [[nodiscard]] std::string dump() const;
    static void dump_to(const Value& v, std::string& out);

private:
    Storage data_{nullptr};
};

struct ParseOptions {
    std::size_t max_depth = 64;          // stack guard against hostile nesting
    std::size_t max_nodes = 2'000'000;   // allocation budget guard
    bool allow_trailing_garbage = false; // Falco stream lines are one-object-per-line
};

struct ParseError {
    std::size_t offset{0};
    std::string message;
};

/// Parse exactly one JSON document from `text`.
[[nodiscard]] std::optional<Value> parse(std::string_view text, const ParseOptions& opts = {},
                                         ParseError* err = nullptr) noexcept;

/// Streaming newline-delimited JSON (ndjson) reader: Falco's `-o json` and
/// Suricata EVE both emit one object per line, sometimes split across recv()
/// boundaries. Feed it bytes, get complete values out.
class NdjsonReader {
public:
    explicit NdjsonReader(std::size_t max_line_bytes = 1 << 20) noexcept
        : max_line_{max_line_bytes} {}

    /// Append raw socket bytes; returns the number of complete JSON values now
    /// available via next().
    void feed(std::string_view chunk);

    [[nodiscard]] std::optional<Value> next() noexcept;

    /// True if the peer sent a line longer than the cap -> we truncate and flag
    /// it, because an over-long line is itself an anomaly worth reporting.
    [[nodiscard]] bool truncated_line_seen() const noexcept { return truncated_; }
    [[nodiscard]] std::size_t pending_lines() const noexcept { return ready_.size(); }
    [[nodiscard]] std::size_t bytes_buffered() const noexcept { return buf_.size(); }

private:
    std::string buf_;
    std::vector<Value> ready_;
    std::size_t max_line_;
    bool truncated_{false};
};

}  // namespace hyprnova::core::json
