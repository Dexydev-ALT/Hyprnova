// SPDX-License-Identifier: Apache-2.0
// Suite: core JSON — parsing, malformed input, typed access, bounds.
#include "test_main.hpp"

#include "core/json.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

void test_core_json() {
    {
        const auto v = core::json::parse(R"({"a":1,"b":"two","c":[1,2,3],"d":{"e":true}})");
        check(v.has_value(), "json: valid object parses");
        check(v->at("b") && v->at("b")->is_string(), "json: string field typed");
        check(v->at("d") && v->at("d")->at("e") && v->at("d")->at("e")->is_bool(),
              "json: nested object access");
        check(v->at("c") && v->at("c")->is_array() && v->at("c")->as_array()->size() == 3,
              "json: array length");
    }
    {
        const auto bad1 = core::json::parse("{\"a\":}");
        const auto bad2 = core::json::parse("{nope}");
        const auto bad3 = core::json::parse("[1,2");
        const auto empty = core::json::parse("");
        check(!bad1.has_value(), "json: value missing rejects");
        check(!bad2.has_value(), "json: bare word rejects");
        check(!bad3.has_value(), "json: truncated array rejects");
        check(!empty.has_value(), "json: empty input rejects");
    }
    {
        const auto v = core::json::parse("\"just a string\"");
        const auto n = core::json::parse("42");
        const auto f = core::json::parse("-3.5");
        const auto t = core::json::parse("true");
        check(v.has_value() && v->is_string(), "json: bare string document");
        check(n.has_value() && n->is_int() && n->as_int() == 42, "json: bare int document");
        check(f.has_value() && f->is_number(), "json: bare float document");
        check(t.has_value() && t->is_bool(), "json: bare bool document");
    }
    {
        const auto v = core::json::parse(R"({"p":"/etc/pass\u0077ord"})");
        check(v.has_value() && v->at("p") &&
                  v->at("p")->as_string() == "/etc/password",
              "json: unicode escapes decode",
              v && v->at("p") ? std::string(v->at("p")->as_string()) : std::string("(none)"));
    }
    {
        // Access with defaults never throws on wrong types.
        const auto v = core::json::parse(R"({"x":"str","y":7})");
        check(v.has_value() && v->at("x")->as_int(9) == 9,
              "json: wrong-type integer read returns default");
        check(v->at("zzz") == nullptr, "json: absent key returns null pointer");
    }
    {
        const auto v = core::json::parse(R"({"big":9007199254740993})");
        check(v.has_value() && v->at("big")->is_int(), "json: 64-bit integers stay integers");
    }
    {
        const std::string dump = core::json::Value(core::json::Object{
            {"k", core::json::Value{std::string{"v"}}},
            {"n", core::json::Value{static_cast<std::int64_t>(5)}}}).dump();
        const auto back = core::json::parse(dump);
        check(back.has_value() && back->at("k") && back->at("n") &&
                  back->at("n")->as_int() == 5,
              "json: dump->parse round trip");
    }
}
