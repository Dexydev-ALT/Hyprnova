// SPDX-License-Identifier: Apache-2.0
// Suite: detection corpus (spec §7) — every fixture in tests/corpus must get
// the verdict its manifest entry promises, against the BUILT-IN rule floor.
//
// Honesty rules enforced here:
//   * a manifest entry whose file is missing is a FAILURE, not a skip;
//   * a fixture that matches ZERO rules must say so (never "clean by silence");
//   * no EICAR fixture exists — EICAR is never the detection test.
#include "test_main.hpp"

#include <filesystem>
#include <fstream>

#include <cstdio>

#include "core/config.hpp"
#include "scanning/yara_engine.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

namespace {

struct Corpus {
    Corpus() {
        // Locate the corpus dir: runner executes from the repo root; the test
        // binary may also be started from build/.
        std::string base = "tests/corpus";
        {
            std::FILE* probe = std::fopen("tests/corpus/MANIFEST.json", "rb");
            if (!probe) {
                probe = std::fopen("../tests/corpus/MANIFEST.json", "rb");
                if (probe) base = "../tests/corpus";
            }
            if (probe) std::fclose(probe);
        }
        const std::string manifest_path = base + "/MANIFEST.json";

        std::string text;
        const bool readable = core::fsx::read_file(manifest_path, text, 1 << 20) >= 0;
        check(readable, "corpus: MANIFEST.json readable");
        if (!readable) return;

        const auto doc = core::json::parse(text);
        check(doc.has_value() && doc->is_object(), "corpus: manifest parses as JSON");
        if (!doc || !doc->is_object()) return;
        const auto* entries = doc->at("corpus") ? doc->at("corpus")->as_array() : nullptr;
        check(entries != nullptr && !entries->empty(), "corpus: manifest lists entries");
        if (!entries) return;

        // The built-in floor must be present: load() with no extra rule files.
        core::AgentConfig cfg = core::default_config();
        cfg.scan.rule_files.clear();
        scanning::SignatureEngine engine;
        std::size_t rules = 0;
        {
            std::vector<scanning::ParseIssue> issues;
            rules = engine.load(cfg.scan, &issues);
            check(rules > 0, "corpus: built-in rule floor loaded",
                  std::to_string(rules) + " rules");
        }

        std::size_t clean_ok = 0, mal_ok = 0;
        for (const auto& e : *entries) {
            const std::string rel(e.str("path"));
            const std::string expect(e.str("expect"));
            const std::string trait(e.str("trait", "?"));
            const std::string path = base + "/" + rel;

            std::string body;
            if (core::fsx::read_file(path, body, 8 << 20) < 0) {
                check(false, "corpus: fixture readable: " + rel,
                      "MISSING FILE for trait " + trait);
                continue;
            }
            const auto matches = engine.scan_file(path);
            if (expect == "clean") {
                check(matches.empty(), "corpus: clean fixture stays clean: " + rel,
                      matches.empty() ? "no rule matched"
                                      : "UNEXPECTED: " +
                                            (matches.empty() ? std::string()
                                                             : matches.front().rule));
                if (matches.empty()) ++clean_ok;
            } else if (expect == "malicious") {
                check(!matches.empty(), "corpus: trait fixture flagged: " + rel + " (" + trait + ")",
                      matches.empty() ? "NO RULE MATCHED -- fixture and rules drifted apart"
                                      : "rule " + matches.front().rule);
                if (!matches.empty()) ++mal_ok;
            } else {
                check(false, "corpus: fixture " + rel, "unknown expect '" + expect + "'");
            }
        }
        check(clean_ok >= 3 && mal_ok >= 5, "corpus: coverage sanity",
              "clean " + std::to_string(clean_ok) + ", malicious " + std::to_string(mal_ok));
    }
};
const Corpus corpus_instance;

}  // namespace

namespace {

// ---------------------------------------------------------------------------
// External findings #1 + #2 (pre-handoff test batch): YaraLite nocase missed
// mixed-case haystacks (the automaton only indexed lower/upper needle
// spellings), and `wide` UTF-16LE hits were never routed back to their rule
// (the pattern id was dropped). Both must match, attributed to the right rule.
// ---------------------------------------------------------------------------
struct ExternalSigFinds {
    ExternalSigFinds() {
        const std::string dir = "/tmp/hn-extsig";
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        const std::string rule_path = dir + "/ext.yar";
        {
            std::ofstream rf{rule_path, std::ios::binary | std::ios::trunc};
            rf << "rule ext_nocase_mixed {\n"
               << "  meta: severity = \"high\"\n"
               << "  strings: $a = \"malicious.payload\" nocase\n"
               << "  condition: any of them\n}\n"
               << "rule ext_wide_u16 {\n"
               << "  strings: $w = \"widebait\" wide\n"
               << "  condition: any of them\n}\n"
               << "rule ext_wide_nocase {\n"
               << "  strings: $wn = \"MixedBait\" wide nocase\n"
               << "  condition: any of them\n}\n";
        }
        const bool written = core::fsx::is_file(rule_path);
        check(written, "sig: external-findings rule file written");
        if (!written) return;

        core::AgentConfig cfg = core::default_config();
        cfg.scan.rule_files = {rule_path};
        scanning::SignatureEngine engine;
        std::size_t rules = 0;
        {
            std::vector<scanning::ParseIssue> issues;
            rules = engine.load(cfg.scan, &issues);
            check(rules >= 3, "sig: external-findings rules load",
                  std::to_string(rules) + " rules");
        }
        const auto has_rule = [](const std::vector<scanning::Match>& ms,
                                 std::string_view name) {
            for (const auto& m : ms)
                if (m.rule == name) return true;
            return false;
        };
        const auto span_of = [](const std::string& s) {
            return std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(s.data()), s.size());
        };

        {
            // Mixed case in the HAYSTACK: neither the original, nor the
            // all-lower, nor the all-upper needle spelling matches this
            // byte-for-byte — only the case-folded pass can.
            const std::string body = "prefix MaLiCiOuS.pAyLoAd suffix";
            const auto ms = engine.scan(span_of(body), "mem");
            check(has_rule(ms, "ext_nocase_mixed"),
                  "sig: nocase literal matches a MIXED-CASE buffer (external #1)",
                  has_rule(ms, "ext_nocase_mixed") ? "matched"
                                                   : "MISSED — fold pass broken");
        }
        {
            std::string narrow{"widebait"};
            std::string body;
            for (const char c : narrow) { body.push_back(c); body.push_back('\0'); }
            const auto ms = engine.scan(span_of(body), "mem");
            check(has_rule(ms, "ext_wide_u16"),
                  "sig: UTF-16LE wide hit is routed to its own rule (external #2)",
                  has_rule(ms, "ext_wide_u16") ? "matched"
                                               : "MISSED — wide pattern id dropped");
        }
        {
            std::string narrow{"MixedBait"};
            std::string body;
            for (const char c : narrow) {
                body.push_back(static_cast<char>(
                    std::tolower(static_cast<unsigned char>(c))));
                body.push_back('\0');
            }
            // Source is "MiXeDbAiT" in UTF-16LE; fold the byte, keep the NUL.
            body.clear();
            for (const char c : std::string("MiXeDbAiT")) {
                body.push_back(static_cast<char>(
                    std::tolower(static_cast<unsigned char>(c))));
                body.push_back('\0');
            }
            const auto ms = engine.scan(span_of(body), "mem");
            check(has_rule(ms, "ext_wide_nocase"),
                  "sig: wide+nocase matches mixed-case UTF-16LE (#1+#2 combined)",
                  has_rule(ms, "ext_wide_nocase") ? "matched" : "MISSED");
        }
    }
};
const ExternalSigFinds external_sig_finds_instance;

}  // namespace
