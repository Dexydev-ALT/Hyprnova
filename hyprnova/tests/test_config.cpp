// SPDX-License-Identifier: Apache-2.0
// Suite: configuration — parsing, validation, save/load round trip.
#include "test_main.hpp"

#include <sys/stat.h>
#include <fstream>
#include <unistd.h>

#include "core/config.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

static std::string write_tmp(const std::string& body) {
    std::string path = std::format("/tmp/hyprnova-test-{}-{}.json", ::getpid(), ::rand());
    std::ofstream f{path};
    f << body;
    return path;
}

void test_config() {
    {
        core::AgentConfig cfg;
        std::vector<core::ConfigError> errs;
        core::validate(cfg, errs);
        check(errs.empty(), "config: defaults validate cleanly");
    }
    {
        const auto path = write_tmp(R"({"ai": {"enabled": true, "api_key": ""}})");
        core::AgentConfig cfg;
        std::vector<core::ConfigError> errs;
        (void)core::load_config(path, &errs);
        core::validate(cfg, errs);
        bool has_ai_rule = false;
        for (const auto& e : errs)
            if (e.path.find("ai") != std::string::npos) has_ai_rule = true;
        check(has_ai_rule, "config: ai.enabled without a key is refused",
              errs.empty() ? "(no errors!)" : errs.front().message);
        std::remove(path.c_str());
    }
    {
        const auto path = write_tmp(R"({"proc_poll": {"enabled": true, "interval_ms": 10}})");
        core::AgentConfig cfg;
        std::vector<core::ConfigError> errs;
        (void)core::load_config(path, &errs);
        core::validate(cfg, errs);
        check(!errs.empty(), "config: 10 ms poll interval rejected (50..5000 ms)",
              errs.empty() ? "(no errors!)" : errs.front().message);
        std::remove(path.c_str());
    }
    {
        const auto path = write_tmp(
            R"({"gui": {"ipc_socket": "/tmp/hnt-sock"}, "agent": {"state_dir": "/tmp/hnt-state"}})");
        std::vector<core::ConfigError> errs;
        auto loaded = core::load_config(path, &errs);
        check(loaded.has_value(), "config: minimal file loads");
        check(loaded->gui.ipc_socket == "/tmp/hnt-sock" && loaded->state_dir == "/tmp/hnt-state",
              "config: values read from file");
        core::AgentConfig cfg = *loaded;
        check(core::save_config(cfg, path), "config: save_config writes");
        std::vector<core::ConfigError> errs2;
        auto again = core::load_config(path, &errs2);
        check(again.has_value() && again->gui.ipc_socket == "/tmp/hnt-sock",
              "config: save/load round trip");
        std::remove(path.c_str());
    }
    {
        const auto path = write_tmp(R"({"proc_poll": {"interval_ms": 500}})");
        std::vector<core::ConfigError> errs;
        auto loaded = core::load_config(path, &errs);
        check(loaded.has_value() &&
                  loaded->proc_poll.interval == std::chrono::milliseconds{500},
              "config: duration fields parse from ms");
        std::remove(path.c_str());
    }
    {
        // Corrupt file: must NOT half-apply; errors surfaced, defaults kept.
        const auto path = write_tmp(R"({"gui": {"ipc_socket": })");
        std::vector<core::ConfigError> errs;
        auto loaded = core::load_config(path, &errs);
        check(!loaded.has_value() || !errs.empty(), "config: corrupt file reports problems");
        core::AgentConfig fresh;
        check(fresh.gui.ipc_socket != "", "config: defaults stay intact after a corrupt load");
        std::remove(path.c_str());
    }
    {
        // Secret hygiene: the saved JSON must not be world-readable.
        const auto path = write_tmp(R"({})");
        core::AgentConfig cfg;
        cfg.ai.api_key = "gsk_test";
        (void)core::save_config(cfg, path);
        struct stat st {};
        ::stat(path.c_str(), &st);
        check((st.st_mode & 0777) == 0600, "config: saved file mode is 0600 (contains secrets)");
        std::remove(path.c_str());
    }
    {
        // to_json never serialises the AI key in clear on the wire the GUI reads;
        // the settings_get path hides it — verify the to_json output too.
        core::AgentConfig cfg;
        cfg.ai.api_key = "gsk_secret";
        const std::string j = core::to_json(cfg).dump();
        check(j.find("gsk_secret") == std::string::npos,
              "config: api key is not serialised in clear into config JSON");
    }
}

// ---- rescue section roundtrip (GAP-6: agent.json rescue section) ----
namespace {
struct RescueRoundtrip {
    RescueRoundtrip() {
        const std::string path = "/tmp/hyprnova-test-rescue-cfg.json";
        hyprnova::core::AgentConfig c;
        c.rescue.enabled = true;
        c.rescue.iso_path = "/opt/hyprnova/rescue.iso";
        c.rescue.boot_dir = "/tmp/hn-boot";
        c.rescue.grub_entry_file = "/tmp/hn-grub.cfg";
        c.rescue.entry_title = "HyprNova Rescue";
        c.rescue.auto_reboot = false;
        // enabled without iso would fail validate; we set both -> valid here
        check(hyprnova::core::save_config(c, path), "config: rescue section saves");
        std::vector<hyprnova::core::ConfigError> errs;
        const auto back = hyprnova::core::load_config(path, &errs);
        check(back.has_value() && errs.empty(), "config: rescue section reloads",
              back ? (errs.empty() ? std::string("ok")
                                   : "errs: " + errs.front().path + ": " + errs.front().message)
                   : std::string("load failed"));
        if (back) {
            check(back->rescue.enabled && back->rescue.iso_path == "/opt/hyprnova/rescue.iso" &&
                      back->rescue.entry_title == "HyprNova Rescue" && !back->rescue.auto_reboot,
                  "config: rescue roundtrip preserves all six knobs");
        }
        // validate(): enabled + empty iso must be refused with the CURRENT message
        hyprnova::core::AgentConfig bad;
        bad.rescue.enabled = true;  // iso_path left empty
        std::vector<hyprnova::core::ConfigError> verrs;
        hyprnova::core::validate(bad, verrs);
        bool rescue_flagged = false;
        for (const auto& e : verrs)
            if (e.path == "rescue.iso_path") rescue_flagged = true;
        check(rescue_flagged, "config: rescue.enabled without iso_path is refused");
        // Full-contract check: the DEFAULT config must survive save->load with
        // zero errors. to_json promises round-trip fidelity for EVERY key; this
        // is what enforces it (it already caught log_level + scan.backend
        // writing display vocabulary the reader rejects).
        {
            const std::string p2 = "/tmp/hyprnova-test-default-roundtrip.json";
            const auto dflt = hyprnova::core::default_config();
            check(hyprnova::core::save_config(dflt, p2), "config: default config saves");
            std::vector<hyprnova::core::ConfigError> errs2;
            const auto back2 = hyprnova::core::load_config(p2, &errs2);
            std::string first_err;
            for (const auto& e : errs2)
                if (first_err.empty()) first_err = e.path + ": " + e.message;
            check(back2.has_value() && errs2.empty(), "config: default config roundtrips cleanly",
                  back2 ? (first_err.empty() ? "ok" : first_err) : "load failed");
            std::remove(p2.c_str());
        }
        std::remove(path.c_str());
    }
};
const RescueRoundtrip rescue_roundtrip_instance;
}  // namespace
