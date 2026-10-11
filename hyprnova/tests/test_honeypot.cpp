// SPDX-License-Identifier: Apache-2.0
// Suite: honeypot decoy configs (gap #11) — classifier floor, profile library
// invariants (plausible + invalid + marked), real plant/read/tamper/delete
// detection against temp files.
#include "test_main.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <thread>

#include "anti_ransomware/canary.hpp"
#include "anti_ransomware/honeypot.hpp"
#include <filesystem>
#include <memory>

#include "core/config.hpp"
#include "core/event.hpp"
#include "core/sensor.hpp"
#include "core/thread_pool.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

namespace {

struct HoneypotSuite {
    HoneypotSuite() {
        using hyprnova::anti_ransomware::honey_classify;
        using hyprnova::anti_ransomware::HoneyVerdict;

        // ---- classifier floor (legacy atime path kept; reads now event-driven) ----
        check(honey_classify(true, false, true, false) == HoneyVerdict::Gone,
              "honeypot: gone beats every other verdict");
        check(honey_classify(true, true, false, false) == HoneyVerdict::Modified,
              "honeypot: hash mismatch is Modified");
        check(honey_classify(true, true, true, true) == HoneyVerdict::Read,
              "honeypot: atime advance with intact hash is Read");
        check(honey_classify(true, true, true, false) == HoneyVerdict::Untouched,
              "honeypot: intact + same atime is Untouched");
        check(honey_classify(false, false, true, false) == HoneyVerdict::Untouched,
              "honeypot: never-planted file stays Untouched");

        // ---- profile library invariants ----
        {
            const auto names = hyprnova::anti_ransomware::honey_profile_names();
            check(names.size() >= 8, "honeypot: >=8 decoy profiles");
            for (const auto& n : names) {
                const auto body = hyprnova::anti_ransomware::honey_profile_body(n);
                check(body.find("hyprnova decoy") != std::string::npos,
                      "honeypot: profile '" + n + "' carries the decoy marker");
                check(!body.empty() && body.size() < 4096,
                      "honeypot: profile '" + n + "' is small and non-empty");
            }
            // Known-bait realism spot checks (structure present, crypto dead)
            const auto aws = hyprnova::anti_ransomware::honey_profile_body("aws/credentials");
            check(aws.find("aws_access_key_id") != std::string::npos,
                  "honeypot: aws decoy has the access-key shape");
            const auto key = hyprnova::anti_ransomware::honey_profile_body("ssh/id_rsa");
            check(key.find("BEGIN OPENSSH PRIVATE KEY") != std::string::npos,
                  "honeypot: ssh decoy has PEM shape");
        }

        // ---- end-to-end against a real temp dir ----
        {
            core::AgentConfig cfg = core::default_config();
            cfg.state_dir = "/tmp/hyprnova-test-honeypots";
            std::error_code ec;
            std::filesystem::remove_all(cfg.state_dir, ec);
            std::filesystem::create_directories(cfg.state_dir, ec);

            core::EventBus bus(64);
            // F11 lesson: the bus is two-phase -- start() spawns the dispatcher
            // thread. Without it, publishes sit in the ring forever (this test
            // silently received nothing until that was understood).
            bus.start();
            core::ThreadPool pool(core::ThreadPoolConfig{});
            hyprnova::anti_ransomware::HoneypotSensor sensor(bus, cfg, pool);

            // Plant via the sensor's start path
            const bool started = sensor.start();
            check(started, "honeypot: sensor starts and plants");
            check(sensor.planted_count() >= 8, "honeypot: all profiles planted");
            const std::string aws = cfg.state_dir + "/honeypots/aws/credentials";
            struct stat st {};
            check(::stat(aws.c_str(), &st) == 0, "honeypot: aws decoy exists");
            check((st.st_mode & 0777) == 0600, "honeypot: decoys are 0600");
            // idempotent re-plant keeps files stable
            (void)st;

            // Reads are event-driven now: a REAL read of the file must fire
            // IN_ACCESS -> HONEYPOT READ, regardless of atime/relatime (F12).
            // The bus is async (dispatcher thread): subscribe first, then act,
            // then POLL for delivery with an explicit deadline.
            std::atomic<int> hits{0};
            std::string last_msg;
            std::mutex msg_mu;
            const auto sub [[maybe_unused]] = bus.subscribe(
                "honeypot-test", [&](const core::TelemetryEvent& ev) {
                    if (ev.message.find("HONEYPOT") == std::string::npos) return;
                    ++hits;
                    std::lock_guard lk{msg_mu};
                    last_msg = ev.message;
                });

            auto wait_hits = [&](int want, int seconds) {
                for (int i = 0; i < seconds * 20; ++i) {
                    if (hits.load() >= want) return true;
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                return hits.load() >= want;
            };

            // Read: actually READ the file (any real reader does exactly this).
            // O_NOATIME is deliberately NOT used here -- this simulates an attacker.
            {
                std::ifstream in(aws, std::ios::binary);
                char buf[64];
                while (in.read(buf, sizeof(buf)), in.gcount() > 0) {}
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(300));  // sensor loop polls
            sensor.check_all();
            check(wait_hits(1, 4), "honeypot: read detection fires",
                  last_msg);

            // Tamper: rewrite the content (real write -> IN_MODIFY + hash net)
            {
                std::ofstream o(aws, std::ios::trunc);
                o << "[default]\naws_access_key_id = ATTACKER\n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            sensor.check_all();
            check(wait_hits(2, 4), "honeypot: modification fires after content change");
            {
                std::lock_guard lk{msg_mu};
                check(last_msg.find("HONEYPOT MODIFIED") != std::string::npos,
                      "honeypot: modified verdict surfaces", last_msg);
            }

            // Delete
            std::filesystem::remove(aws, ec);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            sensor.check_all();
            check(wait_hits(3, 6), "honeypot: deletion detected");
            {
                std::lock_guard lk{msg_mu};
                check(last_msg.find("HONEYPOT DELETED") != std::string::npos,
                      "honeypot: deleted verdict surfaces", last_msg);
            }

            sensor.stop();
            std::filesystem::remove_all(cfg.state_dir, ec);
        }
    }
};
const HoneypotSuite honeypot_suite_instance;

}  // namespace

namespace {

struct SameIdDisambiguationSuite {
    SameIdDisambiguationSuite() {
        // Regression (pre-handoff BUG #1): CanarySensor and HoneypotSensor
        // BOTH register under SensorId::Canary. The GUI snapshot looked the
        // honeypot up by id, got the first-registered canary sensor back from
        // dynamic_cast, and the honeypots section of `canaries` stayed
        // silently empty. Lookup by NAME must disambiguate the shared id.
        core::AgentConfig cfg;
        cfg.state_dir = "/tmp/hn-hp-reg";  // never plant into the repo tree
        core::EventBus bus;
        core::ThreadPool pool{core::ThreadPoolConfig{}};
        core::SensorManager sm{bus, cfg, pool};
        auto canary = std::make_shared<anti_ransomware::CanarySensor>(bus, cfg, pool);
        auto honey = std::make_shared<anti_ransomware::HoneypotSensor>(bus, cfg, pool);
        sm.add_shared(canary);
        sm.add_shared(honey);

        check(sm.find(core::SensorId::Canary) == canary.get(),
              "sameid: find by id returns the FIRST same-id sensor (canary)");
        check(sm.find("canary") == canary.get(),
              "sameid: find by name finds the canary");
        check(sm.find("honeypot") == honey.get(),
              "sameid: find by NAME disambiguates the shared SensorId (BUG #1 regression)");
        check(sm.find("nonexistent") == nullptr,
              "sameid: find by unknown name is nullptr (no throw)");
    }
};
const SameIdDisambiguationSuite same_id_suite_instance;

}  // namespace
