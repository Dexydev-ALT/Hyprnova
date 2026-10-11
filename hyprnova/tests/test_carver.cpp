// SPDX-License-Identifier: Apache-2.0
// Suite: file carving (spec §5E) — pure artifact finder, opt-in gate,
// extraction + signature scan of carved artifacts. Synthetic bytes only.
#include "test_main.hpp"

#include <fstream>

#include "core/config.hpp"
#include "scanning/carver.hpp"
#include "scanning/yara_engine.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

namespace {

struct CarverSuite {
    CarverSuite() {

        // ---- synthetic container: text + ELF + JPEG + PNG + ZIP + tail ----
        const std::string prefix(64, 'A');
        // minimal plausible ELF header
        const std::string elf = std::string("\x7f"
                                            "ELF\x02\x01\x01\x00",
                                            8) +
                                std::string(72, '\0');
        // JPEG: SOI ... EOI
        const std::string jpeg = "\xff\xd8\xff\xe0" + std::string(48, 'j') + "\xff\xd9";
        // PNG: signature ... IEND + CRC
        const std::string png =
            std::string("\x89PNG\x0d\x0a\x1a\x0a", 8) + std::string(24, 'p') + "IEND\xae\x42\x60\x82";
        // ZIP: LFH ... EOCD
        const std::string zip = "PK\x03\x04" + std::string(40, 'z') + "PK\x05\x06" +
                                std::string(18, '\0');
        const std::string tail(32, 'T');
        const std::string blob = prefix + elf + jpeg + png + zip + tail;

        const std::span<const std::byte> view(reinterpret_cast<const std::byte*>(blob.data()),
                                              blob.size());

        // ---- pure finder ----
        const auto spans = scanning::Carver::find_artifacts(view);
        check(spans.size() == 4, "carver: finds exactly the 4 embedded artifacts",
              std::to_string(spans.size()));
        if (spans.size() == 4) {
            check(spans[0].kind == scanning::ArtifactKind::Elf &&
                      spans[1].kind == scanning::ArtifactKind::Jpeg &&
                      spans[2].kind == scanning::ArtifactKind::Png &&
                      spans[3].kind == scanning::ArtifactKind::Zip,
                  "carver: kinds in offset order (elf, jpeg, png, zip)");
            check(spans[0].offset == prefix.size(),
                  "carver: ELF offset correct after the prefix");
            check(spans[1].size == jpeg.size(), "carver: JPEG extent runs to EOI");
            check(spans[2].size == png.size(), "carver: PNG extent runs past IEND+CRC");
        }
        // MZ without a PE signature is NOT an artifact (weak-magic guard)
        {
            const std::string mz_only = std::string(8, 'M') + "MZ" + std::string(120, 'x');
            const auto r = scanning::Carver::find_artifacts(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(mz_only.data()),
                                           mz_only.size()));
            check(r.empty(), "carver: bare MZ text is not flagged as PE");
        }
        // clean text yields nothing
        {
            const std::string clean = "just an ordinary text document with no embedded objects";
            const auto r = scanning::Carver::find_artifacts(
                std::span<const std::byte>(reinterpret_cast<const std::byte*>(clean.data()),
                                           clean.size()));
            check(r.empty(), "carver: clean text yields no artifacts");
        }

        // ---- file workflow ----
        const std::string src = "/tmp/hyprnova-test-carve-container.bin";
        {
            std::ofstream o(src, std::ios::binary);
            o.write(blob.data(), static_cast<std::streamsize>(blob.size()));
        }
        // malicious variant: ransomware-trait strings inside the ZIP artifact
        const std::string mal_zip =
            "PK\x03\x04" + std::string("all your files have been encrypted; see "
                                       "README_RESTORE; vssadmin delete shadows done") +
            "PK\x05\x06" + std::string(18, '\0');
        const std::string mal_blob = prefix + elf + mal_zip + tail;
        const std::string mal_src = "/tmp/hyprnova-test-carve-malicious.bin";
        {
            std::ofstream o(mal_src, std::ios::binary);
            o.write(mal_blob.data(), static_cast<std::streamsize>(mal_blob.size()));
        }

        core::AgentConfig cfg = core::default_config();

        // inventory: read-only, works while the feature is OFF
        {
            const auto inv = scanning::Carver::inventory(src);
            check(inv.error.empty() && inv.artifacts.size() == 4,
                  "carver: inventory (read-only) lists 4 artifacts with carving disabled",
                  inv.error);
            bool wrote_anything = false;
            for (const auto& a : inv.artifacts)
                if (!a.path.empty()) wrote_anything = true;
            check(!wrote_anything, "carver: inventory never writes extractions");
        }

        // opt-in gate: carve refuses while disabled
        {
            scanning::Carver off(cfg.scan.carve);
            const auto rep = off.carve_file(src, "/tmp/hyprnova-test-carved", nullptr);
            check(!rep.error.empty(), "carver: carve refused while scan.carving_enabled=false",
                  rep.error);
        }

        // enabled: extract + scan
        {
            cfg.scan.carve.enabled = true;
            std::string rules_err;
            scanning::SignatureEngine engine;
            core::ScanConfig scfg = cfg.scan;
            scfg.rule_files.clear();
            check(engine.load(scfg, nullptr) > 0, "carver: rule floor for artifact scan");
            scanning::Carver on(cfg.scan.carve);

            const auto clean_rep = on.carve_file(src, "/tmp/hyprnova-test-carved", &engine);
            check(clean_rep.error.empty() && clean_rep.artifacts.size() == 4,
                  "carver: carve extracts 4 artifacts when enabled", clean_rep.error);
            std::size_t extracted = 0;
            bool any_suspicious = false;
            for (const auto& a : clean_rep.artifacts) {
                if (!a.path.empty()) ++extracted;
                if (!a.rules.empty()) any_suspicious = true;
            }
            check(extracted == 4, "carver: all 4 artifacts written to the carve dir");
            std::string hit_detail;
            for (const auto& a : clean_rep.artifacts)
                if (!a.rules.empty())
                    hit_detail += std::format("[{} {} -> {}]", a.span.offset, a.span.size,
                                              a.rules.empty() ? "?" : a.rules.front());
            check(!any_suspicious, "carver: clean container yields no rule hits", hit_detail);

            const auto mal_rep = on.carve_file(mal_src, "/tmp/hyprnova-test-carved", &engine);
            bool flagged = false;
            for (const auto& a : mal_rep.artifacts)
                if (a.span.kind == scanning::ArtifactKind::Zip && !a.rules.empty())
                    flagged = true;
            check(flagged, "carver: ransomware-trait strings inside a carved ZIP are flagged",
                  "no rule hit in carved zip");
            check(mal_rep.suspicious(), "carver: report marks the malicious container suspicious");

            // permissions: extraction is 0600
            struct stat st {};
            bool mode_ok = false;
            for (const auto& a : mal_rep.artifacts)
                if (!a.path.empty() && ::stat(a.path.c_str(), &st) == 0)
                    mode_ok = ((st.st_mode & 0777) == 0600);
            check(mode_ok, "carver: carved files are 0600");
        }
        std::remove(src.c_str());
        std::remove(mal_src.c_str());
    }
};
const CarverSuite carver_suite_instance;

}  // namespace
