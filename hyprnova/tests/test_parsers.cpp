// SPDX-License-Identifier: Apache-2.0
// Suite: tool-output parsers (kvrt / pkg-verify / crowdsec / sshd / clamav / rkhunter).
#include "test_main.hpp"

#include <algorithm>

#include "hardening/sshd_audit.hpp"
#include "tools/toolbox.hpp"

using namespace hyprnova;
using hyprnova::testing::check;

void test_parsers() {
    // ---- KVRT ----
    {
        const auto k = tools::Toolbox::parse_kvrt(
            "11:00:00 Detected object: /tmp/e (Trojan.Linux.X)\n"
            "11:00:01 Object deleted: /tmp/e\n"
            "Scan completed cleanly.\n");
        check(k.size() == 2, "kvrt: detection + deletion lines kept, noise dropped",
              std::format("{} line(s)", k.size()));
    }
    {
        const auto k = tools::Toolbox::parse_kvrt("nothing to see here");
        check(k.empty(), "kvrt: clean output yields no findings");
    }
    // ---- pkg-verify (dpkg) ----
    {
        const auto d = tools::Toolbox::parse_pkg_verify(
            "dpkg",
            "??5??????  /usr/bin/tool\n"
            "??5??????  /etc/app.conf\n"
            "missing /usr/lib/libx.so\n");
        const auto has = [&](const char* tag, const char* path) {
            return std::any_of(d.begin(), d.end(), [&](const std::string& s) {
                return s.find(tag) != std::string::npos && s.find(path) != std::string::npos;
            });
        };
        check(d.size() == 3, "pkg-verify: three divergences parsed");
        check(has("[UNEXPLAINED]", "/usr/bin/tool"),
              "pkg-verify: /usr change is UNEXPLAINED (supply-chain class)");
        check(has("[ADMIN]", "/etc/app.conf"),
              "pkg-verify: /etc change classified ADMIN");
        check(has("[MISSING]", "/usr/lib/libx.so"),
              "pkg-verify: deleted package file is MISSING");
    }
    {
        const auto d = tools::Toolbox::parse_pkg_verify("rpm", "SM5....T.  /usr/bin/y\n");
        check(d.size() == 1 && d.front().find("UNEXPLAINED") != std::string::npos,
              "pkg-verify: rpm -Va flag line parsed");
        const auto ok = tools::Toolbox::parse_pkg_verify("dpkg", "\n");
        check(ok.empty(), "pkg-verify: empty verify output is empty findings");
    }
    // ---- CrowdSec ----
    {
        const auto c = tools::Toolbox::parse_crowdsec_decisions(
            R"({"decisions":[{"value":"198.51.100.9","type":"ban","reason":"scan","until":"x"}]})");
        check(c.size() == 1 && c.front().find("198.51.100.9") != std::string::npos &&
                  c.front().find("scan") != std::string::npos,
              "crowdsec: ban with reason parsed");
        check(tools::Toolbox::parse_crowdsec_decisions("{{{bad").empty(),
              "crowdsec: malformed JSON yields no findings");
        check(tools::Toolbox::parse_crowdsec_decisions(R"({"decisions":[]})").empty(),
              "crowdsec: empty decision list yields no findings");
    }
    // ---- sshd audit ----
    {
        const auto w = hardening::audit_sshd_config(
            "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n");
        bool root = false, pwd = false;
        for (const auto& x : w) {
            if (x.key == "PermitRootLogin") root = !x.fix.empty();
            if (x.key == "PasswordAuthentication") pwd = !x.fix.empty();
        }
        check(root && pwd, "sshd: weak root+password knobs flagged with fixes");
    }
    {
        const auto w = hardening::audit_sshd_config(
            "PermitRootLogin no\nPasswordAuthentication no\n");
        bool weak = false;
        for (const auto& x : w)
            if (x.key == "PermitRootLogin" || x.key == "PasswordAuthentication") weak = true;
        check(!weak, "sshd: hardened values are not flagged");
        // first-value-wins (sshd_config(5))
        const auto w2 = hardening::audit_sshd_config(
            "PermitRootLogin no\nPermitRootLogin yes\n");
        bool flag = false;
        for (const auto& x : w2)
            if (x.key == "PermitRootLogin") flag = true;
        check(!flag, "sshd: later duplicate directive cannot fabricate a weakness");
    }
    // ---- clamav ----
    {
        const auto c = tools::Toolbox::parse_clamav(
            "/tmp/a: Eicar-Signature FOUND\n/tmp/b: OK\n");
        check(c.size() == 1 && c.front().find("Eicar") != std::string::npos,
              "clamav: FOUND lines become findings, OK lines do not");
    }
    // ---- rkhunter ----
    {
        const auto r = tools::Toolbox::parse_rkhunter(
            "Warning: file /usr/bin/x has been changed\n[ OK ]\n");
        check(!r.empty() && r.front().find("Warning") != std::string::npos,
              "rkhunter: warnings become findings");
    }

    // ---- built-in SSH weak-settings audit (parse_sshd_audit) ----
    {
        const auto r = tools::Toolbox::parse_sshd_audit(
            "# comment\nPort 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
            "PermitEmptyPasswords yes\nMatch User backup\n    PasswordAuthentication yes\n");
        check(r.size() >= 3, "sshd: weak config yields >=3 findings");
        bool root = false, empty_pw = false;
        for (const auto& f : r) {
            if (f.find("PermitRootLogin=yes") != std::string::npos) root = true;
            if (f.find("PermitEmptyPasswords=yes") != std::string::npos) empty_pw = true;
        }
        check(root, "sshd: PermitRootLogin=yes flagged with value echoed");
        check(empty_pw, "sshd: PermitEmptyPasswords=yes flagged");
        const auto clean = tools::Toolbox::parse_sshd_audit(
            "PermitRootLogin prohibit-password\nPasswordAuthentication no\n"
            "PermitEmptyPasswords no\nMaxAuthTries 4\nLoginGraceTime 30\n"
            "ClientAliveInterval 300\nClientAliveCountMax 2\nAllowTcpForwarding no\n");
        check(clean.empty(), "sshd: hardened config yields no findings");
        // first-wins: a weak LATER value must not override an earlier strong one
        const auto fw = tools::Toolbox::parse_sshd_audit(
            "PasswordAuthentication no\nPasswordAuthentication yes\n");
        bool pw_flagged = false;
        for (const auto& f : fw)
            if (f.find("PasswordAuthentication=yes") != std::string::npos) pw_flagged = true;
        check(!pw_flagged, "sshd: first-wins semantics (later weak value ignored)");
    }
}
