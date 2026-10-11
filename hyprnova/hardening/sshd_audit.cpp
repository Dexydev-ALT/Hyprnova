// SPDX-License-Identifier: Apache-2.0
// HyprNova :: sshd_config audit implementation.

#include "hardening/sshd_audit.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>

namespace hyprnova::hardening {

std::string load_sshd_config(const std::string& path) noexcept {
    std::ifstream f{path};
    if (!f) return {};
    std::string out;
    std::string line;
    while (std::getline(f, line)) {
        // Keep only effective directives: strip comments and blank lines.
        const auto h1 = line.find_first_not_of(" \t");
        if (h1 == std::string::npos || line[h1] == '#' || line[h1] == '\r') continue;
        out += line;
        out += '\n';
    }
    return out;
}

std::vector<SshdWeakness> audit_sshd_config(std::string_view text) noexcept {
    // Effective value = FIRST occurrence of a keyword (sshd_config(5)).
    std::map<std::string, std::string> kv;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const auto eol = text.find('\n', pos);
        const auto line = text.substr(pos, eol == std::string_view::npos ? std::string_view::npos
                                                                         : eol - pos);
        pos = eol == std::string_view::npos ? text.size() : eol + 1;
        const auto h = line.find_first_not_of(" \t");
        if (h == std::string_view::npos || line[h] == '#') continue;
        std::string_view body = line.substr(h);
        const auto sp = body.find_first_of(" \t");
        if (sp == std::string_view::npos) continue;
        const std::string key{body.substr(0, sp)};
        const auto v0 = body.find_first_not_of(" \t", sp);
        if (v0 == std::string_view::npos) continue;
        std::string value{body.substr(v0)};
        while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) value.pop_back();
        if (!kv.contains(key)) kv.emplace(key, value);  // first wins
    }

    std::vector<SshdWeakness> out;
    auto get = [&](std::string_view k) -> const std::string* {
        const auto it = kv.find(std::string{k});
        return it == kv.end() ? nullptr : &it->second;
    };
    auto eqi = [](const std::string& v, std::string_view l) {
        std::string a{v};
        std::transform(a.begin(), a.end(), a.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return a == l;
    };

    if (const auto* v = get("PermitRootLogin"); v && eqi(*v, "yes"))
        out.push_back({"PermitRootLogin", *v,
                       "root can SSH in directly: one password or key guess is the whole machine",
                       "set 'PermitRootLogin prohibit-password' (or 'no') and reload sshd"});
    if (const auto* v = get("PasswordAuthentication"); v && eqi(*v, "yes"))
        out.push_back({"PasswordAuthentication", *v,
                       "password logins allowed: brute-forceable over the network; keys are not",
                       "set 'PasswordAuthentication no' (deploy keys FIRST) and reload sshd"});
    if (const auto* v = get("PermitEmptyPasswords"); v && eqi(*v, "yes"))
        out.push_back({"PermitEmptyPasswords", *v,
                       "accounts with empty passwords may log in over SSH",
                       "set 'PermitEmptyPasswords no' and reload sshd"});
    if (const auto* v = get("X11Forwarding"); v && eqi(*v, "yes"))
        out.push_back({"X11Forwarding", *v,
                       "X11 tunneling widens the session attack surface for little operator value on servers",
                       "set 'X11Forwarding no' unless desktop users need it"});
    if (const auto* v = get("ClientAliveInterval"); !v || eqi(*v, "0"))
        out.push_back({"ClientAliveInterval", v ? *v : "(unset)",
                       "idle sessions live forever: a hijacked session never times out",
                       "set 'ClientAliveInterval 300' and 'ClientAliveCountMax 2'"});
    if (!get("MaxAuthTries"))
        out.push_back({"MaxAuthTries", "(unset)",
                       "default allows 6 guesses per connection; paired with password auth that is free brute force",
                       "set 'MaxAuthTries 3'"});
    if (const auto* v = get("AllowTcpForwarding"); v && eqi(*v, "yes") && get("PasswordAuthentication") &&
                                                      eqi(*get("PasswordAuthentication"), "yes"))
        out.push_back({"AllowTcpForwarding", *v,
                       "TCP forwarding plus password auth turns any stolen password into a pivot",
                       "set 'AllowTcpForwarding no' for user accounts"});
    if (!get("LoginGraceTime"))
        out.push_back({"LoginGraceTime", "(unset)",
                       "unauthenticated connections may linger in the pre-auth window",
                       "set 'LoginGraceTime 30'"});
    return out;
}

}  // namespace hyprnova::hardening
