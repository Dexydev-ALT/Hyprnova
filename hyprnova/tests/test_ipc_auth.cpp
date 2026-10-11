// SPDX-License-Identifier: Apache-2.0
// HyprNova :: IPC group authorisation (the KNOWN_LIMITATIONS "Sandbox
// boundary" item). The DECISION is pure and pinned here; the OS membership
// read is pinned on the one identity this environment guarantees (our own).
#include "test_main.hpp"

#include <unistd.h>

#include <optional>
#include <string>

#include <pwd.h>

#include "gui/gui_bridge.hpp"

namespace {

using namespace hyprnova;
using hyprnova::testing::check;

struct IpcAuthSuite {
    IpcAuthSuite() {
        using Decision = bool (*)(uid_t, uid_t, const std::optional<gid_t>&, bool);
        const Decision decide = &hyprnova::GuiBridge::auth_decision;

        // ---- pure decision table ---------------------------------------------
        check(decide(0, 1000, std::nullopt, false), "ipcauth: root is always allowed");
        check(decide(1000, 1000, std::nullopt, false),
              "ipcauth: the daemon's own uid is allowed (its CLI/GUI)");
        check(!decide(1001, 1000, std::nullopt, false),
              "ipcauth: a foreign uid with NO operator group is refused");
        check(decide(1001, 1000, std::optional<gid_t>{977}, true),
              "ipcauth: an operator-group member is allowed");
        check(!decide(1001, 1000, std::optional<gid_t>{977}, false),
              "ipcauth: a same-host uid OUTSIDE the operator group is refused");
        check(!decide(1001, 1002, std::optional<gid_t>{977}, false),
              "ipcauth: a foreign uid with a different primary group is refused");

        // ---- OS membership read (self: the only identity guaranteed here) ----
        const uid_t me = ::geteuid();
        struct ::passwd* pw = ::getpwuid(me);
        if (pw) {
            check(hyprnova::GuiBridge::os_user_in_group(me, pw->pw_gid),
                  "ipcauth: every user is a member of their PRIMARY group (getgrouplist path)");
            check(hyprnova::GuiBridge::os_user_in_group(me, pw->pw_gid) ==
                      hyprnova::GuiBridge::os_user_in_group(me, pw->pw_gid),
                  "ipcauth: the membership read is deterministic");
        } else {
            testing::skip("ipcauth: primary-group membership", "no passwd entry for our uid");
        }
        // root group membership of a normal user must not be granted by accident:
        // the function answers honestly either way, and the DECISION above is
        // what keeps unauthorised uids out.
        check(hyprnova::GuiBridge::os_user_in_group(999999, 0) == false,
              "ipcauth: a nonexistent uid is in no group (honest false, no crash)");
    }
};
const IpcAuthSuite ipcauth_suite_instance;

}  // namespace
