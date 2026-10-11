// SPDX-License-Identifier: Apache-2.0
// HyprNova :: product identity, in exactly one place.
//
// The product is "HyprNova Anti-Malware Sec", short "HyprNova". Per the owner's
// direction the rename is TOTAL: binaries (hyprnovad, hyprnova-cli, hyprnova-gui),
// paths (/etc/hyprnova, /var/lib/hyprnova, /run/hyprnova, /var/log/hyprnova),
// the C++ namespace (hyprnova::) and every human-visible string. From here on the
// rule is the mirror of the usual one: nothing in the tree may reintroduce a
// second name -- add surfaces by referencing these constants, never by typing
// the product name again.
#pragma once

namespace hyprnova::core {

inline constexpr std::string_view kProductName = "HyprNova Anti-Malware Sec";
inline constexpr std::string_view kShortName = "HyprNova";
inline constexpr std::string_view kCoreName = "hyprnova";

}  // namespace hyprnova::core
