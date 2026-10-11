#!/usr/bin/env bash
# HyprNova Anti-Malware Sec -- dependency installer.
#
# Installs everything the product can USE (nothing here is hard-required; the
# agent degrades visibly without any of it). Distro-detected: Debian/Ubuntu
# (apt), Fedora (dnf), Arch (pacman), openSUSE (zypper).
#
#   ./scripts/install-deps.sh          # interactive
#   ./scripts/install-deps.sh --yes    # CI / unattended
#   ./scripts/install-deps.sh --tools-only
set -u

YES=0; TOOLS_ONLY=0
for a in "$@"; do
  case "$a" in
    --yes|-y) YES=1 ;;
    --tools-only) TOOLS_ONLY=1 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

pkg() { $SUDO env DEBIAN_FRONTEND=noninteractive "$@"; }

install_list() {
  local mgr="$1"; shift
  echo "[install-deps] installing: $*"
  if [ "$YES" -eq 1 ]; then
    case "$mgr" in
      apt)     pkg apt-get install -y "$@" ;;
      dnf)     $SUDO dnf install -y "$@" ;;
      pacman)  $SUDO pacman -S --noconfirm --needed "$@" ;;
      zypper)  $SUDO zypper --non-interactive install "$@" ;;
    esac
  else
    case "$mgr" in
      apt)     pkg apt-get install "$@" ;;
      dnf)     $SUDO dnf install "$@" ;;
      pacman)  $SUDO pacman -S --needed "$@" ;;
      zypper)  $SUDO zypper install "$@" ;;
    esac
  fi
}

detect_mgr() {
  for m in apt dnf pacman zypper; do command -v "$m" >/dev/null 2>&1 && { echo "$m"; return; }; done
  echo unknown
}

# ---- what HyprNova can use, per distro -------------------------------------
# build + gui are the only groups that change what the PRODUCT itself can do;
# everything else extends the Toolbox's scanner/runner set.
case "$(detect_mgr)" in
  apt)
    BUILD="build-essential cmake ninja-build"
    GUI="qt6-base-dev qt6-declarative-dev qml6-module-qtquick-controls qml6-module-qtquick-layouts qml6-module-qtquick-window"
    TOOLS="clamav rkhunter chkrootkit aide lynis auditd suricata nmap nftables usbutilshave"
    TOOLS="${TOOLS/ usbutilshave/}"
    TOOLS="clamav rkhunter chkrootkit aide lynis auditd suricata nmap nftables"
    EXTRA="libcap2-bin libnftables1 libaudit-dev" ;;
  dnf)
    BUILD="gcc-c++ cmake ninja-build"
    GUI="qt6-qtbase-devel qt6-qtdeclarative-devel"
    TOOLS="clamav rkhunter chkrootkit aide lynis audit suricata nmap nftables"
    EXTRA="libcap-devel libnftables-devel libaudit-devel" ;;
  pacman)
    BUILD="gcc cmake ninja"
    GUI="qt6-base qt6-declarative"
    TOOLS="clamav rkhunter chkrootkit aide lynis audit suricata nmap nftables"
    EXTRA="libcap libnftables audit" ;;
  zypper)
    BUILD="gcc-c++ cmake ninja"
    GUI="qt6-base-devel qt6-declarative-devel"
    TOOLS="clamav rkhunter chkrootkit aide lynis audit suricata nmap nftables"
    EXTRA="libcap-devel libnftables-devel audit-devel" ;;
  *)
    echo "Unsupported distro: install build-essential/cmake/Qt6 manually."; exit 1 ;;
esac

echo "[install-deps] distro package manager: $(detect_mgr)"

if [ "$TOOLS_ONLY" -eq 0 ]; then
  install_list "$(detect_mgr)" $BUILD || echo "[install-deps] WARN: build group had failures (continuing)"
  install_list "$(detect_mgr)" $EXTRA || echo "[install-deps] WARN: optional dev libs failed (in-tree fallbacks exist)"
  install_list "$(detect_mgr)" $GUI    || echo "[install-deps] WARN: Qt6 not installed -> GUI will not build (agent unaffected)"
fi
install_list "$(detect_mgr)" $TOOLS || echo "[install-deps] WARN: some tools unavailable on this distro -- the Toolbox reports them as not installed"

# osquery: not in the base repos of most distros; give the honest pointer.
command -v osqueryi >/dev/null 2>&1 || cat <<'EOF'
[install-deps] NOTE: osquery is not in the default repos. For Debian/Ubuntu:
  apt install osquery  # or download the .deb from https://pkg.osquery.io
EOF

cat <<'EOF'
[install-deps] done. After this:
  cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build -j$(nproc)
  sudo ./build/hyprnovad --self-test
  ./build/hyprnova-cli toolbox        # coverage matrix now shows the new tools
EOF

# ---- CrowdSec (optional, zero-day community blocklist) --------------------
# Not in most base repos; use the official packagecloud repo, or skip —
# HyprNova degrades honestly when cscli is absent.
cat <<'HINT'
[crowdsec] optional: official install instructions:
  https://doc.crowdsec.net/docs/getting_started/installation
  (apt: add the crowdsec repo, then: apt-get install -y crowdsec)
HINT

