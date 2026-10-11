#!/usr/bin/env bash
# Fetch the Kaspersky Virus Removal Tool (KVRT) — the default second-opinion
# engine for HyprNova's quick/deep/full scans. Free tool, official Kaspersky
# distribution. We never mirror it: the checksum is whatever Kaspersky's CDN
# serves today, and the script says so.
set -u
DEST="${HYPRNOVA_KVRT_DIR:-/opt/kaspersky/kvrt}"
mkdir -p "$DEST" 2>/dev/null || DEST="$HOME/.local/share/hyprnova/kvrt" && mkdir -p "$DEST"

echo "[*] resolving the current KVRT build from devbuilds.s.kaspersky-labs.com..."
INDEX=$(curl -fsSL --max-time 60 "https://devbuilds.s.kaspersky-labs.com/kvrt/linux/" 2>/dev/null) || {
  echo "!! could not reach the Kaspersky CDN (offline?)."
  echo "!! manual step: download KVRT from https://www.kaspersky.com/downloads/kvrt"
  echo "!! then:  mv kvrt.run $DEST/kvrt && chmod +x $DEST/kvrt"
  exit 1
}
LATEST=$(printf '%s' "$INDEX" | grep -oE 'kvrt-[0-9]+\.[0-9]+\.[0-9]+\.[0-9a-z]+\.run' | sort -V | tail -1)
[ -n "$LATEST" ] || { echo "!! could not parse the CDN listing; fetch manually (see above)"; exit 1; }
URL="https://devbuilds.s.kaspersky-labs.com/kvrt/linux/$LATEST"
echo "[*] downloading $URL"
curl -fSL --max-time 600 -o "$DEST/kvrt.download" "$URL" || { echo "!! download failed"; exit 1; }
# NOTE: no checksum verification is possible without a Kaspersky-signed manifest;
# state that honestly instead of pretending.
echo "[!] no third-party checksum available for KVRT; trusting the Kaspersky CDN."
mv "$DEST/kvrt.download" "$DEST/kvrt"
chmod +x "$DEST/kvrt"
echo "[+] KVRT staged at $DEST/kvrt"
echo "[*] HyprNova probes: kvrt on PATH or $DEST/kvrt (or /opt/kaspersky/kvrt/kvrt)."
echo "    Run a scan:  hyprnova-cli deep-scan quick     (KVRT runs by default)"
