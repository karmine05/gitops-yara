#!/bin/bash
# Fleet script - deploy YARA rules to macOS hosts for yara_events.
# Run as a Fleet script (executes as root). Idempotent.
set -euo pipefail

RULE_URL="https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos-file-events.yar"
DEST_DIR="/opt/fleetdm/yara"
DEST="$DEST_DIR/malware_rules.yar"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

install -d -m 0755 -o root -g wheel "$DEST_DIR"

curl --fail --silent --show-error --location --max-time 120 \
     --proto '=https' --tlsv1.2 \
     -o "$TMP" "$RULE_URL"

# Refuse to install something that is not a rule file.
if [ ! -s "$TMP" ]; then
  echo "FAIL: downloaded file is empty" >&2; exit 1
fi
if ! grep -qE '^[[:space:]]*rule[[:space:]]+' "$TMP"; then
  echo "FAIL: downloaded file contains no YARA rules - refusing to install" >&2; exit 1
fi
RULES=$(grep -cE '^[[:space:]]*rule[[:space:]]+' "$TMP")

# Only replace on change, so we do not churn the file needlessly.
if [ -f "$DEST" ] && cmp -s "$TMP" "$DEST"; then
  echo "unchanged: $DEST ($RULES rules)"
  exit 0
fi

install -m 0644 -o root -g wheel "$TMP" "$DEST"
echo "installed: $DEST ($RULES rules)"

# osquery compiles YARA signatures when the config loads. A changed file on disk
# is NOT picked up until then, so restart the agent.
if launchctl list | grep -q com.fleetdm.orbit; then
  launchctl kickstart -k system/com.fleetdm.orbit && echo "restarted fleetd"
else
  echo "WARN: fleetd service not found - restart it manually so the new rules compile" >&2
fi
