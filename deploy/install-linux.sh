#!/bin/bash
# Fleet script - deploy YARA rules to Linux hosts for yara_events.
# Run as a Fleet script (executes as root). Idempotent.
set -euo pipefail

RULE_URL="https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux-file-events.yar"
DEST_DIR="/etc/fleetdm/yara"
DEST="$DEST_DIR/malware_rules.yar"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

install -d -m 0755 -o root -g root "$DEST_DIR"

curl --fail --silent --show-error --location --max-time 120 \
     --proto '=https' --tlsv1.2 \
     -o "$TMP" "$RULE_URL"

if [ ! -s "$TMP" ]; then
  echo "FAIL: downloaded file is empty" >&2; exit 1
fi
if ! grep -qE '^[[:space:]]*rule[[:space:]]+' "$TMP"; then
  echo "FAIL: downloaded file contains no YARA rules - refusing to install" >&2; exit 1
fi
RULES=$(grep -cE '^[[:space:]]*rule[[:space:]]+' "$TMP")

if [ -f "$DEST" ] && cmp -s "$TMP" "$DEST"; then
  echo "unchanged: $DEST ($RULES rules)"
  exit 0
fi

install -m 0644 -o root -g root "$TMP" "$DEST"
echo "installed: $DEST ($RULES rules)"

if systemctl is-active --quiet orbit; then
  systemctl restart orbit && echo "restarted fleetd"
else
  echo "WARN: orbit service not active - restart it manually so the new rules compile" >&2
fi
