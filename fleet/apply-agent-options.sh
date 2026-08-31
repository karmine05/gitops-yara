#!/usr/bin/env bash
# Apply fleet/agent-options-v4.yml to a Fleet team.
#
# Reads credentials from the environment - nothing is hardcoded:
#   export FLEET_URL='https://fleet-f9fl.onrender.com'
#   export FLEET_TOKEN='...'
#
# Usage:
#   ./apply-agent-options.sh --list                 # show teams and exit
#   ./apply-agent-options.sh --team <id>            # dry run: back up + diff
#   ./apply-agent-options.sh --team <id> --apply    # prompt, then PATCH
#   ./apply-agent-options.sh --global               # same, against global config
#
# Dry run is the default. Nothing is written without --apply and a typed yes.
set -euo pipefail

YAML="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/agent-options-v4.yml"
TEAM=""; APPLY=0; GLOBAL=0; LIST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --team)   TEAM="$2"; shift 2 ;;
    --global) GLOBAL=1; shift ;;
    --apply)  APPLY=1; shift ;;
    --list)   LIST=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

: "${FLEET_URL:?set FLEET_URL}"
: "${FLEET_TOKEN:?set FLEET_TOKEN}"
FLEET_URL="${FLEET_URL%/}"

command -v jq >/dev/null || { echo "need jq" >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo "need pyyaml: pip3 install pyyaml" >&2; exit 1; }
[ -f "$YAML" ] || { echo "missing $YAML" >&2; exit 1; }

api() {  # api <method> <path> [body-file]
  local m="$1" p="$2" f="${3:-}"
  if [ -n "$f" ]; then
    curl -sS --fail-with-body -X "$m" -H "Authorization: Bearer $FLEET_TOKEN" \
         -H 'Content-Type: application/json' --data-binary "@$f" "$FLEET_URL$p"
  else
    curl -sS --fail-with-body -X "$m" -H "Authorization: Bearer $FLEET_TOKEN" "$FLEET_URL$p"
  fi
}

echo "==> authenticating against $FLEET_URL"
api GET /api/v1/fleet/me | jq -r '"    logged in as \(.user.email)  (global_role=\(.user.global_role // "none"))"'

if [ "$LIST" = 1 ]; then
  echo "==> teams"
  api GET /api/v1/fleet/teams | jq -r '.teams[] | "    id=\(.id)  hosts=\(.host_count)  \(.name)"'
  exit 0
fi

if [ "$GLOBAL" = 1 ]; then
  GET_PATH=/api/v1/fleet/config;          PATCH_PATH=/api/v1/fleet/config;          LABEL="GLOBAL config"
elif [ -n "$TEAM" ]; then
  GET_PATH="/api/v1/fleet/teams/$TEAM";   PATCH_PATH="/api/v1/fleet/teams/$TEAM";   LABEL="team $TEAM"
else
  echo "specify --team <id>, --global, or --list" >&2; exit 2
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="agent-options-backup-${TEAM:-global}-$STAMP.json"

echo "==> reading current agent options from $LABEL"
api GET "$GET_PATH" | jq '.team.agent_options // .agent_options' > "$BACKUP"
echo "    backup written: $BACKUP"

python3 -c "
import yaml, json, sys
json.dump(yaml.safe_load(open('$YAML')), open('/tmp/ao-new.json','w'), indent=2, sort_keys=True)
" 
jq -S . "$BACKUP" > /tmp/ao-old.json

echo "==> diff (current -> v3)"
if diff -u /tmp/ao-old.json /tmp/ao-new.json > /tmp/ao.diff; then
  echo "    no change - already at v3"; rm -f "$BACKUP"; exit 0
fi
sed -n '1,200p' /tmp/ao.diff
LINES=$(wc -l < /tmp/ao.diff)
[ "$LINES" -gt 200 ] && echo "    ... $((LINES-200)) more diff lines in /tmp/ao.diff"

if [ "$APPLY" != 1 ]; then
  echo
  echo "==> DRY RUN. Nothing written. Re-run with --apply to PATCH $LABEL."
  exit 0
fi

echo
printf 'Type APPLY to PATCH %s: ' "$LABEL"
read -r ans
[ "$ans" = "APPLY" ] || { echo "aborted"; exit 1; }

jq -n --slurpfile ao /tmp/ao-new.json '{agent_options: $ao[0]}' > /tmp/ao-patch.json
echo "==> patching"
api PATCH "$PATCH_PATH" /tmp/ao-patch.json | jq -r '"    ok"'

echo "==> verifying"
api GET "$GET_PATH" | jq '.team.agent_options // .agent_options' | jq -S . > /tmp/ao-after.json
if diff -q /tmp/ao-new.json /tmp/ao-after.json >/dev/null; then
  echo "    server state matches v3"
else
  echo "    WARNING: server state differs from what was sent:" >&2
  diff -u /tmp/ao-new.json /tmp/ao-after.json | head -40 >&2
  exit 1
fi
echo
echo "Done. command_line_flags changes need a fleetd restart on each host."
echo "Rollback: jq -n --slurpfile ao $BACKUP '{agent_options:\$ao[0]}' > r.json && \\"
echo "          curl -sS -X PATCH -H \"Authorization: Bearer \$FLEET_TOKEN\" \\"
echo "               -H 'Content-Type: application/json' -d @r.json $FLEET_URL$PATCH_PATH"
