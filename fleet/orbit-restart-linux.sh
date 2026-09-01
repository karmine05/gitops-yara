#!/bin/sh
# Restart the orbit (osquery) service on Linux/Ubuntu, via Fleet ad-hoc script
# execution (fleetctl run-script). No SSH needed - Fleet pushes the script to
# the host and orbit runs it as root.
#
# Key pitfall: fleetctl run-script executes THROUGH the orbit agent, so the
# script is its own child. A plain `systemctl restart orbit` kills the running
# script (fleetctl reports "signal: terminated"). The restart still succeeds.
# Pattern: pre-check, fire a DETACHED child (nohup + sleep) that does the
# restart after the parent exits, then verify with a second run-script.
#
# Verified: all 24 homelab Linux hosts, 2026-09-01.
set -u
state=$(systemctl is-active orbit 2>/dev/null)
if [ "$state" != "active" ]; then
  echo "SKIP: orbit not active before restart (state: ${state:-unknown})"
  exit 0
fi
old_pid=$(systemctl show orbit -p MainPID --value 2>/dev/null)
nohup sh -c "sleep 1; systemctl restart orbit" >/dev/null 2>&1 &
echo "TRIGGERED: restart in flight (old orbit pid ${old_pid:-?}). Verify with orbit-check-linux.sh after ~10s."
