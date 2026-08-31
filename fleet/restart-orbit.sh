#!/usr/bin/env bash
#
# restart-orbit.sh - restart the orbit (osquery) service across hosts,
# with per-host verification before and after.
#
# Fleet installs orbit as ONE service per host; osqueryd is its child
# process (same systemd cgroup / launchd group / Windows service tree),
# so restarting orbit restarts osqueryd too. There is no separate
# osquery service to manage.
#
# Verified service identities (2026-08-31, live):
#   linux/ubuntu  systemd service "orbit"        (docker-worker-01)
#   macos         launchd  com.fleetdm.orbit     (Beast's Mac mini)
#   windows       Windows service (orbit.exe)    process verified; service
#                 NAME must be confirmed on the host - see WINDOWS section.
#
# Usage:
#   ./restart-orbit.sh --list                 # show targets, no changes
#   ./restart-orbit.sh --host 192.168.89.202  # single Linux host
#   ./restart-orbit.sh --fleet-linux          # all known Linux swarm/infra hosts
#   ./restart-orbit.sh --mac-local            # this machine, if it is the Mac mini
#
# Safety:
#   * default is DRY RUN - nothing restarts until you add --apply
#   * every host is verified ACTIVE before (no point restarting a dead one
#     blindly) and after (a failed restart is reported per host)
#   * hosts are done SEQUENTIALLY on purpose: a fleet-wide restart at once
#     creates a re-enrollment stampede against fleetd

set -u

SSH_KEY="${HOME}/.ssh/proxmox_key"
SSH_OPTS="-i ${SSH_KEY} -o ConnectTimeout=6 -o BatchMode=yes -o StrictHostKeyChecking=accept-new"

# Known Linux fleet hosts (proxmox_key, ubuntu@). Extend as needed.
LINUX_HOSTS="192.168.89.202 192.168.89.203 192.168.89.204 192.168.89.205 192.168.89.206 192.168.89.207 192.168.89.114 192.168.89.115 192.168.89.201"

APPLY=0
MODE=""
TARGETS=()
prev=""
for arg in "$@"; do
  if [ "$prev" = "--host" ]; then
    TARGETS+=("$arg"); prev=""; continue
  fi
  prev="$arg"
  case "$arg" in
    --apply) APPLY=1 ;;
    --list) ;;
    --host) ;;
    --fleet-linux) MODE=linux; TARGETS+=($LINUX_HOSTS) ;;
    --mac-local) MODE=mac ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- linux
verify_linux() { # $1 = ip
  ssh $SSH_OPTS ubuntu@"$1" 'systemctl is-active orbit' 2>/dev/null
}

restart_linux() { # $1 = ip
  local ip=$1
  local before; before=$(verify_linux "$ip")
  if [ "$before" != "active" ]; then
    echo "SKIP $ip - orbit was not active before restart (state: ${before:-unreachable}). Investigate, do not blind-restart."
    return 1
  fi
  if [ "$APPLY" -eq 0 ]; then
    echo "DRYRUN $ip - would run: sudo systemctl restart orbit"
    return 0
  fi
  if ! ssh $SSH_OPTS ubuntu@"$ip" 'sudo systemctl restart orbit' 2>/dev/null; then
    echo "FAIL $ip - restart command returned non-zero"
    return 1
  fi
  sleep 3
  local after; after=$(verify_linux "$ip")
  local pid; pid=$(ssh $SSH_OPTS ubuntu@"$ip" 'systemctl show orbit -p MainPID --value' 2>/dev/null)
  if [ "$after" = "active" ]; then
    echo "OK   $ip - active, orbit MainPID=$pid"
  else
    echo "FAIL $ip - not active after restart (state: ${after:-unknown})"
    return 1
  fi
}

# ---------------------------------------------------------------- macos
mac_local() {
  if [ ! -d /opt/orbit ]; then
    echo "SKIP mac-local - /opt/orbit not present on this machine"
    return 1
  fi
  local before; before=$(pgrep -x orbit | head -1 || true)
  if [ -z "$before" ]; then
    echo "SKIP mac-local - no orbit process found. Do not blind-restart."
    return 1
  fi
  if [ "$APPLY" -eq 0 ]; then
    echo "DRYRUN mac-local - orbit PID=$before - would run: sudo launchctl kickstart -k system/com.fleetdm.orbit"
    return 0
  fi
  # -k = stop then start (full restart, matches the manual -k run)
  sudo launchctl kickstart -k system/com.fleetdm.orbit
  sleep 3
  local pid; pid=$(pgrep -x orbit | head -1)
  echo "OK   mac-local - orbit restarted, new PID=${pid:-unknown}"
}

# ---------------------------------------------------------------- windows
# Windows has NO remote restart path here (no WinRM/PsHock configured, and
# live queries to WRK-AI are too slow for service management). Do it in an
# elevated terminal on the host. Step 1 is mandatory: confirm the service
# name first, because it is installation-specific.
print_windows() {
  cat <<'EOF'
WINDOWS (run in an elevated PowerShell on the host):

  1. Confirm the service name (one of these will match):
       Get-Service -Name orbit
       Get-Service | Where-Object { $_.Name -like '*orbit*' -or $_.DisplayName -like '*Fleet*' }

  2. Restart it (use the name from step 1):
       Restart-Service -Name orbit -Force

  3. Verify:
       Get-Service -Name orbit                # Status: Running
       Get-Process orbit, osqueryd            # both present, osqueryd StartTime is now
EOF
}

# ---------------------------------------------------------------- main
LIST_ONLY=0
case " $* " in *" --list "*) LIST_ONLY=1 ;; esac
if [ "$LIST_ONLY" -eq 1 ] || { [ "${#TARGETS[@]}" -eq 0 ] && [ "$MODE" != "mac" ]; }; then
  echo "Targets (--list):"
  echo "  linux:  ${LINUX_HOSTS}"
  echo "  macos:  this machine, if it is the Mac mini (--mac-local)"
  echo "  windows: manual - see below"
  print_windows
  echo
  echo "Nothing was restarted. Add --apply to act."
  exit 0
fi

for ip in ${TARGETS[@]+"${TARGETS[@]}"}; do
  restart_linux "$ip"
done
if [ "$MODE" = "mac" ]; then
  mac_local
fi
echo
print_windows
