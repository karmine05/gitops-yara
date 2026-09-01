#!/bin/sh
# Read-only post-check for orbit-restart-linux.sh: state, PID, active-since.
state=$(systemctl is-active orbit 2>/dev/null)
pid=$(systemctl show orbit -p MainPID --value 2>/dev/null)
up=$(systemctl show orbit -p ActiveEnterTimestamp --value 2>/dev/null)
osq=$(pgrep -x osqueryd | head -1 || echo none)
echo "orbit=$state pid=$pid active_since=$up osqueryd=$osq"
