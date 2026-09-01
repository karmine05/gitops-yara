# Restart "Fleet osquery" on Windows, via Fleet ad-hoc script execution
# (fleetctl run-script). Service name verified on WRK-AI 2026-08-31.
#
# Key pitfall: the script runs THROUGH the orbit agent. On Windows the agent
# uses a job object, so a detached child (Start-Process) does NOT survive -
# the job kills it. Use a DIRECT Restart-Service instead: the script dies mid
# restart (or completes its Write-Output first), and the restart succeeds.
# Verify with orbit-check-windows.ps1.
#
# Verified: 5/6 homelab Windows hosts (DC02 offline), 2026-09-01.
$svc = Get-Service "Fleet osquery" -ErrorAction SilentlyContinue
if ($null -eq $svc) { Write-Output "SKIP: service 'Fleet osquery' not found"; exit 0 }
if ($svc.Status -ne 'Running') { Write-Output "SKIP: not running before restart ($($svc.Status))"; exit 0 }
$old = (Get-Process osqueryd -ErrorAction SilentlyContinue).Id
Write-Output "RESTARTING: old osqueryd pid $old"
Restart-Service "Fleet osquery" -Force
