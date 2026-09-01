# Read-only post-check for orbit-restart-windows.ps1.
$svc = Get-Service "Fleet osquery" -ErrorAction SilentlyContinue
if ($null -eq $svc) { Write-Output "service not found"; exit 1 }
$osq = Get-Process osqueryd -ErrorAction SilentlyContinue
if ($osq) {
  Write-Output "service=$($svc.Status) osqueryd pid=$($osq.Id) started=$($osq.StartTime)"
} else {
  Write-Output "service=$($svc.Status) osqueryd=NOT RUNNING (may still be starting - re-check in 10s)"
}
