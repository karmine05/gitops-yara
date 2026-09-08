# Validated Hunt Query Library

osquery on Windows via fleet-mcp run_live_query. All queries executed successfully on a loaded Win10 VM (2026-09-07 hunt, host 1590) using the first-fire-then-wait-90s-and-refire pattern.

Default time bound on every row-returning windows_events query: time > strftime('%s','now') - 86400 (24h). User may request longer. Log-integrity probes (min/max/count, no rows) may omit it.

host_ids param is a string: "<host_id>".

## Baseline
```sql
SELECT name, version, build FROM os_version;
SELECT days, hours, minutes, total_seconds FROM uptime;
SELECT port, protocol, family, address, pid FROM listening_ports ORDER BY port;
SELECT l.port, l.protocol, l.address, p.name, p.path FROM listening_ports l JOIN processes p ON l.pid = p.pid;
```

## Phase 2 - Log integrity (unbounded allowed, no rows)
```sql
SELECT source, min(time) AS oldest, max(time) AS newest, count(*) AS n FROM windows_events WHERE source IN ('Security','System','Application') GROUP BY source;
SELECT time, substr(data,1,300) AS data FROM windows_events WHERE source = 'Security' AND eventid = 1102;
SELECT time, substr(data,1,300) AS data FROM windows_events WHERE source = 'System' AND eventid = 1102;
```
Durable access timeline (survives log clears):
```sql
SELECT * FROM logon_sessions;
-- logon_type: 2=interactive, 3=network, 10=RDP. Verify columns from specs/windows/logon_sessions.table first.
```

## 300 authentication_event
```sql
SELECT eventid, time, substr(data,1,800) AS data FROM windows_events
WHERE source = 'Security' AND eventid IN (4624, 4625, 4672)
AND time > strftime('%s','now') - 86400 ORDER BY time DESC LIMIT 100;

SELECT eventid, time, substr(data,1,600) AS data FROM windows_events
WHERE source = 'Security' AND eventid IN (4720, 4721, 4726, 4728, 4732, 4733, 4738, 4768, 4776, 4783)
AND time > strftime('%s','now') - 86400 ORDER BY time DESC LIMIT 100;

-- Targeted IP hunt (ONLY after Phase 2 proves the log is not cleared):
SELECT eventid, time, substr(data,1,800) AS data FROM windows_events
WHERE source = 'Security' AND eventid IN (4624, 4625)
AND time > strftime('%s','now') - 86400 AND data LIKE '%192.168.89.146%'
ORDER BY time DESC LIMIT 40;
```

## 2 configuration_event (persistence)
```sql
-- Non-Windows service paths (result may spill to file; parse client-side):
SELECT name, path, display_name, status, type FROM services WHERE path NOT LIKE 'C:\Windows\%';
-- PsExec signatures:
SELECT name, path FROM services WHERE name GLOB '*PSEXESVC*' OR name GLOB '*PsService*' OR path GLOB '*psexesvc*';
-- Non-Microsoft scheduled tasks:
SELECT name, action, state FROM scheduled_tasks WHERE name NOT GLOB '\Microsoft\*';
-- Run keys (first fire often times out; re-fire after 90s):
SELECT key, name, data FROM registry WHERE key IN (
 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce');
-- WMI persistence via registry (NO osquery wmi_event_* tables exist):
SELECT key, name, data FROM registry WHERE key GLOB 'HKLM\SOFTWARE\Microsoft\WBEM\Cimom*';
-- New service install (SCM):
SELECT time, substr(data,1,400) AS data FROM windows_events
WHERE source = 'System' AND eventid IN (7045, 7036) AND time > strftime('%s','now') - 86400;
```

## 1 process_event
```sql
-- 4688 existence probe FIRST (0 = process auditing off; pattern searches then prove nothing):
SELECT count(*) AS n FROM windows_events WHERE source = 'Security' AND eventid = 4688
AND time > strftime('%s','now') - 86400;
-- 4688 attack patterns (only if count > 0):
SELECT time, substr(data,1,800) AS data FROM windows_events
WHERE source = 'Security' AND eventid = 4688 AND time > strftime('%s','now') - 86400
AND (data LIKE '%wmic%' OR data LIKE '%psexec%' OR data LIKE '%-enc%' OR data LIKE '%DownloadString%' OR data LIKE '%certutil% -urlcache%');
-- PowerShell:
SELECT eventid, time, substr(data,1,1500) AS data FROM windows_events
WHERE source = 'Microsoft-Windows-PowerShell/Operational' AND eventid IN (4103, 4104)
AND time > strftime('%s','now') - 86400 ORDER BY time DESC;
-- ATC (15-min retention only - check events_expiry before relying on it):
SELECT * FROM process_etw_events;
```

## 4 file_event
One directory per query. Add mtime bound to cut scope.
```sql
SELECT path, size, type, mtime FROM file
WHERE path GLOB 'C:\Users\<user>\Downloads\*' AND mtime > strftime('%s','now') - 86400
ORDER BY mtime DESC LIMIT 150;
-- repeat per directory: AppData\Local\Temp, Desktop (then OneDrive\Desktop if empty/timing out), C:\Windows\Temp, C:\ProgramData
-- Object access events:
SELECT time, substr(data,1,500) AS data FROM windows_events
WHERE source = 'Security' AND eventid = 4663 AND time > strftime('%s','now') - 86400
AND data LIKE '%\<user>\%' LIMIT 50;
```

## 5 network_connection_event
```sql
-- RDP client IPs - SEPARATE channel from Security; survives a Security-only clear:
SELECT eventid, time, substr(data,1,800) AS data FROM windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
AND eventid IN (21, 24, 25) AND time > strftime('%s','now') - 86400 ORDER BY time DESC LIMIT 20;
-- WFP allow/block:
SELECT eventid, time, substr(data,1,600) AS data FROM windows_events
WHERE source = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
AND eventid IN (5145, 5156, 5157, 5158, 6274, 6272)
AND time > strftime('%s','now') - 86400 ORDER BY time DESC LIMIT 50;
-- ATC (15-min retention only):
SELECT * FROM dns_lookup_events;
```

## 7 log_event
```sql
SELECT source, eventid, time, substr(data,1,300) AS data FROM windows_events
WHERE eventid IN (1102, 7036, 104) AND time > strftime('%s','now') - 86400
ORDER BY time DESC LIMIT 25;
```

## YARA (yara_file + allowlisted sigurl)
```sql
-- Small rule files first on loaded VMs. One location per query.
SELECT path, count, matches FROM yara_file
WHERE path GLOB 'C:\Windows\Temp\*'
AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/hacktool.yar'
AND count > 0;
-- Then: C:\Users\<user>\AppData\Local\Temp, Downloads, Desktop, ProgramData.
-- Allowlist + larger rule files: read the agent config first (yara_allowlist / sigurl list).
```

## Conversion helpers
- Browser history last_visit_time (Windows file time, 100ns since 1601): unix = last_visit_time/1000000 - 11644473600.
- windows_events.time = unix epoch. file.mtime/atime/ctime = unix epoch.
