# Hunt bundles — pre-vetted, tagged, splittable

Every statement here satisfies the 9-point checklist in `schema-contract.md` §5:
tables exist on Windows, required constraints are present, literals are
type-correct, evented tables carry a `time` predicate, EVTX queries use
pushdown, and results are bounded.

**Contract.** Each bundle is one `QUERY.RUN`. Rows come back tagged
`sig` + `attck`, so report assembly is a lookup in `reporting.md` — no
re-derivation. Every branch is independently runnable: on timeout, split at the
`UNION ALL` seams and fire only the branches the alert implicates.

**Substitute before firing:** `<USER>` with the account name, `<IP>` /
`<SHA256>` / `<NAME>` with the IOC. Time windows are written inline as
`strftime('%s','now') - <seconds>` (state/evented) or `timestamp = '<ms>'`
(EVTX) — change the constant, not the shape. Windows used below: 7 d =
`604800` / `604800000`, 24 h = `86400` / `86400000`, 1 h = `3600` /
`3600000`.

**Cost classes:** `cheap` = enumerations and pushdown EVTX, safe to bundle.
`medium` = one directory of `file`, `processes` joins. `expensive` = recursive
GLOB, `hash` over a directory, `yara_file`, `json_extract` over an unfiltered
channel — these never ride in a bundle and never run unprompted.

---

## B0 PREFLIGHT — one query, answers "what can this host even tell me"

Cost: cheap. Fire this first, always. It replaces four separate discovery
phases and tells you which later bundles are answerable.

```sql
SELECT 'OS' AS sig, name AS a, version AS b, build AS c, arch AS d, platform AS e FROM os_version
UNION ALL SELECT 'BOOT', CAST(strftime('%s','now') - total_seconds AS TEXT), CAST(total_seconds AS TEXT), CAST(days AS TEXT), CAST(hours AS TEXT), '' FROM uptime
UNION ALL SELECT 'HOST', hostname, computer_name, hardware_serial, hardware_model, hardware_vendor FROM system_info
UNION ALL SELECT 'TBL', name, '', '', '', '' FROM osquery_registry WHERE registry = 'table' AND name IN ('windows_eventlog','windows_events','powershell_events','process_etw_events','dns_lookup_events','ntfs_journal_events','shimcache','prefetch','userassist','background_activities_moderator','appcompat_shims','shellbags','office_mru','recent_files','logon_sessions','pipes','process_open_handles','wmi_cli_event_consumers','wmi_event_filters','wmi_script_event_consumers','windows_firewall_rules','windows_security_products','deviceguard_status','authenticode','drivers','yara_file','chrome_url_history','edge_url_history','firefox_url_history','chrome_download_history')
UNION ALL SELECT 'FLAG', name, value, '', '', '' FROM osquery_flags WHERE name IN ('enable_windows_events_publisher','enable_windows_events_subscriber','windows_event_channels','events_expiry','events_max','disable_events','disable_tables','yara_sigurl_authenticate')
UNION ALL SELECT 'PUB', name, publisher, CAST(events AS TEXT), CAST(active AS TEXT), CAST(subscriptions AS TEXT) FROM osquery_events
UNION ALL SELECT 'AUDIT', CAST(audit_process_tracking AS TEXT), CAST(audit_logon_events AS TEXT), CAST(audit_account_logon AS TEXT), CAST(audit_object_access AS TEXT), CAST(audit_policy_change AS TEXT) FROM security_profile_info
UNION ALL SELECT 'SEC', antivirus, firewall, user_account_control, autoupdate, windows_security_center_service FROM windows_security_center
UNION ALL SELECT 'AV', name, type, state, CAST(signatures_up_to_date AS TEXT), state_timestamp FROM windows_security_products
UNION ALL SELECT 'DG', vbs_status, code_integrity_policy_enforcement_status, umci_policy_status, running_security_services, configured_security_services FROM deviceguard_status
UNION ALL SELECT 'SYSMON.SVC', name, path, status, start_type, user_account FROM services WHERE name IN ('Sysmon','Sysmon64','SysmonDrv')
UNION ALL SELECT 'SYSMON.DRV', device_name, image, service, CAST(signed AS TEXT), version FROM drivers WHERE service IN ('SysmonDrv','Sysmon','Sysmon64')
UNION ALL SELECT 'SYSMON.CFG', name, substr(data,1,120), type, CAST(mtime AS TEXT), '' FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SysmonDrv\Parameters'
UNION ALL SELECT 'EVTX', filename, CAST(size AS TEXT), CAST(mtime AS TEXT), CAST(btime AS TEXT), '' FROM file WHERE directory = 'C:\Windows\System32\winevt\Logs' AND filename IN ('Security.evtx','System.evtx','Application.evtx','Microsoft-Windows-PowerShell%4Operational.evtx','Microsoft-Windows-TaskScheduler%4Operational.evtx','Microsoft-Windows-WMI-Activity%4Operational.evtx','Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx','Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx','Microsoft-Windows-Windows Defender%4Operational.evtx','Microsoft-Windows-Sysmon%4Operational.evtx','Microsoft-Windows-Bits-Client%4Operational.evtx');
```

`%4` in an EVTX filename is the literal on-disk encoding of `/` in a channel
name. If B0 times out, drop the `SEC` and `DG` branches first —
`windows_security_center` and `deviceguard_status` go through WSC COM and WMI
respectively and are the only slow parts of this bundle.

Reading it:

- `BOOT.a` = boot epoch. Nothing in any log predates it.
- `AUDIT` fields: 0 none, 1 success, 2 failure, 3 both. `audit_process_tracking = 0`
  means 4688 pattern hunting is worthless — go to B2. Legacy categories only, so
  a 0 is a hint, not proof (see SKILL.md §7).
- `TBL` is the ground truth for what exists on **this agent**. A table missing
  here is missing, whatever the canonical schema says.
- `FLAG.windows_event_channels` lists the only channels `windows_events` can
  hold — `Security,Application,System` on this fleet's agent options. Every other
  channel (PowerShell, TaskScheduler, TerminalServices, WMI-Activity, Defender,
  Bits-Client, Sysmon, Firewall) is reachable **only** through
  `windows_eventlog`. Empty or absent → `windows_events` is useless.
- `FLAG.events_expiry` is 3600 s here, `events_max` 50000. That is the hard
  ceiling on how far back any evented table can see.
- `PUB.events = 0` with `active = 1` on a publisher means it is running and has
  seen nothing since expiry, not that it is broken.
- `SYSMON.*` present → **stop planning around Security-channel event ids and go
  to the S-bundles.** The service is named `Sysmon` **or** `Sysmon64` — the name
  reflects the installer's architecture, not the version, so match both.
  `SysmonDrv\Parameters` carries `ConfigFile`, `ConfigHash`, `ArchiveDirectory`,
  `Options`, `HashingAlgorithm`, `CheckRevocation`, `DnsLookup` and `Rules`.
  **`ConfigHash` is a one-query config-drift check across the whole estate** —
  hosts whose hash differs are running different coverage, and a lab or estate
  usually has one or two odd ones out. `ConfigFile` may be a relative path
  (`.\sysmonconfig.xml`), which tells you nothing about where the file now is.
  `HashingAlgorithm` of `-2147483633` (0x8000000F) means all four algorithms,
  so `Hashes` will carry IMPHASH. **`DnsLookup = 00` disables reverse DNS**, so
  event 3's `DestinationHostname` comes back empty — read that value before
  promising yourself hostnames in S-NET. `SYSMON.SVC` gives the service and its binary,
  `SYSMON.DRV` the filter driver (absent driver with present service = Sysmon is
  installed but not collecting), `SYSMON.CFG.mtime` is when the config was last
  written — a config write inside the incident window is itself a finding
  (T1562.001).
- `EVTX` sizes are the cheapest log-tamper tell available: a `Security.evtx` of
  a few hundred KB on a host with weeks of uptime, or a `mtime` far from now,
  contradicts a busy channel. Corroborate with E-CLEAR, never conclude alone.

**Retention bracket** (two cheap probes, only when the alert is older than
~24 h). Substitute real ISO 8601 UTC bounds:

```sql
SELECT channel, count(*) AS n FROM windows_eventlog WHERE channel = 'Security' AND time_range = '2026-09-01T00:00:00.000Z;2026-09-01T00:30:00.000Z';
```

Zero rows there plus non-zero at `timestamp = '3600000'` means retention does
not reach the incident window — say so instead of reporting "no evidence".

---

## B1 PERSISTENCE — durable config surfaces

Cost: cheap. `services` may be wide on servers; the `LIMIT`s hold it down.
ATT&CK: T1543.003, T1053.005, T1547.001, T1546.003, T1546.011, T1574.001,
T1021.002, T1014, T1068.

```sql
SELECT * FROM (SELECT 'PERSIST.SVC' AS sig, 'T1543.003' AS attck, name AS a, path AS b, start_type AS c, user_account AS d FROM services WHERE path NOT LIKE 'C:\Windows\%' AND path NOT LIKE 'C:\Program Files%' AND path != '' LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'PERSIST.SVC.REMOTEEXEC','T1569.002', name, path, status, display_name FROM services WHERE name LIKE '%PSEXESVC%' OR name LIKE '%PAExec%' OR name LIKE '%RemCom%' OR name LIKE '%CSExec%' OR path LIKE '%psexesvc%' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'PERSIST.TASK','T1053.005', name, action, state, path FROM scheduled_tasks WHERE name NOT LIKE '\Microsoft\%' LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'PERSIST.TASK.HIDDEN','T1053.005', name, action, CAST(hidden AS TEXT), last_run_message FROM scheduled_tasks WHERE hidden = 1 LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'PERSIST.STARTUP','T1547.001', name, path, source, username FROM startup_items LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'PERSIST.AUTOEXEC','T1547.001', name, path, source, '' FROM autoexec LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'PERSIST.WMI.CONSUMER','T1546.003', name, COALESCE(command_line_template, executable_path), class, namespace FROM wmi_cli_event_consumers LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'PERSIST.WMI.SCRIPT','T1546.003', name, substr(script_text,1,300), scripting_engine, namespace FROM wmi_script_event_consumers LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'PERSIST.WMI.FILTER','T1546.003', name, substr(query,1,300), query_language, namespace FROM wmi_event_filters LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'PERSIST.WMI.BIND','T1546.003', consumer, filter, class, namespace FROM wmi_filter_consumer_binding LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'PERSIST.SHIM','T1546.011', executable, path, description, sdb_id FROM appcompat_shims LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'DEFEND.DRIVER','T1068', device_name, image, provider, CAST(signed AS TEXT) FROM drivers WHERE signed = 0 OR image NOT LIKE 'C:\Windows\%' LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'LATERAL.SHARE','T1021.002', name, path, type_name, description FROM shared_resources LIMIT 50);
```

Notes:

- `services.path` is the binary; `services.module_path` is the hosting DLL for
  svchost-style services — check both before clearing a service.
- `autoexec` is a synthetic union of startup sources; it overlaps
  `startup_items` and the run keys. Overlap is a corroboration signal, not noise.
- A WMI **binding** row with a consumer and filter you cannot attribute is the
  finding. Consumers alone are common; bindings are how the subscription fires.
- `drivers.signed = 0` on a modern build is rare and high-signal. A signed but
  known-vulnerable driver is B7's job (LOLDrivers rule files).

### B1R REGISTRY AUTOSTARTS — separate query, times out first more often

Cost: cheap-to-medium. Registry walks are the classic first-fire timeout; keep
this out of B1 so a retry costs one branch, not thirteen.

**Hive names must be full.** `HKLM` / `HKCU` short forms resolve to no hive and
return zero rows. `HKEY_CURRENT_USER` is not queryable by the agent at all
(it runs as SYSTEM) — reach user hives through `HKEY_USERS\%\…` or an explicit
SID.

```sql
SELECT 'PERSIST.RUN' AS sig, 'T1547.001' AS attck, key AS a, name AS b, data AS c, CAST(mtime AS TEXT) AS d FROM registry WHERE key IN ('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run','HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run','HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
UNION ALL SELECT 'PERSIST.RUN.USER','T1547.001', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run'
UNION ALL SELECT 'PERSIST.RUN.USER','T1547.001', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\RunOnce'
UNION ALL SELECT 'PERSIST.WINLOGON','T1547.004', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' AND name IN ('Userinit','Shell','Taskman','AppSetup','GinaDLL')
UNION ALL SELECT 'PERSIST.IFEO','T1546.012', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%' AND name IN ('Debugger','GlobalFlag','ReportingMode','MonitorProcess')
UNION ALL SELECT 'PERSIST.APPINIT','T1546.010', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key IN ('HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows','HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') AND name IN ('AppInit_DLLs','LoadAppInit_DLLs','Load','Run')
UNION ALL SELECT 'CRED.LSA.PKG','T1547.005', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa' AND name IN ('Security Packages','Authentication Packages','Notification Packages','RunAsPPL','LsaCfgFlags')
UNION ALL SELECT 'PERSIST.LOGONSCRIPT','T1037.001', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_USERS\%\Environment' AND name = 'UserInitMprLogonScript'
UNION ALL SELECT 'PERSIST.ACCESSIBILITY','T1546.008', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe%' OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe%'
UNION ALL SELECT 'DEFEND.RDP','T1021.001', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server' AND name IN ('fDenyTSConnections','fSingleSessionPerUser')
UNION ALL SELECT 'CRED.WDIGEST','T1003.001', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest' AND name = 'UseLogonCredential'
UNION ALL SELECT 'DEFEND.AVOFF','T1562.001', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender%' OR key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinDefend'
UNION ALL SELECT 'DEFEND.LOGOFF','T1562.002', key, name, data, CAST(mtime AS TEXT) FROM registry WHERE key LIKE 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog%' OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell%';
```

`registry.mtime` is the key write time — the closest thing to a persistence
installation timestamp, and it survives a log clear. Correlate every hit's
`mtime` against the incident window before dismissing it as pre-existing.

COM hijack coverage (`…\Software\Classes\CLSID\%\InprocServer32`, T1546.015) is
deliberately **not** in this bundle: the walk is expensive-class. Fire it alone,
scoped to one hive, only when a COM-hijack hypothesis exists.

---

## B2 EXECUTION — durable execution evidence, works with auditing off

Cost: cheap. This is the bundle that answers "what ran" when 4688 is disabled
and Security was cleared. ATT&CK: T1204.002, T1059.001, T1059.003, T1218.*,
T1036.005.

```sql
SELECT 'EXEC.SHIMCACHE' AS sig, 'T1204.002' AS attck, path AS a, CAST(modified_time AS TEXT) AS b, CAST(entry AS TEXT) AS c, CAST(execution_flag AS TEXT) AS d FROM shimcache WHERE entry <= 128
UNION ALL SELECT * FROM (SELECT 'EXEC.PREFETCH','T1204.002', path, CAST(last_run_time AS TEXT), CAST(run_count AS TEXT), filename FROM prefetch WHERE last_run_time > strftime('%s','now') - 604800 LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'EXEC.USERASSIST','T1204.002', path, CAST(last_execution_time AS TEXT), CAST(count AS TEXT), sid FROM userassist WHERE last_execution_time > strftime('%s','now') - 604800 LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'EXEC.BAM','T1204.002', path, CAST(last_execution_time AS TEXT), '', sid FROM background_activities_moderator WHERE last_execution_time > strftime('%s','now') - 604800 LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'EXEC.LIVE','T1057', path, CAST(start_time AS TEXT), substr(cmdline,1,300), CAST(pid AS TEXT) FROM processes WHERE start_time > strftime('%s','now') - 604800 LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'EXEC.ETW','T1059', path, CAST(time AS TEXT), substr(cmdline,1,300), username FROM process_etw_events WHERE time > 0 AND type = 'ProcessStart' LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'EXEC.PS.BLOCK','T1059.001', script_path, CAST(time AS TEXT), substr(script_text,1,400), script_name FROM powershell_events WHERE time > 0 LIMIT 100);
```

Reading it:

- **shimcache** is ordered evidence: `entry = 1` is the most recent execution.
  On Win10+ `execution_flag` is `-1` (absent) — that is not "did not execute".
  Cache is flushed to disk at shutdown, so a host that has not rebooted since
  the incident may hold the entry in memory only.
- **prefetch** gives run counts, first/last run and the accessed-file list —
  `accessed_files` is how you tie a dropper to what it touched. Prefetch may be
  disabled on SSD-backed servers; B0's `TBL` shows the table, not the setting.
- **BAM** and **UserAssist** are per-SID: they attribute execution to a user.
  UserAssist covers Explorer-launched GUI programs; BAM covers background
  execution. Neither is complete alone; together they are strong.
- **ETW/PowerShell** rows are limited by `events_expiry` (often 900 s). Present
  = high fidelity, absent = says nothing.
- Suspicion ranking for the paths that come back: user-writable directory
  (`\AppData\`, `\Temp\`, `\Downloads\`, `\Public\`, `\ProgramData\`), a system
  binary name outside `System32`, a double extension, an RMM/remote-admin tool
  the estate does not deploy, or an unsigned binary (confirm with a targeted
  `authenticode` query, see B6).

---

## B3 ACCOUNTS AND ACCESS — who is, and was, on the box

Cost: cheap. ATT&CK: T1136.001, T1098, T1078.*, T1021.001, T1069.001, T1033.

```sql
SELECT * FROM (SELECT 'IAM.USER' AS sig, 'T1136.001' AS attck, username AS a, CAST(uid AS TEXT) AS b, directory AS c, description AS d FROM users LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'IAM.GROUP','T1069.001', groupname, group_sid, comment, CAST(gid AS TEXT) FROM groups LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'IAM.MEMBER','T1069.001', (SELECT username FROM users u WHERE u.uid = user_groups.uid), (SELECT groupname FROM groups g WHERE g.gid = user_groups.gid), CAST(uid AS TEXT), CAST(gid AS TEXT) FROM user_groups LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'IAM.SESSION','T1078', user, logon_type, CAST(logon_time AS TEXT), logon_domain || '\' || COALESCE(logon_server,'') FROM logon_sessions LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'IAM.LOGGEDIN','T1033', user, type, CAST(time AS TEXT), COALESCE(host,'') FROM logged_in_users LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'IAM.DOMAIN','T1016', name, domain_name, domain_controller_name, status FROM ntdomains LIMIT 20)
UNION ALL SELECT * FROM (SELECT 'IAM.PROFILE','T1078', path, filename, CAST(btime AS TEXT), CAST(mtime AS TEXT) FROM file WHERE directory = 'C:\Users' LIMIT 100);
```

`logon_sessions` is live LSA state: it **survives `wevtutil cl`** and is the
durable access timeline when Security is gone. `logon_type` is TEXT with spaces
(`Remote Interactive`, `Network Cleartext`, `New Credentials`) — never compare
it to the numeric Security-event logon types. `New Credentials` (runas
/netonly) and `Network Cleartext` both deserve a second look.

A profile directory in `C:\Users` with no matching `users` row means the account
was deleted after logging on — a hard finding, and a common post-intrusion
cleanup artefact.

---

## B4 NETWORK — live state and local resolver cache

Cost: cheap. ATT&CK: T1071.001, T1071.004, T1090, T1571, T1572, T1049, T1562.004.

```sql
SELECT * FROM (SELECT 'NET.LISTEN' AS sig, 'T1571' AS attck, CAST(l.port AS TEXT) AS a, l.address AS b, p.path AS c, CAST(l.protocol AS TEXT) AS d FROM listening_ports l LEFT JOIN processes p ON l.pid = p.pid LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'NET.CONN','T1071.001', s.remote_address || ':' || CAST(s.remote_port AS TEXT), s.state, p.path, CAST(s.pid AS TEXT) FROM process_open_sockets s LEFT JOIN processes p ON s.pid = p.pid WHERE s.remote_address != '' AND s.remote_address NOT LIKE '127.%' AND s.remote_address != '::' LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'NET.DNSCACHE','T1071.004', name, type, '', '' FROM dns_cache LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'NET.ARP','T1016', address, mac, interface, permanent FROM arp_cache LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'DEFEND.FWRULE','T1562.004', name, app_name, action || '/' || direction, COALESCE(remote_addresses,'') FROM windows_firewall_rules WHERE enabled = 1 AND action != 'Block' AND direction = 'In' LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'NET.PIPE','T1021.002', name, CAST(pid AS TEXT), CAST(instances AS TEXT), flags FROM pipes LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'NET.HOSTS','T1565.001', address, hostnames, '', '' FROM etc_hosts LIMIT 100);
```

- `listening_ports.protocol`: 6 TCP, 17 UDP. `family`: 2 IPv4, 23 IPv6.
- Every listener must map to a process you can name. An unmapped listener, or a
  listener whose process path is user-writable, is the finding.
- `dns_cache` is a survivor: it holds resolutions long after an evented DNS
  buffer has expired, and it is the cheapest C2-domain corroboration available.
- Named pipes are how PsExec-class tooling, Cobalt Strike SMB beacons and many
  agents talk. A pipe name that is a GUID or random string, with no owning
  process you recognise, is worth an OSINT lookup.
- An inbound `Allow` firewall rule whose `app_name` sits in a user directory is
  a persistence-adjacent finding, not a hygiene note.

---

## B5 BROWSER AND DOWNLOAD ORIGIN — where it came from

Cost: cheap. These are ATC tables: present on this fleet by agent options
(`edge_url_history`, `chrome_url_history`, `firefox_url_history`,
`chrome_download_history`), every column TEXT, and **zero rows when the browser
holds the `History` file locked** — a running Chrome is the usual reason this
comes back empty. ATT&CK: T1189, T1204.002, T1566.002, T1105.

```sql
SELECT 'WEB.EDGE' AS sig, 'T1189' AS attck, url AS a, title AS b, CAST(CAST(last_visit_time AS INTEGER)/1000000 - 11644473600 AS TEXT) AS c, visit_count AS d FROM edge_url_history WHERE CAST(last_visit_time AS INTEGER) > (strftime('%s','now') - 604800 + 11644473600) * 1000000
UNION ALL SELECT * FROM (SELECT 'WEB.CHROME','T1189', url, title, CAST(CAST(last_visit_time AS INTEGER)/1000000 - 11644473600 AS TEXT), visit_count FROM chrome_url_history WHERE CAST(last_visit_time AS INTEGER) > (strftime('%s','now') - 604800 + 11644473600) * 1000000 LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'WEB.FIREFOX','T1189', url, title, CAST(CAST(last_visit_date AS INTEGER)/1000000 AS TEXT), visit_count FROM firefox_url_history WHERE CAST(last_visit_date AS INTEGER) > (strftime('%s','now') - 604800) * 1000000 LIMIT 300)
UNION ALL SELECT * FROM (SELECT 'WEB.DOWNLOAD','T1105', target_path, current_path, '', id FROM chrome_download_history LIMIT 200);
```

Referrer chain for one suspect URL — how the user got there, which separates a
typed visit from a redirect chain (Chrome only; Edge's ATC table omits
`from_visit`/`transition`):

```sql
SELECT 'WEB.REFERRER' AS sig, 'T1189' AS attck, h.url AS a, h.title AS b, h.transition AS c, p.url AS d FROM chrome_url_history h LEFT JOIN chrome_url_history p ON CAST(h.from_visit AS INTEGER) = CAST(p.id AS INTEGER) WHERE h.url LIKE '%<DOMAIN>%' LIMIT 100;
```

Reading it:

- A `WEB.DOWNLOAD` `target_path` that matches a `FILE.DROP` or `EXEC.PREFETCH`
  path is initial access, established. The download table has no timestamp — take
  the landing time from `file.btime` and label it inferred.
- `current_path` different from `target_path` means the download was still in
  flight (`.crdownload`) or was moved afterwards.
- A `transition` of `link` or `redirect` into an executable download, with no
  typed visit anywhere in the chain, is drive-by shaped. A typed visit is
  user-initiated and changes the conversation with the user, not the technical
  finding.
- No Edge or Firefox download table exists. For those browsers, pair the visited
  URL with `FILE.DROP` on `\Downloads` and say the link is inferred.
- URLs are the one artefact class safe to send to OSINT (§4 of
  `pivot-and-osint.md`) — the domain, not the full URL with its query string.

## E-bundles — EVTX, one channel per query, pushdown always

Cost: cheap **because** of pushdown. `eventid IN (…)` + `timestamp = '<ms>'`
become an XPath filter inside `EvtQuery`; the channel is not walked. Never drop
either constraint.

Selecting `substr(data,1,800)` keeps the row small; use
`json_extract(data,'$.EventData.<Field>')` when you need one specific field out
of an already-filtered set.

### E-AUTH — logons, privilege, account and group change (T1078, T1136.001, T1098, T1550.002)

```sql
SELECT 'AUTH.LOGON' AS sig, 'T1078' AS attck, eventid, datetime, json_extract(data,'$.EventData.TargetUserName') AS user, json_extract(data,'$.EventData.LogonType') AS logon_type, json_extract(data,'$.EventData.IpAddress') AS src_ip, json_extract(data,'$.EventData.ProcessName') AS proc FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4624,4625,4648,4672,4776,4771,4768,4769) AND timestamp = '604800000' LIMIT 400;
```

```sql
SELECT 'IAM.CHANGE' AS sig, 'T1098' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4740,4756,4757,4767,4798,4799) AND timestamp = '604800000' LIMIT 200;
```

Event-code logon types (numeric, Security channel only — a different vocabulary
from `logon_sessions.logon_type`): 2 interactive, 3 network, 4 batch, 5 service,
7 unlock, 8 network cleartext, 9 new credentials, 10 remote interactive (RDP),
11 cached interactive.

Targeted source-IP hunt, only after E-CLEAR shows the channel is intact:

```sql
SELECT 'AUTH.LOGON.IP' AS sig, 'T1078' AS attck, eventid, datetime, substr(data,1,800) AS data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4624,4625) AND timestamp = '604800000' AND data LIKE '%<IP>%' LIMIT 100;
```

### E-PROC — process creation and audit-policy state (T1059, T1218.*, T1036.005)

Probe first — one number decides whether pattern hunting means anything:

```sql
SELECT 'AUDIT.4688' AS sig, 'T1562.002' AS attck, count(*) AS n FROM windows_eventlog WHERE channel = 'Security' AND eventid = 4688 AND timestamp = '86400000';
```

`n = 0` → process auditing is off (cross-check `AUDIT` in B0); stop here and use
B2. `n > 0` → hunt the patterns:

```sql
SELECT 'EXEC.4688' AS sig, 'T1059' AS attck, datetime, json_extract(data,'$.EventData.NewProcessName') AS proc, json_extract(data,'$.EventData.ParentProcessName') AS parent, json_extract(data,'$.EventData.CommandLine') AS cmdline, json_extract(data,'$.EventData.SubjectUserName') AS user FROM windows_eventlog WHERE channel = 'Security' AND eventid = 4688 AND timestamp = '604800000' LIMIT 500;
```

Filter client-side for: `-enc`/`-EncodedCommand`, `-w hidden`, `-nop`,
`DownloadString`, `DownloadFile`, `IEX`, `FromBase64String`,
`certutil -urlcache`, `certutil -decode`, `bitsadmin /transfer`,
`regsvr32 /i:http`, `rundll32 javascript:`, `mshta http`, `wmic process call
create`, `msiexec /i http`, `curl -o`, `Invoke-WebRequest`, `vssadmin delete
shadows`, `wbadmin delete`, `bcdedit /set`, `wevtutil cl`, `net user /add`,
`net localgroup administrators /add`, `reg save hklm\sam`, `nltest`,
`whoami /priv`, unusual parents (`winword.exe`/`excel.exe`/`outlook.exe` →
shell), and `svchost.exe` with a parent that is not `services.exe`.

Doing the filtering client-side beats stacking `LIKE`s: a multi-`eventid` +
multi-`LIKE` predicate is the slowest query class on a loaded host, and the
pushdown has already cut the result to a readable size.

### E-PS — PowerShell (T1059.001, T1027.010)

```sql
SELECT 'EXEC.PS' AS sig, 'T1059.001' AS attck, eventid, datetime, substr(json_extract(data,'$.EventData.ScriptBlockText'),1,1500) AS script, json_extract(data,'$.EventData.Path') AS path FROM windows_eventlog WHERE channel = 'Microsoft-Windows-PowerShell/Operational' AND eventid IN (4103,4104) AND timestamp = '604800000' LIMIT 200;
```

Legacy engine channel, worth a shot when the modern one is empty:

```sql
SELECT 'EXEC.PS.LEGACY' AS sig, 'T1059.001' AS attck, eventid, datetime, substr(data,1,1000) AS data FROM windows_eventlog WHERE channel = 'Windows PowerShell' AND eventid IN (400,403,600,800) AND timestamp = '604800000' LIMIT 100;
```

4104 at `level = 3` (warning) is the suspicious-block classification Microsoft
applies itself — sort on it first. Empty 4104 with a healthy channel means
script-block logging is off, not that PowerShell did not run.

### E-SYS — services, drivers, boot, shutdown (T1543.003, T1489, T1562.001, T1014)

```sql
SELECT 'PERSIST.SVCINSTALL' AS sig, 'T1543.003' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'System' AND eventid IN (7045,7040,7034,7031,7000,7009,104,6005,6006,6008,1074,219) AND timestamp = '604800000' LIMIT 200;
```

`7045` names the service, its image path and start type — the single highest-value
System event. `7040` (start type changed) is how a service is disabled without
being deleted. `104` is a System-channel log clear.

### E-TASK — scheduled task lifecycle (T1053.005)

```sql
SELECT 'PERSIST.TASKEVENT' AS sig, 'T1053.005' AS attck, eventid, datetime, substr(data,1,500) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-TaskScheduler/Operational' AND eventid IN (106,140,141,200,201,325,329) AND timestamp = '604800000' LIMIT 200;
```

Security-channel equivalents, when the TaskScheduler channel is disabled:
`eventid IN (4698,4699,4700,4701,4702)` on `channel = 'Security'`.

### E-RDP — remote desktop, with the client IP (T1021.001)

Two different channels; do not conflate them.

```sql
SELECT 'LATERAL.RDP.AUTH' AS sig, 'T1021.001' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' AND eventid IN (1149,261) AND timestamp = '604800000' LIMIT 100;
```

```sql
SELECT 'LATERAL.RDP.SESSION' AS sig, 'T1021.001' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' AND eventid IN (21,22,23,24,25,39,40) AND timestamp = '604800000' LIMIT 100;
```

- `1149` (RemoteConnectionManager) = authentication succeeded, carries the
  source network address.
- `21`/`25` (LocalSessionManager) = session logon / reconnection, also carry the
  source address.
- Both channels are **separate from Security**: a Security-only clear leaves them
  intact. This is how you recover an attacker's client IP after 1102.
- Their `data` arrives under `UserData`, not `EventData` — use
  `json_extract(data,'$.UserData…')` or read `substr(data,1,600)` and parse.

### E-WMI — WMI activity (T1047, T1546.003)

```sql
SELECT 'EXEC.WMI' AS sig, 'T1047' AS attck, eventid, datetime, substr(data,1,700) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-WMI-Activity/Operational' AND eventid IN (5857,5858,5859,5860,5861) AND timestamp = '604800000' LIMIT 200;
```

`5861` is the permanent-event-subscription record — the event-log counterpart of
B1's WMI binding rows. Two independent sources agreeing is a confirmed finding.

### E-DEFENDER — AV detections and tampering (T1562.001)

```sql
SELECT 'DETECT.AV' AS sig, 'T1562.001' AS attck, eventid, datetime, substr(data,1,700) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Windows Defender/Operational' AND eventid IN (1006,1007,1008,1009,1015,1116,1117,1118,1119,5001,5004,5007,5010,5012,5013) AND timestamp = '604800000' LIMIT 200;
```

`1116`/`1117` are detection and action-taken. `5001`/`5010`/`5012` are
real-time/scanning disabled — tampering, and often the first move.

### E-FW — filtering platform and firewall policy (T1562.004, T1571)

WFP connection events live in **Security**, not the Firewall channel. Getting
this backwards returns zero rows and reads like a clean host.

```sql
SELECT 'NET.WFP' AS sig, 'T1571' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (5140,5145,5152,5154,5156,5157,5158) AND timestamp = '86400000' LIMIT 300;
```

```sql
SELECT 'DEFEND.FWCHANGE' AS sig, 'T1562.004' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' AND eventid IN (2004,2005,2006,2009,2033) AND timestamp = '604800000' LIMIT 100;
```

`5156` volume is enormous — keep the window at 24 h or narrow with a
`data LIKE '%<IP>%'` predicate for a known indicator.

### E-CLEAR — log integrity (T1070.001, T1562.002)

```sql
SELECT 'LOG.CLEAR' AS sig, 'T1070.001' AS attck, eventid, datetime, substr(data,1,400) AS data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (1102,4719,4907,4906,1100) AND timestamp = '2592000000' LIMIT 50;
```

```sql
SELECT 'LOG.CLEAR.SYS' AS sig, 'T1070.001' AS attck, eventid, datetime, substr(data,1,400) AS data FROM windows_eventlog WHERE channel = 'System' AND eventid = 104 AND timestamp = '2592000000' LIMIT 50;
```

A clear removes its own `1102`. Absence proves nothing on its own — combine with
B0's `EVTX` file sizes, the retention bracket, and boot time. `4719` (audit
policy changed) is the quieter cousin: it turns collection off without leaving a
gap that looks like a gap.

### E-BITS — background transfer abuse (T1197, T1105)

```sql
SELECT 'EXEC.BITS' AS sig, 'T1197' AS attck, eventid, datetime, substr(data,1,600) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Bits-Client/Operational' AND eventid IN (3,4,59,60,61) AND timestamp = '604800000' LIMIT 100;
```

### E-SYSMON — superseded

When Sysmon is present, use the **S-bundles** below instead of a flat event-id
sweep. They extract the fields that make Sysmon worth having.

---

## S-bundles — Sysmon, and why they outrank the Security channel

Fire these instead of `E-PROC` whenever B0 reports `SYSMON.SVC` **and**
`SYSMON.DRV`. Channel: `Microsoft-Windows-Sysmon/Operational`. Every Sysmon
event puts its fields under `EventData`, so
`json_extract(data,'$.EventData.<Field>')` works directly, and `eventid IN` +
`timestamp` still push down into `EvtQuery`.

What you gain over Security-channel ids — this is why the substitution is worth
making, not a stylistic preference:

| Question | Security channel | Sysmon |
|---|---|---|
| what ran, with arguments | 4688, and only if the "include command line" policy is on | event 1: `CommandLine` **and** `ParentCommandLine`, always |
| is the binary what it claims | nothing | event 1: `Hashes` (MD5/SHA256/IMPHASH) + `OriginalFileName` — catches renamed system binaries (T1036.003) |
| process lineage across pid reuse | none — 4688 has no GUID | `ProcessGuid` / `ParentProcessGuid` |
| which process made this connection | 5156 (off by default, very noisy) | event 3: process, user, resolved hostname, both endpoints |
| which process resolved this domain | nothing (`dns_lookup_events` expires in ~1 h) | event 22: `QueryName`, `QueryResults`, `Image` |
| DLL sideloading | nothing | event 7: `ImageLoaded` + `Signed` + `SignatureStatus` |
| who touched LSASS | 4656/4663, and only with a SACL on the object | event 10: `GrantedAccess` + `CallTrace` |
| registry autostart writes | 4657, and only with a SACL | events 12/13: `TargetObject`, `Details` |
| MOTW / alternate data streams | nothing | event 15: `Contents`, `Hash` |
| a file deleted to cover tracks | nothing | event 23: `TargetFilename`, `Hashes`, `Archived` |
| process hollowing | nothing | event 25: `Type` |

**Sysmon present is not Sysmon complete.** Coverage is entirely a function of
the config XML, and the common public configs exclude large swathes of activity.
Run the profile probe first — one query, and it is the Sysmon equivalent of the
4688 count probe.

### S-PROFILE — which event ids this config actually emits (gate)

```sql
SELECT 'SYSMON.PROFILE' AS sig, 'T1562.001' AS attck, eventid, count(*) AS n FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,25,255) AND timestamp = '86400000' GROUP BY eventid;
```

An event id with `n = 0` is excluded by config **or** genuinely did not happen.
Absence there proves nothing on its own, and you must say so rather than
reporting "no injection observed". Two zeros are **provable exclusions**, because
the paired id makes them arithmetically impossible:

| Zero id | Paired id non-zero | Conclusion |
|---|---|---|
| 5 ProcessTerminate | 1 ProcessCreate | processes were created, so they terminated — the config drops 5 |
| 18 PipeConnected | 17 PipeCreated | pipes were created, so they were connected — the config drops 18 |
| 2 FileCreateTime or 11 FileCreate | 23 FileDelete | files were deleted, so they existed |

Everything else (6, 8, 9, 14, 15, 19–21, 23) is genuinely ambiguous from this
probe. Say "ambiguous — id absent, config coverage unknown", never "did not
occur".

**A non-zero count is not coverage — check the ratio.** Verified live: a domain
controller emitted `1` ProcessTerminate against `187` ProcessCreate in the same
24 h. Event 5 is not excluded there, it is scoped by a narrow *include* rule, and
a naive "non-zero means covered" read would trust a feed that sees one event in
two hundred. Sanity ratios: 5 should roughly track 1; 18 should track 17; 13 and
12 should be the same order of magnitude on a workstation. An id that is
non-zero but two or more orders of magnitude below its pair is **effectively
excluded** — treat it as ambiguous and say so.

**Two hosts on different `ConfigHash` values have different hunt capabilities.**
Verified live in one small estate: the config on three hosts emitted 5,225
event-12 records in 24 h while a fourth host, on a different `ConfigHash`,
emitted **zero** event 12 and 2,795 event 13. Registry-key creation was simply
not collected there. Run `S-PROFILE` per host rather than assuming the estate is
uniform, and group hosts by `ConfigHash` from B0 before generalising any finding
across them.

Two coverage gaps to check for explicitly, because the routing in `SKILL.md` §8
leans on them:

- **event 15 (`FileCreateStreamHash`) at zero** removes the mark-of-the-web
  origin from the phishing route. Fall back to B5 browser history and
  `FILE.RECENT`.
- **event 23 (`FileDelete`) at zero while `ArchiveDirectory` is set** means
  archiving is configured but the config's rules match nothing — the deleted-file
  hash pivot is unavailable. Fall back to `EXEC.SHIMCACHE` and `EXEC.PREFETCH`,
  which survive the file itself.

**Sysmon channel retention is shorter than you expect on a noisy host.** The
default `maxsize` puts the EVTX at ~64 MiB (`67112960` bytes in B0's `EVTX` row);
a workstation emitting 26k `FileCreate` and 12k `ImageLoad` events per day fills
and wraps that in a day or two. Bracket Sysmon retention with `time_range` the
same way you bracket Security (B0), and never assume the channel reaches back as
far as the Security channel does.

### S-PROC — process creation with full context (T1059, T1036.003, T1218.*)

```sql
SELECT 'SYSMON.PROC' AS sig, 'T1059' AS attck, datetime, json_extract(data,'$.EventData.Image') AS image, json_extract(data,'$.EventData.CommandLine') AS cmdline, json_extract(data,'$.EventData.ParentImage') AS parent, substr(json_extract(data,'$.EventData.ParentCommandLine'),1,300) AS parent_cmdline, json_extract(data,'$.EventData.User') AS user, json_extract(data,'$.EventData.IntegrityLevel') AS integrity, json_extract(data,'$.EventData.OriginalFileName') AS original_name, json_extract(data,'$.EventData.Hashes') AS hashes, json_extract(data,'$.EventData.ProcessGuid') AS pguid, json_extract(data,'$.EventData.ParentProcessGuid') AS parent_guid FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid = 1 AND timestamp = '86400000' LIMIT 500;
```

- `OriginalFileName` != the filename in `Image` is a renamed binary. This is the
  cheapest LOLBin-rename detection that exists.
- `Hashes` is a single string, `SHA256=…,IMPHASH=…` per the config's
  `HashAlgorithms`. Split it client-side; **IMPHASH is the strongest OSINT pivot
  Sysmon gives you** (see `pivot-and-osint.md` §1).
- Build the tree from `ProcessGuid` / `ParentProcessGuid`, never from pid — pids
  are reused and an attacker's short-lived process will collide.
- **Sysmon writes a literal `-` for a field it could not resolve**, and
  `ParentImage` / `ParentCommandLine` / `ParentProcessGuid` are the common
  casualties (verified live: `WmiPrvSE.exe` rows come back with
  `ParentImage = "-"`). Treat `-` as null. Never report a parent process named
  `-`, and never conclude "no parent" from it — fall back to `processes.parent`
  from `EXEC.LIVE`, or to the surrounding event-1 rows ordered by `datetime`.
- `IntegrityLevel` of `High`/`System` from a parent running as `Medium` is an
  elevation to explain (T1548.002).
- Same client-side pattern list as `E-PROC`; the pushdown has already cut the set.

### S-NET — network and DNS with process attribution (T1071.001, T1071.004, T1571)

```sql
SELECT 'SYSMON.NET' AS sig, 'T1071.001' AS attck, datetime, json_extract(data,'$.EventData.Image') AS image, json_extract(data,'$.EventData.User') AS user, json_extract(data,'$.EventData.DestinationIp') AS dst_ip, json_extract(data,'$.EventData.DestinationPort') AS dst_port, json_extract(data,'$.EventData.DestinationHostname') AS dst_host, json_extract(data,'$.EventData.Protocol') AS proto, json_extract(data,'$.EventData.Initiated') AS initiated FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid = 3 AND timestamp = '86400000' LIMIT 500;
```

```sql
SELECT 'SYSMON.DNS' AS sig, 'T1071.004' AS attck, datetime, json_extract(data,'$.EventData.QueryName') AS query, json_extract(data,'$.EventData.QueryStatus') AS status, substr(json_extract(data,'$.EventData.QueryResults'),1,300) AS results, json_extract(data,'$.EventData.Image') AS image FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid = 22 AND timestamp = '86400000' LIMIT 500;
```

`DestinationHostname` and `SourceHostname` are populated only when the config
leaves reverse DNS on. B0's `SYSMON.CFG` row shows `DnsLookup`; `00` means both
come back empty and you resolve the IP yourself (B4 `NET.DNSCACHE`, S-DNS event
22, or OSINT). Do not report an empty `DestinationHostname` as "unresolvable".

Event 3 answers what `NET.CONN` cannot: the connection that has already closed,
with the process that made it. Event 22 is the only durable process-to-domain
mapping on the host — `dns_lookup_events` expires within the hour and
`dns_cache` has no process attribution.

### S-IMG — driver and image load (T1574.001, T1574.002, T1068, T1014)

```sql
SELECT 'SYSMON.IMGLOAD' AS sig, 'T1574.002' AS attck, eventid, datetime, json_extract(data,'$.EventData.Image') AS image, json_extract(data,'$.EventData.ImageLoaded') AS loaded, json_extract(data,'$.EventData.Signed') AS signed, json_extract(data,'$.EventData.SignatureStatus') AS sig_status, json_extract(data,'$.EventData.Hashes') AS hashes FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (6,7) AND timestamp = '86400000' LIMIT 400;
```

`Signed = false` on a DLL loaded from a user-writable directory by a signed
system binary is sideloading. Event 6 with `Signed = true` but a driver you
cannot attribute is the BYOVD case — pivot the hash into LOLDrivers, and the
path into B7's `loldrivers_*.yar` rule files.

### S-INJECT — injection, credential access, tampering (T1055, T1003.001, T1055.012)

```sql
SELECT 'SYSMON.INJECT' AS sig, 'T1055' AS attck, eventid, datetime, json_extract(data,'$.EventData.SourceImage') AS src_image, json_extract(data,'$.EventData.TargetImage') AS tgt_image, json_extract(data,'$.EventData.GrantedAccess') AS granted, substr(json_extract(data,'$.EventData.CallTrace'),1,400) AS call_trace, json_extract(data,'$.EventData.StartModule') AS start_module, json_extract(data,'$.EventData.Type') AS tamper_type FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (8,10,25) AND timestamp = '86400000' LIMIT 300;
```

- Event 10 with `TargetImage` ending `lsass.exe` and `GrantedAccess` containing
  read/VM rights (`0x1010`, `0x1410`, `0x1438`, `0x143a`) is credential dumping
  in progress — the single highest-value Sysmon event for T1003.001. Compare the
  source image against the estate's known EDR/AV agents before calling it.
- `CallTrace` entries with `UNKNOWN` frames mean unbacked memory: shellcode.
- Event 25 `Type` of `Image is replaced` is process hollowing (T1055.012).

### S-FILE — creation, streams, deletion, timestomping (T1105, T1564.004, T1070.004, T1070.006)

```sql
SELECT 'SYSMON.FILE' AS sig, 'T1105' AS attck, eventid, datetime, json_extract(data,'$.EventData.Image') AS image, json_extract(data,'$.EventData.TargetFilename') AS target, json_extract(data,'$.EventData.Hashes') AS hashes, json_extract(data,'$.EventData.Contents') AS stream_contents, json_extract(data,'$.EventData.PreviousCreationUtcTime') AS prev_ctime, json_extract(data,'$.EventData.IsExecutable') AS is_exe FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (2,11,15,23) AND timestamp = '86400000' LIMIT 500;
```

- Event 15 is the mark-of-the-web record: `Contents` holds the `Zone.Identifier`
  with the download host and referrer. It ties a file to its origin even when
  browser history is gone — pair it with B5.
- Event 2 with a `PreviousCreationUtcTime` earlier than `CreationUtcTime` is
  timestomping (T1070.006), and it defeats the `btime` reasoning everything else
  relies on.
- Event 23 archives the deleted file's hash, so a wiped dropper is still
  identifiable and still sweepable fleet-wide.
- This covers what `ntfs_journal_events` cannot: the journal is scoped to
  Desktop/Downloads/Documents, Sysmon 11 is scoped only by its own config.

### S-REG — registry writes with the writing process (T1547.001, T1112, T1562.001)

```sql
SELECT 'SYSMON.REG' AS sig, 'T1112' AS attck, eventid, datetime, json_extract(data,'$.EventData.EventType') AS event_type, json_extract(data,'$.EventData.TargetObject') AS target, json_extract(data,'$.EventData.Details') AS details, json_extract(data,'$.EventData.Image') AS image FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (12,13,14) AND timestamp = '86400000' LIMIT 400;
```

`registry.mtime` from B1R tells you *when* a Run key was written; this tells you
**which process wrote it**. Two independent sources on the same persistence
artefact is what moves a finding to high confidence.

### S-PIPE / S-WMI — named pipes and WMI subscriptions (T1021.002, T1047, T1546.003)

```sql
SELECT 'SYSMON.PIPE' AS sig, 'T1021.002' AS attck, eventid, datetime, json_extract(data,'$.EventData.PipeName') AS pipe, json_extract(data,'$.EventData.Image') AS image FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (17,18) AND timestamp = '86400000' LIMIT 300;
```

```sql
SELECT 'SYSMON.WMI' AS sig, 'T1546.003' AS attck, eventid, datetime, json_extract(data,'$.EventData.Operation') AS op, json_extract(data,'$.EventData.User') AS user, json_extract(data,'$.EventData.Name') AS name, substr(json_extract(data,'$.EventData.Query'),1,300) AS query, json_extract(data,'$.EventData.Consumer') AS consumer, json_extract(data,'$.EventData.Destination') AS destination FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (19,20,21) AND timestamp = '604800000' LIMIT 200;
```

Sysmon 17/18 give the pipe **and its process** — B4's `NET.PIPE` gives only what
is open right now. Sysmon 19/20/21 record the subscription being *created*, with
the user who did it; B1's WMI tables show only that it exists.

### S-TAMPER — Sysmon's own integrity (T1562.001, T1562.002)

```sql
SELECT 'SYSMON.TAMPER' AS sig, 'T1562.001' AS attck, eventid, datetime, substr(data,1,500) AS data FROM windows_eventlog WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid IN (4,16,255) AND timestamp = '2592000000' LIMIT 100;
```

Event 4 is service state change, 16 is a config change, 255 is a Sysmon internal
error. A stop or a config rewrite inside the incident window is an anti-forensics
finding in its own right, and it explains a gap in the other S-bundles instead of
leaving it unexplained. Cross-check `SYSMON.CFG.mtime` from B0.

A freshly installed Sysmon with no history is expected, not tampering — check the
service install time (B1 `PERSIST.SVC`, E-SYS `7045`) before flagging it.

## B6 FILE SURFACE — one directory per query

Cost: medium. Never GLOB a tree in a hunt. ATT&CK: T1105, T1204.002, T1564.004,
T1036.005, T1070.006.

```sql
SELECT 'FILE.DROP' AS sig, 'T1105' AS attck, path, filename, CAST(size AS TEXT) AS size, CAST(mtime AS TEXT) AS mtime, CAST(btime AS TEXT) AS btime, type FROM file WHERE directory = 'C:\Users\<USER>\Downloads' AND mtime > strftime('%s','now') - 604800 LIMIT 200;
```

Rotate the directory, one query each, highest yield first:
`C:\Users\<USER>\Downloads`, `C:\Users\<USER>\AppData\Local\Temp`,
`C:\Windows\Temp`, `C:\Users\<USER>\Desktop` (then
`C:\Users\<USER>\OneDrive\Desktop` if empty or slow — it is usually a junction),
`C:\ProgramData`, `C:\Users\Public`,
`C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
`C:\Windows\System32\Tasks`.

Signature and hash for the specific candidates the earlier bundles named — never
for a directory:

```sql
SELECT 'FILE.SIG' AS sig, 'T1553.002' AS attck, a.path, a.result, a.subject_name, a.issuer_name, h.sha256 FROM authenticode a LEFT JOIN hash h ON h.path = a.path WHERE a.path IN ('<PATH1>','<PATH2>') LIMIT 20;
```

`authenticode.result` is lowercase: suspicious is
`result NOT IN ('trusted','valid')`. `hash` re-reads the file — one path at a
time, and never on a large binary during an active incident.

Recently touched user artefacts, cheap and often decisive for phishing:

```sql
SELECT * FROM (SELECT 'FILE.RECENT' AS sig, 'T1204.002' AS attck, r.path AS a, r.filename AS b, CAST(r.mtime AS TEXT) AS c, r.shortcut_path AS d FROM recent_files r WHERE r.mtime > strftime('%s','now') - 604800 LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'FILE.OFFICEMRU','T1566.001', path, application, CAST(last_opened_time AS TEXT), sid FROM office_mru WHERE last_opened_time > strftime('%s','now') - 604800 LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'FILE.SHELLBAG','T1083', path, source, CAST(modified_time AS TEXT), sid FROM shellbags LIMIT 200);
```

Filesystem journal, when the agent has the include paths configured:

```sql
SELECT 'FILE.JOURNAL' AS sig, 'T1105' AS attck, action, path, old_path, CAST(time AS TEXT) AS t, category FROM ntfs_journal_events WHERE time > 0 LIMIT 300;
```

`action` values are CamelCase: `FileCreation`, `FileDeletion`, `FileWrite`,
`FileRename_OldName`, `FileRename_NewName`, `AttributesChange`, plus the
`Directory*` forms. `FILE_CREATE`-style names match nothing.

---

## B7 YARA SWEEP — narrow rules, one location, hits only

Cost: expensive. Read `schema-contract.md` §9 first. Rule-file size, not scan
size, is what times out.

```sql
SELECT 'DETECT.YARA' AS sig, 'T1204.002' AS attck, path, sigrule, CAST(count AS TEXT) AS n, substr(matches,1,300) AS matches, tags FROM yara_file WHERE path GLOB 'C:\Windows\Temp\*' AND sigurl = '<ALLOWLISTED_RULE_URL>' AND count > 0;
```

- Pick the narrowest family file that matches the hypothesis (ransomware,
  infostealer, hacktool, loldrivers_maldriver) rather than an omnibus file.
- One location per query. Rotate the same directories as B6.
- Prove the pipeline works before reporting "clean": scan a path with a known
  benign test hit. A failed rule fetch or compile is indistinguishable from a
  clean scan in the result.
- `yara_process` (with `pid`) is for a specific suspicious PID from B2/B4 — not
  for sweeping every process.

---

## B9 CREDENTIAL ACCESS — targeted, after a lead

Cost: medium. ATT&CK: T1003.001, T1003.002, T1003.004, T1552.001, T1552.002,
T1555.004.

```sql
SELECT 'CRED.LSASS.HANDLE' AS sig, 'T1003.001' AS attck, CAST(h.pid AS TEXT) AS a, h.type AS b, h.access AS c, COALESCE(h.name,'') AS d FROM process_open_handles h WHERE h.pid IN (SELECT pid FROM processes WHERE name = 'lsass.exe') LIMIT 200;
```

Reverse direction — who else holds a handle into LSASS — is not expressible in
one cheap query; get there from the process list instead:

```sql
SELECT * FROM (SELECT 'CRED.SUSPECT.PROC' AS sig, 'T1003.001' AS attck, CAST(p.pid AS TEXT) AS a, p.path AS b, substr(p.cmdline,1,300) AS c, CAST(p.elevated_token AS TEXT) AS d FROM processes p WHERE p.path NOT LIKE 'C:\Windows\%' AND p.path NOT LIKE 'C:\Program Files%' AND p.path != '' LIMIT 200)
UNION ALL SELECT * FROM (SELECT 'CRED.DUMPFILE','T1003.001', path, filename, CAST(size AS TEXT), CAST(mtime AS TEXT) FROM file WHERE directory = 'C:\Windows\Temp' AND (filename LIKE '%.dmp' OR filename LIKE '%lsass%' OR filename LIKE '%.7z' OR filename LIKE '%.zip' OR filename LIKE '%.kirbi') LIMIT 100)
UNION ALL SELECT * FROM (SELECT 'CRED.CERT','T1552.004', COALESCE(path,''), common_name, issuer, store FROM certificates WHERE self_signed = 1 LIMIT 100);
```

Also fire the `CRED.WDIGEST` and `CRED.LSA.PKG` branches of B1R: a
`UseLogonCredential = 1` value, or an unfamiliar `Security Packages` entry, is
credential-theft preparation with a registry write time attached.

---

## B8 FLEET SWEEP — one query, whole estate

Cost: cheap per host, so scope it. Use `QUERY.RUN` with `platform='windows'`
(plus `fleet` / `label` when the estate is large). One query per IOC family, not
per host — never loop.

By hash (strongest, most expensive per host — scope the directory):

```sql
SELECT 'IOC.HASH' AS sig, 'T1105' AS attck, path, sha256 FROM hash WHERE directory = 'C:\Windows\Temp' AND sha256 = '<SHA256>';
```

By filename or path pattern (cheap, use as the wide first pass):

```sql
SELECT * FROM (SELECT 'IOC.PATH' AS sig, 'T1105' AS attck, path AS a, filename AS b, CAST(mtime AS TEXT) AS c, CAST(size AS TEXT) AS d FROM file WHERE path GLOB 'C:\Users\*\AppData\Local\Temp\<NAME>' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.PREFETCH','T1204.002', path, filename, CAST(last_run_time AS TEXT), CAST(run_count AS TEXT) FROM prefetch WHERE filename LIKE '%<NAME>%' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.SHIMCACHE','T1204.002', path, '', CAST(modified_time AS TEXT), CAST(entry AS TEXT) FROM shimcache WHERE path LIKE '%<NAME>%' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.SVC','T1543.003', name, path, start_type, user_account FROM services WHERE path LIKE '%<NAME>%' OR name LIKE '%<NAME>%' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.TASK','T1053.005', name, action, state, path FROM scheduled_tasks WHERE action LIKE '%<NAME>%' LIMIT 50);
```

By network indicator:

```sql
SELECT * FROM (SELECT 'IOC.CONN' AS sig, 'T1071.001' AS attck, s.remote_address AS a, CAST(s.remote_port AS TEXT) AS b, p.path AS c, CAST(s.pid AS TEXT) AS d FROM process_open_sockets s LEFT JOIN processes p ON s.pid = p.pid WHERE s.remote_address = '<IP>' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.DNS','T1071.004', name, type, '', '' FROM dns_cache WHERE name LIKE '%<DOMAIN>%' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.ARP','T1016', address, mac, interface, permanent FROM arp_cache WHERE address = '<IP>' LIMIT 20)
UNION ALL SELECT * FROM (SELECT 'IOC.WEB','T1189', url, title, '', visit_count FROM chrome_url_history WHERE url LIKE '%<DOMAIN>%' LIMIT 50)
UNION ALL SELECT * FROM (SELECT 'IOC.WEB','T1189', url, title, '', visit_count FROM edge_url_history WHERE url LIKE '%<DOMAIN>%' LIMIT 50);
```

Fleet-wide EVTX sweeps are affordable **only** with pushdown, and only for a
narrow event set:

```sql
SELECT 'IOC.AUTH' AS sig, 'T1078' AS attck, eventid, datetime, substr(data,1,400) AS data FROM windows_eventlog WHERE channel = 'Security' AND eventid IN (4624,4625) AND timestamp = '86400000' AND data LIKE '%<IP>%' LIMIT 50;
```

Before firing anything estate-wide, use `TARGET.RESOLVE` to see the host count.
A wide sweep is visible in EDR telemetry and costs device CPU on every host —
scope it, and say in the report how many hosts answered.

---

## Bundle index

| Bundle | Cost | Answers | Splittable |
|---|---|---|---|
| B0 PREFLIGHT | cheap | what this host can tell me | yes, but never needs it |
| B1 PERSISTENCE | cheap | how it stays | 13 branches |
| B1R REGISTRY | cheap–medium | autostart + defence-tamper registry | 13 branches |
| B2 EXECUTION | cheap | what ran, without 4688 | 7 branches |
| B3 ACCOUNTS | cheap | who, and who was | 7 branches |
| B4 NETWORK | cheap | where it talks | 7 branches |
| B5 BROWSER | cheap | where it came from | 4 branches |
| E-AUTH / E-PROC / E-PS / E-SYS / E-TASK / E-RDP / E-WMI / E-DEFENDER / E-FW / E-CLEAR / E-BITS | cheap | the narrative | one channel each |
| S-PROFILE | cheap | which Sysmon event ids this config emits — **gate for every S-bundle** | no |
| S-PROC / S-NET / S-IMG / S-INJECT / S-FILE / S-REG / S-PIPE / S-WMI / S-TAMPER | cheap | the narrative, with process attribution and hashes — **replaces E-PROC when Sysmon is present** | one event group each |
| B6 FILE | medium | what landed | one directory each |
| B7 YARA | expensive | is it known-bad | one location each |
| B9 CREDENTIAL | medium | was credential theft attempted | 4 branches |
| B8 SWEEP | cheap/host | where else | one IOC family each |
