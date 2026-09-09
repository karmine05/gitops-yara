# Schema contract — vet before you fire

The gate that makes a live query correct on the first attempt. Source of truth
for every claim here: `schema/osquery_fleet_schema.json` in `fleetdm/fleet`
(the same file behind `get_osquery_schema` and <https://fleetdm.com/tables>) and
the osquery table specs and implementations at
`raw.githubusercontent.com/osquery/osquery/master/…` — default branch is
**master**, not main.

## 1. Why this file exists

Fleet MCP pre-validates SQL, but only two bug classes:

1. a referenced table not supported on the target platform;
2. a **TEXT** column compared against a **bare integer literal ≥ 2**.

Everything else it passes through. Its blind spots, all of which produce a
query that runs and returns wrong or zero rows:

| Blind spot | Example that passes validation and fails on the host |
|---|---|
| misspelled or non-existent **column** | `SELECT pathname FROM file` — types are checked, names are not |
| missing **required constraint** | `SELECT * FROM registry` — no `key`, returns nothing |
| reversed comparison | `WHERE 4624 = eventid` — the type check needs the column on the left |
| TEXT vs `0`/`1` | `WHERE last_run_code = 0` — deliberately not flagged; `last_run_code` is TEXT |
| negative literal | `WHERE execution_flag = -1` — the pattern only matches unsigned digits |
| table on-platform but not on-**agent** | ATC/extension tables, or anything in `--disable_tables` |
| evented-table cursor | no `time` predicate → "rows since this query last ran", not "rows" |
| column that exists at runtime but not in the schema | `windows_eventlog.time` is written by the implementation and has no column — unselectable |
| CTE / subquery aliases | the table extractor skips them, so nothing in them is validated at all |

So: **the MCP's yes is necessary, not sufficient.** Run §5 yourself, every time.

## 2. Windows table inventory (138 tables, canonical)

Everything below exists on Windows. Anything not on this list does not — do not
author against it.

**Events / logs**: `windows_events`, `windows_eventlog`, `windows_crashes`,
`powershell_events`, `process_etw_events`, `dns_lookup_events`,
`ntfs_journal_events`, `osquery_events`

**Execution artefacts**: `shimcache`, `prefetch`, `userassist`,
`background_activities_moderator`, `appcompat_shims`, `recent_files`,
`office_mru`, `shellbags`, `windows_search`

**Process / memory**: `processes`, `process_open_sockets`,
`process_open_handles`, `process_memory_map`, `pipes`, `winbaseobj`

**Persistence / config**: `services`, `scheduled_tasks`, `startup_items`,
`autoexec`, `registry`, `drivers`, `wmi_cli_event_consumers`,
`wmi_event_filters`, `wmi_script_event_consumers`,
`wmi_filter_consumer_binding`, `wmi_bios_info`, `ie_extensions`,
`chrome_extensions`, `firefox_addons`, `vscode_extensions`,
`jetbrains_plugins`, `adobe_plugins`

**Identity / access**: `users`, `groups`, `user_groups`, `logged_in_users`,
`logon_sessions`, `ntdomains`, `certificates`, `user_ssh_keys`,
`security_profile_info`

**Network**: `listening_ports`, `interface_addresses`, `interface_details`,
`routes`, `arp_cache`, `dns_cache`, `etc_hosts`, `etc_services`,
`etc_protocols`, `connectivity`, `windows_firewall_rules`, `shared_resources`,
`curl`, `curl_certificate`, `sntp_request`, `mcp_listening_servers`

**File / integrity**: `file`, `file_lines`, `file_contents`, `hash`,
`authenticode`, `ntfs_acl_permissions`, `logical_drives`, `disk_info`,
`physical_disk_performance`, `carves`

**Detection**: `yara_file`, `yara_process`, `windows_security_center`,
`windows_security_products`, `deviceguard_status`, `secureboot`,
`bitlocker_info`, `bitlocker_key_protectors`, `tpm_info`, `carbon_black_info`,
`cis_audit`, `kva_speculative_info`, `intel_me_info`, `cryptoinfo`

**Inventory / patch**: `programs`, `patches`, `windows_updates`,
`windows_update_history`, `windows_optional_features`, `chocolatey_packages`,
`python_packages`, `npm_packages`, `go_binaries`, `ai_tools`,
`google_chrome_profiles`, `chrome_extension_content_scripts`,
`firefox_preferences`, `ssh_configs`, `default_environment`

**Host / agent**: `os_version`, `system_info`, `uptime`, `time`,
`platform_info`, `kernel_info`, `cpu_info`, `cpuid`, `memory_devices`,
`chassis_info`, `battery`, `video_info`, `osquery_info`, `osquery_flags`,
`osquery_schedule`, `osquery_packs`, `osquery_extensions`, `osquery_registry`,
`orbit_info`, `fleetd_logs`, `mdm_bridge`, `puppet_info`, `puppet_logs`,
`puppet_state`, `parse_ini`, `parse_json`, `parse_jsonl`, `parse_xml`,
`yaml_to_json`, `azure_instance_metadata`, `azure_instance_tags`,
`ec2_instance_metadata`, `ec2_instance_tags`, `ycloud_instance_metadata`

**Explicitly NOT on Windows** — these are the recurring guesses:
`file_events` (darwin/linux only; the Windows FIM feed is
`ntfs_journal_events`), `es_process_events`, `es_process_file_events`,
`bpf_process_events`, `bpf_socket_events`, `socket_events`, `process_events`,
`crontab`, `launchd`, `rpm_packages`, `deb_packages`, `apps`,
`quarantine_items`, `edge_download_history`.

**Non-existent everywhere** (never author these): `wmi_binding`, any
`wmi_event_*` name other than the four real ones above, `atc_*` anything
(auto-table-construction tables carry no prefix), `yara_rules`,
`atc_logon_sessions`, `atc_security_events`, `info`. For the live table
inventory of a specific agent use
`SELECT name FROM osquery_registry WHERE registry = 'table'` — it lists every
table on that build, extensions and ATC included.

## 3. Required constraints — omit and you get zero rows, not an error

| Table | Must constrain | Notes |
|---|---|---|
| `registry` | `key` (`=` or `IN`) | one key per predicate; `key GLOB '…*'` walks subkeys |
| `file` | `path` **or** `directory` | `directory = 'C:\Dir'` lists that dir; `path GLOB` walks. One directory per query |
| `hash` | `path` **or** `directory` | hashing is I/O bound — never GLOB a tree |
| `file_lines`, `file_contents` | `path` | reads content off the device; treat as exfiltration-capable |
| `authenticode` | `path` | one binary per row; feed it paths from another branch |
| `yara_file` | `path` **and** one of `sigrule` / `sigfile` / `sig_group` / `sigurl` | `sigurl` must be on the agent's allowlist |
| `yara_process` | `pid` **and** a signature source | |
| `process_open_handles` | `pid` | |
| `windows_eventlog` | `channel` **or** `xpath` | mutually exclusive, see §4 |
| `windows_search` | `query` | Advanced Query Syntax, not SQL |
| `curl`, `curl_certificate` | `url` / `hostname` | makes outbound requests from the device — do not use in a hunt |

A `SELECT *` against any of these with none of its constraints is not a slow
query. On a 2-core host it is a timeout that also stalls the worker queue for
every query behind it.

## 4. `windows_eventlog` vs `windows_events` — pick correctly

This is the highest-value distinction in the whole skill.

### `windows_eventlog` — real EVTX, pushdown, prefer it

Not evented. Calls `EvtQuery` against the live channel in **reverse order**
(newest first). Reaches as far back as the channel retains, regardless of what
the osquery agent was configured to subscribe to.

Columns: `channel`, `datetime`, `task`, `level`, `provider_name`,
`provider_guid`, `computer_name`, `eventid`, `keywords`, `data`, `pid`, `tid`,
plus the constraint-only `time_range`, `timestamp`, `xpath`.
**There is no `time` column.**

Constraints that push down into the XPath filter — use these, they cut cost at
the source:

| Constraint | Becomes | Example |
|---|---|---|
| `eventid = N` / `eventid IN (…)` | `(EventID=N) or (EventID=M)` | `eventid IN (4624,4625,4672)` |
| `pid = N` | `Execution[@ProcessID=N]` | |
| `timestamp = '<ms>'` | `TimeCreated[timediff(@SystemTime) <= ms]` | `timestamp = '86400000'` = last 24 h |
| `time_range = '<start>'` | `@SystemTime >= start` | `'2026-09-07T00:00:00.000Z'` |
| `time_range = '<start>;<end>'` | bounded window | `'2026-09-07T10:00:00.000Z;2026-09-07T18:00:00.000Z'` |

Rules:

- `xpath` cannot be combined with `channel`, `time_range` or `timestamp` — the
  implementation refuses and returns nothing. Either drive it with
  `channel` + `eventid` + `timestamp`/`time_range` (normal case), or supply a
  complete `<QueryList>` in `xpath` alone.
- Only one `xpath` value per query.
- Filter time with `timestamp`/`time_range`, never with `datetime` — `datetime`
  is a post-read string compare, so the whole channel is walked first.
- `datetime` is the raw `TimeCreated/@SystemTime`, i.e. ISO 8601 UTC with
  sub-second precision (`2026-09-07T14:03:11.1234567Z`). Sort on it as text;
  convert client-side if you need epoch.
- `data` is JSON built from the event's `EventData` and `UserData` nodes:
  `json_extract(data, '$.EventData.NewProcessName')`,
  `json_extract(data, '$.EventData.ScriptBlockText')`,
  `json_extract(data, '$.UserData.EventXML.Param3')`. Named `<Data Name="X">`
  elements become keys; unnamed ones become an array.
- An event whose XML has **no** `EventData` and no `UserData` node, or is missing
  `Task`/`Level`/`Computer`, fails the parser and is dropped from the result
  entirely. Absence of a specific event id can be a parser artefact.
- `json_extract` over a *pushdown-filtered* set is fine. `json_extract` over an
  unfiltered channel is the classic timeout. Filter first, extract second, and
  on wide sets prefer `substr(data,1,800)` (1500 for 4104) and parse client-side.

### `windows_events` — osquery ring buffer, opportunistic only

Evented subscriber. Requires **all** of
`--enable_windows_events_publisher=true`,
`--enable_windows_events_subscriber=true`, and
`--windows_event_channels=<comma list>`; only the listed channels exist in the
table. Retention is `events_expiry` / `events_max`, not the channel's.

- `time` is when osquery **received** the event, not when it occurred;
  `datetime` is the occurrence time.
- `source` holds the channel with original casing (`Security`,
  `Microsoft-Windows-PowerShell/Operational`). The lowercasing applies only to
  the subscription list. `source LIKE 'Security'` is casing-proof;
  `source = 'security'` matches nothing.
- Always carry `time > 0` at minimum (see §6).
- Use it when B0 shows the needed channel subscribed and healthy and you want
  cheap recent history; fall back to `windows_eventlog` for anything older or
  any channel not in `--windows_event_channels`.
- **On this fleet's agent options `windows_event_channels = Security,Application,System`.**
  So `windows_events` can never answer for PowerShell/Operational,
  TaskScheduler/Operational, TerminalServices-*, WMI-Activity/Operational,
  Windows Defender/Operational, Bits-Client/Operational, Sysmon/Operational or
  the Firewall channel — every one of those needs `windows_eventlog`. Confirm
  the live value from B0's `FLAG` rows rather than trusting this line.

## 5. The 11-point pre-fire checklist

Run this on every statement before it leaves your hands. It is cheaper than one
failed round trip.

1. **Every table** in the statement appears in §2 as a Windows table.
2. **Every column** appears in the `SCHEMA.CANON` response for that table —
   name spelled exactly, no invention. Common slips: `file.path` not `pathname`;
   `services.path` (binary) vs `services.module_path`; `scheduled_tasks.action`
   not `command`; `registry.data` not `value`.
3. **Required constraints** from §3 are present for every table used.
4. **Type-correct literals**: quote TEXT, never quote INTEGER/BIGINT. Column on
   the left of the comparison.
5. **Evented tables** carry a `time` predicate (`time > 0` floor).
6. **EVTX queries** carry `channel` plus `eventid` plus a `timestamp`/`time_range`
   bound, and no `time` column reference.
7. **UNION ALL branches** agree on column count and order; names come from the
   first branch; wrap divergent types in `CAST(x AS TEXT)`.
8. **Cost class** is declared to yourself: cheap enumeration, medium, or
   expensive (`file` GLOB over a tree, `hash` over a directory, `yara_file`,
   `processes` joined to `process_open_handles`). Expensive never rides in a
   bundle.
9. **Result shape** is bounded: `LIMIT` on anything that could return thousands,
   `substr()` on `data`/`cmdline`/`script_text` instead of whole blobs.
10. **Selective `WHERE`, named columns, no walks.** The statement names its
    columns (no `SELECT *` outside a `SELECT * FROM (…)` wrapper) and carries a
    `WHERE` that uses the table's §3 constraint plus a time bound on any
    event/log table (12 h or the incident `time_range` — SKILL.md §6).
    `SELECT * FROM registry` / `file` / `windows_eventlog` with no constraint,
    and recursive walks (`key GLOB` over a hive, `path GLOB '…\**'`,
    config-style `%%`), do not leave your hands.
11. **Fits the host.** B0 `HW`/`EVTX` said constrained (SKILL.md §3 rule 10) →
    the statement is one table or one event group, has no `JOIN`, its EVTX
    window is ≤ 12 h, and `LIMIT ≤ 200`. On any host a `JOIN` is allowed only
    between two already-constrained **state** tables on `pid` or `path`
    (`listening_ports` ⋈ `processes`, `authenticode` ⋈ `hash`) — never touching
    `windows_eventlog` or an evented table, whose row volume is what makes the
    join fall over.

Fail any point → fix the SQL, do not fire it.

## 6. Evented-table semantics (the zero-row trap)

`windows_events`, `powershell_events`, `process_etw_events`,
`dns_lookup_events`, `ntfs_journal_events` are subscriber-backed. In osqueryd, a
query with **no** `time` constraint returns only the events accumulated since
that same query last ran, and the cursor persists across agent restarts. A
re-run therefore returns 0 and is indistinguishable from a dead publisher.

- Always constrain: `WHERE time > 0` as a floor, or a real window
  (`time > strftime('%s','now') - 3600`).
- Check publisher health from B0 (`osquery_events.events` / `.active`) before
  concluding "no activity".
- `events_expiry` on this fleet's agent options is **3600 s** with
  `events_max = 50000`; other deployments commonly use 900 s. Read the live
  values from B0's `FLAG` rows. Either way these tables cannot answer questions
  about day-old activity — that is what EVTX and state tables are for.
- `ntfs_journal_events` only emits for paths in the agent's configured include
  set. On this fleet that set is `C:\Users\%%\Desktop\%%`,
  `C:\Users\%%\Downloads\%%` and `C:\Users\%%\Documents\%%` under category
  `Win_Yara_File_Path` (the category name is historical and has nothing to do
  with YARA — do not rename it, saved queries key on it). `\AppData\`,
  `\Temp\` and `C:\ProgramData` are **not** journaled, so file-creation
  ordering in those directories has to come from `btime`. Action values are CamelCase: `FileCreation`, `FileDeletion`,
  `FileWrite`, `FileRename_OldName`, `FileRename_NewName`, `AttributesChange`
  and the `Directory*` equivalents. `FILE_CREATE`-style names match nothing.

## 7. Type traps (verified against canonical schema)

| Table.column | Type | Trap |
|---|---|---|
| `logon_sessions.logon_type` | TEXT | values are words with spaces: `Interactive`, `Network`, `Batch`, `Service`, `Proxy`, `Unlock`, `Network Cleartext`, `New Credentials`, `Remote Interactive`, `Cached Interactive`, `Cached Remote Interactive`, `Cached Unlock`, `Undefined Logon Type`. Never compare to `2`/`3`/`10` — those are Security-event codes, a different vocabulary |
| `scheduled_tasks.last_run_code` | TEXT | `= '0'`, not `= 0` |
| `scheduled_tasks.enabled`, `.hidden` | INTEGER | unquoted `1`/`0` |
| `windows_update_history.result_code` | TEXT | `'Succeeded'`, `'SucceededWithErrors'`, `'Failed'`, `'Aborted'` |
| `windows_update_history.date` | BIGINT | unix epoch |
| `authenticode.result` | TEXT | lowercase enum: `valid`, `trusted`, `invalid`, `missing`, `distrusted`, `untrusted`, `unknown`. "suspicious" = `result NOT IN ('trusted','valid')` |
| `drivers.signed` | INTEGER | `1`/`0`; `drivers.date` is BIGINT epoch |
| `windows_security_center.*` | TEXT | `Good`, `Poor`, `Snoozed`, `Not Monitored`, `Error` |
| `windows_security_products.state` | TEXT | `On` / `Off`; `signatures_up_to_date` is INTEGER |
| `security_profile_info.audit_*` | INTEGER | 0 none, 1 success, 2 failure, 3 both — legacy categories only (§7 of SKILL.md) |
| `shimcache.execution_flag` | INTEGER | `1` executed, `0` not, `-1` absent on Win10+ — do not treat `-1` as false |
| `shimcache.entry` | INTEGER | 1 = most recent execution; ordering is the evidence |
| `file.mtime/atime/ctime/btime` | BIGINT | unix epoch. `btime` is creation time — a recent `btime` on an old-looking binary is timestomp-adjacent |
| `registry.mtime` | BIGINT | key write time, the closest thing to a persistence timestamp |
| `userassist.last_execution_time`, `background_activities_moderator.last_execution_time` | BIGINT | unix epoch |
| `prefetch.last_run_time` | INTEGER | unix epoch; `other_run_times` is a space-separated list of epochs |
| `processes.start_time` | BIGINT | unix epoch on Windows; `elevated_token` INTEGER |
| `listening_ports.protocol`, `.family` | INTEGER | 6 = TCP, 17 = UDP; 2 = AF_INET, 23 = AF_INET6 |
| browser `last_visit_time` (Chromium ATC tables) | BIGINT | Windows FILETIME 100 ns since 1601: `unix = last_visit_time/1000000 - 11644473600` |

Fleet MCP passes `host_ids` as a **string** (`"1590"`, or `"1590,1591"`).

## 8. ATC (auto-table-construction) tables

- Names carry **no** `atc_` prefix.
- Only the tables listed in the agent config's `auto_table_construction` block
  exist; the canonical Fleet schema does not contain them at all, which also
  means the MCP validator cannot check them — every column name and type here is
  on you.
- **Every ATC column is TEXT**, whatever the underlying SQLite column held.
  Wrap numeric comparisons: `CAST(last_visit_time AS INTEGER) > …`. Comparing a
  TEXT column to a bare number is a lexicographic compare that happens to work
  for fixed-width timestamps and silently fails for anything else.
- An ATC table reads a live application database. A locked Chromium `History`
  file (browser running) returns **zero rows**, not an error.
- Confirm presence with `SELECT name FROM osquery_registry WHERE registry = 'table'`
  (B0 does this).

The Windows set on this fleet is exactly four tables:

| Table | Columns | Time field |
|---|---|---|
| `edge_url_history` | `url`, `title`, `last_visit_time`, `visit_count` | Chromium epoch |
| `chrome_url_history` | `id`, `url`, `title`, `visit_count`, `last_visit_time`, `hidden`, `visit_time`, `from_visit`, `visit_duration`, `transition`, `source` | Chromium epoch |
| `firefox_url_history` | `guid`, `url`, `title`, `visit_count`, `last_visit_date`, `hidden` | PRTime |
| `chrome_download_history` | `id`, `current_path`, `target_path` | **none** |

- There is **no** `edge_download_history` on Windows, and no Firefox download
  table. Edge and Firefox downloads have to be inferred from `FILE.DROP` /
  `FILE.RECENT` plus the visited URL.
- `chrome_download_history` carries no timestamp. Correlate `target_path` to
  `file.btime` for the landing time, and say in the report that the download
  time is inferred.
- Chromium epoch (`chrome_url_history`, `edge_url_history`): microseconds since
  1601-01-01. `unix = last_visit_time/1000000 - 11644473600`.
- PRTime (`firefox_url_history.last_visit_date`): microseconds since
  1970-01-01. `unix = last_visit_date/1000000`.
- `chrome_url_history.typed_count` appears in the ATC `query` but **not** in its
  `columns` list, so it is not exposed. Selecting it fails. Only the columns in
  the table above exist.
- `from_visit` + `transition` on `chrome_url_history` give the referrer chain —
  the difference between "user typed the URL" and "a page redirected them there".
  That is the drive-by / phishing discriminator; see B5.

## 9. YARA on Windows

- `yara_file` needs `path` plus a signature source. `sigurl` fetches over HTTPS
  (certificate always validated) and must match the agent's allowlist. On this
  fleet the allowlist is two regexes:
  `https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/.*\.yar`
  and
  `https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/.*\.yar`.
  Anything else is refused by the agent, not by the network.
- `yara_sigurl_authenticate` is **not** TLS verification — it switches the fetch
  to POST with the node key in the body, for a server that authenticates rule
  requests. GitHub rejects that, so it must stay `false`.
- The bottleneck is rule-file size: the fetch + compile times out before the
  scan does. Small files (a few KB, tens of rules) complete on a loaded 2-core
  VM; multi-hundred-rule files do not. Pick the narrowest family file that
  matches the hypothesis.
- One directory per query, and always `count > 0` so only hits come back.
- A failed compile and a clean scan look identical. Prove the rule file works by
  scanning a known-hit path (an EICAR drop) before reporting "clean".

## 9a. Confirmed live (lab, Fleet 4.90.2, osquery on Windows 10/11/Server 2022)

Verified by execution rather than by reading source, so these are facts and not
inferences:

- `registry` with a full hive name returns rows:
  `key = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SysmonDrv\Parameters'`
  yields the eight expected values. The full-hive-name requirement in §2 is real
  and the short forms are what fail.
- `windows_eventlog` with `channel` + `eventid` + `timestamp` pushdown returns
  in one fire against a 64 MiB Sysmon channel, and `GROUP BY eventid` over it
  works. The same query against two domain controllers did **not** return inside
  140 s — the retry ladder is for hosts, not for queries.
- `json_extract(data,'$.EventData.<Field>')` resolves on `windows_eventlog`
  rows: `Image`, `CommandLine`, `ParentImage`, `User`, `IntegrityLevel`,
  `OriginalFileName`, `Hashes`, `ProcessGuid` all populate.
- `datetime` is ISO 8601 UTC with a 7-digit fraction:
  `2026-09-08T20:28:07.1257601Z`. Text sort is chronological.
- `EvtQuery`'s reverse direction is real: `LIMIT 3` returns the three **newest**
  matching events, with no `ORDER BY`.
- Sysmon `Hashes` with `HashingAlgorithm = -2147483633` returns
  `SHA1=…,MD5=…,SHA256=…,IMPHASH=…` in one string.
- Sysmon writes a literal `-` for unresolved fields (`ParentImage = "-"`).
- The observations above were captured through a direct CLI session because the
  Fleet MCP was not reachable at the time. They are osquery/agent-side
  behaviours and hold identically through `QUERY.RUN` — the transport does not
  change what a table returns. Nothing in this skill requires a CLI: every
  capability in SKILL.md §2 is an MCP tool.

## 10. Path and glob behaviour

- Windows paths in SQL take single backslashes: `'C:\Windows\Temp\'`. In YAML
  configs they are doubled, and osquery normalises the doubled form through
  `fs::canonical()` — so a YAML `c:\\Users\\%%\\Desktop\\%%` does resolve. The
  "double-escaped paths never match" claim is false; do not rewrite configs to
  chase it.
- `%%` is the osquery config wildcard (recursive); `*` and `**` are the SQL-side
  GLOB wildcards. Do not mix vocabularies.
- A user's `Desktop` / `Documents` may be a OneDrive junction. If
  `C:\Users\<u>\Desktop\*` is empty or times out, try
  `C:\Users\<u>\OneDrive\Desktop\*` before concluding anything.
- `directory = 'C:\Dir'` enumerates one level. `path GLOB 'C:\Dir\*'` also one
  level; `'C:\Dir\**'` recurses and is an expensive-class query.
