---
name: windows-endpoint-threat-hunting
description: Windows compromise hunts via fleet-mcp, schema-first, OCSF.
---

# Windows Endpoint Threat Hunting (Fleet MCP only)

Fluent osquery + Fleet via fleet-mcp. Every rule below was paid for with a wasted hunt window. Do not re-learn them.

## Hard rules
1. **fleet-mcp only** for data gathering: get_host, get_host_users, get_software, prepare_live_query, run_live_query, get_osquery_schema. No SSH, no WinRM, no browser for host data.
2. **Schema-first, always.** Never guess a table name, column name, or event schema. Phase 0 is a gate: it completes before the first run_live_query. Guessed names that do NOT exist (do not re-fire them): wmi_binding, atc_logon_sessions, atc_registry_runs, atc_process_lineage, atc_security_events, edge_download_history on Windows, yara_rules (often), and any wmi_event_* table (osquery has no WMI persistence tables; use registry in Phase 3).
3. **24h default time bound** on every row-returning windows_events query: time > strftime('%s','now') - 86400. Widen only when the user explicitly asks for a longer span. One narrow exception: log-integrity probes returning min/max/count (no rows) may be unbounded, their job is to detect a log clear.
4. **One live query at a time.** Parallel run_live_query clogs the osquery agent queue; saturation makes even os_version time out.
5. **First-fire rule:** heavy queries (full processes scan, registry, wide file GLOBs, windows_events multi-eventid + multiple LIKEs) reliably time out on FIRST fire on loaded hosts. Wait 90s+ and re-fire the SAME SQL. After 3 total failures the query is dead: shrink scope, do not abandon the hunt. If nothing responds, sleep 180 to let the queue drain, then resume.
6. **OCSF output:** every finding in the final report is an OCSF JSON record. Event-class mapping + JSON templates: references/ocsf-mapping.md. Validated SQL per module: references/hunt-queries.md.

## Phase 0 — Schema verification (gate)
- prepare_live_query with a probe embeds table schemas + OCF examples; read the returned schema for EVERY table you plan to query.
- get_osquery_schema for core tables.
- Authoritative column list for core Windows tables: raw.githubusercontent.com/osquery/osquery/master/specs/windows/<table>.table — default branch is **master, NOT main** (404s on main are a URL bug, not missing tables).
- Ground truth for what is loaded on the agent: SELECT name FROM info WHERE name LIKE '<prefix>%' — info lists every table on that exact agent build, extension tables included.
- ATC (osquery-atc extension) special notes:
  - Table names carry NO atc_ prefix.
  - ONLY tables listed in the agent config's auto_table_construction section exist. Confirm the agent's actual list from the config or the info probe before querying.
  - Typical dexterlabs set: logon_sessions, process_etw_events, powershell_events, dns_lookup_events, file_events, ntfs_journal_events, edge_url_history (url/title/last_visit_time/visit_count), chrome_url_history, firefox_url_history, chrome_download_history. There is no edge_download_history on Windows.
  - ATC event tables retain only events_expiry (900s = 15 min on this fleet). They CANNOT show hours-old activity. Durable evidence = windows_events, file, registry, services, scheduled_tasks, logon_sessions.
- YARA: yara_rules may be absent; yara_file + sigurl works only for allowlisted URLs (agent config, e.g. gitops-yara rules/windows + rules/multi, Neo23x0). Read the allowlist from the agent config before choosing a sigurl.

## Phase 1 — Host discovery & baseline
1. get_host by name/identifier, record host_id; every later query uses it.
2. get_host_users — extra local admin account not matching AD = flag.
3. SELECT days, hours, minutes, total_seconds FROM uptime; — boot time anchors the whole hunt; nothing in any event log predates boot.
4. listening_ports joined to processes by pid; every listener must map to a known service.
5. get_software with query= substring filter — non-standard install dirs.

## Phase 2 — Log integrity BEFORE trusting any empty event result (T1070.001)
1. Per-channel span, no rows, unbounded allowed: SELECT source, min(time) oldest, max(time) newest, count(*) n FROM windows_events WHERE source IN ('Security','System','Application') GROUP BY source;
2. Compare oldest to boot time. Retained window << uptime means the log was cleared. An empty 4624 on a cleared log is NOT no-logons.
3. Probe 1102 in Security and System. A clear removes its own 1102 marker, so absence is not exoneration.
4. SELECT * FROM logon_sessions; — live LSA session state SURVIVES wevtutil cl. This is the durable access timeline. logon_type: 2=interactive, 3=network, 10=RDP. Verify exact columns from the spec first.

## Phase 3 — OCSF hunt modules (in this order)
Validated SQL per module in references/hunt-queries.md; keep the 24h bound on row-returning event queries.
1. **300 authentication_event** — 4624/4625/4672 + 4720/4721/4726/4728/4732/4733/4738/4768/4776/4783 + logon_sessions. IP hunt via data LIKE '<full dotted IP>%' only after Phase 2 proves the log is not cleared.
2. **2 configuration_event (persistence)** — services (non-C:\Windows\ paths; *PSEXESVC*/*PsService*), scheduled_tasks (non-\Microsoft\), registry Run/RunOnce keys, WMI persistence via registry key GLOB 'HKLM\\SOFTWARE\\Microsoft\\WBEM\\Cimom*' (no osquery wmi_event_* tables exist), startup folder files, SCM 7045.
3. **1 process_event** — 4688 (run a count(*) probe first: 0 means process auditing is off and pattern searches prove nothing), PowerShell 4103/4104, process_etw_events (15-min retention only).
4. **4 file_event** — 4663, file GLOBs (ONE directory per query, add mtime > strftime('%s','now') - 86400), hash, ntfs_journal_events.
5. **5 network_connection_event** — listening_ports, WFP 5145/5156/5157/5158/6274/6272, RDP client IP from Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational event 21 (separate channel — a Security-only clear does not touch it; this is how you recover the client IP after a Security clear), dns_lookup_events.
6. **7 log_event** — 1102, 7036, 104.

## Phase 4 — YARA sweep
- yara_file + allowlisted sigurl, one location per query, filter count > 0.
- Rule-file SIZE is the bottleneck on loaded VMs: the sigurl download + compile times out, not the scan. Small files (hacktool.yar, ~3.6 KB) complete; large ones (malware.yar, 779 rules) do not on 2-core VMs with Defender + Wazuh FIM running. Prefer small files; wait for the VM to be quiet for wide coverage.
- High-value locations in order: C:\Users\<u>\AppData\Local\Temp, C:\Windows\Temp, C:\Users\<u>\Downloads, C:\Users\<u>\Desktop (if the plain Desktop path times out or is empty it is likely a OneDrive-redirected junction — try C:\Users\<u>\OneDrive\Desktop), C:\ProgramData.

## Query hygiene (learned the hard way)
- NEVER json_extract(data, ...) on windows_events.data — it forces timeouts. Select substr(data,1,800) (1500 for 4104) and parse JSON client-side.
- Narrow event queries: one eventid (or a small IN list) + at most ONE LIKE. Multi-eventid IN + multi-LIKE is the slowest class.
- file column is path, not pathname.
- Browser history last_visit_time is Windows file time (100ns since 1601): unix = last_visit_time/1000000 - 11644473600.
- fleet-mcp host_ids is a string, e.g. "1590".
- Docker swarm hosts: docker tables exist even when absent from the MCP schema file; names/ports columns are slow (2nd API call per container) — query id/image/state/status/created instead.

## Anti-forensics interpretation (never misread these)
- Empty 4624 does NOT mean no logons — check logon_sessions.
- Empty 1102 does NOT mean no clear — circular buffer plus a clear removes its own marker; check per-channel retained span vs uptime.
- Empty ATC event tables do NOT mean no activity — events_expiry.
- Empty 4103/4104 does NOT mean no PowerShell — auditing may be off, or the channel cleared.
- Freshly installed Sysmon with zero events is expected, not a red flag — check the service install time before flagging.

## Report format
1. Plain-terms verdict first: {supported, answer, evidence_used, missing_information, confidence} JSON.
2. One OCSF JSON record per finding (templates in references/ocsf-mapping.md).
3. Explicit residual-risk list: what could NOT be verified and why (saturation, cleared channel, OneDrive junction).

## Knowledge loop (standing rule)
After ANY hunt: update the relevant wiki entities/ page + append 20-knowledge-base/log.md, then gbrain sync --source default --working-tree, then gbrain dream --drain in background if the sync created chunks. Lab specifics (host ids, operator accounts, client IPs) live in the wiki/memory — reference them, do not hardcode them here.
