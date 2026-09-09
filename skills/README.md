# skills/

Agent skills for the threat-hunting stack in this repo, maintained alongside the
YARA rules in `rules/` and the OCSF report specs in `fleet/ocsf/`.

Written to the standard agent-skill layout (`SKILL.md` + `references/`) and
deliberately **harness-agnostic**: capabilities are named and then bound to
concrete tool names in one table, so the same files work in any runtime that has
a Fleet/osquery MCP and a web tool. No runtime-specific tool syntax appears in
the skill body.

## windows-endpoint-threat-hunting

Alert-driven Windows compromise hunting over Fleet/osquery. Entry point is an
EDR/NDR/SIEM signal that resolves to a Windows host; output is an OCSF-shaped
verdict with ATT&CK references, a timeline, an IOC table and an explicit
residual-risk list.

Design goals, in order: **correct on the first fire**, **fewest round trips**,
**honest about gaps**.

| File | Contents |
|---|---|
| `SKILL.md` | operating contract — capability binding, non-negotiables, the 6–9 call fast path, retry ladder, time-window law, absence interpretation, alert-type routing, autonomy triggers, stop conditions, report contract |
| `references/schema-contract.md` | the schema gate: Windows table inventory, required constraints, `windows_eventlog` vs `windows_events`, evented-table semantics, type traps, the MCP validator's blind spots, 11-point pre-fire checklist |
| `references/hunt-bundles.md` | every pre-vetted query bundle (B0–B9, E-* per EVTX channel, S-* for Sysmon), `sig`/`attck` tagged in-row, with cost class and split points |
| `references/reporting.md` | OCSF class map (core + `win` extension), `type_uid` maths, Detection Finding template, ATT&CK fields, observable types, verdict wrapper |
| `references/pivot-and-osint.md` | IOC extraction and normalisation, the sweep ladder, OSINT rules of engagement and exfiltration guardrails |

### Why it is fast

- **One schema call, one preflight query.** B0 collapses agent-capability
  discovery, boot time, audit-policy state, security posture and log-integrity
  signals into a single round trip.
- **Bundles, not drips.** Each hunt surface is one `UNION ALL` query that comes
  back pre-tagged with its `sig` and ATT&CK technique, and splits cleanly at its
  seams when a host is too loaded to answer the whole thing.
- **Durable artefacts first.** shimcache, prefetch, BAM, UserAssist,
  `logon_sessions`, `registry.mtime` and `dns_cache` answer "what ran, who was
  here, what did it talk to" even when process auditing is off and the Security
  channel has been cleared — no waiting on telemetry that may not exist.
- **EVTX with pushdown.** `channel` + `eventid IN` + `timestamp` become an XPath
  filter inside `EvtQuery`, so the channel is never walked. Bundles ship at a
  12 h window; the incident `time_range` replaces it when the alert time is
  known.
- **Sized to the host.** B0 reads cores, RAM and EVTX sizes first. A constrained
  host gets single-table branches instead of `UNION ALL` bundles, no `JOIN`s,
  and tight windows — fewer timeouts beats fewer round trips.

### Verified facts behind the rewrite

Each of these was checked against `fleetdm/fleet`
(`schema/osquery_fleet_schema.json`, `cmd/fleet-mcp/`) or the osquery sources on
`master`, and each one silently breaks a query that looks correct:

- `registry` accepts **full hive names only** — `HKLM\…` / `HKCU\…` resolve to no
  hive and return zero rows. `HKEY_CURRENT_USER` is not queryable by the agent
  at all; user hives are reachable only as `HKEY_USERS\<SID>\…` (or
  `HKEY_USERS\%\…`, where `%` globs one level and a trailing `%%` recurses).
- `windows_eventlog` has **no `time` column**, requires `channel` **or** `xpath`
  (mutually exclusive), and pushes `eventid` / `pid` / `timestamp` / `time_range`
  down into the XPath filter.
- `windows_events` is a subscriber ring buffer gated on
  `--enable_windows_events_publisher`, `--enable_windows_events_subscriber` and
  `--windows_event_channels`; its `time` is receive time, `datetime` is
  occurrence time, and `source` keeps the channel's original casing.
- osquery **does** have WMI persistence tables — `wmi_cli_event_consumers`,
  `wmi_event_filters`, `wmi_script_event_consumers`,
  `wmi_filter_consumer_binding`. There is no `wmi_event_*` table beyond those,
  and no `atc_*`-prefixed or `info` table.
- `logon_sessions.logon_type` is TEXT with spaces (`Remote Interactive`,
  `Network Cleartext`, `New Credentials`) — a different vocabulary from the
  numeric Security-event logon types.
- `authenticode.result` is a lowercase enum: `valid`, `trusted`, `invalid`,
  `missing`, `distrusted`, `untrusted`, `unknown`.
- RDP client IPs: event **1149** lives in
  `…TerminalServices-RemoteConnectionManager/Operational`; events **21/22/23/24/25**
  live in `…TerminalServices-LocalSessionManager/Operational`. WFP connection
  events (5156/5157/5158) live in **Security**, not the Firewall channel.
- OCSF class UIDs are the real ones: Process Activity 1007, File System Activity
  1001, Script Activity 1009, Scheduled Job Activity 1006, Event Log Activity
  1008, Authentication 3002, Account Change 3001, Group Management 3006, Network
  Activity 4001, DNS Activity 4003, RDP Activity 4005, Detection Finding 2004,
  and Registry Key/Value Activity 201001/201002 from the `win` extension. On
  Detection Finding, `verdict_id` 1 is **False Positive** and 2 is **True
  Positive**.
- **Sysmon, when present, outranks the Security channel** and the skill routes to
  it: full `CommandLine` + `ParentCommandLine` without the GPO that 4688 needs,
  `Hashes` incl. IMPHASH, `OriginalFileName` (renamed-LOLBin detection),
  `ProcessGuid` lineage that survives pid reuse, per-process network (event 3)
  and DNS (event 22), image load (7), LSASS `GrantedAccess` (10), registry writes
  with the writing process (12/13), mark-of-the-web (15), archived file deletes
  (23) and process hollowing (25) — none of which the Security channel provides.
  Gated on `S-PROFILE`, a per-event-id count probe, because Sysmon coverage is
  whatever its config XML allows.
- The Windows ATC set on this fleet is exactly `edge_url_history`,
  `chrome_url_history`, `firefox_url_history`, `chrome_download_history` — all
  columns TEXT, absent from the canonical Fleet schema (so the MCP validator
  cannot check them), zero rows while the browser holds `History` locked.
  `chrome_url_history.typed_count` is in the ATC query but not its `columns`
  list, so it does not exist. There is no Edge or Firefox download table.
- `windows_event_channels = Security,Application,System`, `events_expiry = 3600`,
  `events_max = 50000`. Every other channel — PowerShell, TaskScheduler,
  TerminalServices, WMI-Activity, Defender, Bits-Client, Sysmon, Firewall — is
  reachable only through `windows_eventlog`.
- `ntfs_journal_events` covers only `Desktop`, `Downloads` and `Documents` per
  user (category `Win_Yara_File_Path`). `\AppData\`, `\Temp\` and
  `C:\ProgramData` are not journaled.
- Fleet MCP validates two bug classes only — wrong platform for a table, and a
  TEXT column compared against a bare integer ≥ 2. Column-name typos, missing
  required constraints, reversed comparisons and evented-table cursor semantics
  all pass validation and fail on the host. `schema-contract.md` §1 lists the
  full blind-spot set; §5 is the checklist that covers it.

### Installing

Copy the `windows-endpoint-threat-hunting/` directory into whatever skill
directory the harness reads. To use it as a plain runbook, read `SKILL.md` top to
bottom and pull a reference when it points at one.

Sync rule: patch the operator-host copy first, then mirror it here and push, so
the version-controlled copy never lags the one that ran the hunt.
