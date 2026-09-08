---
name: windows-endpoint-threat-hunting
description: Alert-driven Windows compromise hunting over Fleet/osquery. Schema-vetted SQL before any live query, MITRE ATT&CK routing, OCSF-shaped findings, autonomous IOC pivot and OSINT enrichment. Use when an EDR/NDR/SIEM alert points at a Windows host and the question is "is this host compromised, how, and where else".
---

# Windows Endpoint Threat Hunting

Harness-agnostic. Written for any agent runtime with a Fleet/osquery MCP plus a
web tool. No runtime-specific syntax appears below — bind the capabilities in
§2 once and the rest of the file is portable.

Optimised for **wall-clock to verdict**, not for coverage theatre. Budget: a
single-host verdict in **6–9 tool calls**. Every extra round trip is a defect.

## 1. Scope and entry condition

Fires when an investigator holds a signal — EDR detection, NDR flow, SIEM
correlation, phishing report, abuse ticket — that resolves to at least one
Windows host, and needs the host interrogated.

Inputs to extract from the alert before anything else (no tool calls):

| Input | Use |
|---|---|
| `W0` alert timestamp (UTC) | anchors every time bound (§6) |
| host identity (hostname / IP / serial / user) | resolves to `host_id` (§4 call 1) |
| claimed technique / detection name | routes to bundles (§8) |
| supplied IOCs (hash, IP, domain, path, cmdline, mutex) | seeds sweep + OSINT (§9) |

Missing `W0` → default the event window to 7 days and say so in the report.
Never block on it.

## 2. Capability binding (do this once, in-head, from the tool list)

| Capability | Fleet MCP tool | Notes |
|---|---|---|
| `HOST.RESOLVE` | `get_host` (`host_id` preferred, else `identifier`) | returns candidate list on hostname collision — re-call with `host_id` |
| `HOST.FIND` | `get_endpoints` (`query` / `fleet` / `platform` / `label` / `status`) | `query` matches hostname, serial, primary IP, model, user inventory — not display name |
| `HOST.USERS` | `get_host_users` | cached, free, no host CPU |
| `HOST.SOFTWARE` | `get_software` (`host_id`) | cached — prefer over a live `programs` query |
| `HOST.POLICIES` | `get_host_policies` | compliance drift as corroboration |
| `SCHEMA.CANON` | `get_osquery_schema(tables=…)` | one call, all tables you intend to touch |
| `TARGET.RESOLVE` | `prepare_live_query` | only when the target set is ambiguous or fleet-wide |
| `QUERY.RUN` | `run_live_query(sql, host_ids=…)` | the only expensive capability |
| `FLEET.SCOPE` | `get_fleets`, `get_labels`, `get_aggregate_platforms` | sweep scoping |
| `VULN.HOSTS` | `get_vulnerability_hosts`, `get_vulnerability_impact` | exploit-alert corroboration |
| `WEB.SEARCH` / `WEB.FETCH` | the harness's web tools | OSINT only, never for host data |
| `KB.SEARCH` | user-supplied RAG / notes / memory / wiki | read before web |

If a capability is absent, continue and list it under residual risk. Do not
substitute SSH, WinRM, RDP or a browser for host data — Fleet is the only
host-data path.

`QUERY.RUN` is annotated destructive in Fleet MCP: it burns device CPU and shows
up in EDR telemetry. Treat every fired query as an operational cost.

## 3. Non-negotiables

1. **Schema gate before the first query.** One `SCHEMA.CANON` call listing every
   table you plan to touch. No query is authored from memory.
   `references/schema-contract.md` is the law; read it once per session.
2. **Self-validate every statement** against the 9-point checklist in
   `schema-contract.md` §5 *before* handing it to `QUERY.RUN`. The MCP validator
   catches only two bug classes (wrong platform, TEXT-vs-bare-int); the other
   seven are yours. A query that returns zero rows because of a missed required
   constraint costs the same wall clock as a correct one and lies to you.
3. **Bundle, don't drip.** Fire pre-vetted `UNION ALL` bundles from
   `references/hunt-bundles.md` — one round trip per hunt surface, not one per
   table. Bundles are written to split cleanly at their `UNION ALL` seams when a
   host is too loaded to answer the whole thing.
4. **Prefer durable state over event buffers.** `windows_eventlog` reads the real
   EVTX with server-side XPath pushdown; `windows_events` is an osquery ring
   buffer that only holds channels the agent was configured to subscribe to and
   expires on `events_expiry`. Registry, services, tasks, shimcache, prefetch,
   BAM, UserAssist and `logon_sessions` survive log clears entirely.
5. **Best-available telemetry wins.** B0 reports whether Sysmon is installed and
   collecting. When it is, the **S-bundles replace `E-PROC`** and augment the
   network, registry, file and injection surfaces — Sysmon carries full command
   lines, parent command lines, hashes including IMPHASH, `OriginalFileName`,
   `ProcessGuid` lineage and per-process network and DNS, none of which the
   Security channel can give you. Gate on `S-PROFILE` first: Sysmon coverage is
   whatever its config XML allows, and an event id its config excludes proves
   nothing. `hunt-bundles.md` §S has the comparison table and the queries.
6. **Absence is never a negative** until §7 is satisfied.
7. **Fleet-wide sweeps are one query, not N.** `QUERY.RUN` with
   `platform='windows'` (plus `fleet` / `label`) fans out server-side and returns
   within the REST period. Never loop hosts.
8. **Every finding is an OCSF record with an ATT&CK reference.** Bundles emit the
   `sig` and `attck` tags in-row, so report assembly is a lookup in
   `references/reporting.md`, not a judgement call.

## 4. The fast path (single host)

| # | Capability | Purpose | Gate it clears |
|---|---|---|---|
| 1 | `HOST.RESOLVE` | `host_id`, platform, OS build, last-seen, labels, fleet | wrong-host error; offline host |
| 2 | `SCHEMA.CANON` | canonical columns/types for every table in the bundles you selected | rule 1 |
| 3 | `QUERY.RUN` **B0 PREFLIGHT** | agent table inventory, publisher flags, boot time, audit policy, AV/DG posture, EVTX file sizes | tells you which later bundles are even answerable |
| 4 | `QUERY.RUN` **B1 PERSISTENCE** | services, tasks, run keys, WMI subscriptions, startup, drivers, IFEO, COM hijack | most alerts resolve here |
| 5 | `QUERY.RUN` **B2 EXECUTION** | shimcache, prefetch, UserAssist, BAM, ETW process events, PowerShell blocks | works with 4688 off and Security cleared |
| 6 | `QUERY.RUN` **S-bundle** (Sysmon present) or **E-bundle** | the one channel the alert implicates, `eventid IN` + `timestamp` pushdown. With Sysmon: `S-PROFILE` once, then the S-bundle for the technique | the incident-window narrative |
| 7 | `HOST.USERS` + `HOST.SOFTWARE` | account and package corroboration — cached, no host cost | free, run in parallel with 4–6 |
| 8 | conditional | B5 browser origin / B6 file surface / B7 YARA / B9 credential-access / B8 IOC fleet sweep | only when 3–6 raised a lead |
| 9 | — | report (§11) | — |

Calls 1 and 2 are unconditional. Calls 3–6 are the spine. Skip a spine call only
when B0 proves its data source is unavailable, and record that as residual risk.

Parallelism: `HOST.*` reads are cached Fleet lookups — issue them alongside the
live queries. Live queries against the **same host** go one at a time: a
saturated osquery worker queue makes even `os_version` time out. Live queries
against **different hosts** are one fan-out call, not several.

## 5. Retry ladder (per live query)

1. First fire. Heavy bundles on a loaded host time out on first fire more often
   than not — this is queue warm-up, not a bad query.
2. Wait ~90 s. Re-fire the **identical** SQL. Do not edit it; editing hides
   whether the timeout was scope or queue.
3. Still nothing → split the bundle at its `UNION ALL` seams, fire the two or
   three branches that answer the alert's technique first.
4. Three total failures on the same SQL → that surface is dead for this hunt.
   Shrink scope (one directory, one channel, one eventid), never abandon the
   hunt, and record the gap.
5. Nothing at all responds → the host may be offline or the queue is wedged.
   Confirm with `HOST.RESOLVE` (`status`, last-seen) before blaming the query.

**An empty result set with zero responding hosts is not evidence.** The MCP
returns the resolved target set with the results — check that a host actually
answered before reading a `0` as a fact.

**Verify *which* hosts answered, not just how many.** Label-based targeting has
been observed to validate the label name and then ignore it for host selection:
a query aimed at a five-host manual label executed against 23 hosts, including
every Linux host in the estate (which returned `no such table: registry`).
Reproduced with a built-in platform label too. So:

- Prefer explicit `host_ids` (or `hostnames`) whenever you know them.
- When you must scope by `label` / `platform` / `fleet`, resolve the intended set
  with `TARGET.RESOLVE` **first**, then compare the answering host list against
  it and say in the report if they differ.
- A host that answers with a `no such table` error is telling you it is the wrong
  platform, not that the table is missing on the platform you meant to query.

## 6. Time-window law

| Window | Value | Applies to |
|---|---|---|
| incident | `W0 - 2h` → `W0 + 6h` | the narrative reconstruction |
| event | `min(7d, channel retention)`, ending now | every EVTX / evented-table query |
| state | none needed | registry, services, tasks, shimcache, prefetch, BAM, UserAssist — these are current state, not events |

Rules:

- Never fire an unbounded EVTX scan. `windows_eventlog` bounds go in
  `timestamp = '<milliseconds>'` (lookback) or
  `time_range = '<ISO8601Z>;<ISO8601Z>'` (absolute) — both push down into
  `EvtQuery`, so they cut cost at the source rather than filtering after the read.
- `windows_eventlog` has **no `time` column**. A `time > strftime(...)` predicate
  on it is a hard error, not a slow query.
- Evented tables (`windows_events`, `powershell_events`, `process_etw_events`,
  `dns_lookup_events`, `ntfs_journal_events`) need an explicit `time` predicate —
  at minimum `time > 0`. Without one, osquery returns only rows since that
  query last ran and the cursor survives agent restarts, so a live re-run looks
  identical to a dead publisher.
- Anchor everything against boot time (`uptime.total_seconds`) and the retention
  bracket from B0. Nothing in any log predates boot; nothing outside retention
  can be proven absent.
- Widen past 7 days only on explicit request, and only on state tables plus a
  bracketed `time_range` probe.

## 7. Absence interpretation (anti-forensics)

Read this before writing "no evidence of X".

| Empty result | Does NOT mean | Prove it with |
|---|---|---|
| no 4624/4625 | no logons | `logon_sessions` (live LSA state, survives `wevtutil cl`), B2 execution artifacts |
| no 1102 | logs were not cleared | a clear removes its own marker — bracket retention with `time_range`, compare oldest reachable event to boot time, check `winevt\Logs` EVTX sizes from B0 |
| no 4688 | nothing executed | audit subcategory may be off — B0 reports `security_profile_info.audit_process_tracking`; then shimcache / prefetch / BAM / UserAssist / ETW |
| no 4103/4104 | no PowerShell | script-block logging off, or channel cleared — check `powershell_events` publisher counts in B0 |
| empty evented table | no activity | `events_expiry` (often 900 s); publisher disabled; missing `time > 0` predicate |
| no rows from an EVTX channel | channel is empty | events lacking an `EventData`/`UserData` node are silently dropped by the osquery parser and never appear in either table |
| no YARA hit | file is clean | rule file may have failed to fetch/compile within the timeout — a hit count of 0 and a failed compile look identical |
| Sysmon installed, zero events for an id | the behaviour did not happen | Sysmon coverage is its config XML — `S-PROFILE` shows which ids this config emits; also check `S-TAMPER` (4/16/255) and the service install time, since a fresh install with no history is expected |
| host returned nothing | host is clean | offline, or worker queue saturated (§5) |

`security_profile_info` audit fields report the **legacy** audit categories. When
Advanced Audit Policy is in force they can read 0 while subcategories are
enabled — treat a 0 as a hint, and settle it with a bounded `count(*)` probe on
the channel.

## 8. Alert-type routing

Enter at the alert's technique, not at phase 1. Full bundle SQL and the
technique index live in `references/hunt-bundles.md`.

| Alert class | Bundles, in order | Primary ATT&CK |
|---|---|---|
| suspicious process / LOLBin / script | B0, B2, E-PROC, E-PS, B1 | T1059.001, T1218.*, T1047, T1027 |
| persistence / autorun / new service | B0, B1, B1R, E-SYS, B2 | T1543.003, T1053.005, T1547.001, T1546.003 |
| credential access / LSASS | B0, B9, B1R, B2, E-PROC | T1003.001, T1003.002, T1555.*, T1552.* |
| lateral movement inbound (RDP/SMB/WinRM) | B0, B3, E-AUTH, E-RDP, B4 | T1021.001, T1021.002, T1021.006, T1550.002 |
| C2 beacon / NDR flow | B0, B4, B5, B2, E-FW, B1 | T1071.001, T1071.004, T1090, T1572, T1571 |
| ransomware precursor | B0, B1, B2, E-SYS, B6 | T1486, T1490, T1489, T1562.001 |
| account anomaly / new admin | B0, B3, E-AUTH, B1 | T1136.001, T1098, T1078.*, T1548.002 |
| log tampering / EDR silence | B0, E-CLEAR, B1R, B1, B2 | T1070.001, T1562.001, T1562.002 |
| driver / kernel / BYOVD | B0, B1 (driver branch), B2, E-SYS | T1068, T1543.003, T1014, T1553.006 |
| phishing / user-opened file | B0, B5, B6, B2, E-PROC | T1566.001, T1204.002, T1564.004 |
| exploit against a known CVE | `VULN.HOSTS`, B0, B2, B4 | T1190, T1203, T1068 |
| unknown / "just look at it" | B0, B1, B2, B3, B4, B5 | broad |

**Sysmon substitution.** If B0 reports `SYSMON.SVC` and `SYSMON.DRV`, run
`S-PROFILE` once, then read the table above with these swaps: `E-PROC` → `S-PROC`;
C2 and NDR rows add `S-NET`; credential-access rows add `S-INJECT`; persistence
rows add `S-REG`; phishing rows add `S-FILE` (event 15 carries the
mark-of-the-web origin); driver/BYOVD rows add `S-IMG`; log-tampering rows add
`S-TAMPER`. Keep the `E-*` bundle for anything `S-PROFILE` shows the config does
not emit, and say which source answered in the report.

## 9. Autonomy: pivot and enrichment

Trigger without being asked, in this order, and stop at the first that answers:

1. **Extract.** Every finding yields IOCs — SHA256, path, filename, service or
   task name, registry value, cmdline fragment, remote IP/port, domain, named
   pipe, mutex, cert subject/serial, scheduled-task author. Normalise them into
   the observable table in `references/pivot-and-osint.md`.
2. **Sweep local.** Second-order artifacts on the same host that the first
   finding implies (a dropper implies a download source; a service implies its
   binary's signature and prefetch entry).
3. **Sweep fleet.** One `QUERY.RUN` with `platform='windows'` per IOC family.
   Hash and path sweeps are cheap; parent-child and cmdline sweeps are not.
   Scope with `fleet` / `label` when the fleet is large.
4. **Enrich internal.** `KB.SEARCH` before any web call — prior hunts, the local
   YARA corpus, asset ownership, known-good baselines.
5. **Enrich external.** `WEB.SEARCH` / `WEB.FETCH` for hash reputation, malware
   family behaviour, C2 infrastructure, CVE exploitation status, LOLBAS/LOLDrivers
   entries, vendor write-ups. Convert what you learn into *one more host query*,
   or drop it — OSINT that does not change a query or a verdict is a wasted call.

Evidence discipline (non-negotiable, see `pivot-and-osint.md` §4):

- Never send customer identifiers to third parties. Hashes, public IPs and
  domains are fine; usernames, hostnames, serials, internal IPs and file paths
  containing a username are not.
- Every external claim carries its source URL, or it is not stated.
- Model output about exploitability, KEV listing, attribution or compliance
  impact is a claim, not a fact. No source, no claim.
- Thin evidence → an explicitly thin verdict. Empty arrays beat invented
  campaigns and IOCs.

## 10. Stop conditions

Stop and report when any of these is true:

- The alert is explained: a finding chain covers initial access → execution →
  persistence (or the subset the alert asserted), with named artefacts.
- Three consecutive bundles return nothing new and B0 says the remaining
  surfaces are unavailable.
- The next query would cost more than the answer is worth (a wide `file` GLOB or
  a large-rule YARA sweep on a saturated host).
- 12 live queries fired on one host without a verdict → report the partial
  picture plus a ranked list of what remains, and let the investigator choose.

Do not keep hunting for symmetry. An honest "insufficient telemetry, here is
what would settle it" is a valid deliverable.

## 11. Report contract

Order is fixed. Details and templates in `references/reporting.md`.

1. **Verdict**, plain terms, first:
   `{supported, answer, confidence, evidence_used[], missing_information[]}`.
   `confidence` ∈ `high|medium|low`, justified by which sources answered — not a
   vibe.
2. **Timeline**, one line per event, UTC, monotonic, boot time as row zero.
3. **OCSF findings**, one record per finding, `class_uid` from the `sig` mapping
   table, ATT&CK in `finding_info.attacks[]`.
4. **IOC table**, machine-readable, ready to hand to a blocklist or a sweep.
5. **Residual risk**: every gap, with its cause — cleared channel, expired
   buffer, disabled table, saturated host, missing capability, retention shorter
   than the incident window.
6. **Next actions**, ranked, each naming the one query or containment step it
   needs.

Never present a bundle's raw rows as the report. Never claim a query ran that
did not. If a step was skipped, say which and why.

## 12. References

Read on demand, not up front:

- `references/schema-contract.md` — the schema gate: Windows table inventory,
  required constraints, type traps, evented-table semantics, the MCP validator's
  blind spots, and the 9-point pre-fire checklist. **Read once per session,
  before the first query.**
- `references/hunt-bundles.md` — every pre-vetted bundle, `sig`/`attck` tagged,
  with cost class and split points.
- `references/reporting.md` — OCSF class map, `type_uid` maths, record templates,
  ATT&CK fields, verdict wrapper.
- `references/pivot-and-osint.md` — IOC extraction and normalisation, fleet-sweep
  patterns, OSINT rules of engagement, exfiltration guardrails.
