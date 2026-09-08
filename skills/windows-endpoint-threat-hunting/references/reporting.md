# Reporting — OCSF records and ATT&CK references

Class UIDs, activity enums and object shapes below were read from
`schema.ocsf.io` (core plus the `win` platform extension). Class UIDs and
activity enums have been stable since OCSF 1.1 and later versions are additive,
so `metadata.version` is the only field to bump. Pin the version you emit and
say so.

## 1. Two layers, not one

| Layer | Class | Purpose |
|---|---|---|
| **Finding** | Detection Finding **2004** | the hunt's conclusion — one per finding, carries ATT&CK, confidence, evidence |
| **Evidence** | the source-shaped class (§3) | the observed rows that justify it |

A hunt conclusion is a finding, not a process event. Emitting only raw activity
records loses the analysis; emitting only findings loses the proof. Emit both,
with the evidence nested under `evidences[]` or referenced by
`finding_info.related_events[]`.

`type_uid = class_uid * 100 + activity_id`. Always compute it; consumers key on
it.

## 2. Base attributes on every record

| Attribute | Value |
|---|---|
| `class_uid`, `class_name` | from §3 |
| `category_uid`, `category_name` | 1 System Activity, 2 Findings, 3 Identity & Access Management, 4 Network Activity, 5 Discovery |
| `activity_id`, `activity_name` | from the class's own enum (§3) |
| `type_uid` | `class_uid * 100 + activity_id` |
| `severity_id`, `severity` | 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal |
| `time` | **epoch milliseconds** |
| `time_dt` | RFC 3339 UTC |
| `metadata.version` | the OCSF version you are emitting, e.g. `1.4.0` |
| `metadata.product.name`, `.vendor_name` | `osquery`, `Fleet` |
| `metadata.log_name` | the osquery table or EVTX channel the row came from |
| `device.hostname`, `device.uid` | from `system_info` (`hostname`, `uuid`) |
| `observables[]` | every IOC in the record, typed (§6) |

Required by the schema on essentially every class: `class_uid`,
`category_uid`, `activity_id`, `type_uid`, `severity_id`, `time`, `metadata`,
plus that class's principal object (`file`, `process`, `user`, `job`, `script`,
`module`, `group`, `finding_info`). Anything the source genuinely cannot supply
is **absent, never faked** — `actor` on a `file`-table row and `user` on a raw
`windows_eventlog` row are the usual honest omissions. Source columns with no
OCSF home go under `unmapped.*`.

Fleet returns flat rows, so when you emit OCSF **as query output** keep the
repo's flattening convention: `.` for nesting, `[0]` for the first array
element (`"process.file.path"`, `"finding_info.attacks[0].technique.uid"`).
When you emit OCSF **in a report**, emit real nested JSON.

## 3. `sig` → OCSF class map

Bundle rows arrive tagged. Look the tag up here; do not re-derive.

| `sig` prefix | Class | UID | Category | Typical `activity_id` |
|---|---|---|---|---|
| `EXEC.4688`, `EXEC.ETW`, `EXEC.LIVE`, `EXEC.WMI` | Process Activity | 1007 | 1 | 1 Launch |
| `EXEC.SHIMCACHE`, `EXEC.PREFETCH`, `EXEC.USERASSIST`, `EXEC.BAM` | Process Activity | 1007 | 1 | 1 Launch (historical — set `first_seen_time`/`last_seen_time`, not a live `time`) |
| `EXEC.PS`, `EXEC.PS.BLOCK`, `EXEC.PS.LEGACY` | Script Activity | 1009 | 1 | 1 Execute (`script.type_id = 2` PowerShell) |
| `EXEC.BITS` | Network Activity | 4001 | 4 | 1 Open |
| `FILE.DROP`, `FILE.RECENT`, `FILE.JOURNAL`, `FILE.SIG`, `FILE.OFFICEMRU`, `FILE.SHELLBAG` | File System Activity | 1001 | 1 | 1 Create, 3 Update, 4 Delete, 5 Rename, 6 Set Attributes, 14 Open |
| `PERSIST.RUN*`, `PERSIST.WINLOGON`, `PERSIST.IFEO`, `PERSIST.APPINIT`, `PERSIST.LOGONSCRIPT`, `PERSIST.ACCESSIBILITY`, `CRED.WDIGEST`, `CRED.LSA.PKG`, `DEFEND.AVOFF`, `DEFEND.LOGOFF`, `DEFEND.RDP` | Registry Value Activity (`win` ext) | 201002 | 1 | 1 Get, 2 Set, 3 Modify, 4 Delete |
| a registry **key** created/deleted rather than a value | Registry Key Activity (`win` ext) | 201001 | 1 | 1 Create, 2 Read, 3 Modify, 4 Delete, 5 Rename, 6 Set Security |
| `PERSIST.TASK*` | Scheduled Job Activity | 1006 | 1 | 1 Create, 2 Update, 3 Delete, 4 Enable, 5 Disable, 6 Start |
| `PERSIST.SVC*`, `PERSIST.SVCINSTALL` | Module Activity (service binary load) | 1005 | 1 | 1 Load |
| `PERSIST.SVC*` as inventory state | Service Query | 5016 | 5 | 1 Query |
| `PERSIST.WMI.*` | Scheduled Job Activity | 1006 | 1 | 1 Create (a permanent subscription is a scheduled job) |
| `PERSIST.STARTUP`, `PERSIST.AUTOEXEC`, `PERSIST.SHIM` | Startup Item Query | 5022 | 5 | 1 Query |
| `DEFEND.DRIVER` | Kernel Extension Activity | 1002 | 1 | 1 Load |
| `AUTH.LOGON*`, `IAM.SESSION`, `IAM.LOGGEDIN` | Authentication | 3002 | 3 | 1 Logon, 2 Logoff, 3 Authentication Ticket, 4 Service Ticket Request, 6 Preauth |
| `IAM.CHANGE` (4720/4722/4723/4724/4725/4726/4738/4740/4767) | Account Change | 3001 | 3 | 1 Create, 2 Enable, 3 Password Change, 4 Password Reset, 5 Disable, 6 Delete, 9 Lock, 12 Unlock |
| `IAM.CHANGE` (4728/4729/4732/4733/4756/4757) | Group Management | 3006 | 3 | 3 Add User, 4 Remove User, 1 Assign Privileges |
| `IAM.USER`, `IAM.GROUP`, `IAM.MEMBER` | User Inventory Info / Admin Group Query | 5003 / 5009 | 5 | 1 Query |
| `LATERAL.RDP.*` | RDP Activity | 4005 | 4 | 3 Connect Request, 4 Connect Response, 7 Disconnect, 8 Reconnect |
| `LATERAL.SHARE`, `NET.PIPE`, `NET.WFP` (5140/5145) | SMB Activity | 4006 | 4 | 2 File Open, 3 File Create |
| `NET.LISTEN`, `NET.CONN`, `NET.WFP`, `IOC.CONN` | Network Activity | 4001 | 4 | 1 Open, 2 Close, 5 Refuse, 7 Listen |
| `NET.DNSCACHE`, `IOC.DNS` | DNS Activity | 4003 | 4 | 1 Query, 2 Response |
| `NET.ARP`, `NET.HOSTS`, `IAM.DOMAIN` | Networks Query | 5013 | 5 | 1 Query |
| `LOG.CLEAR*` | Event Log Activity | 1008 | 1 | 1 Clear, 2 Delete, 9 Enable, 10 Disable |
| `DEFEND.AV`, `DETECT.AV`, `DETECT.YARA` | Detection Finding | 2004 | 2 | 1 Create |
| `SYSMON.PROC` | Process Activity | 1007 | 1 | 1 Launch |
| `SYSMON.NET` | Network Activity | 4001 | 4 | 1 Open |
| `SYSMON.DNS` | DNS Activity | 4003 | 4 | 1 Query |
| `SYSMON.IMGLOAD` (event 7) | Module Activity | 1005 | 1 | 1 Load |
| `SYSMON.IMGLOAD` (event 6) | Kernel Extension Activity | 1002 | 1 | 1 Load |
| `SYSMON.INJECT` | Process Activity | 1007 | 1 | 4 Inject (event 8/25), 3 Open (event 10) |
| `SYSMON.FILE` | File System Activity | 1001 | 1 | 1 Create (11/15), 4 Delete (23), 6 Set Attributes (2) |
| `SYSMON.REG` | Registry Key Activity 201001 (12/14) / Registry Value Activity 201002 (13) | 201001 / 201002 | 1 | 1 Create, 2 Set, 3 Modify, 4 Delete, 5 Rename |
| `SYSMON.PIPE` | SMB Activity | 4006 | 4 | 3 File Create (17), 2 File Open (18) |
| `SYSMON.WMI` | Scheduled Job Activity | 1006 | 1 | 1 Create |
| `SYSMON.TAMPER` | Event Log Activity | 1008 | 1 | 7 Stop, 10 Disable (event 4), 2 Delete / 99 Other (event 16) |
| `SYSMON.PROFILE`, `SYSMON.SVC`, `SYSMON.DRV`, `SYSMON.CFG` | collection-state gates, **not findings** — report them as telemetry provenance | 5002 | 5 | 1 Query |
| `CRED.LSASS.HANDLE`, `CRED.SUSPECT.PROC` | Process Activity | 1007 | 1 | 3 Open (handle acquisition) |
| `CRED.DUMPFILE` | File System Activity | 1001 | 1 | 1 Create |
| `CRED.CERT` | Detection Finding | 2004 | 2 | 1 Create |
| `IOC.*` sweep hits | the class of the artefact found, per the rows above | | | |
| `WEB.EDGE`, `WEB.CHROME`, `WEB.FIREFOX`, `WEB.REFERRER`, `IOC.WEB` | HTTP Activity | 4002 | 4 | 3 Get |
| `WEB.DOWNLOAD` | File System Activity | 1001 | 1 | 1 Create (time inferred from `file.btime` — the table has none) |
| `IAM.PROFILE` | User Inventory Info | 5003 | 5 | 1 Query |
| `DEFEND.FWRULE` | Device Config State | 5002 | 5 | 1 Query |
| `DEFEND.FWCHANGE` | Device Config State Change | 5019 | 5 | 1 Query |
| `AUDIT.4688`, and every B0 `sig` (`OS`, `BOOT`, `HOST`, `TBL`, `FLAG`, `PUB`, `AUDIT`, `SEC`, `AV`, `DG`, `EVTX`) | host context and collection-state gates, **not findings** — carry them in the report header; emit as Device Inventory Info 5001 / Device Config State 5002 only if a consumer needs them | 5001 / 5002 | 5 | 1 Query |

Ambiguity rule: when a row is both current state and historical activity
(a service that exists **and** was installed at time T), emit the activity class
with the timestamp when you have one, and the Discovery class when you only have
state. Never invent a timestamp to justify an activity class.

## 4. Detection Finding template (the per-finding record)

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "activity_id": 1,
  "activity_name": "Create",
  "type_uid": 200401,
  "severity_id": 4,
  "severity": "High",
  "confidence_id": 3,
  "confidence": "High",
  "verdict_id": 2,
  "verdict": "True Positive",
  "status_id": 1,
  "status": "New",
  "time": 1788815064000,
  "time_dt": "2026-09-07T14:24:24Z",
  "metadata": {
    "version": "1.4.0",
    "product": {"name": "osquery", "vendor_name": "Fleet"},
    "log_name": "services",
    "logged_time": 1788815100000
  },
  "device": {"hostname": "WKSTN-4821", "uid": "5f3c…", "type_id": 6},
  "finding_info": {
    "uid": "hunt-2026-09-07-wkstn4821-01",
    "title": "Unsigned service persisting an implant from ProgramData",
    "desc": "Service 'UpdateSvcHost' runs C:\\ProgramData\\svchost.exe, unsigned, created 2026-09-07T13:58Z, 12 minutes before the EDR alert. Registry write time and prefetch run count corroborate.",
    "types": ["Persistence"],
    "created_time": 1788815064000,
    "first_seen_time": 1788814680000,
    "last_seen_time": 1788815064000,
    "data_sources": ["services", "registry", "prefetch", "authenticode"],
    "attacks": [
      {
        "version": "17",
        "tactics": [{"uid": "TA0003", "name": "Persistence"}],
        "technique": {"uid": "T1543", "name": "Create or Modify System Process"},
        "sub_technique": {"uid": "T1543.003", "name": "Windows Service"}
      }
    ]
  },
  "evidences": [
    {
      "process": {
        "file": {"path": "C:\\ProgramData\\svchost.exe", "name": "svchost.exe",
                 "signature": {"algorithm": null, "certificate": null},
                 "hashes": [{"algorithm_id": 3, "algorithm": "SHA-256", "value": "9f2b…"}]},
        "cmd_line": "C:\\ProgramData\\svchost.exe -k netsvcs"
      },
      "actor": {"user": {"name": "NT AUTHORITY\\SYSTEM"}}
    }
  ],
  "observables": [
    {"name": "process.file.path", "type": "File Name", "type_id": 7, "value": "C:\\ProgramData\\svchost.exe"},
    {"name": "process.file.hashes[0].value", "type": "Hash", "type_id": 8, "value": "9f2b…"}
  ],
  "unmapped": {"service_name": "UpdateSvcHost", "start_type": "AUTO_START"},
  "message": "Unsigned auto-start service installed 12 minutes before the alert."
}
```

Rules:

- `finding_info.uid` is stable and unique per finding — reuse it in the timeline
  and IOC table so a reader can join them.
- `verdict_id`: 1 False Positive, 2 True Positive, 3 Disregard, 4 Suspicious,
  5 Benign, 6 Test, 7 Insufficient Data, 8 Security Risk, 9 Managed Externally,
  10 Duplicate. **1 is false positive, 2 is true positive** — the order is
  counterintuitive; do not guess it. `7 Insufficient Data` is the honest value
  when telemetry was missing, and it is used far too rarely.
- `confidence_id`: 1 Low, 2 Medium, 3 High. Justify it from source count and
  source independence, not from how the finding feels.
- `severity_id` is impact, `confidence_id` is certainty. A high-severity
  low-confidence finding is a legitimate and common output.
- When a Sysmon record is the evidence, set
  `metadata.log_name = "Microsoft-Windows-Sysmon/Operational"` and put the
  Sysmon fields where OCSF expects them:
  `process.cmd_line`, `process.parent_process.cmd_line`,
  `process.file.hashes[]` (split the `Hashes` string — `algorithm_id` 1 MD5,
  2 SHA-1, 3 SHA-256; IMPHASH has no OCSF algorithm id, so carry it as
  `unmapped.imphash`), `process.uid` from `ProcessGuid`, and
  `process.integrity` from `IntegrityLevel`.
- **Sysmon plus a state table agreeing is what earns `confidence_id = 3`.**
  A Run key seen in `registry` (B1R) *and* the process that wrote it (S-REG
  event 13) are two independent sources. A single Sysmon event with an excluded
  neighbouring id is `confidence_id = 2` at most — say which id the config
  excluded.
- `data_sources` lists the osquery tables and EVTX channels that produced the
  evidence. This is what makes a finding auditable — always populate it.

## 5. ATT&CK reference rules

- Technique goes in `finding_info.attacks[]`. A sub-technique goes in
  `sub_technique`, with its parent in `technique` — not both flattened into
  `technique`.
- `tactics[]` is an array: one technique can serve several (T1543.003 is
  Persistence **and** Privilege Escalation — list both).
- Tactic UIDs: TA0043 Reconnaissance, TA0042 Resource Development, TA0001
  Initial Access, TA0002 Execution, TA0003 Persistence, TA0004 Privilege
  Escalation, TA0005 Defense Evasion, TA0006 Credential Access, TA0007
  Discovery, TA0008 Lateral Movement, TA0009 Collection, TA0011 Command and
  Control, TA0010 Exfiltration, TA0040 Impact.
- State the ATT&CK version you mapped against in `attacks[].version`.
- Map only what the evidence shows. A service binary in ProgramData is
  T1543.003; it is not also T1055 because implants often inject. **One technique
  per observed behaviour**, and no speculative chains.
- If a bundle's `attck` tag is broader than what you actually observed (`T1059`
  for a shell you cannot classify further), keep the broad ID. Precision you did
  not earn is worse than a parent technique.

## 6. Observable types (`observables[].type_id`)

The ones a Windows hunt actually produces:

| Type | `type_id` | | Type | `type_id` |
|---|---|---|---|---|
| Hostname | 1 | | Command Line | 13 |
| IP Address | 2 | | Process ID | 15 |
| MAC Address | 3 | | CVE Object: uid | 18 |
| User Name | 4 | | Registry Key | 28 |
| URL String | 6 | | Registry Value | 29 |
| File Name | 7 | | Fingerprint | 30 |
| Hash | 8 | | Serial Number | 37 |
| Process Name | 9 | | File Path | 45 |
| Port | 11 | | Registry Key Path | 46 |

Full enum also carries the object-reference forms (20 Endpoint, 21 User,
24 File, 25 Process, 34/35 Account name/uid, 36 Script Content, 47 Device uid).
Use a scalar type for a bare IOC and an object-reference type only when you are
also emitting the object.

Put every IOC in `observables[]`. This is the array a SOAR platform reads for
blocking, and the one the IOC table in §8 is generated from.

## 7. Verdict wrapper (always first in the report)

```json
{
  "supported": true,
  "answer": "WKSTN-4821 is compromised. An unsigned binary in C:\\ProgramData executed at 13:58Z via a manually installed auto-start service, 12 minutes before the EDR alert, launched from a Remote Interactive session by dexterlabs\\jsmith from 10.4.2.19. Persistence is the service plus an HKEY_USERS Run value written at 13:59Z. No credential-dumping evidence and no lateral movement from this host within the telemetry available.",
  "confidence": "high",
  "evidence_used": [
    "B1 services -> UpdateSvcHost, C:\\ProgramData\\svchost.exe, AUTO_START",
    "B6 authenticode -> result=unsigned",
    "B2 prefetch -> run_count=3, last_run_time=13:58:04Z",
    "B1R registry -> HKEY_USERS\\S-1-5-21-…\\...\\Run value, mtime=13:59:11Z",
    "B3 logon_sessions -> jsmith, Remote Interactive, 13:41Z",
    "E-RDP 1149 -> client 10.4.2.19"
  ],
  "missing_information": [
    "4688 unavailable: audit_process_tracking=0 — parent-child chain reconstructed from prefetch and BAM instead",
    "Security channel retention starts 2026-09-05T02:11Z, so pre-alert logons older than 48h cannot be excluded",
    "ntfs_journal_events not configured on this agent — file-creation ordering inferred from btime"
  ],
  "ocsf_findings": []
}
```

`confidence` in the wrapper and `confidence_id` in each finding must agree. If
one finding is weak, say so per finding rather than downgrading the whole
verdict.

## 8. Timeline, IOC table, residual risk

**Timeline** — UTC, ascending, boot as row zero, one line each, source named:

```
2026-09-04T07:12:03Z  boot                                        uptime
2026-09-07T13:41:22Z  logon  jsmith  Remote Interactive           logon_sessions / RCM 1149 (10.4.2.19)
2026-09-07T13:58:04Z  exec   C:\ProgramData\svchost.exe  run 1    prefetch
2026-09-07T13:59:11Z  persist HKEY_USERS\…\Run = svchost.exe      registry.mtime
2026-09-07T14:24:24Z  alert  EDR: suspicious service              external
```

**IOC table** — machine-readable, ready to hand to a sweep or a blocklist:

| type | value | first_seen | source | confidence | swept fleet-wide |
|---|---|---|---|---|---|
| sha256 | `9f2b…` | 2026-09-07T13:58Z | `hash` | high | yes, 0 other hosts |
| path | `C:\ProgramData\svchost.exe` | 2026-09-07T13:57Z | `file.btime` | high | yes, 0 other hosts |
| service_name | `UpdateSvcHost` | 2026-09-07T13:59Z | `services` | high | yes, 0 other hosts |
| ip | `10.4.2.19` | 2026-09-07T13:41Z | RCM 1149 | medium | no — internal, ask network team |

**Residual risk** — every gap with its cause, in these categories: cleared or
truncated channel; retention shorter than the incident window; disabled audit
subcategory; expired evented buffer; table absent on the agent; host saturated
or offline; capability missing from the harness; scope not swept. A gap with no
stated cause is not a residual risk, it is an unfinished hunt.

**Next actions**, ranked, each naming the one query or containment step it
needs. "Investigate further" is not a next action.
