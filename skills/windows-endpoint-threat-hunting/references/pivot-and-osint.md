# Pivot and OSINT — turning one finding into scope

The point of a pivot is to change a query or a verdict. Enrichment that does
neither is a wasted round trip.

## 1. Extraction — what to lift from each bundle

| Source row | Extract | Pivot it into |
|---|---|---|
| `PERSIST.SVC` | service name, binary path, `module_path`, `user_account` | B8 `IOC.SVC` fleet-wide; B6 `authenticode` + `hash` on the path |
| `PERSIST.TASK` | task name, `action` string, author | B8 `IOC.TASK`; E-TASK for the creation event |
| `PERSIST.RUN*` | value name, `data`, `mtime` | B8 path sweep on `data`; timeline anchor from `mtime` |
| `EXEC.PREFETCH` | filename, `run_count`, `accessed_files` | the dropper's own dependencies and output files → B6 |
| `EXEC.SHIMCACHE` | path, `entry` ordinal | execution ordering; B8 `IOC.SHIMCACHE` |
| `EXEC.BAM` / `EXEC.USERASSIST` | path + SID | attribution to a user → B3 to resolve the SID |
| `EXEC.PS` | script text | URLs, IPs, base64 blobs, function names, mutex names → decode locally, then B8 + OSINT |
| `FILE.DROP` | path, `size`, `btime`, `mtime` | `hash` on that one path; OSINT on the hash |
| `NET.CONN` / `NET.LISTEN` | remote IP:port, owning process | B8 `IOC.CONN` fleet-wide; OSINT on the IP |
| `NET.DNSCACHE` | domain | B8 `IOC.DNS`; OSINT on the domain |
| `NET.PIPE` | pipe name | B8 pipe-name sweep; OSINT on the name pattern |
| `AUTH.LOGON` | account, source IP, logon type | B3 on other hosts that account touched; B8 `IOC.AUTH` |
| `LATERAL.RDP.*` | client IP, session id | the source host — resolve it with `HOST.FIND` (`query=<IP>`) and hunt it too |
| `SYSMON.PROC` | `Hashes` (MD5/SHA256/**IMPHASH**), `OriginalFileName`, `ProcessGuid`, full `CommandLine` | IMPHASH → OSINT family clustering (it survives recompilation and repacking in a way file hashes do not); `ProcessGuid` → the whole process tree on this host; `OriginalFileName` mismatch → renamed-LOLBin sweep fleet-wide |
| `SYSMON.NET` / `SYSMON.DNS` | `DestinationIp`, `DestinationHostname`, `QueryName`, and the `Image` that owned it | B8 network sweep; OSINT on the domain — and now you can name the process, which most C2 write-ups key on |
| `SYSMON.FILE` (event 15) | `Contents` of the `Zone.Identifier` stream | the download host and referrer URL — initial access, even with browser history gone |
| `SYSMON.IMGLOAD` | `ImageLoaded`, its `Hashes`, `SignatureStatus` | unsigned DLL hash → OSINT; driver hash → LOLDrivers |
| `SYSMON.INJECT` | `SourceImage`, `GrantedAccess`, `CallTrace` | the source binary is the next artefact to hash and sweep |
| `DETECT.AV` | detection name, path, action taken | vendor name → family behaviour → the specific artefacts to look for next |
| `DETECT.YARA` | rule name, matched strings | rule's family → its known persistence and C2 patterns |

Second-order rule: **every artefact implies a neighbour.** A binary implies its
download source (browser history, BITS, `FILE.RECENT`); a service implies its
registry key and prefetch entry; a logon implies a source host; a domain implies
the process that resolved it. Chase the neighbour before going wide.

## 2. Normalised IOC record

Keep one table in working state for the whole hunt. Every row is either swept or
explicitly deferred with a reason.

```json
{
  "type": "sha256|md5|sha1|path|filename|service_name|task_name|registry_value|ip|domain|url|pipe|mutex|cert_serial|user|ua",
  "value": "…",
  "first_seen": "2026-09-07T13:58:04Z",
  "source": "prefetch | services | registry.mtime | RCM 1149 | yara_file",
  "host": "<host_id>",
  "confidence": "high|medium|low",
  "swept": {"scope": "fleet:windows | fleet:Workstations | none",
            "hosts_answered": 412, "hits": 0, "deferred_reason": null},
  "osint": {"checked": true, "verdict": "known-bad|unknown|benign",
            "sources": ["https://…"]}
}
```

Rules:

- Normalise before sweeping: lowercase hashes, strip `\\?\` prefixes, expand
  `%APPDATA%` and short (8.3) paths, resolve environment variables in registry
  `data`.
- A hash sweep with `hosts_answered` far below the fleet size is not a clean
  result — record the answer rate, not just the hit count.
- `deferred_reason` exists so an unswept IOC is a stated gap rather than an
  omission.

## 3. Sweep ladder — cheapest discriminator first

1. **Filename / service / task name** (`LIKE`, no I/O) — wide, cheap, noisy.
   Good first pass across the whole Windows estate.
2. **Path** (`GLOB` on one level) — cheap, much more specific.
3. **Registry value** (exact key + name) — cheap and highly specific.
4. **Network** (`process_open_sockets`, `dns_cache`, `arp_cache`) — cheap, but
   only catches what is live or cached now.
5. **Hash** (`hash` with a `directory` constraint) — definitive, and the only
   one that costs real device I/O. Scope it to the directory the first pass
   named, never to a tree.
6. **EVTX with pushdown** (`channel` + `eventid IN` + `timestamp`) — affordable
   estate-wide only for a narrow event set.
7. **YARA** — last. One location, one narrow rule file, per host.

Scoping discipline: `TARGET.RESOLVE` first to see the host count. State the
count in the report. A wide sweep burns CPU on every host and shows up in EDR
telemetry — it is an operational act, not a free lookup.

## 4. OSINT rules of engagement

**Order:** internal knowledge (`KB.SEARCH` — prior hunts, local YARA corpus,
asset ownership, known-good baselines) before any external call. Most "unknown
binary" questions are answered by the estate's own software inventory
(`HOST.SOFTWARE`), which costs nothing and leaks nothing.

**What may leave the environment:**

| Safe to send | Never send |
|---|---|
| file hashes (md5/sha1/sha256) | usernames, email addresses, SIDs |
| public IPs and domains | internal hostnames, serials, asset tags |
| public CVE ids | RFC1918 / internal IPs |
| malware family and rule names | full file paths containing a username |
| generic command-line patterns | actual command lines, script contents, config blobs |
| vendor detection names | customer, org or project names |

Uploading a **file** or a **script body** to a third-party service is
exfiltration of customer data. Do not do it. Search for the hash, not the
sample.

**Query construction:** neutral and multi-angle. Searching
`"<hash> APT ransomware exploit"` biases every result toward attribution
theatre. Search the artefact plainly first (`"<hash>"`, `"<filename>"
service persistence`, `"<domain>" passive dns`), then the family name once you
have one. Prefer primary sources: vendor advisories, CVE/KEV records, LOLBAS
and LOLDrivers entries, the maintainer's own docs. Take at least two
independent sources before calling a family.

**What to bring back:** exactly one of —

1. a **new query** (a second path, registry key, service name or domain to
   sweep). This is the valuable outcome;
2. a **classification** with sources (family, tool, or "benign, ships with
   product X");
3. **nothing**, stated as nothing.

## 5. Evidence discipline (hard rules)

- Every external claim carries its source URL in the finding's
  `finding_info.src_url` or in `osint.sources[]`. No source, no claim.
- Never assert exploitability, KEV listing, CISA mandate, attribution, or
  compliance impact without a record that says so. Local ground truth
  (`VULN.HOSTS`, `HOST.POLICIES`, the vulnerability's own record) outranks any
  model recollection.
- If local data says `cisa_known_exploit = false`, no amount of web narrative
  overrides it. Post-check every external claim against the authoritative local
  flag and drop what contradicts it.
- Thin evidence produces a cautious verdict and an **empty** campaign/IOC array.
  Invented threat-actor names, fabricated IOC lists and speculative kill chains
  are the failure mode this section exists to prevent.
- Distinguish, in the report's own words: *observed on this host*, *observed
  elsewhere in the estate*, *reported by a third party*. Three different
  confidence levels; never collapse them into one sentence.

## 6. When to stop pivoting

- The IOC set has stopped growing across two consecutive sweeps.
- The next pivot is expensive-class (fleet-wide hash, wide YARA) and the
  cheaper discriminators already answered the scoping question.
- The pivot would need a capability you do not have (network flow data, mail
  logs, identity provider logs) — record it as a hand-off, name the team, and
  stop.
- OSINT has returned nothing new on two independent searches. Say "unknown to
  public sources as of <date>" — that is a finding, and a useful one.
