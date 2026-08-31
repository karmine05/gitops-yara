# gitops-yara

YARA rules served by URL for on-demand scanning with Fleet and osquery.

This repo builds its rules from [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts)
and [magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers),
redistributing them unmodified. The Elastic rules carry the Elastic License 2.0;
the LOLDrivers rules carry Apache-2.0. Read
[LICENSE-NOTICE.md](LICENSE-NOTICE.md) before any customer-facing use.

## How it works

Point `sigurl` at any file in `rules/` from the `yara_file` or `yara_process`
table. Nothing lands on hosts.

```sql
SELECT path, count, matches
FROM yara_file
WHERE path = '/tmp/suspect.bin'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/ransomware.yar';
```

[`rules/INDEX.md`](rules/INDEX.md) lists every file with its rule count and the
exact `sigurl` to paste.

## Layout

```
rules/macos/     trojan, infostealer, backdoor, virus, cryptominer, hacktool, creddump, exploit
rules/linux/     trojan, exploit, cryptominer, generic, hacktool, ransomware, rootkit,
                 shellcode, backdoor, virus, worm, webshell, packer, proxy, downloader
rules/windows/   vulndriver, trojan, generic, rootkit, hacktool, ransomware, exploit,
                 infostealer, wiper, virus, pup, backdoor, shellcode, remoteadmin,
                 attacksimulation, clickfraud, cryptominer, packer,
                 loldrivers_vulndriver, loldrivers_maldriver
rules/multi/     trojan, ransomware, hacktool, cryptominer, generic, attacksimulation, eicar
```

The two `windows/loldrivers_*.yar` files come from
[magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers)
(Apache-2.0): `loldrivers_vulndriver.yar` is 744 rules against known-vulnerable
kernel drivers, `loldrivers_maldriver.yar` is 47 rules against malicious ones.
They complement the Elastic `vulndriver` file, which uses a different rule set
and does not overlap.

Each platform also has `_all.yar`: every Elastic rule for that platform plus
the cross-platform `Multi_*` rules. The LOLDrivers files are always fetched by
their own URL, not folded into `_all.yar`. Fetch a category file when you know
what you are hunting; fetch `_all.yar` when you do not.

54 files, no module imports, all compile-checked in CI.

## Agent options

`signature_urls` is an allowlist, and osquery treats the URL **path as a regex**
(host and scheme must match exactly). One entry covers the whole tree, so adding
a rule file to this repo needs no config change:

```yaml
yara:
  signature_urls:
    - 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/.*\.yar'
    - 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/.*\.yar'
```

Apply with [`fleet/agent-options-v5.yml`](fleet/agent-options-v5.yml):

```bash
export FLEET_URL='https://fleet-f9fl.onrender.com'
export FLEET_TOKEN='...'
cd fleet
./apply-agent-options.sh --list            # find the team id
./apply-agent-options.sh --team 3          # backs up + diffs, writes nothing
./apply-agent-options.sh --team 3 --apply  # prompts before PATCH
```

`command_line_flags` changes need a fleetd restart on each host.

## Things that will bite you

**This repo must be public.** osquery has no client authentication for signature
URLs. A private repo returns 404 to the agent.

**`yara_sigurl_authenticate` must stay `false`.** It does not control TLS
verification; it switches the fetch from GET to POST with the node key in a JSON body, for a
server that authenticates rule requests. GitHub rejects that. osquery validates
the HTTPS certificate either way.

**Nothing scans on its own.** This is on-demand only. A malicious file landing
in Downloads produces a `file_events` row but no YARA verdict until someone runs
a query. The intended pattern is in `fleet/verify.sql` query 5: let FIM tell you
what changed, then scan those paths.

**`yara_delay` costs you per file.** At the 50 ms default, a 1,000-file directory
sweep spends ~50 seconds in delay alone. Narrow the path or lower the flag.

**osquery caches fetched rules** per the server's `Last-Modified` header, so a push
to this repo is not instantly live on every host.

## Smoke test

`multi/eicar.yar` exists for this. On a test host:

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
```

```sql
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/eicar.com'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/eicar.yar';
```

Expect `count=1` and `Multi_EICAR_ac8f42d6`. A "signature url not allowed" error
means the allowlist regex did not match. An empty result means the host could
not reach raw.githubusercontent.com.

## Refreshing

```bash
pip install yara-python
python3 tools/build_rules.py --out rules --verify
```

Deterministic: the same upstream commit produces byte-identical output.
`.github/workflows/refresh-rules.yml` runs it every Monday 06:00 UTC, fails if
any file stops compiling, and commits only on change. The fetch is by URL,
so a merged refresh reaches hosts on its own once their cache expires.

## Scan cost

Cost tracks file size, not rule count. A 10 MB file takes ~70 ms against either
the 150-rule macOS bundle or the 2,024-rule Windows one. Prefer category files
over `_all.yar` to cut fetch size and transfer, not match time.

| Input | Scan |
|---|---:|
| 50 KB text | 0.3 ms |
| 1 MB binary | ~7 ms |
| 10 MB binary | ~70 ms |

## Verification gotcha: evented tables

In osqueryd (which runs Fleet's live *and* scheduled queries) an evented-table
query with **no `time` constraint** returns only events since that query last
ran. The cursor lives in RocksDB, survives agent restarts, and
`expireEventBatches()` purges the rows it read. `SELECT count(*) FROM
es_process_events` then gives a real number once and `0` on every rerun,
which looks exactly like a dead publisher.

Every query in `fleet/health-check.sql`, `fleet/test-pack.sql`, and
`fleet/detect.sql` carries `WHERE time > 0` for this reason. Leave it off for
real scheduled detection queries, where since-last-run is the behaviour you want.

`sudo orbit shell` is not the daemon, so it never optimizes. If the shell shows
events and Fleet shows none, that is this, not a broken publisher.

## Known time bomb: BPF on Linux

osquery removed all BPF support in commit `484e1d05` ("Upgrade Linux toolchain
to 1.3.0", [#8814](https://github.com/osquery/osquery/pull/8814), 2026-04-30).
Release **5.23.1 is the last one that has it**; the removal is on main and not
yet in a tagged release. Tracking: [fleetdm/fleet#30639](https://github.com/fleetdm/fleet/issues/30639).

Agent options set `enable_bpf_events: true`. On an osqueryd built after that
commit the flag is unknown and `bpf_process_events` / `bpf_socket_events` do not
exist. Since the audit family is deliberately off, Linux would then have **no
process or socket eventing at all**, and nothing would raise an error.

Section 4 of [`fleet/test-pack.sql`](fleet/test-pack.sql) is the canary. Run it
on every Linux host after any agent upgrade. If it trips, either switch the
Linux hosts to the audit family in their own team, or pin the agent version.
