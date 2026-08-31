# gitops-yara

YARA rules served by URL for on-demand scanning with Fleet and osquery.

Rules are generated from [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts)
and redistributed unmodified under the Elastic License 2.0. Read
[LICENSE-NOTICE.md](LICENSE-NOTICE.md) before any customer-facing use.

## How it works

Point `sigurl` at any file in `rules/` from the `yara_file` or `yara_process`
table. Nothing is deployed to hosts.

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
                 attacksimulation, clickfraud, cryptominer, packer
rules/multi/     trojan, ransomware, hacktool, cryptominer, generic, attacksimulation, eicar
```

Each platform also has `_all.yar` — every rule for that platform plus the
cross-platform `Multi_*` rules. Fetch a category file when you know what you are
hunting; fetch `_all.yar` when you do not.

52 files, no module imports, all compile-checked in CI.

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

Apply with [`fleet/agent-options-v4.yml`](fleet/agent-options-v4.yml):

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

**`yara_sigurl_authenticate` must stay `false`.** It is not TLS verification —
it switches the fetch from GET to POST with the node key in a JSON body, for a
server that authenticates rule requests. GitHub rejects that. osquery validates
the HTTPS certificate either way.

**Nothing scans on its own.** This is on-demand only. A malicious file landing
in Downloads produces a `file_events` row but no YARA verdict until someone runs
a query. The intended pattern is in `fleet/verify.sql` query 5: let FIM tell you
what changed, then scan those paths.

**`yara_delay` is paid per file.** At the 50 ms default, a 1,000-file directory
sweep spends ~50 seconds in delay alone. Narrow the path or lower the flag.

**Fetched rules are cached** per the server's `Last-Modified` header, so a push
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

Deterministic — the same upstream commit produces byte-identical output.
`.github/workflows/refresh-rules.yml` runs it every Monday 06:00 UTC, fails if
any file stops compiling, and commits only on change. Because rules are fetched
by URL, a merged refresh reaches hosts on its own once their cache expires.

## Scan cost

Cost tracks file size, not rule count. A 10 MB file takes ~70 ms against either
the 150-rule macOS bundle or the 2,024-rule Windows one. Prefer category files
over `_all.yar` to cut fetch size and transfer, not match time.

| Input | Scan |
|---|---:|
| 50 KB text | 0.3 ms |
| 1 MB binary | ~7 ms |
| 10 MB binary | ~70 ms |
