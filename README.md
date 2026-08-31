# gitops-yara

YARA rules for Fleet, and the agent options that wire them in.

Rules are generated from [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts)
and redistributed unmodified under the Elastic License 2.0. Read
[LICENSE-NOTICE.md](LICENSE-NOTICE.md) before any customer-facing use.

## Bundles

| Bundle | Rules | Size | Consumed by |
|---|---:|---:|---|
| `rules/macos-file-events.yar` | 150 | 151 KB | `yara_events` on macOS, and on-demand `yara_file` |
| `rules/linux-file-events.yar` | 957 | 756 KB | `yara_events` on Linux, and on-demand `yara_file` |
| `rules/windows-ondemand.yar` | 2,024 | 2.4 MB | on-demand `yara_file` only |

Each bundle includes the 55 cross-platform `Multi_*` rules. All three compile
with zero module imports, so they carry no dependency on which YARA modules
osquery was built with.

`rules/MANIFEST.txt` records the upstream commit and a SHA-256 per bundle.

## Two tiers, and why

osquery consumes YARA rules two different ways, and they do not overlap.

**`yara_events` reads local files only.** It compiles whatever `yara.signatures`
points at on disk when the config loads. It cannot fetch a URL. So continuous
monitoring needs the rules deployed to each host — that is what `deploy/` does.

**`yara_file` fetches URLs on demand.** `signature_urls` in agent options is an
allowlist; an analyst passes one of those URLs as `sigurl` in a query. This
reads straight from this repo, no deployment step.

**Windows has no `yara_events`.** Windows gets the on-demand tier only. The
Windows `file_paths` category drives `ntfs_journal_events`, not YARA.

## Rollout

1. Push this repo to `github.com/karmine05/gitops-yara`. It must be public —
   osquery has no client authentication for signature URLs.

2. Apply the agent options. Dry run first:

   ```bash
   export FLEET_URL='https://fleet-f9fl.onrender.com'
   export FLEET_TOKEN='...'
   cd fleet
   ./apply-agent-options.sh --list           # find the team id
   ./apply-agent-options.sh --team 3         # backs up, diffs, writes nothing
   ./apply-agent-options.sh --team 3 --apply # prompts before PATCH
   ```

3. Deploy the rule files. Add `deploy/install-macos.sh` and
   `deploy/install-linux.sh` as Fleet scripts and run them against macOS and
   Linux hosts. Each script verifies the download contains rules before
   installing, and restarts fleetd so osquery recompiles.

4. Restart fleetd on every host. `command_line_flags` changes do not take
   effect without it.

5. Verify with `fleet/verify.sql`. Query 5 is the end-to-end smoke test.

## Smoke test

Every bundle contains `Multi_EICAR_ac8f42d6`. Drop an EICAR file into a
monitored path on a test host:

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.com
```

Then query `yara_events` and look for the match. If `file_events` shows the
write but `yara_events` shows nothing, the rules did not compile — check the
rule file exists and restart fleetd.

## Refreshing rules

`tools/build_bundles.py` clones upstream, groups rules by platform, and writes
the bundles. It is deterministic: the same upstream commit produces
byte-identical output.

```bash
pip install yara-python
python3 tools/build_bundles.py --out rules --verify
```

`.github/workflows/refresh-rules.yml` runs this every Monday at 06:00 UTC,
fails the job if any bundle stops compiling, and commits only on change.

Changing rules in this repo does **not** update hosts on its own. Re-run the
deploy scripts after a refresh — osquery only recompiles rules on config load.

## Cost

Scan cost tracks file size, not rule count. Measured against these bundles:

| File | Scan time |
|---|---:|
| 50 KB text | 0.3 ms |
| 1 MB binary | ~7 ms |
| 10 MB binary | ~70 ms |

The 957-rule Linux bundle costs the same per file as the 150-rule macOS one.
Rule count is not the lever — monitored path breadth is. `yara_delay`
(default 50 ms) throttles between scans; raise it if bulk file activity costs
too much CPU.

## Layout

```
rules/      generated bundles + MANIFEST.txt   (do not hand-edit)
tools/      build_bundles.py
deploy/     Fleet scripts that place rules on hosts
fleet/      agent-options-v3.yml, apply script, verify.sql
```
