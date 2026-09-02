# OCSF reports

Every SQL query in `fleet/*.sql`, as Fleet report specs (`apiVersion: v1`,
`kind: report`). One file per source file; each file holds a list of reports
separated by `---`. `detect.yml` is the detection logic and every row it
returns is an OCSF 1.4.0 event. The other three files are agent diagnostics and
keep osquery's native columns.

| File             | Source           | Reports | Output                          |
|------------------|------------------|---------|---------------------------------|
| detect.yml       | detect.sql       | 22      | OCSF 1.4.0 events (21) + 1 diagnostic |
| health-check.yml | health-check.sql | 7       | osquery columns                 |
| test-pack.yml    | test-pack.sql    | 34      | osquery columns                 |
| verify.yml       | verify.sql       | 12      | osquery columns                 |

All reports carry the fields Fleet uses: interval 0, logging snapshot,
discard_data false, automations disabled, observer can not run. Each report
names its platform (darwin / linux / windows), or leaves it empty for all
platforms. Reports on `file_events` are darwin,linux: that table does not
exist on Windows.

## OCSF shape

Fleet returns flat rows, so nested OCSF attributes are flattened: `.` is a
nested object, `[0]` is the first array element. Unflatten before handing rows
to an OCSF consumer, or use the keys as-is in Splunk or Athena.

Every event row carries:

| Attribute | Value |
|---|---|
| `class_uid`, `class_name`, `category_uid`, `category_name` | the OCSF class |
| `activity_id`, `activity_name` | from the source table's action / event_type |
| `type_uid` | `class_uid * 100 + activity_id` |
| `severity_id`, `severity` | 1 Informational, 2 Low, 3 Medium |
| `time` | epoch milliseconds |
| `time_dt` | RFC 3339 UTC |
| `metadata.version` | `1.4.0` |
| `metadata.product.name`, `metadata.product.vendor_name` | `osquery`, `Fleet` |
| `metadata.log_name` | the osquery table the row came from |
| `metadata.uid` | osquery `eid` where the table has one |
| `device.hostname`, `device.uid` | from `system_info` |

Aggregated reports (per binary, per destination, per NTFS action) add `count`,
`start_time` and `end_time`. Source columns with no OCSF home sit under
`unmapped.*`.

Class per source:

| Source | Class | activity |
|---|---|---|
| `es_process_events`, `bpf_process_events`, `process_etw_events` | Process Activity 1007 | 1 Launch |
| `es_process_file_events`, `file_events`, `ntfs_journal_events`, `chrome_download_history`, `quarantine_items` | File System Activity 1001 | 1 Create, 3 Update, 4 Delete, 5 Rename, 6 Set Attributes, 14 Open |
| `bpf_socket_events` | Network Activity 4001 | 1 Open, `connection_info.direction_id` 2 Outbound |
| `dns_lookup_events` | DNS Activity 4003 | 1 Query, 2 Response |
| `powershell_events` | Script Activity 1009 | 1 Execute, `script.type_id` 2 PowerShell |
| `windows_events` 4624 / 4688 / 4720 | Authentication 3002 / Process Activity 1007 / Account Change 3001 | 1 |
| `chrome_url_history` | HTTP Activity 4002 | 3 Get |

Required OCSF attributes the source cannot supply are absent, not faked:
`actor` on `file_events`, `ntfs_journal_events` and the browser tables; `user`
on the `windows_events` rows (it lives inside the XML in `raw_data`). The
Chrome downloads table has no timestamp, so those rows use the FIM sighting
time or the query time. `detect-0-1-publisher-row-counts` is a publisher
health check kept next to the detections; it is not an OCSF event.

Enums and attribute names were checked against schema.ocsf.io 1.4.0 on
2026-09-02. Later OCSF versions are additive, so bumping `metadata.version` is
a one-line change in detect.sql.

## Keeping .sql and .yml in step

The `.sql` files are the source. Statement N of `fleet/X.sql` is the `query:`
of report N in `fleet/ocsf/X.yml`, collapsed to one line (whitespace outside
string literals only).

```
python3 tools/sync_reports.py          # regenerate every query: from the .sql
python3 tools/sync_reports.py --check  # what CI runs
```

`--check` also compiles every statement against stub tables built from
Fleet's osquery schema and the ATC tables in `agent-options-v5.yml`, so a wrong
table or column name fails in CI instead of on a host, and verifies that every
detect.yml event carries the OCSF base attributes. Pass
`--schema /path/to/osquery_fleet_schema.json` to use a local copy of the
schema.

## Import

```
fleetctl apply -f fleet/ocsf/detect.yml
fleetctl apply -f fleet/ocsf/verify.yml
```

Imported reports are global (no fleet/team tag). To scope them to a team,
edit the `fleet:` key before applying.

## Notes learned the hard way

- `kind: report` and the `fleet:` key need fleetctl 4.83 or newer. Older
  fleetctl only knows `kind: query` / `team:`.
- A report spec cannot carry both `fleet:` and `team:` in the same apply.
  Fleet 4.90 rejects it. These files use `fleet:` only; Fleet adds `team: ""`
  back on read, which is normal.
- `fleetctl apply` contacts the server before it parses the file, so there is
  no offline validation; a bad spec fails only against a live server.
  `tools/sync_reports.py --check` is the offline check.
- `fleetctl delete -f` with a multi-document file deletes only the first
  report. Delete one file per report.
- Do not hand-edit a `query:` in the .yml. Edit the .sql and run the sync.

Verified live 2026-08-31: single and 12-report files applied and read back
identical against the 4.90.0 server (pre-OCSF shape; the OCSF rewrite of
detect.yml has not yet been applied to a live server).
