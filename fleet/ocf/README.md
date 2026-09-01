# OCF reports

Every SQL query in this project, converted to OCF (apiVersion v1 / kind
report) in the exact format Fleet stores. One file per source SQL file; each
file holds a list of reports separated by `---`.

| File             | Source          | Reports |
|------------------|-----------------|---------|
| detect.yml       | detect.sql      | 22      |
| health-check.yml | health-check.sql| 7       |
| test-pack.yml    | test-pack.sql   | 34      |
| verify.yml       | verify.sql      | 12      |

All queries carry the fields Fleet uses: interval 0, logging snapshot,
discard_data false, automations disabled, observer can not run. Each report
names its platform (darwin / linux / windows), or leaves it empty for all
platforms.

## Import

```
fleetctl apply -f fleet/ocf/verify.yml      # one file
fleetctl apply -f fleet/ocf/detect.yml      # and so on
```

Imported reports are global (no fleet/team tag). To scope them to a team,
edit the `fleet:` key before applying.

## Notes learned the hard way

- A report spec cannot carry both `fleet:` and `team:` in the same apply.
  Fleet 4.90 rejects it. These files use `fleet:` only; Fleet adds `team: ""`
  back on read, which is normal.
- `fleetctl delete -f` with a multi-document file deletes only the first
  report. Delete one file per report.
- The SQL in these files is byte-identical to the source .sql files. Do not
  hand-edit one without the other.

Verified live 2026-08-31: single and 12-report files applied and read back
identical against the 4.90.0 server.
