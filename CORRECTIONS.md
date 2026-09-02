# Corrections

Claims made during this work that later turned out to be wrong, and what the
evidence actually shows. Kept because the wrong versions shipped in earlier
commits and in the query comments.

## 1. The Windows "double-escaped path" bug did not exist

**Claimed:** v1's `c:\\Users\\%%\\Desktop\\%%` in YAML produced two literal
backslashes per separator, so osquery never matched the paths, and
`ntfs_journal_events` plus all four Windows ATC tables were returning zero rows.

**Actually:** the YAML/JSON analysis was right: osquery does receive
`c:\\Users\\%%\\Desktop\\%%`, but it normalises the value. In
`osquery/filesystem/filesystem.cpp`, `replaceGlobWildcards()` runs the
pre-wildcard base through `fs::canonical()`:

```cpp
auto base = fs::path(pattern.substr(0, pattern.find('*'))).make_preferred().string();
auto canonicalized = fs::canonical(base, ec).make_preferred().string();
```

`boost::filesystem::canonical()` resolves against the real filesystem, which
collapses repeated separators. `c:\\Users\\` becomes `C:\Users\`.

**Evidence from the fleet:** host WRK-AI returned 5 `ntfs_journal_events` rows
under category `Win_Yara_File_Path`. `NTFSEventSubscriber::shouldEmit()` only
emits when an event matches the resolved include-path set, so a category whose
paths failed to resolve emits nothing at all. Five rows means those paths
resolved and matched.

**What this cost:** the v2 path rewrite was unnecessary. Worse, the v3 rename
of `Win_Yara_File_Path` to `windows_file_events` broke saved queries: it
changes the `category` column, and the justification was a bug that was not real.
Anything keyed on the old category name stopped matching for no gain.

**Verification error behind it:** we tested the YAML-to-JSON encoding and
confirmed the double backslashes. We never tested whether osquery *rejects*
them. The evidence proved the encoding; the behaviour was an assumption.

## 2. `yara_sigurl_authenticate` is not TLS verification

**Claimed:** set it `true` to verify the certificate when fetching
rules over HTTPS.

**Actually:** it switches the fetch from GET to POST with the node key in a JSON
body, for a server that authenticates rule requests. GitHub rejects that, so it
must stay `false`. osquery validates the HTTPS certificate unconditionally.
Caught before it shipped.

## 3. macOS ES FIM is not unmuted and noisy

**Claimed:** `es_process_file_events` has no mutes configured and will be
high-volume; add `es_fim_mute_path_prefix`.

**Actually:** `EndpointSecurityFileEventPublisher::setUp()` calls
`es_invert_muting(ES_MUTE_INVERSION_TYPE_TARGET_PATH)` and then *selects* only
the paths from the `file_paths` config. The publisher is already scoped to those
directories. Adding mute prefixes would have narrowed an already narrow feed.

## 4. Verification queries produced false negatives

**Claimed:** `SELECT count(*) FROM es_process_events` shows whether the
publisher is healthy.

**Actually:** in osqueryd, an evented-table query with no `time` constraint
returns only events since that query last ran, and the cursor survives restarts.
Rerunning returns 0 and looks identical to a dead publisher. Every verification
query now carries `WHERE time > 0`. See the header block in `fleet/test-pack.sql`.

## 5. FSEvents action names are CREATED / UPDATED

**Claimed:** detect.sql query 5 filtered `file_events` with
`action IN ('CREATE','UPDATE')`.

**Actually:** osquery's FSEvents publisher (`osquery/events/darwin/fsevents.cpp`,
`kMaskActions`) emits `CREATED`, `UPDATED`, `DELETED`, `MOVED_TO`,
`ATTRIBUTES_MODIFIED`, `MOUNTED`, `UNMOUNTED`, `ROOT_CHANGED`,
`COLLISION_WITHIN` and `UNKNOWN`. The filter matched nothing. test-pack.sql 3.6
and verify.sql 5 already used the right names. Fixed 2026-09-02.

## 6. `quarantine_items.data_url` is a remote URL

**Claimed:** detect.sql query 8 joined `file_events.target_path` to
`quarantine_items.data_url` to line up a download with its FIM sighting.

**Actually:** `LSQuarantineDataURLString` is the URL the bytes were downloaded
from and `LSQuarantineOriginURLString` is the referring page. Neither is a local
path, so the join never matched and the FIM columns were always NULL. The
quarantine database does not store the local path; the file's
`com.apple.quarantine` xattr carries the event id instead. The join is gone.
The report now lists quarantine downloads with the source URL, the file name
taken from that URL, and the downloading app.

## 7. Security event 4720 is "user account created"

**Claimed:** comments and the report description called 4720 "account locked".

**Actually:** 4720 is "A user account was created". Account lockout is 4740.
The report maps 4720 to OCSF Account Change / Create.

## 8. `ntfs_journal_events` action names are CamelCase

**Claimed:** detect.sql query 6 filtered on
`'FILE_RENAME_OLD','FILE_RENAME_NEW','FILE_DELETE'`.

**Actually:** `kNTFSEventToStringMap` in
`osquery/events/windows/usn_journal_reader.cpp` emits `FileCreation`,
`FileDeletion`, `FileRename_OldName`, `FileRename_NewName`, `FileWrite`,
`AttributesChange` and the `Directory*` equivalents. The old filter matched
nothing; query 7 (activity by action) was the only one that would have shown
the real values.

## 9. `dns_lookup_events` already carries the process

**Claimed:** query 3 needed a LEFT JOIN to `process_etw_events` for the
username.

**Actually:** `dns_lookup_events` has `pid`, `path` and `username` columns. The
join was redundant and, because pids are reused, could return one DNS row per
matching ProcessStart. Removed.
