-- Detection queries for the evented tables and ATC tables.
-- Built against agent options v5. Column names verified against the canonical
-- osquery schema (fleetdm.com/tables) 2026-08-31; action / event_type string
-- values verified against osquery source 2026-09-02.
--
-- These are analysis queries, not verification. test-pack.sql checks whether
-- the publishers are alive; this file mines what they captured.
--
-- Output is OCSF 1.4.0 (schema.ocsf.io). Fleet returns flat rows, so nested
-- attributes are flattened: "." is a nested object, "[0]" the first array
-- element. Every event row carries the base attributes: class_uid, class_name,
-- category_uid, category_name, activity_id, activity_name,
-- type_uid = class_uid*100 + activity_id, severity_id, severity, time (epoch
-- milliseconds), time_dt (RFC 3339 UTC), metadata.*, device.*. Source columns
-- with no OCSF home sit under unmapped.*. Aggregated reports add count,
-- start_time and end_time. tools/sync_reports.py --check enforces this and
-- regenerates fleet/ocsf/detect.yml from this file.
--
-- Conventions:
--   * Fleet live queries run ONE statement at a time. Each block is one
--     copy-pasteable query.
--   * Every evented-table query carries WHERE time > 0. In osqueryd a query
--     without a time constraint only returns events since its last run.
--   * The audit family (process_events, socket_events, user_events,
--     process_file_events) is OFF by decision on Linux (disable_audit).
--     Use the bpf_* queries there.
--
-- 0. WHICH PUBLISHERS HAVE DATA (all platforms)
-- 0.1  Per-publisher row counts since last run of this query. Diagnostic,
--      not an OCSF event.
SELECT name, publisher, events, active
FROM osquery_events
ORDER BY events DESC;

-- ============================================================
-- macOS
-- ============================================================

-- 1. EXECUTABLES - distinct binaries executed, with activity count
--    and the user(s) who ran them. Process Activity, aggregated per binary.
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       max(time)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', max(time), 'unixepoch') AS time_dt,
       min(time)*1000 AS start_time, max(time)*1000 AS end_time, count(*) AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'es_process_events' AS "metadata.log_name",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       path AS "process.file.path",
       group_concat(DISTINCT username) AS "unmapped.users"
FROM es_process_events
WHERE time > 0 AND event_type = 'EXEC'
GROUP BY path ORDER BY count DESC LIMIT 50;

-- 2. UNSIGNED OR AD-HOC BINARIES EXECUTED
--    codesigning_flags is a comma list: NOT_VALID, ADHOC, NOT_RUNTIME, INSTALLER.
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       3 AS severity_id, 'Medium' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'es_process_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       pid AS "process.pid", path AS "process.file.path",
       substr(cmdline, 1, 200) AS "process.cmd_line", username AS "process.user.name",
       parent AS "actor.process.pid",
       codesigning_flags AS "unmapped.codesigning_flags"
FROM es_process_events
WHERE time > 0 AND event_type = 'EXEC'
  AND (codesigning_flags LIKE '%ADHOC%' OR codesigning_flags LIKE '%NOT_VALID%')
ORDER BY time DESC LIMIT 25;

-- 3. SHELL-SPAWNED INTERPRETERS AND DOWNLOAD TOOLS
--    parent and child are both joined from es_process_events on pid. The
--    child is process.*, the shell that spawned it is actor.process.*.
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       3 AS severity_id, 'Medium' AS severity,
       e.time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', e.time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'es_process_events' AS "metadata.log_name",
       e.eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       e.pid AS "process.pid", e.path AS "process.file.path",
       substr(e.cmdline, 1, 200) AS "process.cmd_line", e.username AS "process.user.name",
       p.pid AS "actor.process.pid", p.path AS "actor.process.file.path"
FROM es_process_events e
JOIN es_process_events p ON e.parent = p.pid AND p.time > 0
WHERE e.time > 0
  AND e.event_type = 'EXEC'
  AND (e.path LIKE '%/curl'   OR e.path LIKE '%/wget'
       OR e.path LIKE '%/python3' OR e.path LIKE '%/perl'
       OR e.path LIKE '%/base64')
  AND (p.path LIKE '%/zsh' OR p.path LIKE '%/bash'
       OR p.path LIKE '%/sh' OR p.path LIKE '%/ssh'
       OR p.path LIKE '%/fish' OR p.path LIKE '%/tmux')
ORDER BY e.time DESC LIMIT 25;

-- 4. FIM CHANGES WITH THE WRITING PROCESS
--    es_process_file_events pairs each monitored-path change with the pid.
--    event_type is lowercase in osquery: create, write, rename, truncate, open.
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       act AS activity_id,
       CASE act WHEN 1 THEN 'Create' WHEN 3 THEN 'Update' WHEN 5 THEN 'Rename'
                WHEN 14 THEN 'Open' ELSE 'Other' END AS activity_name,
       100100 + act AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'es_process_file_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       filename AS "file.path", nullif(dest_filename, '') AS "file_result.path",
       pid AS "actor.process.pid", path AS "actor.process.file.path",
       parent AS "actor.process.parent_process.pid",
       event_type AS "unmapped.event_type"
FROM (SELECT *, CASE event_type WHEN 'create' THEN 1 WHEN 'write' THEN 3
                                WHEN 'truncate' THEN 3 WHEN 'rename' THEN 5
                                WHEN 'open' THEN 14 ELSE 99 END AS act
      FROM es_process_file_events WHERE time > 0)
ORDER BY time DESC LIMIT 50;

-- 5. HASHED FILE CHANGES, READY FOR A YARA SCAN
--    sha256 is only populated when hashed = 1; the size cap keeps the
--    sweep under a sensible yara_delay budget. FSEvents action names are
--    CREATED / UPDATED, not CREATE / UPDATE (CORRECTIONS.md 5).
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       CASE action WHEN 'CREATED' THEN 1 ELSE 3 END AS activity_id,
       CASE action WHEN 'CREATED' THEN 'Create' ELSE 'Update' END AS activity_name,
       CASE action WHEN 'CREATED' THEN 100101 ELSE 100103 END AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'file_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       target_path AS "file.path", size AS "file.size",
       3 AS "file.hashes[0].algorithm_id", 'SHA-256' AS "file.hashes[0].algorithm",
       sha256 AS "file.hashes[0].value",
       category AS "unmapped.category", action AS "unmapped.action"
FROM file_events
WHERE time > 0
  AND action IN ('CREATED','UPDATED')
  AND size > 0 AND size < 104857600
  AND hashed = 1
ORDER BY time DESC LIMIT 50;
-- Feed a file.path into: SELECT path, count, matches FROM yara_file
-- WHERE path = '<file.path>' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/_all.yar';

-- 6. DOWNLOADS THAT FIM ALSO SAW
--    chrome_download_history is ATC; file_events is the FIM stream. The ATC
--    table has no timestamp, so time is the FIM sighting, or the query time
--    when FIM never saw the file.
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Create' AS activity_name, 100101 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       coalesce(f.time, CAST(strftime('%s','now') AS INTEGER))*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', coalesce(f.time, CAST(strftime('%s','now') AS INTEGER)), 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'chrome_download_history' AS "metadata.log_name",
       d.id AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       d.target_path AS "file.path", f.size AS "file.size",
       CASE WHEN f.sha256 != '' THEN 3 END AS "file.hashes[0].algorithm_id",
       CASE WHEN f.sha256 != '' THEN 'SHA-256' END AS "file.hashes[0].algorithm",
       nullif(f.sha256, '') AS "file.hashes[0].value",
       f.action AS "unmapped.fim_action"
FROM chrome_download_history d
LEFT JOIN file_events f ON f.target_path = d.target_path AND f.time > 0
ORDER BY d.id DESC LIMIT 25;

-- 7. BROWSER HISTORY POINTING AT EXECUTABLES AND SCRIPTS
--    HTTP Activity: a history row is a completed GET. Chrome timestamps are
--    microseconds since 1601-01-01.
SELECT 4002 AS class_uid, 'HTTP Activity' AS class_name,
       4 AS category_uid, 'Network Activity' AS category_name,
       3 AS activity_id, 'Get' AS activity_name, 400203 AS type_uid,
       2 AS severity_id, 'Low' AS severity,
       (last_visit_time/1000000 - 11644473600)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', last_visit_time/1000000 - 11644473600, 'unixepoch') AS time_dt,
       visit_count AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'chrome_url_history' AS "metadata.log_name",
       id AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       'GET' AS "http_request.http_method", url AS "http_request.url.url_string",
       title AS "unmapped.title"
FROM chrome_url_history
WHERE url LIKE '%.exe%' OR url LIKE '%.scr%' OR url LIKE '%.vbs%'
   OR url LIKE '%.js%'  OR url LIKE '%.bat%' OR url LIKE '%.php?%'
ORDER BY last_visit_time DESC LIMIT 25;

-- 8. QUARANTINE DOWNLOADS
--    Gatekeeper's record of what each app downloaded. data_url is the remote
--    URL the bytes came from, not a local path, so it cannot be joined to
--    file_events (CORRECTIONS.md 6). Apple epoch is 2001-01-01, hence the
--    +978307200 offset. file.name is the last path segment of data_url:
--    rtrim() strips everything after the final '/', replace() removes that
--    prefix.
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Create' AS activity_name, 100101 AS type_uid,
       2 AS severity_id, 'Low' AS severity,
       CAST((timestamp + 978307200)*1000 AS INTEGER) AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', timestamp + 978307200, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'quarantine_items' AS "metadata.log_name",
       id AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       replace(data_url, rtrim(data_url, replace(data_url, '/', '')), '') AS "file.name",
       data_url AS "file.url.url_string",
       agent_name AS "actor.process.name",
       origin_url AS "unmapped.origin_url"
FROM quarantine_items
ORDER BY timestamp DESC LIMIT 25;

-- ============================================================
-- Linux
-- ============================================================
-- The audit family is off by decision (disable_audit). bpf_process_events
-- and bpf_socket_events are the process and socket sources here, on agents
-- <= 5.23.1. Run section 4 of test-pack.sql first: if the bpf tables are
-- missing, these queries fail, and that failure is the finding.

-- 1. BPF PROCESS ACTIVITY, RECENT EXECUTIONS
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'bpf_process_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       pid AS "process.pid", path AS "process.file.path",
       substr(cmdline, 1, 200) AS "process.cmd_line",
       cwd AS "process.working_directory", uid AS "process.user.uid",
       parent AS "actor.process.pid"
FROM bpf_process_events
WHERE time > 0 AND probe_error = 0
ORDER BY time DESC LIMIT 50;

-- 2. BPF PROCESS ACTIVITY, DISTINCT BINARIES AND COUNTS
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       max(time)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', max(time), 'unixepoch') AS time_dt,
       min(time)*1000 AS start_time, max(time)*1000 AS end_time, count(*) AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'bpf_process_events' AS "metadata.log_name",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       path AS "process.file.path"
FROM bpf_process_events
WHERE time > 0 AND probe_error = 0
GROUP BY path ORDER BY count DESC LIMIT 50;

-- 3. BPF SOCKET ACTIVITY, OUTBOUND CONNECTS
SELECT 4001 AS class_uid, 'Network Activity' AS class_name,
       4 AS category_uid, 'Network Activity' AS category_name,
       1 AS activity_id, 'Open' AS activity_name, 400101 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'bpf_socket_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       remote_address AS "dst_endpoint.ip", remote_port AS "dst_endpoint.port",
       2 AS "connection_info.direction_id", 'Outbound' AS "connection_info.direction",
       pid AS "actor.process.pid", path AS "actor.process.file.path",
       syscall AS "unmapped.syscall"
FROM bpf_socket_events
WHERE time > 0 AND probe_error = 0 AND syscall = 'connect'
ORDER BY time DESC LIMIT 50;
-- If empty, drop the syscall filter and look at the syscall values that come back.

-- 4. BPF SOCKET ACTIVITY, WHAT IS TALKING TO WHAT
SELECT 4001 AS class_uid, 'Network Activity' AS class_name,
       4 AS category_uid, 'Network Activity' AS category_name,
       1 AS activity_id, 'Open' AS activity_name, 400101 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       max(time)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', max(time), 'unixepoch') AS time_dt,
       min(time)*1000 AS start_time, max(time)*1000 AS end_time, count(*) AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'bpf_socket_events' AS "metadata.log_name",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       remote_address AS "dst_endpoint.ip", remote_port AS "dst_endpoint.port",
       2 AS "connection_info.direction_id", 'Outbound' AS "connection_info.direction",
       path AS "actor.process.file.path"
FROM bpf_socket_events
WHERE time > 0 AND probe_error = 0 AND syscall = 'connect'
GROUP BY path, remote_address, remote_port
ORDER BY count DESC LIMIT 50;

-- ============================================================
-- Windows
-- ============================================================

-- 1. PROCESS STARTS BY BINARY, ELEVATION LEVEL, AND USER
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       max(time)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', max(time), 'unixepoch') AS time_dt,
       min(time)*1000 AS start_time, max(time)*1000 AS end_time, count(*) AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'process_etw_events' AS "metadata.log_name",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       path AS "process.file.path", substr(cmdline, 1, 150) AS "process.cmd_line",
       username AS "process.user.name",
       token_elevation_type AS "unmapped.token_elevation_type"
FROM process_etw_events
WHERE time > 0 AND type = 'ProcessStart'
GROUP BY path, cmdline, username, token_elevation_type
ORDER BY time DESC LIMIT 50;

-- 2. ELEVATED PROCESS STARTS ONLY
SELECT 1007 AS class_uid, 'Process Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Launch' AS activity_name, 100701 AS type_uid,
       3 AS severity_id, 'Medium' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'process_etw_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       pid AS "process.pid", path AS "process.file.path",
       substr(cmdline, 1, 200) AS "process.cmd_line", username AS "process.user.name",
       ppid AS "actor.process.pid",
       token_elevation_type AS "unmapped.token_elevation_type"
FROM process_etw_events
WHERE time > 0 AND type = 'ProcessStart'
  AND token_elevation_type = 'TokenElevationTypeFull'
ORDER BY time DESC LIMIT 25;

-- 3. DNS LOOKUPS WITH THE CALLING PROCESS
--    dns_lookup_events carries pid, path and username itself; no join needed
--    (CORRECTIONS.md 9). A row with a response is a Response, else a Query.
SELECT 4003 AS class_uid, 'DNS Activity' AS class_name,
       4 AS category_uid, 'Network Activity' AS category_name,
       act AS activity_id,
       CASE act WHEN 2 THEN 'Response' ELSE 'Query' END AS activity_name,
       400300 + act AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'dns_lookup_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       name AS "query.hostname", type AS "query.type",
       nullif(response, '') AS "answers[0].rdata",
       pid AS "actor.process.pid", path AS "actor.process.file.path",
       username AS "actor.user.name"
FROM (SELECT *, CASE WHEN coalesce(response, '') != '' THEN 2 ELSE 1 END AS act
      FROM dns_lookup_events WHERE time > 0)
ORDER BY time DESC LIMIT 50;

-- 4. POWERSHELL SCRIPT BLOCKS, MOST UNUSUAL FIRST
--    cosine_similarity is the similarity to a "normal" character
--    frequency baseline; low means unusual. Script Activity, type 2 = PowerShell.
SELECT 1009 AS class_uid, 'Script Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Execute' AS activity_name, 100901 AS type_uid,
       3 AS severity_id, 'Medium' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'powershell_events' AS "metadata.log_name",
       script_block_id AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       2 AS "script.type_id", 'PowerShell' AS "script.type",
       script_name AS "script.name", script_path AS "script.file.path",
       substr(script_text, 1, 300) AS "script.script_content",
       cosine_similarity AS "unmapped.cosine_similarity"
FROM powershell_events
WHERE time > 0 AND cosine_similarity < 0.3
ORDER BY cosine_similarity LIMIT 25;

-- 5. SECURITY LOG: LOGONS, PROCESS CREATION, ACCOUNT CREATION
--    One class per event id: 4624 logon -> Authentication, 4688 process
--    created -> Process Activity, 4720 user account created (not "locked",
--    CORRECTIONS.md 7) -> Account Change. All three are activity 1 in their
--    class. The XML payload goes to raw_data; the user object would need XML
--    parsing osquery cannot do.
SELECT cls AS class_uid,
       CASE cls WHEN 3002 THEN 'Authentication' WHEN 1007 THEN 'Process Activity'
                ELSE 'Account Change' END AS class_name,
       CASE cls WHEN 1007 THEN 1 ELSE 3 END AS category_uid,
       CASE cls WHEN 1007 THEN 'System Activity'
                ELSE 'Identity & Access Management' END AS category_name,
       1 AS activity_id,
       CASE cls WHEN 3002 THEN 'Logon' WHEN 1007 THEN 'Launch' ELSE 'Create' END AS activity_name,
       cls*100 + 1 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'windows_events' AS "metadata.log_name",
       eid AS "metadata.uid", CAST(eventid AS TEXT) AS "metadata.event_code",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       substr(data, 1, 400) AS raw_data
FROM (SELECT *, CASE eventid WHEN 4624 THEN 3002 WHEN 4688 THEN 1007 ELSE 3001 END AS cls
      FROM windows_events
      WHERE time > 0 AND source = 'Security' AND eventid IN (4624, 4688, 4720))
ORDER BY time DESC LIMIT 25;

-- 6. NTFS RENAMES AND DELETES UNDER THE MONITORED DIRECTORIES
--    Action names are CamelCase in osquery (CORRECTIONS.md 8). A rename
--    arrives as FileRename_OldName (path = old name) then FileRename_NewName
--    (path = new name, old_path = old name). file is the source name,
--    file_result the destination when known.
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       act AS activity_id,
       CASE act WHEN 4 THEN 'Delete' ELSE 'Rename' END AS activity_name,
       100100 + act AS type_uid,
       2 AS severity_id, 'Low' AS severity,
       time*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', time, 'unixepoch') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'ntfs_journal_events' AS "metadata.log_name",
       eid AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       CASE WHEN old_path != '' THEN old_path ELSE path END AS "file.path",
       CASE WHEN old_path != '' THEN path END AS "file_result.path",
       action AS "unmapped.action", category AS "unmapped.category"
FROM (SELECT *, CASE action WHEN 'FileDeletion' THEN 4 ELSE 5 END AS act
      FROM ntfs_journal_events
      WHERE time > 0 AND action IN ('FileRename_OldName','FileRename_NewName','FileDeletion'))
ORDER BY time DESC LIMIT 25;

-- 7. NTFS ACTIVITY BY ACTION (sanity: what the journal is doing at all)
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       act AS activity_id,
       CASE act WHEN 1 THEN 'Create' WHEN 3 THEN 'Update' WHEN 4 THEN 'Delete'
                WHEN 5 THEN 'Rename' WHEN 6 THEN 'Set Attributes' ELSE 'Other' END AS activity_name,
       100100 + act AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       max(time)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', max(time), 'unixepoch') AS time_dt,
       min(time)*1000 AS start_time, max(time)*1000 AS end_time, count(*) AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'ntfs_journal_events' AS "metadata.log_name",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       action AS "unmapped.action"
FROM (SELECT *, CASE action
                  WHEN 'FileCreation' THEN 1 WHEN 'DirectoryCreation' THEN 1
                  WHEN 'FileWrite' THEN 3 WHEN 'FileOverwrite' THEN 3 WHEN 'FileTruncation' THEN 3
                  WHEN 'FileDeletion' THEN 4 WHEN 'DirectoryDeletion' THEN 4
                  WHEN 'FileRename_OldName' THEN 5 WHEN 'FileRename_NewName' THEN 5
                  WHEN 'DirectoryRename_OldName' THEN 5 WHEN 'DirectoryRename_NewName' THEN 5
                  WHEN 'AttributesChange' THEN 6 ELSE 99 END AS act
      FROM ntfs_journal_events WHERE time > 0)
GROUP BY action ORDER BY count DESC;

-- 8. BROWSER HISTORY POINTING AT EXECUTABLES AND SCRIPTS
SELECT 4002 AS class_uid, 'HTTP Activity' AS class_name,
       4 AS category_uid, 'Network Activity' AS category_name,
       3 AS activity_id, 'Get' AS activity_name, 400203 AS type_uid,
       2 AS severity_id, 'Low' AS severity,
       (last_visit_time/1000000 - 11644473600)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', last_visit_time/1000000 - 11644473600, 'unixepoch') AS time_dt,
       visit_count AS count,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'chrome_url_history' AS "metadata.log_name",
       id AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       'GET' AS "http_request.http_method", url AS "http_request.url.url_string",
       title AS "unmapped.title"
FROM chrome_url_history
WHERE url LIKE '%.exe%' OR url LIKE '%.scr%' OR url LIKE '%.vbs%'
   OR url LIKE '%.js%'  OR url LIKE '%.bat%' OR url LIKE '%.php?%'
ORDER BY last_visit_time DESC LIMIT 25;

-- 9. MOST RECENT DOWNLOADS
--    The ATC table has no timestamp; time is the query time.
SELECT 1001 AS class_uid, 'File System Activity' AS class_name,
       1 AS category_uid, 'System Activity' AS category_name,
       1 AS activity_id, 'Create' AS activity_name, 100101 AS type_uid,
       1 AS severity_id, 'Informational' AS severity,
       CAST(strftime('%s','now') AS INTEGER)*1000 AS time,
       strftime('%Y-%m-%dT%H:%M:%SZ', 'now') AS time_dt,
       '1.4.0' AS "metadata.version", 'osquery' AS "metadata.product.name",
       'Fleet' AS "metadata.product.vendor_name", 'chrome_download_history' AS "metadata.log_name",
       id AS "metadata.uid",
       (SELECT hostname FROM system_info) AS "device.hostname",
       (SELECT uuid FROM system_info) AS "device.uid",
       target_path AS "file.path", current_path AS "unmapped.current_path"
FROM chrome_download_history ORDER BY id DESC LIMIT 25;
-- Follow up per domain or file name as needed.
