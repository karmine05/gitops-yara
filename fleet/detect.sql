-- Detection queries for the evented tables and ATC tables.
-- Built against agent options v5, column names verified against the canonical
-- osquery schema (fleetdm.com/tables) 2026-08-31.
--
-- These are analysis queries, not verification. test-pack.sql checks whether
-- the publishers are alive; this file mines what they captured.
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
-- 0.1  Per-publisher row counts since last run of this query.
SELECT name, publisher, events, active
FROM osquery_events
ORDER BY events DESC;

-- ============================================================
-- macOS
-- ============================================================

-- 1. EXECUTABLES - distinct binaries executed, with activity count
--    and the user(s) who ran them.
SELECT path, count(*) AS n,
       datetime(min(time),'unixepoch') AS first_seen,
       datetime(max(time),'unixepoch') AS last_seen,
       group_concat(DISTINCT username) AS users
FROM es_process_events
WHERE time > 0 AND event_type = 'EXEC'
GROUP BY path ORDER BY n DESC LIMIT 50;

-- 2. UNSIGNED OR AD-HOC BINARIES EXECUTED
--    codesigning_flags is a comma list: NOT_VALID, ADHOC, NOT_RUNTIME, INSTALLER.
SELECT datetime(time,'unixepoch') AS t, pid, path, username,
       substr(cmdline, 1, 200) AS cmdline, codesigning_flags
FROM es_process_events
WHERE time > 0 AND event_type = 'EXEC'
  AND (codesigning_flags LIKE '%ADHOC%' OR codesigning_flags LIKE '%NOT_VALID%')
ORDER BY time DESC LIMIT 25;

-- 3. SHELL-SPAWNED INTERPRETERS AND DOWNLOAD TOOLS
--    parent and child are both joined from es_process_events on pid.
SELECT datetime(e.time,'unixepoch') AS t,
       e.pid AS child_pid, e.path AS child_path,
       substr(e.cmdline, 1, 200) AS child_cmdline,
       p.path AS parent_path
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
SELECT datetime(time,'unixepoch') AS t, pid, path AS writer,
       event_type, dest_filename
FROM es_process_file_events
WHERE time > 0
ORDER BY time DESC LIMIT 50;

-- 5. HASHED FILE CHANGES, READY FOR A YARA SCAN
--    sha256 is only populated when hashed = 1; the size cap keeps the
--    sweep under a sensible yara_delay budget.
SELECT datetime(time,'unixepoch') AS t, target_path, action, size, sha256
FROM file_events
WHERE time > 0
  AND action IN ('CREATE','UPDATE')
  AND size > 0 AND size < 104857600
  AND hashed = 1
ORDER BY time DESC LIMIT 50;
-- Feed a target_path into: SELECT path, count, matches FROM yara_file
-- WHERE path = '<target_path>' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/_all.yar';

-- 6. DOWNLOADS THAT FIM ALSO SAW
--    chrome_download_history is ATC; file_events is the FIM stream.
SELECT d.id, d.target_path,
       f.action, f.size, f.sha256
FROM chrome_download_history d
LEFT JOIN file_events f ON f.target_path = d.target_path AND f.time > 0
ORDER BY d.id DESC LIMIT 25;

-- 7. BROWSER HISTORY POINTING AT EXECUTABLES AND SCRIPTS
SELECT url, title, visit_count,
       datetime(last_visit_time/1000000 - 11644473600,'unixepoch') AS last_visit
FROM chrome_url_history
WHERE url LIKE '%.exe%' OR url LIKE '%.scr%' OR url LIKE '%.vbs%'
   OR url LIKE '%.js%'  OR url LIKE '%.bat%' OR url LIKE '%.php?%'
ORDER BY last_visit_time DESC LIMIT 25;
-- Chrome timestamps are microseconds since 1601-01-01.

-- 8. QUARANTINE ORIGIN TRIANGULATION
--    Gatekeeper tag, download record, and FIM sighting in one row.
SELECT datetime(q.timestamp + 978307200,'unixepoch') AS quarantined,
       q.data_url, q.agent_name, q.origin_url,
       f.action, f.size, f.sha256
FROM quarantine_items q
LEFT JOIN file_events f ON f.target_path = q.data_url AND f.time > 0
ORDER BY q.timestamp DESC LIMIT 25;
-- Apple epoch is 2001-01-01, hence the +978307200 offset.

-- ============================================================
-- Linux
-- ============================================================
-- The audit family is off by decision (disable_audit). bpf_process_events
-- and bpf_socket_events are the process and socket sources here, on agents
-- <= 5.23.1. Run section 4 of test-pack.sql first: if the bpf tables are
-- missing, these queries fail, and that failure is the finding.

-- 1. BPF PROCESS ACTIVITY, RECENT EXECUTIONS
SELECT datetime(time,'unixepoch') AS t, pid, parent,
       path, substr(cmdline, 1, 200) AS cmdline, cwd
FROM bpf_process_events
WHERE time > 0 AND probe_error = 0
ORDER BY time DESC LIMIT 50;

-- 2. BPF PROCESS ACTIVITY, DISTINCT BINARIES AND COUNTS
SELECT path, count(*) AS n,
       datetime(min(time),'unixepoch') AS first_seen,
       datetime(max(time),'unixepoch') AS last_seen
FROM bpf_process_events
WHERE time > 0 AND probe_error = 0
GROUP BY path ORDER BY n DESC LIMIT 50;

-- 3. BPF SOCKET ACTIVITY, OUTBOUND CONNECTS
SELECT datetime(time,'unixepoch') AS t, path, pid,
       remote_address, remote_port, syscall
FROM bpf_socket_events
WHERE time > 0 AND probe_error = 0 AND syscall = 'connect'
ORDER BY time DESC LIMIT 50;
-- If empty, drop the syscall filter and look at the syscall values that come back.

-- 4. BPF SOCKET ACTIVITY, WHAT IS TALKING TO WHAT
SELECT path, remote_address, remote_port, count(*) AS n
FROM bpf_socket_events
WHERE time > 0 AND probe_error = 0 AND syscall = 'connect'
GROUP BY path, remote_address, remote_port
ORDER BY n DESC LIMIT 50;

-- ============================================================
-- Windows
-- ============================================================

-- 1. PROCESS STARTS BY BINARY, ELEVATION LEVEL, AND USER
SELECT path, substr(cmdline, 1, 150) AS cmdline, username,
       token_elevation_type, count(*) AS n, max(datetime) AS last_seen
FROM process_etw_events
WHERE time > 0 AND type = 'ProcessStart'
GROUP BY path, cmdline, username, token_elevation_type
ORDER BY last_seen DESC LIMIT 50;

-- 2. ELEVATED PROCESS STARTS ONLY
SELECT datetime(time,'unixepoch') AS t, pid, path, username,
       substr(cmdline, 1, 200) AS cmdline
FROM process_etw_events
WHERE time > 0 AND type = 'ProcessStart'
  AND token_elevation_type = 'TokenElevationTypeFull'
ORDER BY time DESC LIMIT 25;

-- 3. DNS LOOKUPS WITH THE CALLING PROCESS
SELECT datetime(d.time,'unixepoch') AS t, d.name, d.path,
       p.username, d.response
FROM dns_lookup_events d
LEFT JOIN process_etw_events p
       ON p.pid = d.pid AND p.time > 0 AND p.type = 'ProcessStart'
WHERE d.time > 0
ORDER BY d.time DESC LIMIT 50;

-- 4. POWERSHELL SCRIPT BLOCKS, MOST UNUSUAL FIRST
--    cosine_similarity is the similarity to a "normal" character
--    frequency baseline; low means unusual.
SELECT datetime(time,'unixepoch') AS t, script_name, script_path,
       cosine_similarity, substr(script_text, 1, 300) AS head
FROM powershell_events
WHERE time > 0 AND cosine_similarity < 0.3
ORDER BY cosine_similarity LIMIT 25;

-- 5. SECURITY LOG, LOGONS AND PROCESS CREATION
SELECT datetime(time,'unixepoch') AS t, eventid,
       substr(data, 1, 400) AS data_head
FROM windows_events
WHERE time > 0 AND source = 'Security'
  AND eventid IN (4624, 4688, 4720)
ORDER BY time DESC LIMIT 25;
-- 4624 logon success, 4688 process created, 4720 account locked.

-- 6. NTFS RENAMES AND DELETES UNDER THE MONITORED DIRECTORIES
SELECT datetime(time,'unixepoch') AS t, action, path, old_path
FROM ntfs_journal_events
WHERE time > 0
  AND action IN ('FILE_RENAME_OLD','FILE_RENAME_NEW','FILE_DELETE')
ORDER BY time DESC LIMIT 25;

-- 7. NTFS ACTIVITY BY ACTION (sanity: what the journal is doing at all)
SELECT action, count(*) AS n, datetime(max(time),'unixepoch') AS last_seen
FROM ntfs_journal_events
WHERE time > 0
GROUP BY action ORDER BY n DESC;

-- 8. BROWSER HISTORY POINTING AT EXECUTABLES AND SCRIPTS
SELECT url, title, visit_count,
       datetime(last_visit_time/1000000 - 11644473600,'unixepoch') AS last_visit
FROM chrome_url_history
WHERE url LIKE '%.exe%' OR url LIKE '%.scr%' OR url LIKE '%.vbs%'
   OR url LIKE '%.js%'  OR url LIKE '%.bat%' OR url LIKE '%.php?%'
ORDER BY last_visit_time DESC LIMIT 25;

-- 9. MOST RECENT DOWNLOADS, BOTH BROWSERS
SELECT id, current_path, target_path
FROM chrome_download_history ORDER BY id DESC LIMIT 25;
-- Follow up per domain or file name as needed.
