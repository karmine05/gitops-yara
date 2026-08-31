-- Verification queries for agent options v3 + YARA rollout.
-- Run each as a live query in Fleet against the relevant platform.

-- ============================================================
-- 1. Flags landed  (all platforms; needs a fleetd restart first)
-- ============================================================
SELECT name, value, default_value
FROM osquery_flags
WHERE name IN (
  'disable_events','events_expiry','events_max','enable_file_events',
  'enable_bpf_events','disable_endpointsecurity','disable_endpointsecurity_fim',
  'enable_ntfs_event_publisher','enable_process_etw_events',
  'enable_dns_lookup_events','windows_event_channels',
  'yara_sigurl_authenticate','yara_delay'
);
-- Expect: yara_sigurl_authenticate = false, events_expiry = 3600,
--         windows_event_channels = Security,Application,System

-- ============================================================
-- 2. Publishers active and producing  (all platforms)
-- ============================================================
SELECT name, publisher, type, subscriptions, events, active
FROM osquery_events
ORDER BY events DESC;
-- active=1 with events=0 after an hour of uptime means the publisher started
-- but nothing matched: a path or rule wiring problem, not a flag problem.

-- ============================================================
-- 3. macOS - rule file deployed
-- ============================================================
SELECT path, size, mode, uid, gid, datetime(mtime,'unixepoch') AS modified
FROM file WHERE path = '/opt/fleetdm/yara/malware_rules.yar';
-- Expect ~154 KB, mode 0644, uid 0. Absent means install-macos.sh has not run,
-- and yara_events is scanning against nothing.

-- ============================================================
-- 4. Linux - rule file deployed
-- ============================================================
SELECT path, size, mode, uid, gid, datetime(mtime,'unixepoch') AS modified
FROM file WHERE path = '/etc/fleetdm/yara/malware_rules.yar';
-- Expect ~774 KB, mode 0644, uid 0.

-- ============================================================
-- 5. END-TO-END SMOKE TEST  (macOS and Linux)
-- ------------------------------------------------------------
-- Every bundle contains Multi_EICAR_ac8f42d6. On a test host, drop an EICAR
-- file into a monitored path, wait ~30s, then run this.
--
--   macOS:  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.com
--   Linux:  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
-- ============================================================
SELECT datetime(time,'unixepoch') AS t, target_path, category, action, matches, count
FROM yara_events
ORDER BY time DESC
LIMIT 25;
-- Expect a row with matches containing Multi_EICAR_ac8f42d6.
-- No row at all => rules not compiled (restart fleetd) or path not monitored.

-- ============================================================
-- 6. FIM firing independently of YARA  (macOS and Linux)
-- ============================================================
SELECT datetime(time,'unixepoch') AS t, target_path, category, action
FROM file_events ORDER BY time DESC LIMIT 25;
-- macOS category = Mac_Yara_File_Path, Linux = ubuntu_file_events.

-- ============================================================
-- 7. Windows - RENAMED CATEGORY
-- ------------------------------------------------------------
-- v3 renames Win_Yara_File_Path -> windows_file_events. Any saved query or
-- detection filtering on the old value must be updated.
-- ============================================================
SELECT category, count(*) AS n FROM ntfs_journal_events GROUP BY category;
-- Expect category = windows_file_events, and n > 0 once a file changes under
-- Desktop / Downloads / Documents. This returned nothing before v2 fixed the
-- double-escaped paths, so a non-zero count also confirms that fix.

-- ============================================================
-- 8. Windows browser ATC tables  (were returning 0 rows before v2)
-- ============================================================
SELECT
  (SELECT count(*) FROM chrome_url_history)      AS chrome_history,
  (SELECT count(*) FROM edge_url_history)        AS edge_history,
  (SELECT count(*) FROM chrome_download_history) AS chrome_downloads,
  (SELECT count(*) FROM firefox_url_history)     AS firefox_history;

-- ============================================================
-- 9. PowerShell de-duplication  (Windows)
-- ============================================================
SELECT
  (SELECT count(*) FROM windows_events WHERE eventid = 4104) AS in_windows_events,
  (SELECT count(*) FROM powershell_events)                   AS in_powershell_events;
-- in_windows_events should now be 0 - the channel was dropped from the list.

-- ============================================================
-- 10. On-demand YARA via the repo  (ALL platforms, incl. Windows)
-- ------------------------------------------------------------
-- signature_urls is an allowlist. Only the URLs listed in agent options may be
-- passed as sigurl. Fetched rules are cached per the server's Last-Modified.
-- Table is yara_file (alias: yara).
-- ============================================================
SELECT path, count, matches
FROM yara_file
WHERE path = '/tmp/suspect.bin'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows-ondemand.yar';

-- Scan a whole directory with the platform bundle (macOS example):
SELECT path, count, matches
FROM yara_file
WHERE path LIKE '/Users/%/Downloads/%%'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos-file-events.yar'
  AND count > 0;

-- Scan process memory (Linux/macOS):
SELECT pid, count, matches
FROM yara_process
WHERE pid = 1234
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux-file-events.yar';

-- ============================================================
-- 11. Cost check after rollout
-- ============================================================
SELECT pid, resident_size, user_time, system_time, uptime FROM osquery_info;
-- yara_events adds CPU per file change. If this climbs, raise yara_delay or
-- narrow file_paths. Note the watchdog is disabled, so there is no ceiling.
