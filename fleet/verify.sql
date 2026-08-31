-- Verification queries for agent options v4 (on-demand YARA).
-- Run as live queries in Fleet. Table is yara_file (alias: yara).

-- ============================================================
-- 1. Flags landed  (needs a fleetd restart after applying v4)
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
-- yara_sigurl_authenticate MUST be false. True switches the fetch to a POST
-- with the node key and GitHub rejects it.

-- ============================================================
-- 2. SMOKE TEST - proves the allowlist and the fetch both work
-- ------------------------------------------------------------
-- On a test host:
--   printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
-- (on Windows write it to C:\Users\<you>\Downloads\eicar.com and adjust path)
-- ============================================================
SELECT path, count, matches
FROM yara_file
WHERE path = '/tmp/eicar.com'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/eicar.yar';
-- Expect count=1, matches containing Multi_EICAR_ac8f42d6.
--
-- count=0 with no error   -> file fetched and compiled, but did not match.
-- "signature url not allowed" -> the allowlist regex did not match your URL.
-- empty result / fetch error  -> host cannot reach raw.githubusercontent.com.

-- ============================================================
-- 3. Targeted hunt - one category, small fetch
-- ============================================================
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/suspect.bin' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/ransomware.yar';

SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/suspect.bin' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/infostealer.yar';

SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/suspect.bin' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/windows/vulndriver.yar';

-- ============================================================
-- 4. Directory sweep
-- ------------------------------------------------------------
-- yara_delay (50 ms default) is paid PER FILE. A 1,000-file sweep spends ~50s
-- in delay alone. Narrow the path, or lower yara_delay for sweeps.
-- ============================================================
SELECT path, count, matches
FROM yara_file
WHERE path LIKE '/Users/%/Downloads/%%'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/_all.yar'
  AND count > 0;

-- ============================================================
-- 5. Scan only what changed - FIM feeds the hunt
-- ------------------------------------------------------------
-- This is the pattern that replaces yara_events: file_events records the
-- change, you scan the specific paths it names.
-- ============================================================
SELECT datetime(time,'unixepoch') AS t, target_path, category, action
FROM file_events
WHERE action IN ('CREATED','UPDATED')
ORDER BY time DESC LIMIT 50;
-- Then feed a target_path into query 3.

-- ============================================================
-- 6. Process memory
-- ============================================================
SELECT pid, count, matches FROM yara_process
WHERE pid = 1234 AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/_all.yar';

-- ============================================================
-- 7. Windows - RENAMED CATEGORY
-- ------------------------------------------------------------
-- v3 renamed Win_Yara_File_Path -> windows_file_events. Update any saved query
-- filtering on the old value.
-- ============================================================
SELECT category, count(*) AS n FROM ntfs_journal_events GROUP BY category;
-- Expect windows_file_events, n>0 after a file changes under the monitored dirs.

-- ============================================================
-- 8. Windows browser ATC tables  (returned 0 rows before v2 fixed escaping)
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
-- in_windows_events should be 0 - the channel was dropped from the list.

-- ============================================================
-- 10. Publishers still healthy
-- ============================================================
SELECT name, publisher, type, subscriptions, events, active
FROM osquery_events ORDER BY events DESC;
-- yara_events should now be absent or inactive. That is expected in v4.
