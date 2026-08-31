-- ============================================================================
-- Fleet test pack: evented tables, ATC, YARA
-- Built against agent options v4. Column names verified against osquery specs.
--
-- Fleet live query runs ONE statement at a time. Each block below is a single
-- copy-pasteable query. Run the consolidated one first, then drill down.
--
-- Apply v4 and RESTART fleetd before testing. command_line_flags do not take
-- effect without a restart.
-- ============================================================================
--
-- ############################################################################
-- WHY EVERY EVENTED QUERY BELOW HAS "WHERE time > 0"
-- ----------------------------------------------------------------------------
-- osquery's EventSubscriberPlugin::genTable does this:
--
--     bool can_optimize{true};
--     if (context.constraints["time"].getAll().size() > 0) {
--       can_optimize = false;
--     }
--
-- and generateRows then does:
--
--     if (can_optimize && shouldOptimize()) {   // shouldOptimize = isDaemon() && events_optimize
--       // "only emit events since the last query"
--       start_time = optimize_time - 1;
--     }
--
-- So in osqueryd - which is what runs Fleet live AND scheduled queries - an
-- evented-table query with NO time constraint returns ONLY events since the
-- last time that query ran. The cursor lives in RocksDB and SURVIVES RESTARTS.
-- Worse, after all registered queries have run, expireEventBatches() purges
-- what was read.
--
-- Practical effect: "SELECT count(*) FROM es_process_events" returns a real
-- number the first time and 0 on every rerun. It looks exactly like a broken
-- publisher. Adding any time constraint sets can_optimize=false and returns
-- the whole buffer.
--
-- Use "WHERE time > 0" for verification. Leave it OFF for real scheduled
-- detection queries, where the since-last-run behaviour is what you want.
--
-- Cross-check: osqueryi is not the daemon, so isDaemon() is false and it never
-- optimizes. If `sudo orbit shell` shows events and Fleet shows none, this is
-- why - not a broken publisher.
-- ############################################################################



-- ############################################################################
-- 0. UNIVERSAL - run these first, on every platform
-- ############################################################################

-- 0.1  Which publishers are alive and producing?
SELECT name, publisher, type, subscriptions, events, refreshes, active
FROM osquery_events
ORDER BY active DESC, events DESC;
-- active=1, events>0        -> working
-- active=1, events=0        -> publisher up, nothing matched: paths or rules
-- active=0                  -> flag missing, or unsupported on this platform
-- row absent entirely       -> not compiled into this osqueryd build


-- 0.2  Which evented/ATC tables actually exist in this build?
--      Separates "table missing" from "table present but empty".
SELECT name, active FROM osquery_registry
WHERE registry = 'table' AND name IN (
  'es_process_events','es_process_file_events','file_events','yara_events',
  'yara_file','yara_process','bpf_process_events','bpf_socket_events',
  'process_events','socket_events','user_events','process_file_events',
  'ntfs_journal_events','windows_events','powershell_events',
  'process_etw_events','dns_lookup_events',
  'quarantine_items','chrome_url_history','chrome_download_history',
  'firefox_url_history','edge_url_history'
) ORDER BY name;


-- 0.3  Did the v4 flags land?
SELECT name, value, default_value FROM osquery_flags
WHERE name IN (
  'disable_events','events_expiry','events_max','enable_file_events',
  'enable_bpf_events','disable_audit','disable_endpointsecurity',
  'disable_endpointsecurity_fim','enable_ntfs_event_publisher',
  'enable_windows_events_publisher','enable_powershell_events_subscriber',
  'enable_process_etw_events','enable_dns_lookup_events',
  'windows_event_channels','yara_sigurl_authenticate','yara_delay',
  'disable_watchdog'
) ORDER BY name;
-- yara_sigurl_authenticate MUST be false. events_expiry should be 3600.
-- windows_event_channels should be Security,Application,System.


-- 0.4  Agent version and cost. osquery_info has NO resident_size/uptime columns -
--      those live on `processes`, so join on pid.
SELECT i.version, i.build_platform, i.config_valid,
       p.resident_size, p.user_time, p.system_time,
       (strftime('%s','now') - p.start_time) AS uptime_seconds
FROM osquery_info i JOIN processes p ON p.pid = i.pid;
-- With the watchdog disabled there is no ceiling on resident_size. Check this
-- a day after rollout, especially on Windows where the NTFS and ETW publishers
-- have effectively been off until now.


-- ############################################################################
-- 1. EVENTED TABLES
-- ############################################################################

-- ---------------------------------------------------------------- macOS ----
-- 1.1  Consolidated macOS evented count
SELECT 'es_process_events'      AS tbl, count(*) AS n FROM es_process_events WHERE time > 0
UNION ALL SELECT 'es_process_file_events', count(*) FROM es_process_file_events WHERE time > 0
UNION ALL SELECT 'file_events',            count(*) FROM file_events WHERE time > 0
UNION ALL SELECT 'yara_events',            count(*) FROM yara_events WHERE time > 0;
-- yara_events = 0 is CORRECT in v4: continuous YARA is off by design.
-- es_* = 0 usually means Full Disk Access is not granted to the fleetd
-- osqueryd binary. The flag alone does not enable capture.

-- 1.2  macOS process eventing detail
SELECT datetime(time,'unixepoch') AS t, event_type, pid, path, cmdline,
       username, signing_id, team_id, platform_binary
FROM es_process_events WHERE time > 0 ORDER BY time DESC LIMIT 20;

-- 1.3  macOS ES file eventing detail
SELECT datetime(time,'unixepoch') AS t, event_type, pid, path, dest_filename
FROM es_process_file_events WHERE time > 0 ORDER BY time DESC LIMIT 20;

-- 1.4  macOS FIM. Touch a file first: touch ~/Downloads/fim-test.txt
SELECT datetime(time,'unixepoch') AS t, target_path, category, action, size, sha256
FROM file_events WHERE time > 0 AND category = 'Mac_Yara_File_Path'
ORDER BY time DESC LIMIT 20;


-- ---------------------------------------------------------------- Linux ----
-- 1.5  Consolidated Linux evented count. Read the zeros carefully.
SELECT 'file_events'        AS tbl, count(*) AS n FROM file_events WHERE time > 0
UNION ALL SELECT 'process_events',      count(*) FROM process_events WHERE time > 0
UNION ALL SELECT 'socket_events',       count(*) FROM socket_events WHERE time > 0
UNION ALL SELECT 'user_events',         count(*) FROM user_events WHERE time > 0
UNION ALL SELECT 'process_file_events', count(*) FROM process_file_events WHERE time > 0;
-- The last four SHOULD be 0: the audit family is off by decision
-- (disable_audit defaults true). That is the documented accepted gap.
-- file_events > 0 is the one that must be non-zero.

-- 1.6  Linux FIM. Touch a file first: touch /tmp/fim-test.txt
SELECT datetime(time,'unixepoch') AS t, target_path, category, action, size, sha256
FROM file_events WHERE time > 0 AND category = 'ubuntu_file_events'
ORDER BY time DESC LIMIT 20;

-- 1.7  Linux process/socket eventing - SEE SECTION 4 BEFORE TRUSTING THIS
SELECT count(*) AS n FROM bpf_process_events;


-- -------------------------------------------------------------- Windows ----
-- 1.8  Consolidated Windows evented count
SELECT 'ntfs_journal_events' AS tbl, count(*) AS n FROM ntfs_journal_events WHERE time > 0
UNION ALL SELECT 'windows_events',     count(*) FROM windows_events WHERE time > 0
UNION ALL SELECT 'powershell_events',  count(*) FROM powershell_events WHERE time > 0
UNION ALL SELECT 'process_etw_events', count(*) FROM process_etw_events WHERE time > 0
UNION ALL SELECT 'dns_lookup_events',  count(*) FROM dns_lookup_events WHERE time > 0;

-- 1.9  NTFS journal + the RENAMED category.
--      Create a file first: echo test > %USERPROFILE%\Downloads\fim-test.txt
SELECT category, action, count(*) AS n
FROM ntfs_journal_events WHERE time > 0 GROUP BY category, action ORDER BY n DESC;
-- Expect category = windows_file_events (renamed from Win_Yara_File_Path in v3).
-- Zero rows here also means the v2 backslash fix has not taken effect.

-- 1.10 NTFS journal detail
SELECT datetime(time,'unixepoch') AS t, action, category, path, old_path, drive_letter
FROM ntfs_journal_events WHERE time > 0 ORDER BY time DESC LIMIT 20;

-- 1.11 Windows event log channels
SELECT source, provider_name, eventid, count(*) AS n
FROM windows_events WHERE time > 0 GROUP BY source, provider_name, eventid
ORDER BY n DESC LIMIT 25;
-- Expect only Security, Application, System. If you see
-- Microsoft-Windows-PowerShell/Operational the channel list did not update.

-- 1.12 PowerShell de-duplication check
SELECT
  (SELECT count(*) FROM windows_events WHERE time > 0 AND eventid = 4104) AS in_windows_events,
  (SELECT count(*) FROM powershell_events WHERE time > 0)    AS in_powershell_events;
-- in_windows_events must be 0 in v4. in_powershell_events stays 0 unless
-- Script Block Logging is enabled by GPO - that is a host setting, not a flag.

-- 1.13 PowerShell script blocks
SELECT datetime(time,'unixepoch') AS t, script_name, script_path,
       cosine_similarity, substr(script_text,1,200) AS script_head
FROM powershell_events WHERE time > 0 ORDER BY time DESC LIMIT 10;

-- 1.14 ETW process events
SELECT datetime(time,'unixepoch') AS t, type, pid, ppid, username,
       token_elevation_type, path, cmdline
FROM process_etw_events WHERE time > 0 ORDER BY time DESC LIMIT 20;

-- 1.15 DNS lookups. Generate one first: nslookup example.com
SELECT datetime(time,'unixepoch') AS t, pid, path, username, name, type, response
FROM dns_lookup_events WHERE time > 0 ORDER BY time DESC LIMIT 20;


-- ############################################################################
-- 2. AUTO TABLE CONSTRUCTION (ATC)
-- ############################################################################
-- ATC reads SQLite files directly. Two things break it:
--   a) a wrong path glob - this is what the v2 backslash fix repaired on Windows
--   b) the browser holding a lock on the DB. Close the browser if a table that
--      should have rows returns none.

-- 2.1  Consolidated macOS ATC
SELECT 'quarantine_items'        AS tbl, count(*) AS n FROM quarantine_items
UNION ALL SELECT 'chrome_url_history',      count(*) FROM chrome_url_history
UNION ALL SELECT 'chrome_download_history', count(*) FROM chrome_download_history
UNION ALL SELECT 'firefox_url_history',     count(*) FROM firefox_url_history;

-- 2.2  Consolidated Windows ATC - all four returned 0 before the v2 fix
SELECT 'chrome_url_history'      AS tbl, count(*) AS n FROM chrome_url_history
UNION ALL SELECT 'edge_url_history',        count(*) FROM edge_url_history
UNION ALL SELECT 'chrome_download_history', count(*) FROM chrome_download_history
UNION ALL SELECT 'firefox_url_history',     count(*) FROM firefox_url_history;

-- 2.3  macOS quarantine - what did Gatekeeper tag, and where did it come from?
SELECT datetime(timestamp + 978307200,'unixepoch') AS downloaded,
       agent_name, origin_url, data_url, sender_name
FROM quarantine_items ORDER BY timestamp DESC LIMIT 25;
-- Apple epoch is 2001-01-01, hence the +978307200 offset.

-- 2.4  Recent downloads
SELECT id, current_path, target_path FROM chrome_download_history
ORDER BY id DESC LIMIT 25;

-- 2.5  Browsing history sanity check
SELECT url, title, visit_count,
       datetime(last_visit_time/1000000 - 11644473600,'unixepoch') AS last_visit
FROM chrome_url_history WHERE visit_count > 0
ORDER BY last_visit_time DESC LIMIT 25;
-- Chrome/Edge timestamps are microseconds since 1601-01-01.

-- 2.6  Firefox uses a different epoch again (microseconds since 1970)
SELECT url, title, visit_count,
       datetime(last_visit_date/1000000,'unixepoch') AS last_visit
FROM firefox_url_history WHERE visit_count > 0
ORDER BY last_visit_date DESC LIMIT 25;

-- 2.7  Cross-check ATC against FIM: a download that Gatekeeper quarantined
--      AND that FIM saw land on disk.
SELECT q.origin_url, q.agent_name, f.target_path, f.sha256,
       datetime(f.time,'unixepoch') AS seen
FROM quarantine_items q
JOIN file_events f ON f.target_path LIKE '%' || q.data_url || '%'
ORDER BY f.time DESC LIMIT 20;


-- ############################################################################
-- 3. YARA (on-demand only in v4)
-- ############################################################################
-- Table is yara_file (alias: yara). signature_urls is an allowlist; osquery
-- matches host+scheme exactly and treats the URL PATH as a regex.
-- NOTE: every sigurl below 404s until the repo is public and pushed.

-- 3.1  SMOKE TEST. Create the file first:
--   macOS/Linux: printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/eicar.com'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/eicar.yar';
-- Expect count=1, matches = Multi_EICAR_ac8f42d6.
-- "signature url not allowed"  -> allowlist regex did not match
-- empty result / fetch error   -> host cannot reach raw.githubusercontent.com
-- count=0                      -> fetched and compiled, but no match

-- 3.2  Targeted scan by category - small fetch, fast
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/suspect.bin' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/ransomware.yar';

-- 3.3  Whole-platform scan of one file
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/suspect.bin' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/_all.yar';

-- 3.4  Directory sweep. yara_delay (50ms default) is paid PER FILE:
--      1,000 files costs ~50s in delay alone. Keep the glob narrow.
SELECT path, count, matches FROM yara_file
WHERE path LIKE '/Users/%/Downloads/%%'
  AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/macos/_all.yar'
  AND count > 0;

-- 3.5  Process memory scan
SELECT pid, count, matches FROM yara_process
WHERE pid = 1234 AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/linux/_all.yar';

-- 3.6  The pattern that replaces yara_events: let FIM pick the targets.
--      Run this, take a target_path, feed it to 3.2 or 3.3.
SELECT datetime(time,'unixepoch') AS t, target_path, category, action, size, sha256
FROM file_events
WHERE time > 0 AND action IN ('CREATED','UPDATED') AND size > 0
ORDER BY time DESC LIMIT 50;

-- 3.7  Confirm the signature-base URL still works alongside your own repo
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/eicar.com'
  AND sigurl = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar';


-- ############################################################################
-- 4. BPF CANARY - Linux process/socket eventing
-- ############################################################################
-- osquery removed all BPF support in commit 484e1d05 ("Upgrade Linux toolchain
-- to 1.3.0", #8814, 2026-04-30). 5.23.1 is the LAST release that has it; the
-- removal is on main and not yet in a tagged release. Related: fleetdm/fleet#30639.
--
-- When your fleetd picks up an osqueryd built after that commit,
-- enable_bpf_events becomes an unknown flag and the tables disappear. Linux
-- would then have NO process or socket eventing at all, silently, because the
-- audit family is also off.
--
-- Run this on every Linux host after any agent upgrade.
SELECT
  (SELECT version FROM osquery_info)                                          AS osquery_version,
  (SELECT count(*) FROM osquery_flags WHERE name='enable_bpf_events')         AS bpf_flag_exists,
  (SELECT count(*) FROM osquery_registry
     WHERE registry='table' AND name='bpf_process_events')                    AS bpf_table_exists,
  (SELECT count(*) FROM osquery_flags
     WHERE name='disable_audit' AND value='false')                            AS audit_enabled;
-- bpf_flag_exists=1 AND bpf_table_exists=1  -> fine, nothing to do
-- either is 0 AND audit_enabled=0           -> NO Linux process/socket eventing.
--                                              Switch that team to the audit
--                                              family, or pin the agent version.
