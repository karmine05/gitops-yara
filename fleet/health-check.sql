-- Post-deployment health check for agent options v5.
-- One query per platform. Each returns check/value/expected rows - run it,
-- paste the whole result. Run Q1 everywhere, then the query for the platform.
--
-- The bpf_* tables are not referenced directly: on a post-5.23.1 agent those
-- tables do not exist and a direct reference would fail the whole query.
-- Q3 checks their existence through osquery_registry instead.
--
-- WHY EVERY EVENTED QUERY HAS "WHERE time > 0"
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
-- In osqueryd, which runs Fleet live AND scheduled queries, an evented-table
-- query with no time constraint therefore returns only events since the last
-- run of that query. The cursor lives in RocksDB and survives restarts.
-- Worse, after all registered queries have run, expireEventBatches() purges
-- what was read.
--
-- Practical effect: "SELECT count(*) FROM es_process_events" returns a real
-- number the first time and 0 on every rerun. It looks exactly like a broken
-- publisher. Adding any time constraint sets can_optimize=false and returns
-- the whole buffer.
--
-- Use "WHERE time > 0" for verification. Leave it off for real scheduled
-- detection queries, where the since-last-run behaviour is what you want.
--
-- Cross-check: osqueryi is not the daemon, so isDaemon() is false and it never
-- optimizes. If `sudo orbit shell` shows events and Fleet shows none, this is
-- why - not a broken publisher.
--
-- ####################### Q1 - ALL PLATFORMS ################################
SELECT 'agent_version' AS check_name,
       (SELECT version FROM osquery_info) AS value,
       'note it' AS expected
UNION ALL SELECT 'config_valid',       (SELECT CAST(config_valid AS TEXT) FROM osquery_info), '1'
UNION ALL SELECT 'flag:disable_events',(SELECT value FROM osquery_flags WHERE name='disable_events'), 'false'
UNION ALL SELECT 'flag:events_expiry', (SELECT value FROM osquery_flags WHERE name='events_expiry'), '3600'
UNION ALL SELECT 'flag:enable_file_events', (SELECT value FROM osquery_flags WHERE name='enable_file_events'), 'true'
UNION ALL SELECT 'flag:yara_sigurl_authenticate', (SELECT value FROM osquery_flags WHERE name='yara_sigurl_authenticate'), 'false'
UNION ALL SELECT 'flag:yara_delay',    (SELECT value FROM osquery_flags WHERE name='yara_delay'), '50'
UNION ALL SELECT 'flag:disable_audit', (SELECT value FROM osquery_flags WHERE name='disable_audit'), 'true (by design)'
UNION ALL SELECT 'flag:enable_bpf_events EXISTS',
       (SELECT CAST(count(*) AS TEXT) FROM osquery_flags WHERE name='enable_bpf_events'), '1 on <=5.23.1'
UNION ALL SELECT 'tbl:bpf_process_events EXISTS',
       (SELECT CAST(count(*) AS TEXT) FROM osquery_registry WHERE registry='table' AND name='bpf_process_events'), '1 on <=5.23.1'
UNION ALL SELECT 'tbl:yara_file EXISTS',
       (SELECT CAST(count(*) AS TEXT) FROM osquery_registry WHERE registry='table' AND name='yara_file'), '1'
UNION ALL SELECT 'publishers_active',
       (SELECT CAST(count(*) AS TEXT) FROM osquery_events WHERE active=1), '>0'
UNION ALL SELECT 'publishers_with_events',
       (SELECT CAST(count(*) AS TEXT) FROM osquery_events WHERE events>0), '>0'
UNION ALL SELECT 'osqueryd_resident_mb',
       (SELECT CAST(p.resident_size/1048576 AS TEXT) FROM osquery_info i JOIN processes p ON p.pid=i.pid), 'watchdog is off - watch this';

-- ####################### Q2 - macOS ########################################
-- First: touch ~/Downloads/fim-test.txt
SELECT 'es_process_events' AS tbl, CAST(count(*) AS TEXT) AS n, '>0 (else no Full Disk Access)' AS expected FROM es_process_events WHERE time > 0
UNION ALL SELECT 'es_process_file_events', CAST(count(*) AS TEXT), '>0 (else no Full Disk Access)' FROM es_process_file_events WHERE time > 0
UNION ALL SELECT 'file_events (all)',      CAST(count(*) AS TEXT), '>0' FROM file_events WHERE time > 0
UNION ALL SELECT 'file_events Mac_Yara_File_Path', CAST(count(*) AS TEXT), '>0 after you touch a file'
       FROM file_events WHERE time > 0 AND category='Mac_Yara_File_Path'
UNION ALL SELECT 'yara_events',            CAST(count(*) AS TEXT), '0 - correct, v5 is on-demand only' FROM yara_events WHERE time > 0;

-- ####################### Q3 - Linux ########################################
-- First: touch /tmp/fim-test.txt
SELECT 'file_events (all)' AS tbl, CAST(count(*) AS TEXT) AS n, '>0' AS expected FROM file_events WHERE time > 0
UNION ALL SELECT 'file_events ubuntu_file_events', CAST(count(*) AS TEXT), '>0 after you touch a file'
       FROM file_events WHERE time > 0 AND category='ubuntu_file_events'
UNION ALL SELECT 'process_events',      CAST(count(*) AS TEXT), '0 - audit off by design' FROM process_events WHERE time > 0
UNION ALL SELECT 'socket_events',       CAST(count(*) AS TEXT), '0 - audit off by design' FROM socket_events WHERE time > 0
UNION ALL SELECT 'user_events',         CAST(count(*) AS TEXT), '0 - audit off by design' FROM user_events WHERE time > 0
UNION ALL SELECT 'process_file_events', CAST(count(*) AS TEXT), '0 - audit off by design' FROM process_file_events WHERE time > 0
UNION ALL SELECT 'BPF CANARY: bpf table present',
       (SELECT CAST(count(*) AS TEXT) FROM osquery_registry WHERE registry='table' AND name='bpf_process_events'),
       '1 = fine. 0 = NO Linux process/socket eventing at all';

-- ####################### Q4 - Windows ######################################
-- First: echo test > %USERPROFILE%\Downloads\fim-test.txt  &&  nslookup example.com
SELECT 'ntfs_journal_events' AS tbl, CAST(count(*) AS TEXT) AS n, '>0 after you create a file' AS expected FROM ntfs_journal_events WHERE time > 0
UNION ALL SELECT 'ntfs category=Win_Yara_File_Path', CAST(count(*) AS TEXT), '>0 after you create a file'
       FROM ntfs_journal_events WHERE time > 0 AND category='Win_Yara_File_Path'
UNION ALL SELECT 'ntfs category=windows_file_events (v3/v4 only)', CAST(count(*) AS TEXT), '0 once v5 is applied'
       FROM ntfs_journal_events WHERE time > 0 AND category='windows_file_events'
UNION ALL SELECT 'windows_events',      CAST(count(*) AS TEXT), '>0' FROM windows_events WHERE time > 0
UNION ALL SELECT 'windows_events 4104', CAST(count(*) AS TEXT), '0 - channel dropped in v4'
       FROM windows_events WHERE time > 0 AND eventid=4104
UNION ALL SELECT 'powershell_events',   CAST(count(*) AS TEXT), '0 unless Script Block Logging on' FROM powershell_events WHERE time > 0
UNION ALL SELECT 'process_etw_events',  CAST(count(*) AS TEXT), '>0' FROM process_etw_events WHERE time > 0
UNION ALL SELECT 'dns_lookup_events',   CAST(count(*) AS TEXT), '>0 after nslookup' FROM dns_lookup_events WHERE time > 0;

-- ####################### Q5 - ATC macOS ####################################
-- Run separately: if an ATC table failed to register, this query errors and
-- that error is itself the finding.
SELECT 'quarantine_items' AS tbl, CAST(count(*) AS TEXT) AS n FROM quarantine_items
UNION ALL SELECT 'chrome_url_history',      CAST(count(*) AS TEXT) FROM chrome_url_history
UNION ALL SELECT 'chrome_download_history', CAST(count(*) AS TEXT) FROM chrome_download_history
UNION ALL SELECT 'firefox_url_history',     CAST(count(*) AS TEXT) FROM firefox_url_history;

-- ####################### Q6 - ATC Windows ##################################
SELECT 'chrome_url_history' AS tbl, CAST(count(*) AS TEXT) AS n FROM chrome_url_history
UNION ALL SELECT 'edge_url_history',        CAST(count(*) AS TEXT) FROM edge_url_history
UNION ALL SELECT 'chrome_download_history', CAST(count(*) AS TEXT) FROM chrome_download_history
UNION ALL SELECT 'firefox_url_history',     CAST(count(*) AS TEXT) FROM firefox_url_history;

-- ####################### Q7 - YARA smoke test ##############################
-- First, on a macOS or Linux host:
--   printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
SELECT path, count, matches FROM yara_file
WHERE path = '/tmp/eicar.com' AND sigurl = 'https://raw.githubusercontent.com/karmine05/gitops-yara/main/rules/multi/eicar.yar';
-- count=1, matches=Multi_EICAR_ac8f42d6  -> the whole chain works
-- "signature url not allowed"            -> v5 allowlist did not apply
-- empty / fetch warning in osqueryd log   -> host cannot reach GitHub
