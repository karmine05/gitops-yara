# OCSF Mapping for Windows Hunt Queries

OCSF is the organizing framework: each hunt module is an OCSF event class. Every finding in the final report is emitted as an OCSF JSON record.

## Event class to Windows source mapping
| OCSF Class | ID | Windows source | Hunt module |
|---|---|---|---|
| authentication_event | 300 | Security 4624/4625/4672, 4720/4721/4726/4728/4732/4733/4738/4768/4776/4783; logon_sessions | 300 authentication |
| configuration_event | 200 | services, scheduled_tasks, registry (Run/WBEM Cimom), SCM 7045 | 2 configuration (persistence) |
| process_event | 100 | Security 4688, PowerShell 4103/4104, process_etw_events (ATC, 15-min) | 1 process |
| file_event | 400 | Security 4663, file table, hash, ntfs_journal_events (ATC) | 4 file |
| network_connection_event | 500 | listening_ports, WFP 5145/5156/5157/5158/6274/6272, RDP ConnectionManager 21/24/25, dns_lookup_events (ATC) | 5 network |
| dns_event | 501 | dns_lookup_events (ATC, 15-min) | 5 network |
| log_event | 700 | 1102, 7036, 104 (log cleared), 4688 audit policy | 7 log |

## OCSF JSON templates (one record per finding)

authentication_event (logon, esp. RDP/network from logon_sessions or 4624):
```json
{
  "event_class_name": "Authentication Event",
  "event_class_id": 300,
  "event_code": "4624",
  "meta": {"product": "dexterlabs", "vendor": "windows", "time": 1788815064000},
  "activity_id": "Authentication",
  "actor": {
    "user_id": "jamie",
    "principal": {"name": "dexterlabs\\jamie", "roles": ["Domain Admins"]},
    "hostname": "LAB-WIN-10.dexterlabs.local",
    "ip": null,
    "process": {"name": "winlogon"}
  },
  "result": {"outcome": "Success", "reason": "logon_type 10 = RDP, 3 = network/NTLM"},
  "status": "Success"
}
```

configuration_event (persistence: service/task/runkey/WMI):
```json
{
  "event_class_name": "Configuration Event",
  "event_class_id": 200,
  "event_code": "7045",
  "meta": {"product": "dexterlabs", "vendor": "windows", "time": 1788815064000},
  "activity_id": "Configuration Change",
  "target": {
    "type": "service",
    "name": "<service/task/runkey name>",
    "binary_path": "<path>"
  },
  "result": {"outcome": "Success"},
  "status": "Success"
}
```

process_event (4688 / PowerShell 4103-4104):
```json
{
  "event_class_name": "Process Event",
  "event_class_id": 100,
  "event_code": "4688",
  "meta": {"product": "dexterlabs", "vendor": "windows", "time": 1788815064000},
  "activity_id": "Exec",
  "process": {"name": "powershell.exe", "cmd_line": "<from 4103/4688 data>", "pid": 0},
  "parent_process": {"name": "<parent>"},
  "result": {"outcome": "Success"},
  "status": "Success"
}
```

file_event (dropped file / YARA hit):
```json
{
  "event_class_name": "File Event",
  "event_class_id": 400,
  "event_code": "file_created",
  "meta": {"product": "dexterlabs", "vendor": "windows", "time": 1788815064000},
  "activity_id": "File Create",
  "file": {"path": "<path>", "name": "<name>", "size": 0},
  "result": {"outcome": "Success", "reason": "<yara rule / mtime evidence>"},
  "status": "Success"
}
```

network_connection_event (RDP client IP from RCM event 21 / WFP):
```json
{
  "event_class_name": "Network Connection Event",
  "event_class_id": 500,
  "event_code": "21",
  "meta": {"product": "dexterlabs", "vendor": "windows", "time": 1788815064000},
  "activity_id": "Connection",
  "client": {"ip": "<client ip from RCM 21>"},
  "server": {"hostname": "LAB-WIN-10", "ip": "192.168.89.158", "port": 3389},
  "protocol": "RDP",
  "result": {"outcome": "Success"},
  "status": "Success"
}
```

log_event (log cleared 1102 / 7036):
```json
{
  "event_class_name": "Log Event",
  "event_class_id": 700,
  "event_code": "1102",
  "meta": {"product": "dexterlabs", "vendor": "windows", "time": 1788815064000},
  "activity_id": "Log Clear",
  "result": {"outcome": "Success", "reason": "Security channel cleared <time>"},
  "status": "Success"
}
```

## Verdict wrapper (always first in report)
```json
{
  "supported": true,
  "answer": "<one-paragraph verdict>",
  "evidence_used": ["query -> result", "logon_sessions -> jamie RDP 16:44"],
  "missing_information": ["RDP client IP: RCM channel also cleared"],
  "confidence": "high",
  "ocsf_findings": [ ...records above... ]
}
```
