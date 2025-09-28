from Lib.redis_stream_api import RedisStreamAPI

alerts = [
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 communicating with known C2 server",
        "description": "Host FIN-WKS-JDOE-05 initiated outbound connection to IP address 198.51.100.50 marked as malicious C2 server. Traffic characteristics match Cobalt Strike Beacon pattern highly.",
        "artifact": [
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
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T14:40:15Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 maintaining persistent communication with known C2 server",
        "description": "Persistent, low-volume periodic outbound connections observed between FIN-WKS-JDOE-05 and known C2 server known-bad.c2.server (198.51.100.50). This communication pattern is characteristic of ongoing command and control beaconing.",
        "artifact": [
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
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 communicated with known C2 server",
        "description": "Detected host FIN-WKS-JDOE-05 initiating outbound connection to malicious C2 server IP 198.51.100.50. Traffic pattern closely matches Cobalt Strike Beacon profile.",
        "artifact": [
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
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 communicated with known C2 server",
        "description": "Detected host FIN-WKS-JDOE-05 initiating outbound connection to malicious C2 server IP 198.51.100.50. Traffic pattern closely matches Cobalt Strike Beacon profile.",
        "artifact": [
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
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-19T09:20:15Z",
        "tags": ["c2", "metasploit", "network"],
        "severity": "Critical",
        "reference": "Host FIN-SRV-ACCT-03 communicated with known C2 server",
        "description": "Detected host FIN-SRV-ACCT-03 initiating outbound connection to malicious C2 server IP 198.51.100.60. Traffic pattern closely matches Metasploit payload profile.",
        "artifact": [
            {"type": "hostname", "value": "FIN-SRV-ACCT-03"},
            {"type": "source_ip", "value": "192.168.2.55"},
            {"type": "destination_ip", "value": "198.51.100.60"},
            {"type": "destination_domain", "value": "metasploit.c2.server"},
            {"type": "destination_port", "value": "8080"},
            {"type": "protocol", "value": "HTTP"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-19T09:20:14.500Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.2.55",
                "source_port": 61123,
                "destination_ip": "198.51.100.60",
                "destination_port": 8080,
                "protocol": "TCP",
                "bytes_in": 789,
                "bytes_out": 456,
                "duration_seconds": 8
            },
            "network_context": {
                "destination_domain": "metasploit.c2.server",
                "threat_intel": {"source": "threat-feed-Y", "match": "Metasploit C2 server"}
            },
            "device_details": {"hostname": "FIN-SRV-ACCT-03"}
        }
    },
]
if __name__ == "__main__":
    redis_stream_api = RedisStreamAPI()
    for mail in alerts:
        redis_stream_api.send_message("NDR-Rule-05-Suspect-C2-Communication", mail)
