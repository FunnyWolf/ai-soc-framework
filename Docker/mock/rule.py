from Lib.ruledefinition import RuleDefinition

rule_list = [
    RuleDefinition(
        rule_id="EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        rule_name="Office应用启动可疑进程",
        deduplication_fields=["hostname", "process_name"],
        source="EDR"
    ),
    RuleDefinition(
        rule_id="EDR-Rule-21-CobaltStrike-Beacon-Detected",
        rule_name="检测到Cobalt Strike C2 Beacon",
        deduplication_fields=["hostname"],
        deduplication_window="1h",
        source="EDR"
    ),
    RuleDefinition(
        rule_id="EDR-Rule-07-Credential-Dumping-LSASS",
        rule_name="LSASS内存凭据窃取",
        deduplication_fields=["hostname", "target_process"],
        source="EDR"
    ),
    RuleDefinition(
        rule_id="EDR-Rule-01-Suspicious-PowerShell-Execution",
        rule_name="可疑的PowerShell命令执行",
        deduplication_fields=["hostname"],
        deduplication_window="1h",
        source="EDR"
    ),
    RuleDefinition(
        rule_id="EDR-Rule-02-Unusual-Network-Connection-to-External",
        rule_name="异常外部网络连接",
        deduplication_fields=["hostname", "destination_ip"],
        source="EDR"
    ),
    RuleDefinition(
        rule_id="NDR-Rule-05-Suspect-C2-Communication",
        rule_name="可疑的命令与控制（C2）通信",
        deduplication_fields=["hostname"],
        source="NDR"
    ),
    RuleDefinition(
        rule_id="NDR-Rule-12-Lateral-Movement-Attempt",
        rule_name="主机到主机的横向移动尝试",
        deduplication_fields=["hostname", "destination_ip"],
        deduplication_window="1h",
        source="NDR"
    ),
    RuleDefinition(
        rule_id="NDR-Rule-15-Unauthorized-Data-Exfiltration",
        rule_name="异常数据外泄",
        deduplication_fields=["hostname", "data_volume"],
        source="NDR"
    ),
    RuleDefinition(
        rule_id="NDR-Rule-01-C2-Beaconing",
        rule_name="C2 信标（Beaconing）流量",
        deduplication_fields=["hostname", "destination_ip"],
        deduplication_window="1h",
        source="NDR"
    ),
    RuleDefinition(
        rule_id="NDR-Rule-02-Internal-Port-Scan",
        rule_name="内部端口扫描",
        deduplication_fields=["source_ip", "scan_type"],
        source="NDR"
    ),
    RuleDefinition(
        rule_id="DLP-Rule-08-Financial-Record-Transfer-to-USB",
        rule_name="财务记录传输到可移动设备",
        deduplication_fields=["hostname", "username"],
        source="DLP"
    ),
    RuleDefinition(
        rule_id="DLP-Rule-09-Source-Code-Upload-to-Pastebin",
        rule_name="源代码上传到公共网站",
        deduplication_fields=["hostname", "username"],
        deduplication_window="1h",
        source="DLP"
    ),
    RuleDefinition(
        rule_id="DLP-Rule-10-Health-Information-Transfer",
        rule_name="受保护健康信息（PHI）传输",
        deduplication_fields=["hostname", "username", "data_classification"],
        source="DLP"
    ),
    RuleDefinition(
        rule_id="DLP-Rule-11-Leaked-API-Key-in-Code",
        rule_name="API密钥泄露",
        deduplication_fields=["hostname", "username", "repository"],
        source="DLP"
    ),
    RuleDefinition(
        rule_id="DLP-Rule-12-Internal-SSN-Transfer",
        rule_name="",
        deduplication_fields=["hostname", "username"],
        deduplication_window="1h",
        source="DLP"
    ),
    RuleDefinition(
        rule_id="ES-Rule-01-Phishing-URL-Detected",
        rule_name="邮件中检测到钓鱼URL",
        deduplication_fields=["sender_email"],
        source="Email"
    ),
    RuleDefinition(
        rule_id="ES-Rule-02-Malicious-Attachment-Detected",
        rule_name="邮件中检测到恶意附件",
        deduplication_fields=["sender_email"],
        source="Email"
    ),
    RuleDefinition(
        rule_id="ES-Rule-03-BEC-Spoofing-CEO",
        rule_name="商业邮件欺诈（BEC）- 冒充CEO",
        deduplication_fields=["sender_email", "subject"],
        source="Email"
    ),
    RuleDefinition(
        rule_id="ES-Rule-04-Credential-Phishing-Page",
        rule_name="凭据钓鱼页面链接",
        deduplication_fields=["sender_email", "subject"],
        deduplication_window="10m",
        source="Email"
    ),
    RuleDefinition(
        rule_id="ES-Rule-05-Fileless-Malware-Detected",
        rule_name="邮件中检测到无文件恶意软件",
        deduplication_fields=["sender_email"],
        source="Email"
    ),
    RuleDefinition(
        rule_id="OT-Rule-01-PLC-Configuration-Change",
        rule_name="PLC配置未经授权修改",
        deduplication_fields=["device_id"],
        source="OT"
    ),
    RuleDefinition(
        rule_id="OT-Rule-02-Unusual-Protocol-Activity",
        rule_name="SCADA网络中可疑协议活动",
        deduplication_fields=["source_device"],
        source="OT"
    ),
    RuleDefinition(
        rule_id="OT-Rule-03-Controller-Stop-Command",
        rule_name="控制器收到停止命令",
        deduplication_fields=["device_id"],
        source="OT"
    ),
    RuleDefinition(
        rule_id="PROXY-Rule-01-Malware-Download-Blocked",
        rule_name="阻止恶意软件下载",
        deduplication_fields=["source_ip"],
        source="Proxy"
    ),
    RuleDefinition(
        rule_id="PROXY-Rule-02-C2-Communication-Blocked",
        rule_name="阻止C2通信",
        deduplication_fields=["source_ip"],
        source="Proxy"
    ),
    RuleDefinition(
        rule_id="PROXY-Rule-03-Phishing-URL-Detected",
        rule_name="访问钓鱼网站被阻止",
        deduplication_fields=["source_ip"],
        source="Proxy"
    ),
    RuleDefinition(
        rule_id="UEBA-Rule-01-Lateral-Movement-Spike",
        rule_name="夜间异常横向移动",
        deduplication_fields=["username"],
        source="UEBA"
    ),
    RuleDefinition(
        rule_id="UEBA-Rule-02-Unusual-Data-Volume-Download",
        rule_name="非正常数据外发量",
        deduplication_fields=["username", "data_destination"],
        source="UEBA"
    ),
    RuleDefinition(
        rule_id="UEBA-Rule-03-Account-Brute-Force-Multiple-Sources",
        rule_name="多源账户暴力破解",
        deduplication_fields=["target_username"],
        source="UEBA"
    ),
    RuleDefinition(
        rule_id="TI-Rule-01-Malicious-IP-Inbound",
        rule_name="来自恶意IP的入站连接",
        deduplication_fields=["destination_ip"],
        source="TI"
    ),
    RuleDefinition(
        rule_id="TI-Rule-02-C2-Domain-Outbound",
        rule_name="内部主机尝试连接C2域名",
        deduplication_fields=["destination_domain"],
        source="TI"
    ),
    RuleDefinition(
        rule_id="TI-Rule-03-Malicious-File-Hash-Match",
        rule_name="内部文件哈希匹配恶意情报",
        deduplication_fields=["hostname"],
        source="TI"
    ),
    RuleDefinition(
        rule_id="IAM-Rule-01-Excessive-Permission-Grant",
        rule_name="账户权限异常提升",
        deduplication_fields=["username", "platform"],
        source="IAM"
    ),
    RuleDefinition(
        rule_id="IAM-Rule-02-Impossible-Travel-Login",
        rule_name="异地登录（不可能行程）",
        deduplication_fields=["username"],
        source="IAM"
    ),
    RuleDefinition(
        rule_id="IAM-Rule-03-Brute-Force-Attack-Password-Spraying",
        rule_name="多账户密码喷洒攻击",
        deduplication_fields=["source_ip"],
        source="IAM"
    ),
    RuleDefinition(
        rule_id="CLOUD-AWS-IAM-01-Root-User-Activity",
        rule_name="Root账户活动",
        deduplication_fields=["platform", "service"],
        source="Cloud"
    ),
    RuleDefinition(
        rule_id="CLOUD-AZ-COMPUTE-02-VM-Reconnaissance",
        rule_name="虚拟机内部侦察",
        deduplication_fields=["vm_name", "vm_ip"],
        source="Cloud"
    ),
    RuleDefinition(
        rule_id="CLOUD-GCP-STORAGE-03-Public-Bucket-Access",
        rule_name="公开访问的存储桶",
        deduplication_fields=["bucket_name"],
        source="Cloud"
    ),
]
