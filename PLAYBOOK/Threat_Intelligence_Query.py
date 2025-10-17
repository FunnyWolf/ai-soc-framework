from Lib.baseplaybook import BasePlaybook


class Module(BasePlaybook):

    def __init__(self, params):
        super().__init__(params)  # do not delete this code

    def run(self):
        type = self.param("type")
        value = self.param("value")
        self.logger.info(f"Querying threat intelligence for type: {type}, value: {value}")
        # 模拟查询威胁情报数据库
        # 在实际应用中，这里应该调用外部API或数据库进行查询
        if type not in ["ip", "domain", "hash"]:
            result = {"error": "Unsupported type. Please use 'ip', 'domain', or 'hash'."}
        else:
            result = {"malicious": True, "score": 85, "description": "This IP is associated with known malicious activities.", "source": "ThreatIntelDB",
                      "last_seen": "2024-10-01T12:34:56Z"}
        result = {"enrichment": json.dumps(result)}
        return result


if __name__ == "__main__":
    import json

    params = {'playbook': 'Threat_Intelligence_Query', 'rowid': 'bce78786-9a99-42f1-9c3a-8eb7ffc76bfa', 'worksheet': 'Artifact'}
    module = Module(params)
    result = module.run()
    print(json.dumps(result))
