import json

from Lib.baseplaybook import BasePlaybook


class Module(BasePlaybook):

    def __init__(self, custom_param):
        super().__init__(custom_param)  # do not delete this code

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
