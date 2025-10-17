import json

from Lib.External.nocolyapi import WorksheetRow
from Lib.baseplaybook import BasePlaybook


class Module(BasePlaybook):

    def __init__(self, params):
        super().__init__(params)  # do not delete this code

    def run(self):
        worksheet = self.param("worksheet")
        rowid = self.param("rowid")
        artifact = WorksheetRow.get(worksheet, rowid)
        self.logger.info(f"Querying threat intelligence for : {artifact}")
        # 模拟查询威胁情报数据库
        # 在实际应用中，这里应该调用外部API或数据库进行查询
        if artifact.get("type") not in ["ip", "domain", "hash", "vm_ip"]:
            ti_result = {"error": "Unsupported type. Please use 'ip', 'domain', or 'hash'."}
        else:
            ti_result = {"malicious": True, "score": 85, "description": "This IP is associated with known malicious activities.", "source": "ThreatIntelDB",
                         "last_seen": "2024-10-01T12:34:56Z"}
        ti_result = {"enrichment": json.dumps(ti_result)}
        return ti_result


if __name__ == "__main__":
    params = {'playbook': 'TI_artifact_query_mock', 'rowid': 'c6caa5eb-b4af-44df-aa10-b94829243fd4', 'worksheet': 'Artifact'}
    module = Module(params)
    result = module.run()
    print(result)
