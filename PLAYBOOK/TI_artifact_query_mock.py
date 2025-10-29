import json

from Lib.External.nocolyapi import WorksheetRow
from Lib.baseplaybook import BasePlaybook


class Playbook(BasePlaybook):

    def __init__(self):
        super().__init__()  # do not delete this code

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
    params_debug = {'playbook': 'TI_artifact_query_mock', 'rowid': 'a966036e-b29e-4449-be48-23293bacac5d', 'worksheet': 'Artifact'}
    module = Playbook()
    module._params = params_debug
    result = module.run()
    print(result)
