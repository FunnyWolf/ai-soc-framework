import os

import requests

from CONFIG import SIRP_NOTICE_WEBHOOK
from Lib.External.nocolyapi import WorksheetRow, InputAlert, OptionSet
from Lib.api import string_to_timestamp, get_current_time_string
from Lib.ruledefinition import RuleDefinition


class Artifact(object):
    WORKSHEET_ID = "artifact"

    def __init__(self):
        pass

    @staticmethod
    def list(filter: dict):
        result = WorksheetRow.list(Artifact.WORKSHEET_ID, filter)
        return result

    @staticmethod
    def update(rowid, fields: list):
        row_id = WorksheetRow.update(Artifact.WORKSHEET_ID, rowid, fields)
        return row_id

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Artifact.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def get_by_deduplication_key(deduplication_key: str):
        filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "deduplication_key",
                    "operator": "eq",
                    "value": deduplication_key
                },
            ]
        }
        rows = WorksheetRow.list(Artifact.WORKSHEET_ID, filter)
        if rows:
            if len(rows) > 1:
                raise Exception(f"found multiple rows with deduplication_key {deduplication_key}")
            return rows[0]
        else:
            return None

    @staticmethod
    def update_by_type_and_value(data: dict):
        # 第一层必须是group
        filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "type",
                    "operator": "eq",
                    "value": data["type"]
                },
                {
                    "type": "condition",
                    "field": "value",
                    "operator": "eq",
                    "value": data["value"]
                }
            ]
        }
        rows = Artifact.list(filter)
        if rows:
            for row in rows:
                rowid = row['rowId']
                fields = [
                    {"id": "enrichment", "value": data["enrichment"]},
                ]
                rowid_updated = Artifact.update(rowid, fields)
                return rowid_updated
        else:
            fields = [
                {"id": "type", "value": data["type"], "type": 2},
                {"id": "value", "value": data["value"]},
                {"id": "enrichment", "value": data["enrichment"]},
            ]
            rowid_created = Artifact.create(fields)
            return rowid_created


class Alert(object):
    WORKSHEET_ID = "alert"

    def __init__(self):
        pass

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Alert.WORKSHEET_ID, fields)
        return row_id


class Case(object):
    WORKSHEET_ID = "case"

    def __init__(self):
        pass

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Case.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Case.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def get_by_deduplication_key(deduplication_key: str):
        filter = {
            "type": "group",
            "logic": "AND",
            "children": [
                {
                    "type": "condition",
                    "field": "deduplication_key",
                    "operator": "eq",
                    "value": deduplication_key
                },
            ]
        }
        rows = WorksheetRow.list(Case.WORKSHEET_ID, filter)
        if rows:
            if len(rows) > 1:
                raise Exception(f"found multiple rows with deduplication_key {deduplication_key}")
            return rows[0]
        else:
            return None

    @staticmethod
    def load_workbook_md(workbook_name: str) -> str:
        """
        根据 workbook 名称读取 DATA/WORKBOOK/{workbook_name}.md 的内容并返回字符串。
        路径相对于项目根 (两级向上到 asf 文件夹)。
        """
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        md_path = os.path.join(base_dir, 'DATA', 'WORKBOOK', f"{workbook_name}.md")
        if not os.path.exists(md_path):
            raise FileNotFoundError(f"workbook md not found: {md_path}")
        with open(md_path, 'r', encoding='utf-8') as f:
            return f.read()


class Playbook(object):
    WORKSHEET_ID = "playbook"

    def __init__(self):
        pass

    @staticmethod
    def create(fields: list):
        row_id = WorksheetRow.create(Playbook.WORKSHEET_ID, fields)
        return row_id

    @staticmethod
    def update(row_id, fields: list):
        row_id = WorksheetRow.update(Playbook.WORKSHEET_ID, row_id, fields)
        return row_id

    @staticmethod
    def update_status_and_remark(row_id, status, remark):
        fields = [
            {"id": "job_status", "value": status},
            {"id": "remark", "value": remark},
        ]
        row_id = WorksheetRow.update(Playbook.WORKSHEET_ID, row_id, fields)
        return row_id


class Notice(object):

    @staticmethod
    def send(user, title, body=None):
        result = requests.post(SIRP_NOTICE_WEBHOOK, json={"title": title, "body": body, "user": user})
        return result


def common_handler(alert: InputAlert, rule_def: RuleDefinition) -> str:
    artifact_rowid_list = []
    artifacts = alert.get("artifact", [])
    for artifact in artifacts:
        deduplication_key = artifact["deduplication_key"]
        artifact_fields = [
            {"id": "type", "value": artifact["type"]},
            {"id": "value", "value": artifact["value"]},
            {"id": "enrichment", "value": artifact["enrichment"]},
            {"id": "deduplication_key", "value": deduplication_key},
        ]

        row = Artifact.get_by_deduplication_key(deduplication_key)
        if row is None:
            row_id = Artifact.create(artifact_fields)
        else:
            row_id = row.get("rowId")
            Artifact.update(row_id, artifact_fields)

        artifact_rowid_list.append(row_id)

    alert_fields = [
        {"id": "tags", "value": alert.get("tags"), "type": 2},
        {"id": "severity", "value": alert.get("severity")},
        {"id": "source", "value": alert.get("source")},
        {"id": "alert_date", "value": alert.get("alert_date")},
        {"id": "created_date", "value": alert.get("created_date")},
        {"id": "reference", "value": alert.get("reference")},
        {"id": "description", "value": alert.get("description")},
        {"id": "raw_log", "value": alert.get("raw_log")},
        {"id": "rule_id", "value": alert.get("rule_id")},
        {"id": "rule_name", "value": alert.get("rule_name")},
        {"id": "name", "value": alert.get("name")},
        {"id": "summary_ai", "value": alert.get("summary_ai")},
        {"id": "artifact", "value": artifact_rowid_list},
    ]

    # alert
    row_id_alert = Alert.create(alert_fields)

    # case
    timestamp = string_to_timestamp(alert["alert_date"], "%Y-%m-%dT%H:%M:%SZ")
    deduplication_key = rule_def.generate_deduplication_key(artifacts=artifacts, timestamp=timestamp)

    row = Case.get_by_deduplication_key(deduplication_key)
    if row is None:
        if rule_def.workbook is not None:
            workbook = Case.load_workbook_md(rule_def.workbook)
        else:
            workbook = "# There is no workbook for this source."

        case_field = [
            {"id": "title", "value": rule_def.generate_case_title(artifacts=artifacts)},
            {"id": "deduplication_key", "value": deduplication_key},
            {"id": "alert", "value": [row_id_alert]},
            {"id": "case_status", "value": "New"},
            {"id": "created_at", "value": get_current_time_string()},
            {"id": "tags", "value": alert["tags"], "type": 2},
            {"id": "severity", "value": alert["severity"]},
            {"id": "type", "value": rule_def.source},
            {"id": "description", "value": alert["description"]},
            {"id": "workbook", "value": workbook},
        ]
        row_id_create = Case.create(case_field)
        return row_id_create
    else:
        row_id_case = row.get("rowId")
        existing_alerts = row.get("alert", [])
        if row_id_alert not in existing_alerts:
            existing_alerts.append(row_id_alert)

        option_new_score = OptionSet.get_option_by_name_and_value("alert_case_severity", alert["severity"]).get("score", 0)

        severity_value_exist = row.get("severity")
        option_exist_score = OptionSet.get_option_by_name_and_value("alert_case_severity", severity_value_exist).get("score", 0)

        if option_new_score > option_exist_score:
            severity = alert["severity"]
        else:
            severity = severity_value_exist

        tags_exist = row.get("tags", [])
        for tag in alert["tags"]:
            if tag not in tags_exist:
                tags_exist.append(tag)

        case_field = [
            {"id": "alert", "value": existing_alerts},
            {"id": "severity", "value": severity},
            {"id": "tags", "value": tags_exist, "type": 2}
        ]
        row_id_updated = Case.update(row_id_case, case_field)
        return row_id_updated
