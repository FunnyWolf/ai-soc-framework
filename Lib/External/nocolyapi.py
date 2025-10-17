from typing import TypedDict, Literal, List, Union, Any, Dict, Optional

import requests

from CONFIG import SIRP_URL, SIRP_APPKEY, SIRP_SIGN
from Lib.api import get_current_time_string, string_to_timestamp
from Lib.ruledefinition import RuleDefinition


class InputAlert(TypedDict):
    source: str
    rule_id: str
    rule_name: str
    name: str
    alert_date: str
    created_date: str
    tags: List[str]
    severity: str
    reference: str
    description: str
    summary_ai: Optional[Union[str, Dict[str, Any]]]
    artifacts: List[Dict]
    raw_log: Dict


class FieldType(TypedDict):
    id: str
    name: str
    alias: str
    value: str
    desc: str
    type: str
    required: bool
    isHidden: bool
    isReadOnly: bool
    isHiddenOnCreate: bool
    isUnique: bool
    isTitle: bool
    remark: str


class OptionType(TypedDict):
    key: str
    value: str
    index: int
    score: float


# Define the recursive types first
class ConditionType(TypedDict):
    type: Literal["condition"]
    field: str
    operator: str
    value: Any


class GroupType(TypedDict):
    type: Literal["group"]
    logic: Literal["AND", "OR"]
    children: List[Union["GroupType", ConditionType]]


class Worksheet(object):
    def __init__(self):
        pass

    @staticmethod
    def get_fields(worksheet_id: str) -> Dict[str, FieldType]:
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}"

        response = requests.get(
            url,
            params={"includeSystemFields": True},
            headers=headers
        )
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            fields_list: List[FieldType] = response_data.get("data").get("fields")
            fields_dict = {}
            for field in fields_list:
                fields_dict[field["id"]] = field
            return fields_dict
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")


class WorksheetRow(object):
    def __init__(self):
        pass

    @staticmethod
    def get(worksheet_id: str, row_id: str):
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"
        fields = Worksheet.get_fields(worksheet_id)
        try:
            response = requests.get(
                url,
                params={"includeSystemFields": True},
                headers=headers
            )
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                data = response_data.get("data")
                data_new = {}
                for key in data:
                    if key.startswith("_") or key == "rowId":
                        data_new[key] = data[key]
                    else:
                        alias = fields.get(key).get('alias')
                        data_new[alias] = data[key]
                return data_new
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def list(worksheet_id: str, filter: dict, fields: list = None):
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/list"
        data = {
            "fields": fields,
            "filter": filter,
            "sorts": [
                {
                    "field": "utime",
                    "direction": "desc"
                }
            ],
            "includeTotalCount": True,
            "includeSystemFields": True,
            "useFieldIdAsKey": False,
            "pageSize": 1000,
        }
        try:
            response = requests.post(url,
                                     headers=headers,
                                     json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data").get("rows")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def create(worksheet_id: str, fields: list):
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows"

        data = {
            "triggerWorkflow": True,
            "fields": fields
        }

        try:
            response = requests.post(url,
                                     headers=headers,
                                     json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data").get("id")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')} data: {response_data.get('data')}")
        except Exception as e:
            raise

    @staticmethod
    def update(worksheet_id: str, row_id: str, fields: list):
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"

        data = {
            "triggerWorkflow": True,
            "fields": fields
        }

        try:
            response = requests.patch(url,
                                      headers=headers,
                                      json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def delete(worksheet_id: str, row_ids: list):
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/worksheets/{worksheet_id}/rows/batch"

        data = {
            "rowIds": row_ids,
            "triggerWorkflow": True,
        }

        try:
            response = requests.delete(url,
                                       headers=headers,
                                       json=data)
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise


class OptionSet(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        headers = {"HAP-Appkey": SIRP_APPKEY,
                   "HAP-Sign": SIRP_SIGN}
        url = f"{SIRP_URL}/api/v3/app/optionsets"

        response = requests.get(url,
                                headers=headers)
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            return response_data.get("data").get("optionsets")
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")

    @staticmethod
    def get(name):
        optionsets = OptionSet.list()
        for optionset in optionsets:
            if optionset["name"] == name:
                return optionset
        raise Exception(f"optionset {name} not found")

    @staticmethod
    def get_option_by_name_and_value(name, value) -> OptionType:
        optionsets = OptionSet.list()
        for optionset in optionsets:
            if optionset["name"] == name:
                options = optionset.get("options", [])
                for option in options:
                    if option["value"] == value:
                        return option
        raise Exception(f"optionset {name} {value} not found")

    @staticmethod
    def get_option_key_by_name_and_value(name, value):
        optionsets = OptionSet.list()
        for optionset in optionsets:
            if optionset["name"] == name:
                options = optionset.get("options", [])
                for option in options:
                    if option["value"] == value:
                        return option["key"]
        raise Exception(f"optionset {name} {value} not found")


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


class Option(object):
    def __init__(self):
        pass

    @staticmethod
    def to_value_list(options: list):
        value_list = []
        for option in options:
            value_list.append(option.get("value"))
        return value_list


def common_handler(alert: InputAlert, rule_def: RuleDefinition) -> str:
    # artifact
    artifact_rowid_list = []
    artifacts = alert.get("artifacts", [])
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
        {"id": "artifacts", "value": artifact_rowid_list},
    ]

    # alert
    row_id_alert = Alert.create(alert_fields)

    # case
    timestamp = string_to_timestamp(alert["alert_date"], "%Y-%m-%dT%H:%M:%SZ")
    deduplication_key = rule_def.generate_deduplication_key(artifacts=artifacts, timestamp=timestamp)

    row = Case.get_by_deduplication_key(deduplication_key)
    if row is None:
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
        ]
        row_id_create = Case.create(case_field)
        return row_id_create
    else:
        row_id_case = row.get("rowId")
        existing_alerts = row.get("alert", [])
        if row_id_alert not in existing_alerts:
            existing_alerts.append(row_id_alert)

        option_new_score = OptionSet.get_option_by_name_and_value("alert_case_severity", alert["severity"]).get("score", 0)

        severity_value_exist = row.get("severity")[0].get("value")
        option_exist_score = OptionSet.get_option_by_name_and_value("alert_case_severity", severity_value_exist).get("score", 0)

        if option_new_score > option_exist_score:
            severity = alert["severity"]
        else:
            severity = severity_value_exist

        tags_exist = Option.to_value_list(row.get("tags", []))
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
