from typing import TypedDict, Literal, List, Union, Any

import requests

from CONFIG import NOCOLY_URL, AISOAR_APPKEY, AISOAR_SIGN


class Field(TypedDict):
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


class Option(TypedDict):
    key: str
    value: str
    index: int
    score: float


# Define the recursive types first
class Condition(TypedDict):
    type: Literal["condition"]
    field: str
    operator: str
    value: Any


class Group(TypedDict):
    type: Literal["group"]
    logic: Literal["AND", "OR"]
    children: List[Union["Group", Condition]]


class Worksheet(object):
    def __init__(self):
        pass

    @staticmethod
    def get_fields(worksheet_id: str) -> List[Field]:
        headers = {"HAP-Appkey": AISOAR_APPKEY,
                   "HAP-Sign": AISOAR_SIGN}
        url = f"{NOCOLY_URL}/api/v3/app/worksheets/{worksheet_id}"

        response = requests.get(
            url,
            params={"includeSystemFields": True},
            headers=headers
        )
        response.raise_for_status()

        response_data = response.json()
        if response_data.get("success"):
            return response_data.get("data").get("fields")
        else:
            raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")


class WorksheetRow(object):
    def __init__(self):
        pass

    @staticmethod
    def get(worksheet_id: str, row_id: str):
        headers = {"HAP-Appkey": AISOAR_APPKEY,
                   "HAP-Sign": AISOAR_SIGN}
        url = f"{NOCOLY_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"

        try:
            response = requests.get(
                url,
                params={"includeSystemFields": True},
                headers=headers
            )
            response.raise_for_status()

            response_data = response.json()
            if response_data.get("success"):
                return response_data.get("data")
            else:
                raise Exception(f"error_code: {response_data.get('error_code')} error_msg: {response_data.get('error_msg')}")
        except Exception as e:
            raise

    @staticmethod
    def list(worksheet_id: str, filter: dict):
        headers = {"HAP-Appkey": AISOAR_APPKEY,
                   "HAP-Sign": AISOAR_SIGN}
        url = f"{NOCOLY_URL}/api/v3/app/worksheets/{worksheet_id}/rows/list"
        data = {
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
        headers = {"HAP-Appkey": AISOAR_APPKEY,
                   "HAP-Sign": AISOAR_SIGN}
        url = f"{NOCOLY_URL}/api/v3/app/worksheets/{worksheet_id}/rows"

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
        headers = {"HAP-Appkey": AISOAR_APPKEY,
                   "HAP-Sign": AISOAR_SIGN}
        url = f"{NOCOLY_URL}/api/v3/app/worksheets/{worksheet_id}/rows/{row_id}"

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


class OptionSet(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        headers = {"HAP-Appkey": AISOAR_APPKEY,
                   "HAP-Sign": AISOAR_SIGN}
        url = f"{NOCOLY_URL}/api/v3/app/optionsets"

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
    def get_option_by_name_and_value(name, value) -> Option:
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
                raise Exception(f"found multiple cases with deduplication_key {deduplication_key}")
            return rows[0]
        else:
            return None


class OptionAPI(object):
    def __init__(self):
        pass

    @staticmethod
    def to_value_list(options: list):
        value_list = []
        for option in options:
            value_list.append(option.get("value"))
        return value_list
