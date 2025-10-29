from typing import Annotated

from Lib.External.nocolyapi import WorksheetRow


def get_dfmea_record_by_crs_id(
        crs_id: Annotated[str, "CRS ID"]
) -> Annotated[list, "DFMEA record list with nested Requirement, Failure Mode, Failure Cause, Prevention Control"]:
    """
    根据指定的CRS ID，检索DFMEA记录树，包括Requirement、Failure Mode、Failure Cause和Prevention Control的嵌套结构。

    参数:
        crs_id (str): CRS ID，用于筛选Requirement记录。

    返回:
        list: 包含所有Requirement树的列表，每个Requirement下嵌套Failure Mode、Failure Cause和Prevention Control。

    结构示例:
    [
        {
            "crs_id": ...,
            "requirement": ...,
            "function": ...,
            "classification": ...,
            "failure_mode": [
                {
                    "potential_failure_mode": ...,
                    "local_effect_of_failure": ...,
                    "end_effect_of_failure_effect": ...,
                    "end_effect_of_failure_rationale": ...,
                    "end_effect_of_failure_severity": ...,
                    "failure_cause": [
                        {
                            "cause_of_failure": ...,
                            "occurrence": ...,
                            "detection": ...,
                            "detection_control": ...,
                            "prevention_control": [
                                {
                                    "srs_id": ...,
                                    "prevention_control": ...
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]

    用法示例:
        get_dfmea_record_by_crs_id("PCC-CT.CRS.3400")
    """
    filter = {
        "type": "group",
        "logic": "AND",
        "children": [
            {
                "type": "condition",
                "field": "crs_id",
                "operator": "eq",
                "value": crs_id
            },
        ]
    }
    rows = WorksheetRow.list("requirement", filter)
    result_list = []  # 这将是一个包含所有 "Requirement" 树的列表

    # --- 1. 遍历 A (Requirement) ---
    for row in rows:
        requirement = WorksheetRow.get("requirement", row.get("rowId"))

        # --- A层 (Requirement) 记录 ---
        # 这是我们树的 "根"
        req_record = {
            "crs_id": requirement.get("crs_id"),
            "requirement": requirement.get("requirement"),
            "function": requirement.get("function"),
            "classification": requirement.get("classification"),
        }

        # 准备 B 层的列表
        failure_mode_list = []
        failure_mode_rowid_list = requirement.get("failure_mode", [])

        # --- 2. 遍历 B (Failure Mode) ---
        for failure_mode_rowid in failure_mode_rowid_list:
            failure_mode = WorksheetRow.get("failure_mode", failure_mode_rowid)

            # --- B层 (Failure Mode) 记录 ---
            fm_record = {
                "potential_failure_mode": failure_mode.get("potential_failure_mode"),
                "local_effect_of_failure": failure_mode.get("local_effect_of_failure"),
                "end_effect_of_failure_effect": failure_mode.get("end_effect_of_failure_effect"),
                "end_effect_of_failure_rationale": failure_mode.get("end_effect_of_failure_rationale"),
                "end_effect_of_failure_severity": failure_mode.get("end_effect_of_failure_severity"),
            }

            # 准备 C 层的列表
            failure_cause_list = []
            failure_cause_rowid_list = failure_mode.get("failure_cause", [])

            # --- 3. 遍历 C (Failure Cause) ---
            for failure_cause_rowid in failure_cause_rowid_list:
                failure_cause = WorksheetRow.get("failure_cause", failure_cause_rowid)

                # --- C层 (Failure Cause) 记录 ---
                fc_record = {
                    "cause_of_failure": failure_cause.get("cause_of_failure"),
                    "occurrence": failure_cause.get("occurrence"),
                    "detection": failure_cause.get("detection"),
                    "detection_control": failure_cause.get("detection_control"),
                }

                # 准备 D 层的列表
                prevention_control_list = []
                prevention_control_rowid_list = failure_cause.get("prevention_control", [])

                # --- 4. 遍历 D (Prevention Control) ---
                # 这是最内层，即 "叶子"
                for prevention_control_rowid in prevention_control_rowid_list:
                    prevention_control = WorksheetRow.get("prevention_control", prevention_control_rowid)

                    # --- D层 (Prevention Control) 记录 ---
                    pc_record = {
                        "srs_id": prevention_control.get("srs_id"),
                        "prevention_control": prevention_control.get("prevention_control"),
                    }

                    # 将 D 记录添加到 D 列表
                    prevention_control_list.append(pc_record)

                # --- 循环结束, 向上组装 ---

                # 将 D 列表 (prevention_control) 附加到 C 记录
                if prevention_control_list:  # 你也可以保留空列表: fc_record["prevention_control"] = prevention_control_list
                    fc_record["prevention_control"] = prevention_control_list

                # 将 C 记录添加到 C 列表
                failure_cause_list.append(fc_record)

            # 将 C 列表 (failure_cause) 附加到 B 记录
            if failure_cause_list:
                fm_record["failure_cause"] = failure_cause_list

            # 将 B 记录添加到 B 列表
            failure_mode_list.append(fm_record)

        # 将 B 列表 (failure_mode) 附加到 A 记录
        if failure_mode_list:
            req_record["failure_mode"] = failure_mode_list

        # 将 A 记录 (完整的树) 添加到最终结果列表
        result_list.append(req_record)
    return result_list
