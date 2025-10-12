import datetime
import random

from Lib.External.nocolyapi import Artifact, Alert, Case, OptionSet, Option
from Lib.api import get_current_time_string, string_to_timestamp
from Mock.alert import get_mock_alerts
from Mock.rule import rule_list


def generate_four_random_timestamps(
        days_ago_max: int = 10,
        min_delta_2: int = 0,
        max_delta_2: int = 10,  # T2 在 T1 之后 0 到 10 分钟内
        min_delta_3: int = 0,
        max_delta_3: int = 30,  # T3 在 T2 之后 0 到 30 分钟内
        min_delta_4: int = 0,
        max_delta_4: int = 12 * 60,  # T4 在 T3 之后 0 到 12 小时内 (转换为分钟)
) -> dict:
    """
    生成四个满足指定时间间隔和格式的随机时间戳。

    Args:
        days_ago_max: 第一个时间点 T1 最多在当前时间之前的天数（可配置）。
        min_delta_2, max_delta_2: T2 相对于 T1 的最小/最大分钟间隔。
        min_delta_3, max_delta_3: T3 相对于 T2 的最小/最大分钟间隔。
        min_delta_4, max_delta_4: T4 相对于 T3 的最小/最大分钟间隔（以分钟计）。

    Returns:
        包含四个格式化时间戳的字典。
    """

    # 1. 定义时间戳格式
    # %Y-%m-%dT%H:%M:%SZ 格式对应 ISO 8601，其中 'Z' 表示 UTC/Zulu time
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

    # 2. 获取当前的 UTC 时间作为基准时间
    # 使用 UTC 时间可以避免时区和夏令时问题
    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    # --- 生成 T1 (当前时间点之前 [0, days_ago_max] 天内随机的一个时间) ---

    # 计算 T1 的时间范围：[now_utc - days_ago_max 天, now_utc]
    start_t1 = now_utc - datetime.timedelta(days=days_ago_max)

    # 将时间范围转换为秒数（时间戳）
    time_diff_seconds = int((now_utc - start_t1).total_seconds())

    # 生成一个 T1 之前的随机秒数
    random_seconds_t1 = random.randint(0, time_diff_seconds)

    # 计算 T1
    t1 = start_t1 + datetime.timedelta(seconds=random_seconds_t1)

    # --- 生成 T2 (T1 之后 [min_delta_2, max_delta_2] 分钟内随机的一个时间) ---

    # 随机选择一个分钟间隔
    random_minutes_t2 = random.randint(min_delta_2, max_delta_2)
    # 计算 T2
    t2 = t1 + datetime.timedelta(minutes=random_minutes_t2)

    # --- 生成 T3 (T2 之后 [min_delta_3, max_delta_3] 分钟内随机的一个时间) ---

    # 随机选择一个分钟间隔
    random_minutes_t3 = random.randint(min_delta_3, max_delta_3)
    # 计算 T3
    t3 = t2 + datetime.timedelta(minutes=random_minutes_t3)

    # --- 生成 T4 (T3 之后 [min_delta_4, max_delta_4] 分钟内随机的一个时间) ---

    # 随机选择一个分钟间隔
    random_minutes_t4 = random.randint(min_delta_4, max_delta_4)
    # 计算 T4
    t4 = t3 + datetime.timedelta(minutes=random_minutes_t4)

    # 3. 格式化输出
    # strftime("%Y-%m-%dT%H:%M:%SZ") 将 datetime 对象格式化为所需字符串
    result = {
        "alert_date": t1.strftime(TIME_FORMAT),
        "created_date": t2.strftime(TIME_FORMAT),
        "acknowledged_date": t3.strftime(TIME_FORMAT),
        "closed_date": t4.strftime(TIME_FORMAT),
    }

    return result


if __name__ == "__main__":

    # print("使用自定义参数生成时间戳:")
    # custom_times = generate_four_random_timestamps(
    #     days_ago_max=5,  # T1 在当前时间前 5 天内
    #     min_delta_2=5,  # T2 在 T1 之后 5 到 15 分钟内
    #     max_delta_2=15,
    #     min_delta_3=10,  # T3 在 T2 之后 10 到 45 分钟内
    #     max_delta_3=45,
    #     min_delta_4=6 * 60,  # T4 在 T3 之后 6 到 24 小时内
    #     max_delta_4=24 * 60,
    # )
    # print(custom_times)

    alert_list = get_mock_alerts()
    ALL_RULES = {}
    for rule in rule_list:
        ALL_RULES[rule.rule_id] = rule

    case_status_new = OptionSet.get_option_key_by_name_and_value("case_status", "New")

    for alert in alert_list:
        rule_def = ALL_RULES.get(alert["rule_id"])
        if rule_def is None:
            print(f"未找到规则定义，跳过处理此告警: {alert['rule_id']}")
            continue

        default_times = generate_four_random_timestamps()
        # artifact
        artifact_rowid_list = []
        artifacts = alert.get("artifacts", [])
        for artifact in artifacts:
            artifact_fields = [
                {"id": "type", "value": artifact["type"]},
                {"id": "value", "value": artifact["value"]},
                {"id": "enrichment", "value": {"update_time": get_current_time_string()}},
            ]
            artifact_dict = {"type": artifact["type"], "value": artifact["value"], "enrichment": {"update_time": get_current_time_string()}}

            row_id = Artifact.update_by_type_and_value(artifact_dict)
            artifact_rowid_list.append(row_id)

        alert_fields = [
            {"id": "tags", "value": alert["tags"], "type": 2},
            {"id": "severity", "value": alert["severity"]},
            {"id": "source", "value": alert["source"]},
            {"id": "alert_date", "value": default_times["alert_date"]},
            {"id": "created_date", "value": default_times["created_date"]},
            {"id": "reference", "value": alert["reference"]},
            {"id": "description", "value": alert["description"]},
            {"id": "raw_log", "value": alert["raw_log"]},
            {"id": "rule_id", "value": alert["rule_id"]},
            {"id": "rule_name", "value": alert["rule_name"]},
            {"id": "artifacts", "value": artifact_rowid_list},
        ]
        # alert
        row_id_alert = Alert.create(alert_fields)
        print(f"create alert: {row_id_alert}")

        # case
        timestamp = string_to_timestamp(alert["alert_date"], "%Y-%m-%dT%H:%M:%SZ")
        deduplication_key = rule_def.generate_deduplication_key(artifacts=artifacts, timestamp=timestamp)
        print(f"deduplication_key: {deduplication_key}")

        row = Case.get_by_deduplication_key(deduplication_key)
        if row is None:
            case_field = [
                {"id": "deduplication_key", "value": deduplication_key},
                {"id": "title", "value": rule_def.generate_case_title(artifacts=artifacts)},
                {"id": "case_status", "value": case_status_new},
                {"id": "severity", "value": alert["severity"]},
                {"id": "type", "value": rule_def.source},
                {"id": "created_date", "value": default_times["created_date"]},
                {"id": "tags", "value": alert["tags"], "type": 2},
                {"id": "description", "value": alert["description"]},
                {"id": "alert", "value": [row_id_alert]},

                {"id": "acknowledged_date", "value": default_times["acknowledged_date"]},
                {"id": "closed_date", "value": default_times["closed_date"]},

            ]
            row_id_create = Case.create(case_field)
            print(f"create case: {row_id_create}")
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
            print(f"update case: {row_id_updated}")
