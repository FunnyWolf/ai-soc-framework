import datetime
import time


def timestamp_to_string(timestamp, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    current_timestamp = 1672531200  # 对应 2023-01-01 00:00:00

    # 转换为默认格式的时间字符串
    time_string_default = timestamp_to_string(current_timestamp)
    print(f"默认格式: {time_string_default}")

    # 转换为带毫秒的格式
    time_string_with_ms = timestamp_to_string(current_timestamp, "%Y-%m-%d %H:%M:%S.%f")
    print(f"带毫秒格式: {time_string_with_ms}")

    # 转换为只包含日期和时区的格式
    time_string_custom = timestamp_to_string(current_timestamp, "%Y/%m/%d %Z")
    print(f"自定义格式: {time_string_custom}")
    """
    dt_object = datetime.datetime.fromtimestamp(timestamp)
    return dt_object.strftime(format_str)


def string_to_timestamp(time_string: str, format_str: str = "%Y-%m-%dT%H:%M:%S") -> int:
    """
    time_string = "2023-01-01 00:00:00"

    timestamp_result = string_to_timestamp(time_string)
    print(f"时间戳结果: {timestamp_result}")

    time_string_custom = "2023/12/25 10:30:00"
    timestamp_custom = string_to_timestamp(time_string_custom, "%Y/%m/%d %H:%M:%S")

    time_string = "2025-09-18T14:51:30Z"
    timestamp_result = string_to_timestamp(time_string, "%Y-%m-%dT%H:%M:%SZ")
    """
    dt_object = datetime.datetime.strptime(time_string, format_str)

    return int(dt_object.timestamp())


def get_current_timestamp() -> int:
    """
    current_ts = get_current_timestamp()
    print(f"当前时间戳: {current_ts}")
    """
    return int(time.time())


def get_current_time_string(format_str: str = "%Y-%m-%dT%H:%M:%SZ") -> str:
    """
    # 示例
    # 默认格式
    current_time_str = get_current_time_string()
    print(f"当前时间字符串（默认格式）: {current_time_str}")

    # 自定义格式：年-月-日
    current_date_str = get_current_time_string("%Y-%m-%d")
    print(f"当前时间字符串（自定义格式）: {current_date_str}")
    """
    return datetime.datetime.now().strftime(format_str)
