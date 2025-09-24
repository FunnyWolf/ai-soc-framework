from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union


class RuleDefinition:
    """
    优化版规则定义。
    指纹生成逻辑可以处理一个可选的外部时间戳。
    """

    def __init__(self,
                 rule_id: str,
                 rule_name: str,
                 deduplication_fields: List[str],
                 case_title_template: str = None,
                 deduplication_window: str = "24h",
                 source: str = "Default",
                 ):

        self.rule_id = rule_id
        self.rule_name = rule_name
        self.deduplication_fields = deduplication_fields
        self.case_title_template = case_title_template
        self.source = source
        valid_windows = ['10m', '30m', '1h', '8h', '12h', '24h']
        if deduplication_window not in valid_windows:
            raise ValueError(f"'{deduplication_window}' 不是一个有效的时间窗口选项。请从 {valid_windows} 中选择。")
        self.deduplication_window = deduplication_window

    @staticmethod
    def _get_time_bucket(dt_object: datetime, window: str) -> datetime:
        if window.endswith('m'):
            minutes = int(window[:-1])
            new_minute = (dt_object.minute // minutes) * minutes
            return dt_object.replace(minute=new_minute, second=0, microsecond=0)
        elif window.endswith('h'):
            hours = int(window[:-1])
            if hours == 24:
                return dt_object.replace(hour=0, minute=0, second=0, microsecond=0)
            else:
                new_hour = (dt_object.hour // hours) * hours
                return dt_object.replace(hour=new_hour, minute=0, second=0, microsecond=0)
        return dt_object

    def generate_deduplication_key(self,
                                   artifacts: List[Dict[str, Any]],
                                   timestamp: Optional[Union[int, float]] = None) -> str:
        """
        生成包含“时间桶”的去重指纹。

        :param artifacts: 事件中的凭据列表
        :param timestamp: (可选) 事件的UTC Unix时间戳 (整数或浮点数)。如果为None，则使用当前系统时间。
        :return: 包含时间桶的去重指纹
        """
        if timestamp is not None:
            processing_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:

            processing_dt = datetime.now(timezone.utc)

        time_bucket_dt = self._get_time_bucket(processing_dt, self.deduplication_window)
        time_bucket_str = time_bucket_dt.strftime('%Y-%m-%dT%H:%M:%S')

        key_parts = [self.rule_id, time_bucket_str]
        artifacts_map = {art['type']: art['value'] for art in artifacts}
        for field in sorted(self.deduplication_fields):
            key_parts.append(artifacts_map.get(field, 'N/A'))

        return "-".join(key_parts)

    def generate_case_title(self, artifacts: List[Dict[str, Any]] = None) -> str:
        template_values = {"rule_name": self.rule_name}
        for art in artifacts:
            template_values[art['type']] = art['value']
        if self.case_title_template is None:
            title = ""
            for art in artifacts:
                if art.get('type') in self.deduplication_fields:
                    title += f" {art['type']}:{art['value']}"
            return f"{self.rule_name}{title.strip()}"
        else:
            return self.case_title_template.format_map(template_values)
