import json
import textwrap
from typing import Optional, Union, Dict, Any

from pydantic import BaseModel, Field

from External.difyclient import DifyClient
from External.nocolyapi import InputAlert, common_handler
from Lib.api import string_to_string_time, get_current_time_string
from Lib.basemodule import BaseModule
from Lib.ruledefinition import RuleDefinition


class AnalyzeResult(BaseModel):
    """用于从文本中提取用户信息的结构"""
    is_phishing: bool = Field(description="是否为钓鱼邮件，True或False")
    confidence: float = Field(description="信心指数,范围0到1之间")
    reasoning: Optional[Union[str, Dict[str, Any]]] = Field(description="推理过程", default=None)


class Module(BaseModule):

    def __init__(self):
        super().__init__()

    def alert_preprocess_node(self):
        """预处理告警数据"""
        # 获取stream中的原始告警
        alert = self.read_message()
        if alert is None:
            return

        # 解析数据,此处是获取Splunk Webhook发送的JSON数据的处理样例
        alert = json.loads(alert["_raw"])

        headers = alert["headers"]
        headers = {"From": headers["From"], "To": headers["To"], "Subject": headers["Subject"], "Date": headers["Date"],
                   "Return-Path": headers["Return-Path"],
                   "Authentication-Results": headers["Authentication-Results"]}
        alert["headers"] = headers

        self.agent_state.alert_raw = alert
        return

    def alert_analyze_node(self):
        api_key = self.get_dify_api_key()
        client = DifyClient()

        inputs = {
            "alert_raw": json.dumps(self.agent_state.alert_raw)
        }

        result = client.run_workflow(
            api_key=api_key,
            inputs=inputs,
            user=self.module_name
        )
        self.agent_state.analyze_result = result.get("analyze_result")
        return

    def alert_output_node(self):
        """处理分析结果"""
        analyze_result: AnalyzeResult = AnalyzeResult(**self.agent_state.analyze_result)
        alert_raw = self.agent_state.alert_raw

        mail_to = alert_raw["headers"]["To"]
        mail_subject = alert_raw["headers"]["Subject"]
        mail_from = alert_raw["headers"]["From"]
        if analyze_result.is_phishing and analyze_result.confidence > 0.8:
            severity = "High"
        else:
            severity = "Info"

        alert_date = string_to_string_time(alert_raw.get("@timestamp"), "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
        description = f"""
                        ## Analyze Result (AI)

                        * **confidence**: {analyze_result.confidence}
                        * **is_phishing**: <font color="green">{analyze_result.is_phishing}</font>
                        """
        description = textwrap.dedent(description).strip()

        rule_name = "用户上报的钓鱼邮件"
        input_alert: InputAlert = {
            "source": "Email",
            "rule_id": self.module_name,
            "rule_name": rule_name,
            "name": f"用户上报的钓鱼邮件: {mail_subject}",
            "alert_date": alert_date,
            "created_date": get_current_time_string(),
            "tags": ["phishing", "user-report"],
            "severity": severity,
            "description": description,
            "reference": "https://your-siem-or-device-url.com/data?source=123456",
            "summary_ai": analyze_result.reasoning,
            "artifacts": [
                {
                    "type": "mail_to",
                    "value": mail_to,
                    "deduplication_key": f"mail_to-{mail_to}",
                    "enrichment": {"update_time": get_current_time_string()}  # just for test, no meaning, data should come from TI or other cmdb
                },
                {
                    "type": "mail_subject",
                    "value": mail_subject,
                    "deduplication_key": f"mail_subject-{mail_subject}",
                    "enrichment": {"update_time": get_current_time_string()}
                },
                {
                    "type": "mail_from",
                    "value": mail_from,
                    "deduplication_key": f"mail_from-{mail_from}",
                    "enrichment": {"update_time": get_current_time_string()}
                },
            ],
            "raw_log": alert_raw
        }
        rule = RuleDefinition(
            rule_id=self.module_name,
            rule_name=rule_name,
            deduplication_fields=["mail_from"],
            source="Email"
        )
        case_row_id = common_handler(input_alert, rule)

        return

    def run(self):
        self.alert_preprocess_node()
        self.alert_analyze_node()
        self.alert_output_node()


if __name__ == "__main__":
    module = Module()
    module.debug_alert_name = "ES-Rule-22-Phishing_user_report_mail"
    module.debug_message_id = "0-0"
    module.run()
