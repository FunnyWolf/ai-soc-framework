import json
import uuid
from typing import Optional, Union, Dict, Any

from pydantic import BaseModel, Field
from thehive4py.types.alert import InputAlert, OutputAlert

from External.difyclient import DifyClient
from External.thehiveclient import TheHiveClient
from Lib.base import BaseModule


class AnalyzeResult(BaseModel):
    """用于从文本中提取用户信息的结构"""
    is_phishing: bool = Field(description="是否为钓鱼邮件，True或False")
    confidence: float = Field(description="信心指数,范围0到1之间")
    reasoning: Optional[Union[str, Dict[str, Any]]] = Field(description="推理过程", default=None)


class Module(BaseModule):

    def __init__(self):
        super().__init__()
        self.thehive_client = TheHiveClient()

    def alert_preprocess_node(self):
        """预处理告警数据"""
        # 获取stream中的原始告警
        self.agent_state.alert_raw = self.read_message()

        # 解析数据,此处是获取Elasticsearch Webhook发送的JSON数据的处理样例
        alert = self.agent_state.alert_raw

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

        to = alert_raw["headers"]["To"]
        subject = alert_raw["headers"]["Subject"]
        if analyze_result.is_phishing and analyze_result.confidence > 0.8:
            severity = 2
        else:
            severity = 0

        # 发送到thehive
        input_alert: InputAlert = {
            "type": "phishing",
            "source": "user_report",
            "sourceRef": str(uuid.uuid4()),
            "title": self.module_name,
            "description": f"```json{alert_raw}```",
            "tags": ["phishing", "user_report"],
            "severity": severity,
            "summary": f"{analyze_result.model_dump()}",
            "observables": [
                {"dataType": "mail", "data": to},
                {"dataType": "mail-subject", "data": subject},
            ],
        }

        output_alert: OutputAlert = self.thehive_client.alert_create(input_alert)
        self.logger.debug(output_alert)
        return

    def run(self):
        self.alert_preprocess_node()
        self.alert_analyze_node()
        self.alert_output_node()


if __name__ == "__main__":
    module = Module()
    module.debug_alert_name = "Phishing_User_Report_V2"
    module.debug_message_id = "0-0"
    module.run()
