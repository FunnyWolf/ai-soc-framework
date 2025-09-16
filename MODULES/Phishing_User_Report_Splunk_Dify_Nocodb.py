import json
from typing import Optional, Union, Dict, Any

from pydantic import BaseModel, Field

from External.difyclient import DifyClient
from External.nocodbclient import NocodbClient
from Lib.base import BaseModule


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

        if analyze_result.is_phishing and analyze_result.confidence > 0.8:
            severity = "HIGH"
        else:
            severity = "INFO"

        # 发送到nocodb
        payload = {
            "Title": self.module_name,
            "SEVERITY": severity,
            "RAW": json.dumps(self.agent_state.alert_raw),
            "Description": json.dumps(self.agent_state.alert_raw),
            "Summary": json.dumps(self.agent_state.analyze_result),
            "Status": "NEW",
            "Source": "Splunk"
        }
        result = NocodbClient.create_alert(payload)
        return

    def run(self):
        self.alert_preprocess_node()
        self.alert_analyze_node()
        self.alert_output_node()


if __name__ == "__main__":
    module = Module()
    module.debug_alert_name = "Phishing_User_Report_Splunk_Dify_Nocodb"
    module.debug_message_id = "0-0"
    module.run()
