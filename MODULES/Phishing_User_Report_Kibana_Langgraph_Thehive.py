import json
import uuid
from datetime import datetime
from typing import Optional, Union, Dict, Any

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph
from pydantic import BaseModel, Field
from thehive4py.types.alert import InputAlert, OutputAlert

from External.opanaiapi import OpenAIAPI
from External.thehiveclient import TheHiveClient
from Lib.base import LanggraphModule
from Lib.llmapi import AgentState


class AnalyzeResult(BaseModel):
    """用于从文本中提取用户信息的结构"""
    is_phishing: bool = Field(description="是否为钓鱼邮件，True或False")
    confidence: float = Field(description="信心指数,范围0到1之间")
    reasoning: Optional[Union[str, Dict[str, Any]]] = Field(description="推理过程", default=None)


class Module(LanggraphModule):
    thread_num = 2

    def __init__(self):
        super().__init__()
        self.thehive_client = TheHiveClient()
        self.init()

    def init(self):
        def alert_preprocess_node(state: AgentState):
            """预处理告警数据"""
            # 获取stream中的原始告警
            alert = self.read_message()
            if alert is None:
                return

            # 解析数据,此处是获取Kibana获取的alert样例
            headers = alert["headers"]
            headers = {"From": headers["From"], "To": headers["To"], "Subject": headers["Subject"], "Date": headers["Date"],
                       "Return-Path": headers["Return-Path"],
                       "Authentication-Results": headers["Authentication-Results"]}
            alert["headers"] = headers

            state.alert_raw = alert
            return state

        # 定义node
        def alert_analyze_node(state: AgentState):
            """AI分析告警数据"""

            # 加载system prompt
            system_prompt_template = self.load_system_prompt_template(f"senior_phishing_expert")

            # 演示如何生成动态提示词
            current_date = datetime.now().strftime("%Y-%m-%d")
            system_message = system_prompt_template.format(current_date=current_date)

            # 构建few-shot示例
            few_shot_examples = [
                HumanMessage(
                    content=json.dumps({
                        "headers": {
                            "From": "\"Wang Lei, Project Manager\" <lei.wang@example-corp.com>",
                            "To": "\"Li Na, Marketing Department\" <na.li@example-corp.com>",
                            "Subject": "Project Alpha Weekly Status Report",
                            "Date": "Tue, 2 Sep 2025 10:15:00 +0800",
                            "Return-Path": "lei.wang@example-corp.com",
                            "Authentication-Results": "mx.example-corp.com; spf=pass smtp.mail=lei.wang@example-corp.com;"
                        },
                        "body": {
                            "plain_text": "Hi Li Na,\n\nPlease find attached the weekly status report for Project Alpha.\n\nThis week, we have completed the initial design phase and are on track to begin development next Monday as planned. Please review the attached document and let me know if you have any feedback before our sync-up meeting on Wednesday.\n\nThanks,\n\nBest Regards\nWang Lei / 王雷\nProject Manager / 项目经理\nTechnology Department / 技术部\nExample Corporation / 示例公司\nMobile: +86 13800138000\nEmail / 邮箱: lei.wang@example-corp.com\n",
                            "html": ""
                        },
                        "attachments": [
                            {
                                "filename": "Project_Alpha_Weekly_Report_W35.pdf",
                                "filepath": "attachments/Project_Alpha_Weekly_Report_W35.pdf",
                                "content_type": "application/pdf"
                            }
                        ]
                    })
                ),
                AIMessage(
                    content=str(AnalyzeResult(is_phishing=False, confidence=0.95,
                                              reasoning="The email is from a known colleague within the same organization, discussing a legitimate project.").model_dump())
                ),
                HumanMessage(
                    content=json.dumps({
                        "headers": {
                            "From": "\"Microsoft Support\" <support-noreply@microsft.com>",
                            "To": "\"Valued Customer\" <user@example.com>",
                            "Subject": "紧急：您的账户已被暂停，需要立即验证 Urgent: Your Account is Suspended, Immediate Verification Required",
                            "Date": "Tue, 2 Sep 2025 14:30:10 +0800",
                            "Return-Path": "<bounce-scam@phish-delivery.net>",
                            "Authentication-Results": "mx.example.com; spf=fail smtp.mail=support-noreply@microsft.com; dkim=fail header.d=microsft.com; dmarc=fail (p=REJECT sp=REJECT) header.from=microsft.com",
                            "X-Coremail-Antispam": "1Uf129KBjvdXoW7GF18tw4xZF4xWF4rtw4kCrg_yoWfZFg_GF4DC348Wrnxtr15J398ZwnFy3ZFgrZ8CF9a9r4DZrZ8X3WkXa4kJr98K3y8C3WfJw1fXFW3ArnrZa93tF15tjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT9fnUUvcSsGvfC2KfnxnUUI43ZEXa7IU04v35UUUUU=="
                        },
                        "body": {
                            "plain_text": "尊敬的用户,\n\n我们的系统检测到您的帐户存在异常登录活动。为了保护您的安全，我们已临时暂停您的帐户。\n\n请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：\n\nhttps://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=... (请注意，这只是显示文本，实际链接是恶意的)\n\n如果您不在24小时内完成验证，您的帐户将被永久锁定。\n\n感谢您的合作。\n\n微软安全团队\n\n---\n\nDear User,\n\nOur system has detected unusual sign-in activity on your account. For your security, we have temporarily suspended your account.\n\nPlease click the link below immediately to verify your identity and restore access:\n\nhttp://secure-login-update-required.com/reset-password?user=user@example.com\n\nIf you do not verify within 24 hours, your account will be permanently locked.\n\nThank you for your cooperation.\n\nThe Microsoft Security Team",
                            "html": "<html><head></head><body><p>尊敬的用户,</p><p>我们的系统检测到您的帐户存在异常登录活动。为了保护您的安全，我们已临时暂停您的帐户。</p><p>请立即点击以下链接以验证您的身份并恢复您的帐户访问权限：</p><p><a href='http://secure-login-update-required.com/reset-password?user=user@example.com'>https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...</a></p><p>如果您不在24小时内完成验证，您的帐户将被永久锁定。</p><p>感谢您的合作。</p><p><b>微软安全团队</b></p></body></html>"
                        },
                        "attachments": [
                            {
                                "filename": "Account_Verification_Form.html",
                                "filepath": "attachments/Account_Verification_Form.html",
                                "content_type": "text/html"
                            }
                        ]
                    })
                ),
                AIMessage(
                    content=str(AnalyzeResult(is_phishing=True, confidence=0.92,
                                              reasoning="The email contains several red flags: the sender's domain is misspelled, the Return-Path is from a suspicious domain, SPF and DKIM checks fail, and the email urges immediate action with threatening language. Additionally, the provided links do not match official Microsoft URLs.").model_dump())
                ),
            ]

            # 构建消息列表
            messages = [
                system_message,
                *few_shot_examples,
                HumanMessage(content=json.dumps(state.alert_raw)),
            ]

            # 运行
            openai_api = OpenAIAPI()

            model_kwargs = {
                "extra_body": {
                    "enable_thinking": False
                }
            }

            llm = openai_api.get_model(model_kwargs)
            llm = llm.with_structured_output(AnalyzeResult)
            response: AnalyzeResult = llm.invoke(messages)

            state.analyze_result = response.model_dump()
            return state

        def alert_output_node(state: AgentState):
            """处理分析结果"""
            analyze_result: AnalyzeResult = AnalyzeResult(**state.analyze_result)
            alert_raw = state.alert_raw

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
            return state

        # 编译graph
        workflow = StateGraph(AgentState)

        workflow.add_node("alert_preprocess_node", alert_preprocess_node)
        workflow.add_node("alert_analyze_node", alert_analyze_node)
        workflow.add_node("alert_output_node", alert_output_node)

        workflow.set_entry_point("alert_preprocess_node")
        workflow.add_edge("alert_preprocess_node", "alert_analyze_node")
        workflow.add_edge("alert_analyze_node", "alert_output_node")
        workflow.set_finish_point("alert_output_node")

        self.graph: CompiledStateGraph = workflow.compile(checkpointer=self.get_checkpointer())
        return True


if __name__ == "__main__":
    module = Module()
    module.debug_alert_name = "Phishing_User_Report_Kibana_Langgraph_Thehive"
    module.debug_message_id = "0-0"
    module.run()
