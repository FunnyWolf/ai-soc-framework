import re

import httpx
import urllib3
from langchain_core.messages import AIMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from CONFIG import LLM_PROXY, LLM_TYPE, LLM_BASE_URL, LLM_MODEL, LLM_API_KEY


class LLMAPI(object):
    """
    一个通用的 LLM API 客户端。
    它会自动从 CONFIG.py 读取配置并初始化对应的后端。
    在遇到错误时，它会直接抛出异常。
    """

    def __init__(self):
        """
        初始化 LLM API 客户端。
        客户端类型由 CONFIG.py 中的 LLM_TYPE 变量决定。
        """
        self.client_type = LLM_TYPE
        if self.client_type not in ['openai', 'ollama']:
            raise ValueError(f"Invalid LLM_TYPE in CONFIG.py: '{self.client_type}'. Must be 'openai' or 'ollama'.")

        self.api_key = LLM_API_KEY
        self.base_url = LLM_BASE_URL
        self.model = LLM_MODEL
        self.temperature = 0.0
        self.alive = False

    # 以下 set_* 方法允许在运行时动态覆盖从CONFIG加载的默认值
    def set_api_key(self, api_key: str):
        self.api_key = api_key

    def set_base_url(self, base_url: str):
        self.base_url = base_url.rstrip('/')

    def set_temperature(self, temperature: float):
        self.temperature = temperature

    def set_model(self, model: str):
        self.model = model

    def get_model(self, **kwargs) -> None | ChatOpenAI | ChatOllama:
        """
        根据 client_type 获取并返回相应的 LangChain ChatModel 实例。
        """

        if self.client_type == 'openai':
            params = {
                "base_url": self.base_url,
                "api_key": self.api_key,
                "model": self.model,
                "temperature": self.temperature,
                "http_client": httpx.Client(proxy=LLM_PROXY) if LLM_PROXY else None,
            }
            params.update(kwargs)
            return ChatOpenAI(**params)

        elif self.client_type == 'ollama':
            params = {
                "base_url": self.base_url,
                "model": self.model,
                "temperature": self.temperature,
            }
            params.update(kwargs)
            return ChatOllama(**params)
        else:
            raise ValueError(f"Unsupported client_type: {self.client_type}")

    def is_alive(self) -> bool:
        """
        测试与模型的基本连通性。
        成功则返回 True，否则直接抛出异常 (例如: ConnectionError, ValueError)。
        """
        model = self.get_model()
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "When you receive 'ping', you must reply with 'pong'."),
            ("human", "ping"),
        ]

        # 任何网络或API错误都会在这里自然地作为异常抛出
        ai_msg = chain.invoke(messages)

        if "pong" not in ai_msg.lower():
            # 即使连接成功，但响应不符合预期，也视为失败
            self.alive = False
            raise ValueError(f"Model liveness check failed. Expected 'pong', got: {ai_msg}")

        self.alive = True
        return True

    def is_support_function_calling(self) -> bool:
        """
        测试模型是否支持函数调用（Tool Calling）能力。
        成功则返回 True，否则直接抛出异常。
        """

        def test_func(x: str) -> str:
            """A test function that returns the input string."""
            return x

        model = self.get_model()
        model_with_tools = model.bind_tools([test_func])
        test_messages = [
            ("system", "When user says test, call test_func with 'hello' as argument."),
            ("human", "test"),
        ]

        response = model_with_tools.invoke(test_messages)

        if not response.tool_calls:
            raise ValueError("Model responded but did not use the requested tool.")

        return True

    @staticmethod
    def extract_think(message: AIMessage) -> AIMessage:
        """
        检查 AIMessage 的 content 开头是否存在 <think>...</think> 标签。
        Langchain Bug的临时解决方案
        如果存在，它会:
        1. 提取 <think> 标签内的内容。
        2. 将提取的内容存入 message.additional_kwargs['reasoning_content']。
        3. 从 message.content 中移除 <think>...</think> 标签块。
        4. 返回一个新的、经过修改的 AIMessage 对象。

        如果不存在，则原样返回原始的 message 对象。

        Args:
            message: 要处理的 LangChain AIMessage 对象。

        Returns:
            一个处理过的 AIMessage 对象，或者在没有匹配项时返回原始对象。
        """
        # 确保 content 是字符串类型
        if not isinstance(message.content, str):
            return message

        # 正则表达式匹配开头的 <think> 标签，并捕获其中的内容。
        # re.DOTALL 标志让 '.' 可以匹配包括换行符在内的任意字符。
        # `^`      - 匹配字符串的开头
        # `<think>`- 匹配字面上的 <think>
        # `(.*?)`  - 非贪婪地捕获所有字符，直到下一个模式
        # `</think>`- 匹配字面上的 </think>
        # `\s*`    - 匹配 think 标签后的任何空白字符（包括换行符）
        pattern = r"^<think>(.*?)</think>\s*"

        match = re.match(pattern, message.content, re.DOTALL)

        if match:
            # 提取捕获组1的内容，即<think>标签内部的文本
            reasoning_content = match.group(1).strip()

            # 从原始 content 中移除整个匹配到的 <think>...</think> 部分
            new_content = message.content[match.end():]

            # 创建 additional_kwargs 的一个副本以进行修改
            # 这样做是为了避免直接修改可能在其他地方被引用的原始字典
            updated_kwargs = message.additional_kwargs.copy()
            updated_kwargs['reasoning_content'] = reasoning_content

            # 返回一个新的 AIMessage 实例，因为 LangChain 的消息对象是不可变的
            message.additional_kwargs = updated_kwargs
            message.content = new_content
            return message
        else:
            # 如果没有匹配项，则返回原始消息
            return message
