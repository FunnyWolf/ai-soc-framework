import httpx
import urllib3

from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from CONFIG import OPENAI_MODEL, OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_PROXY


class OpenAIAPI(object):
    def __init__(self):
        self.api_key = None
        self.base_url = None
        self.model = None
        self.temperature = 0
        self.alive = False

    def set_api_key(self, api_key):
        self.api_key = api_key

    def set_base_url(self, base_url: str):
        self.base_url = base_url.rstrip('/')

    def set_temperature(self, temperature: float):
        self.temperature = temperature

    def set_model(self, model: str):
        self.model = model

    def get_model(self, model_kwargs=None):
        if model_kwargs is None:
            model_kwargs = {}
        self.set_api_key(OPENAI_API_KEY)
        self.set_base_url(OPENAI_BASE_URL)
        self.set_model(OPENAI_MODEL)

        http_client = None
        if OPENAI_PROXY:
            http_client = httpx.Client(proxy=OPENAI_PROXY)
        return ChatOpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
            model=self.model,
            temperature=self.temperature,
            http_client=http_client,
            model_kwargs=model_kwargs,

        )

    def is_alive(self):

        model = self.get_model()

        # 基础连通性测试
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "give you `ping` reply `pong`."),
            ("human", "ping"),
        ]
        try:
            ai_msg = chain.invoke(messages)
            self.alive = False
            return True
        except Exception as e:
            self.alive = False
            return False

    def is_support_function_calling(self):
        # Function calling 能力测试
        def test_func(x: str) -> str:
            """A test function that returns the input string."""
            return x

        model = self.get_model()
        try:
            model_with_tools = model.bind_tools([test_func])
            test_messages = [
                ("system", "When user says test, call test_func with 'hello' as argument."),
                ("human", "test"),
            ]
            response = model_with_tools.invoke(test_messages)
            if not response.tool_calls:
                return False
        except Exception as e:
            return False
        return True

    @staticmethod
    def is_model_alive(model: ChatOpenAI):
        parser = StrOutputParser()
        chain = model | parser
        messages = [
            ("system", "give you `ping` reply `pong`."),
            ("human", "ping"),
        ]
        try:
            ai_msg = chain.invoke(messages)
            return True
        except Exception as e:
            return False
