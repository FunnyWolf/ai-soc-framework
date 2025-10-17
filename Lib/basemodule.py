import os

from langchain_core.prompts import SystemMessagePromptTemplate
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph.state import CompiledStateGraph

from CONFIG import DIFY_API_KEY
from Lib.configs import MODULE_DATA_DIR, REDIS_CONSUMER_GROUP
from Lib.llmapi import AgentState
from Lib.log import logger
from Lib.redis_stream_api import RedisStreamAPI


class BaseModule(object):
    thread_num = 1

    def __init__(self):
        self._thread_name = None
        self.logger = logger

        # debug
        self.debug_alert_name = None
        self.debug_message_id = None  # 设置为非None以启用Debug模式

    @property
    def module_name(self):
        """获取模块加载路径"""
        if self.debug_alert_name is None:
            return self.__module__.split(".")[-1]
        else:
            return self.debug_alert_name

    def read_message(self) -> dict:
        """读取消息"""
        redis_stream_api = RedisStreamAPI()
        if self.debug_message_id is not None:
            message = redis_stream_api.read_stream_from_start(self.module_name, start_id=self.debug_message_id)
        else:
            message = redis_stream_api.read_message(stream_key=self.module_name, consumer_group=REDIS_CONSUMER_GROUP, consumer_name=self._thread_name)
        return message

    def get_dify_api_key(self, app_name=None):
        if app_name is None:
            app_name = self.module_name
        return DIFY_API_KEY.get(app_name)

    def run(self):
        raise NotImplementedError


class LanggraphModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.graph: CompiledStateGraph = None
        self.agent_state = None

    ## LLM PART
    @staticmethod
    def get_checkpointer():
        checkpointer = MemorySaver()
        return checkpointer

    def load_system_prompt_template(self, filename):
        """加载系统提示模板。

        优先级：
        1. 如果传入的 filename 作为路径(可包含或不包含 .md)直接存在文件，则直接读取该文件。
        2. 否则，从 MODULES_DATA/<module_name>/ 目录下按原有逻辑加载 (自动补全 .md 后缀)。

        Args:
            filename (str): 可以是一个直接文件路径，或是模板名（不含 .md）。
        Returns:
            SystemMessagePromptTemplate: 解析后的系统提示模板对象。
        Raises:
            Exception: 当文件无法读取时抛出。
        """
        if os.path.isfile(filename):
            template_path = filename
        else:
            if filename.endswith('.md'):
                fname = filename
            else:
                fname = f"{filename}.md"
            template_path = os.path.join(MODULE_DATA_DIR, self.module_name, fname)

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                system_prompt_template: SystemMessagePromptTemplate = SystemMessagePromptTemplate.from_template(f.read())
                logger.debug(f"Loaded system prompt template from: {template_path}")
                return system_prompt_template
        except Exception as e:
            logger.warning(f"Failed to load prompt template {template_path}: {str(e)}")
            raise e

    def run_graph(self):
        self.graph.checkpointer.delete_thread(self.module_name)
        config = RunnableConfig()
        config["configurable"] = {"thread_id": self.module_name}
        if self.agent_state is None:
            self.agent_state = AgentState(messages=[], alert_raw={}, temp_data={}, analyze_result={})
        for event in self.graph.stream(self.agent_state, config, stream_mode="values"):
            self.logger.debug(event)

    def run(self):
        self.run_graph()
