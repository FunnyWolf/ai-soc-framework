import importlib

from Lib.api import data_return
from Lib.baseplaybook import BasePlaybook
from Lib.configs import Playbook_MSG_ZH, Playbook_MSG_EN
from Lib.log import logger


class Playbook(object):
    """任务添加器"""

    def __init__(self):
        pass

    @staticmethod
    def create(playbook=None, params=None):
        # 获取模块实例
        try:
            load_path = f"PLAYBOOK.{playbook}"
            class_intent = importlib.import_module(load_path)
            playbook_intent: BasePlaybook = class_intent.Module(params=params)
        except Exception as E:
            logger.exception(E)
            context = data_return(305, {}, Playbook_MSG_ZH.get(305), Playbook_MSG_EN.get(305))
            return context

        try:
            check_result = playbook_intent.run()
            context = data_return(201, check_result, Playbook_MSG_ZH.get(201), Playbook_MSG_EN.get(201))
            return context
        except Exception as E:
            logger.exception(E)
            context = data_return(301, {}, Playbook_MSG_ZH.get(301), Playbook_MSG_EN.get(301))
            return context
