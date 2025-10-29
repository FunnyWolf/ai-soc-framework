import importlib

from Lib.api import data_return
from Lib.apsmodule import aps_module
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
            playbook_intent: BasePlaybook = class_intent.Playbook()
            playbook_intent._params = params
        except Exception as E:
            logger.exception(E)
            context = data_return(305, {"status": "Failed", "job_id": None}, Playbook_MSG_ZH.get(305), Playbook_MSG_EN.get(305))
            return context

        if playbook_intent.RUN_AS_JOB:
            job_id = aps_module.putin_post_python_module_queue(playbook_intent)
            if job_id:
                context = data_return(201, {"status": "Running", "job_id": job_id}, Playbook_MSG_ZH.get(201), Playbook_MSG_ZH.get(201))
                return context
            else:
                context = data_return(306, {"status": "Failed", "job_id": None}, Playbook_MSG_ZH.get(306), Playbook_MSG_ZH.get(306))
                return context
        else:
            try:
                result = playbook_intent.run()
                context = data_return(201, result, Playbook_MSG_ZH.get(201), Playbook_MSG_EN.get(201))
                return context
            except Exception as E:
                logger.exception(E)
                context = data_return(301, {}, Playbook_MSG_ZH.get(301), Playbook_MSG_EN.get(301))
                return context
