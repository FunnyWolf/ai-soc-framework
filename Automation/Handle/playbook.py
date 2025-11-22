import importlib
import os

from ASF import settings
from Lib.api import data_return
from Lib.apsmodule import aps_module
from Lib.baseplaybook import BasePlaybook
from Lib.configs import Playbook_MSG_ZH, Playbook_MSG_EN
from Lib.log import logger
from Lib.xcache import Xcache


class Playbook(object):
    """任务添加器"""

    def __init__(self):
        pass

    @staticmethod
    def create(playbook=None, params=None, name=None, type=None):
        # 获取模块实例
        if name is not None and type is not None:
            module_config = Xcache.get_module_config_by_name_and_type(type, name)
            if module_config is None:
                # try again to load all module config
                Playbook.load_all_module_config()
                module_config = Xcache.get_module_config_by_name_and_type(type, name)
            if module_config is None:
                context = data_return(305, {"status": "Failed", "job_id": None}, Playbook_MSG_ZH.get(305), Playbook_MSG_EN.get(305))
                return context
            load_path = module_config.get("load_path")
        else:
            load_path = f"PLAYBOOKS.{playbook}"

        try:
            class_intent = importlib.import_module(load_path)
            playbook_intent: BasePlaybook = class_intent.Playbook()
            playbook_intent._params = params
        except Exception as E:
            logger.exception(E)
            context = data_return(305, {"status": "Failed", "job_id": None}, Playbook_MSG_ZH.get(305), Playbook_MSG_EN.get(305))
            return context

        if playbook_intent.RUN_AS_JOB:
            job_id = aps_module.putin_post_python_module_queue(playbook_intent)
            logger.info(f"Create playbook job success: {job_id}")
            if job_id:
                context = data_return(201, {"status": "Running", "job_id": job_id}, Playbook_MSG_ZH.get(201), Playbook_MSG_ZH.get(201))
                return context
            else:
                context = data_return(306, {"status": "Failed", "job_id": None}, Playbook_MSG_ZH.get(306), Playbook_MSG_ZH.get(306))
                return context
        else:
            try:
                logger.info(f"start run playbook : {load_path}")
                result = playbook_intent.run()
                logger.info(f"finish run playbook : {load_path}")
                context = data_return(201, result, Playbook_MSG_ZH.get(201), Playbook_MSG_EN.get(201))
                return context
            except Exception as E:
                logger.exception(E)
                context = data_return(301, {}, Playbook_MSG_ZH.get(301), Playbook_MSG_EN.get(301))
                return context

    @staticmethod
    def get_module_intent(modulename, module_files_dir):
        if modulename == "__init__" or modulename == "__pycache__" or modulename == '':  # __init__.py的特殊处理
            return None
        try:
            class_intent = importlib.import_module(f'{module_files_dir}.{modulename}')
            module_intent = class_intent.Playbook
            return module_intent
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def gen_module_config(modulename, module_files_dir="PLAYBOOKS"):
        module_intent = Playbook.get_module_intent(modulename, module_files_dir)

        if module_intent is None:
            return None

        if module_intent.TYPE is None or module_intent.NAME is None:
            return None

        try:
            one_module_config = {
                "TYPE": module_intent.TYPE,  # 处理器
                "NAME": module_intent.NAME,
                "load_path": f'{module_files_dir}.{modulename}',
            }
            return one_module_config
        except Exception as E:
            logger.exception(E)
            return None

    @staticmethod
    def load_all_module_config():
        all_modules_config = []
        # post 模块
        module_count = 0
        module_filenames = os.listdir(os.path.join(settings.BASE_DIR, 'PLAYBOOKS'))
        for module_filename in module_filenames:
            module_name = module_filename.split(".")[0]
            one_module_config = Playbook.gen_module_config(module_name, 'PLAYBOOKS')
            if one_module_config is not None:
                all_modules_config.append(one_module_config)
                module_count += 1

        Xcache.update_module_configs(all_modules_config)

        logger.info(f"内置剧本加载完成,加载{module_count}个剧本")
