import importlib
import os
import threading
import time

from Lib.log import logger


class Engine:
    def __init__(self):
        self.modules = {}
        self.modules_dir = "MODULES"

    def start(self):

        self._load_initial_modules()

        logger.info("Engine started successfully, beginning module monitoring")

    def stop(self):
        for module_name in list(self.modules.keys()):
            self.unload_module(module_name)
        logger.info("All modules have been stopped")

    def _load_initial_modules(self):
        for filename in os.listdir(self.modules_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                module_name = filename.replace(".py", "")
                file_path = os.path.join(self.modules_dir, filename)
                self.load_module(module_name, file_path)

    def run_loop(self, module_name, instance):
        while module_name in self.modules:
            logger.debug(f"Start Running module: {module_name}")
            try:
                instance.run()
            except Exception as e:
                logger.exception(e)
            logger.debug(f"Finish Running module: {module_name}")
            time.sleep(0.1)

    def load_module(self, module_name: str, file_path: str):
        if module_name in self.modules:
            return

        logger.info(f"Loading module: {module_name}")
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            module_class = getattr(module, "Module")

            threads = []
            for i in range(module_class.thread_num):
                thread_name = f"{module_name}_thread_{i}"
                instance = module_class()
                instance._thread_name = thread_name
                thread = threading.Thread(target=self.run_loop, args=(module_name, instance), name=thread_name)
                thread.daemon = True
                threads.append(thread)

            self.modules[module_name] = threads
            for thread in self.modules[module_name]:
                thread.start()

            logger.info(f"Module '{module_name}' started successfully")

        except Exception as e:
            logger.error(f"Failed to load module: {e}")

    def unload_module(self, module_name: str):
        if module_name not in self.modules:
            return

        logger.info(f"Unloading module: {module_name}")
        del self.modules[module_name]
        logger.info(f"Module '{module_name}' unloaded successfully")

    def reload_module(self, module_name: str, file_path: str):
        logger.info(f"Reloading module: {module_name}")
        self.unload_module(module_name)
        self.load_module(module_name, file_path)
