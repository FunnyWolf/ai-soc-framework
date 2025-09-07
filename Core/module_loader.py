import os

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from Lib.log import logger


class ModuleChangeHandler(FileSystemEventHandler):
    def __init__(self, engine):
        self.engine = engine

    def _is_valid_module(self, path: str) -> bool:
        filename = os.path.basename(path)
        return filename.endswith(".py") and not filename.startswith(("_", "."))

    def on_created(self, event):
        if not event.is_directory and self._is_valid_module(event.src_path):
            logger.info(f"New module file detected: {event.src_path}")
            module_name = os.path.basename(event.src_path).replace(".py", "")
            self.engine.load_module(module_name, event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and self._is_valid_module(event.src_path):
            logger.info(f"Module file deleted: {event.src_path}")
            module_name = os.path.basename(event.src_path).replace(".py", "")
            self.engine.unload_module(module_name)

    def on_modified(self, event):
        if not event.is_directory and self._is_valid_module(event.src_path):
            logger.info(f"Module file modified: {event.src_path}")
            module_name = os.path.basename(event.src_path).replace(".py", "")
            self.engine.reload_module(module_name, event.src_path)


def start_watching(engine, path: str) -> Observer:
    event_handler = ModuleChangeHandler(engine)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    logger.info(f"Starting to monitor directory: '{path}'")
    return observer
