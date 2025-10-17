from abc import ABC

from Lib.log import logger


class BasePlaybook(ABC):
    def __init__(self, params):
        super().__init__()
        self._params = params
        self.logger = logger

    def param(self, key, default=None):
        return self._params.get(key, default)

    def run(self):
        pass
