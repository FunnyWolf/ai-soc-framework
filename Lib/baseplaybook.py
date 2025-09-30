from Lib.log import logger


class BasePlaybook(object):
    def __init__(self, custom_param):
        super().__init__()
        self.custom_param = custom_param
        self.logger = logger

    def param(self, key, default=None):
        return self.custom_param.get(key, default)

    def run(self):
        raise NotImplementedError
