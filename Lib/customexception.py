from Lib.api import data_return
from Lib.log import logger


# https://www.cnblogs.com/KongHuZi/p/13696504.html#_lab2_3_2
def views_except_handler(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except CustomException as E:
            context = data_return(E.code, {}, E.msg_zh, E.msg_en)
            return context
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, str(E), str(E))
            return context

    return wrapper


class CustomException(Exception):
    def __init__(self, msg_zh="", msg_en="", code=300, ):
        self.code = code
        self.msg_zh = msg_zh
        self.msg_en = msg_en
        super().__init__(f"{self.code}-{self.msg_zh}-{self.msg_en}")


class LLMModuleException(Exception):
    def __init__(self, msg_zh="", msg_en=""):
        self.msg_zh = msg_zh
        self.msg_en = msg_en
        super().__init__(f"{self.msg_zh}-{self.msg_en}")
