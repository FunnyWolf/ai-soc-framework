import ast

from django.db import models


# Create your models here.


class DiyListField(models.TextField):
    """数据库中用来存储list类型字段"""
    description = "Stores a python list"

    def __init__(self, *args, **kwargs):
        super(DiyListField, self).__init__(*args, **kwargs)

    def get_prep_value(self, value):  # 将python对象转为查询值
        if value is None:
            return value

        return str(value)  # use str(value) in Python 3

    @staticmethod
    def from_db_value(value, expression, connection):
        if not value:
            value = []
        if isinstance(value, list):
            return value
        # 直接将字符串转换成python内置的list
        try:
            return ast.literal_eval(value)
        except Exception as E:
            from Lib.log import logger
            logger.exception(E)
            logger.error(value)
            return []

    def value_to_string(self, obj):
        value = self._get_val_from_obj(obj)
        return self.get_db_prep_value(value)


class DiyDictField(models.TextField):
    """数据库中用来存储dict类型字段"""
    description = "Stores a python dict"

    def __init__(self, *args, **kwargs):
        super(DiyDictField, self).__init__(*args, **kwargs)

    def get_prep_value(self, value):  # 将python对象转为查询值
        if value is None:
            return value

        return str(value)  # use str(value) in Python 3

    def from_db_value(self, value, expression, connection):
        if not value:
            value = []
        if isinstance(value, dict):
            return value
        # 直接将字符串转换成python内置的list
        try:
            return ast.literal_eval(value)
        except Exception as E:
            from Lib.log import logger
            logger.exception(E)
            logger.error(value)
            return {}

    def value_to_string(self, obj):
        value = self._get_val_from_obj(obj)
        return self.get_db_prep_value(value)
