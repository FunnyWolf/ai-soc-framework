# -*- coding: utf-8 -*-
# @File  : xcache.py
# @Date  : 2021/2/25
# @Desc  :

from django.core.cache import cache

from Lib.configs import EXPIRE_MINUTES


class Xcache(object):
    XCACHE_TOKEN = "XCACHE_TOKEN"
    XCACHE_MODULES_TASK_LIST = "XCACHE_MODULES_TASK_LIST"

    def __init__(self):
        pass

    @staticmethod
    def alive_token(token):
        key = f"{Xcache.XCACHE_TOKEN}-{token}"
        cache_user = cache.get(key)
        return cache_user

    @staticmethod
    def set_token_user(token, user, expire=EXPIRE_MINUTES):
        key = f"{Xcache.XCACHE_TOKEN}-{token}"
        cache.set(key, user, expire)

    @staticmethod
    def clean_all_token():
        re_key = f"{Xcache.XCACHE_TOKEN}-*"
        keys = cache.keys(re_key)
        for key in keys:
            cache.delete(key)

    @staticmethod
    def get_module_task_by_uuid(task_uuid):
        key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_{task_uuid}"
        req = cache.get(key)
        return req

    @staticmethod
    def list_module_tasks():
        re_key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_*"
        keys = cache.keys(re_key)
        reqs = []
        for key in keys:
            reqs.append(cache.get(key))
        return reqs

    @staticmethod
    def create_module_task(req):
        """任务队列"""
        key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_{req.get('uuid')}"
        cache.set(key, req, None)
        return True

    @staticmethod
    def del_module_task_by_uuid(task_uuid):
        key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_{task_uuid}"
        cache.delete(key)

    @staticmethod
    def get_module_task_length():
        re_key = f"{Xcache.XCACHE_MODULES_TASK_LIST}_*"
        keys = cache.keys(re_key)
        return len(keys)
