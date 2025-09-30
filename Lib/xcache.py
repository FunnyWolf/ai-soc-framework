# -*- coding: utf-8 -*-
# @File  : xcache.py
# @Date  : 2021/2/25
# @Desc  :

from django.core.cache import cache

from Lib.configs import EXPIRE_MINUTES


class Xcache(object):
    XCACHE_TOKEN = "XCACHE_TOKEN"

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
