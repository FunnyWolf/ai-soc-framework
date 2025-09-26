# -*- coding: utf-8 -*-
# @File  : baseauth.py
# @Date  : 2021/2/25
# @Desc  :
import datetime

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from Lib.configs import EXPIRE_MINUTES
from Lib.xcache import Xcache


class BaseAuth(TokenAuthentication):
    def authenticate_credentials(self, key=None):
        # 搜索缓存的user token
        cache_user = Xcache.alive_token(key)
        if cache_user:
            return cache_user, key

        # 数据库中校验token
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed()

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed()

        # token超时清理
        time_now = datetime.datetime.now()
        if token.created < time_now - datetime.timedelta(minutes=EXPIRE_MINUTES):
            token.delete()
            raise exceptions.AuthenticationFailed()

        # 缓存token
        if token:
            Xcache.set_token_user(key, token.user)
        return token.user, token
