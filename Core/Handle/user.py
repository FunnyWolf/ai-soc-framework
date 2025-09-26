# -*- coding: utf-8 -*-
# @File  : currentuser.py
# @Date  : 2021/2/25
# @Desc  :
from django.contrib.auth.models import User

from Core.serializers import UserAPISerializer


class UserAPI(object):
    def __init__(self):
        pass

    @staticmethod
    def list():
        models = User.objects.all()
        result = UserAPISerializer(models, many=True).data
        return result

    @staticmethod
    def create_user(username, password):
        if username.lower() == "root":
            return False
        try:
            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            return True
        except User.DoesNotExist:
            try:
                # 创建普通用户
                user = User.objects.create_user(username=username, password=password)
                user.save()
                return True
            except Exception as E:
                return False

    @staticmethod
    def delete_user(username):
        if username.lower() == "root":
            return False
        try:
            user = User.objects.get(username=username)
            user.delete()
            return True
        except User.DoesNotExist:
            return False
