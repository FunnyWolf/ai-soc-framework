# -*- coding: utf-8 -*-
# @File  : serializers.py
# @Date  : 2018/11/15
# @Desc  :


from rest_framework.serializers import Serializer, CharField, BooleanField


class UserAPISerializer(Serializer):
    username = CharField()
    is_superuser = BooleanField()
