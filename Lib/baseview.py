# -*- coding: utf-8 -*-
# @File  : baseview.py
# @Date  : 2021/2/25
# @Desc  :
from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.serializers import Serializer
from rest_framework.viewsets import ModelViewSet


class FakeSerializer(Serializer):
    pass


class BaseView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = []  # 设置类的queryset
    serializer_class = FakeSerializer  # 设置类的serializer_class



