# -*- coding: utf-8 -*-
# @File  : asgi.py
# @Date  : 2019/10/3
# @Desc  :

"""
ASGI entrypoint. Configures Django and then runs the application
defined in the ASGI_APPLICATION setting.
"""
import os

import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ASF.settings')
django.setup()
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

websocket_urlpatterns = [

]

application = ProtocolTypeRouter({
    "http": get_asgi_application(),  # Django 的 WSGI 应用处理 HTTP 请求
    "websocket": AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns  # WebSocket 处理
        )
    ),
})
