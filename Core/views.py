import datetime

from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.generics import UpdateAPIView, DestroyAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from Core.Handle.currentuser import CurrentUser
from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.log import logger


class BaseAuthView(ModelViewSet, UpdateAPIView, DestroyAPIView):
    queryset = []  # 设置类的queryset
    serializer_class = AuthTokenSerializer  # 设置类的serializer_class
    authentication_classes = []
    permission_classes = [AllowAny]

    def create(self, request, pk=None, **kwargs):

        null_response = {"status": "error", "type": "account", "currentAuthority": "guest",
                         "token": "forguest"}

        # 检查是否为diypassword
        # Get encrypted password and decrypt it
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            serializer = AuthTokenSerializer(data={"username": username, "password": password})
            if serializer.is_valid():
                token, created = Token.objects.get_or_create(user=serializer.validated_data['user'])
                time_now = datetime.datetime.now()
                if created or token.created < time_now - datetime.timedelta(minutes=EXPIRE_MINUTES):
                    # 更新创建时间,保持token有效
                    token.delete()
                    token = Token.objects.create(user=serializer.validated_data['user'])
                    token.created = time_now
                    token.save()
                null_response['status'] = 'ok'
                null_response['currentAuthority'] = 'admin'  # 当前为单用户模式,默认为admin
                null_response['token'] = token.key
                context = data_return(201, null_response, BASEAUTH_MSG_ZH.get(201), BASEAUTH_MSG_EN.get(201))
                return Response(context)
            else:
                context = data_return(301, null_response, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
                return Response(context)
        except Exception as E:
            logger.exception(E)
            context = data_return(301, null_response, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
            return Response(context)


class CurrentUserView(BaseView):
    def list(self, request, **kwargs):
        """查询数据库中的host信息"""
        user = request.user
        user_info = CurrentUser.list(user)
        context = data_return(301, user_info, BASEAUTH_MSG_ZH.get(301), BASEAUTH_MSG_EN.get(301))
        return Response(context)
