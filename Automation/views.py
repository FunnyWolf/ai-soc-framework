# Create your views here.
from rest_framework.response import Response

from Automation.Handle.playbook import Playbook
from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import CODE_MSG_ZH, CODE_MSG_EN
from Lib.log import logger


class PlaybookView(BaseView):
    def create(self, request, **kwargs):
        try:
            playbook = request.data.get('playbook')
            context = Playbook.create(playbook, params=request.data)
            return Response(context)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
