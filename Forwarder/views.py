from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from Lib.api import data_return
from Lib.baseview import BaseView
from Lib.configs import CODE_MSG_ZH, CODE_MSG_EN
from Lib.log import logger
from Lib.redis_stream_api import RedisStreamAPI


class WebhookSplunkView(BaseView):
    permission_classes = [AllowAny]

    def create(self, request, **kwargs):
        try:
            result = request.data.get('result')
            search_name = request.data.get('search_name')
            sid = request.data.get('sid')
            app = request.data.get('app')
            owner = request.data.get('owner')
            results_link = request.data.get('results_link')
            app = request.data.get('app')
            logger.info(f"Splunk webhook: {request.data}")
            redis_stream_api = RedisStreamAPI()
            redis_stream_api.send_message(search_name, result)
            logger.info("Message sent to Redis stream")
            context = data_return(200, {}, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return Response(context)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)


class WebhookKibanaView(BaseView):
    permission_classes = [AllowAny]

    def create(self, request, **kwargs):
        try:
            redis_stream_api = RedisStreamAPI()
            rule_name = request.data.get('rule').get("name")
            hits = request.data.get('context').get("hits")
            for hit in hits:
                _source = hit.pop('_source', {})
                logger.info(f"elasticsearch webhook: {hit}")
                redis_stream_api.send_message(rule_name, _source)
                logger.info("Message sent to Redis stream")
            context = data_return(200, {}, CODE_MSG_ZH.get(200), CODE_MSG_EN.get(200))
            return Response(context)
        except Exception as E:
            logger.exception(E)
            context = data_return(500, {}, CODE_MSG_ZH.get(500), CODE_MSG_EN.get(500))
        return Response(context)
