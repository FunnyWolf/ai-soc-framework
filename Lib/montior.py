# -*- coding: utf-8 -*-
# @File  : montior.py
# @Date  : 2021/2/25
# @Desc  :


from apscheduler.schedulers.background import BackgroundScheduler
from django.contrib.auth.models import User

from CONFIG import REDIS_STREAM_STORE_DAYS, ASF_TOKEN
from Lib.engine import Engine
from Lib.log import logger
from Lib.redis_stream_api import RedisStreamAPI
from Lib.xcache import Xcache


class MainMonitor(object):
    BotScheduler: BackgroundScheduler
    MainScheduler: BackgroundScheduler
    HeartBeatScheduler: BackgroundScheduler
    WebModuleScheduler: BackgroundScheduler
    _background_threads = {}

    def __init__(self):
        self.engine = Engine()
        self.redis_stream_api = RedisStreamAPI()
        self.MainScheduler = BackgroundScheduler(timezone='Asia/Shanghai')

    def start(self):
        logger.info("启动后台服务")
        api_usr = User()
        api_usr.username = "api_token"
        api_usr.is_active = True
        Xcache.set_token_user(ASF_TOKEN, api_usr, None)

        self.MainScheduler.add_job(func=self.subscribe_clean_thread,
                                   max_instances=1,
                                   trigger='interval',
                                   minutes=5,
                                   id='subscribe_clean_thread')
        self.MainScheduler.start()

        # engine
        self.engine.start()
        logger.info("后台服务启动成功")

    def subscribe_clean_thread(self):
        self.redis_stream_api.clean_redis_stream(max_age_days=REDIS_STREAM_STORE_DAYS)
