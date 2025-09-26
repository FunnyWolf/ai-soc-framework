# -*- coding: utf-8 -*-
# @File  : montior.py
# @Date  : 2021/2/25
# @Desc  :


from apscheduler.schedulers.background import BackgroundScheduler

from Lib.engine import Engine
from Lib.log import logger


class MainMonitor(object):
    BotScheduler: BackgroundScheduler
    MainScheduler: BackgroundScheduler
    HeartBeatScheduler: BackgroundScheduler
    WebModuleScheduler: BackgroundScheduler
    _background_threads = {}

    def __init__(self):
        pass

    def start(self):
        logger.info("后台服务启动")
        engine = Engine()
        engine.start()
        logger.info("后台服务启动成功")
