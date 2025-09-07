import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_DATA_DIR = os.path.join(BASE_DIR, 'MODULES_DATA')
REDIS_CONSUMER_GROUP = 'AI_SOC_FRAMEWORK_GROUP'
REDIS_CONSUMER_NAME = 'AI_SOC_FRAMEWORK_CONSUMER_0'
