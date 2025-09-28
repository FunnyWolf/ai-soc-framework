# Redis Stack Config
# You can change the Redis URL according to your environment
# Login in Redis Insight by http://serverip:8001 and default/redis-stack-password-for-ai-soc-framework

REDIS_URL = "redis://:redis-stack-password-for-ai-soc-framework@192.168.1.114:6379/"
REDIS_STREAM_STORE_DAYS = 7  # 消息在Redis Stream中保存的天数

# LLM Config
OPENAI_API_KEY = "sk-xxx"
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_MODEL = ""
OPENAI_PROXY = ""

# ollama config example
# OPENAI_BASE_URL = 'http://localhost:11434/v1'
# OPENAI_API_KEY='ollama'
# OPENAI_MODEL = "qwen3:30b-a3b"


# Dify Config
DIFY_BASE_URL = "https://api.dify.ai/v1"
DIFY_PROXY = None

DIFY_API_KEY = {
    "Phishing_User_Report_Splunk_Dify_Nocodb": "app-xxx"
}

# Thehive Config
THEHIVE_URL = "https://192.168.1.114:443"
THEHIVE_API_KEY = "xxx"

# Nocodb Config
NOCODB_URL = "http://192.168.1.114:8080"
NOCODB_TOKEN = "xxx"
NOCODB_ALERT_TABLE_ID = "xxx"
