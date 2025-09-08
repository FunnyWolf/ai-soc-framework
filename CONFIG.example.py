# Flask Config
FLASK_LISTEN_PORT = 7000
FLASK_LISTEN_HOST = "0.0.0.0"

# Redis Stack Config
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = "redis-stack-password-for-ai-soc-framework"

# LLM Config
OPENAI_API_KEY = "sk-xxx"
OPENAI_BASE_URL = "https://api.openai.com/v1"
OPENAI_MODEL = ""
OPENAI_PROXY = ""

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
