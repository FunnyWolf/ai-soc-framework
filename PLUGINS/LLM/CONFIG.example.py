# 支持 'ollama'及'openai'
LLM_API_KEY = 'ollama'
LLM_BASE_URL = 'http://192.168.241.128:8080/v1'
LLM_MODEL = "qwen3:30b"

# ollama
# LLM_API_KEY = 'ollama'
# LLM_BASE_URL = 'http://192.168.241.128:11434' # 注意没有uri后缀

# openai compatible
# LLM_API_KEY = 'sk-XXXXXXXXX'
# LLM_BASE_URL = 'https://dashscope.aliyuncs.com/compatible-mode/v1'

# LLM 代理设置，如可直接访问LLM_BASE_URL则设置为None
# 支持代理格式
# HTTP: http://192.168.1.100:3128
# HTTP带认证: http://user:pass@192.168.1.100:3128
# SOCKS5: socks5://192.168.1.100:1080
# SOCKS5带认证: socks5://user:pass@192.168.1.100:1080
LLM_PROXY = None
