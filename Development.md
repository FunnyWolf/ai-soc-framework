# 开始之前

这里需要再次强调,ASF不是一个开箱即用的产品,而是一个框架.ASF需要使用者有一定的Python编程能力,并且需要开发人员有一定的时间和精力去学习和使用这个框架
(在Cursor和Claude Code帮助下很简单).

## 服务器资源

- 如果需要使用AI SOAR作为工单平台,则需要一台8核32G内存80G硬盘的Ubuntu24.04服务器
- 如果已经有其他工单平台,只需要使用ASF的自动化功能,则需要一台2核4G内存40G硬盘的Ubuntu24.04服务器,可满足绝大多数自动化需求
- 如果需要使用本地化的LLM,则需要可以稳定运行支持格式化输出和函数调用的模型,建议显存不低于24G

## 环境部署

- 安装Docker和Docker Compose,可参考 [Docker官方文档](https://github.com/docker/docker-install/)
- 上传ASF代码到服务器,例如/root/asf
- 修改/root/asf/Docker/redis_stack/docker-compose.yml的`redis-stack-password-for-ai-soc-framework`为你自己的密码
- 同步修改/root/asf/CONFIG.example.py的`REDIS_URL`
- 使用uvicorn --config uvicorn.toml