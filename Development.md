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

## 快速开始

### 1. 环境准备

* Python 3.12+
* Docker 和 Docker Compose (用于运行 Redis Stack)

### 2. 开发环境

1. **克隆项目**
   ```bash
   git clone https://github.com/FunnyWolf/ai-soc-framework
   cd ai-soc-framework
   ```

2. **安装依赖**
   建议在虚拟环境中使用 pip 安装依赖：
   ```bash
   python -m venv venv
   source venv/bin/activate  
   pip install -r requirements.txt
   ```

3. **启动依赖服务**
   项目使用 Redis 作为消息队列。我们提供了 Docker Compose 文件来快速启动一个 Redis Stack 实例。
   ```bash
   cd Docker/redis_stack
   docker-compose up -d
   ```

4. **配置**
   复制配置文件模板，并根据您的环境修改 `CONFIG.py` 文件，填入各个服务的 API 密钥、URL 和其他必要参数。
   ```bash
   cp CONFIG.example.py CONFIG.py
   ```
5. **启动 Forwarder**
   Forwarder 负责将SIEM的 Webhook 推送的告警数据写入 Redis Stream (当前适配Splunk和ELK)
   ```bash
    cd Forwarder
    python app.py
   ```

5. **运行**
   完成上述步骤后，在项目根目录运行主程序：

    ```bash
    python main.py
    ```

   程序将启动核心引擎，加载 `MODULES` 目录下的所有模块，并开始监听和处理事件。

## 模块开发

您可以参考 `MODULES` 目录下的现有模块，开发自己的自动化流程。每个模块都是一个独立的 Python 文件，框架会自动加载并运行它。
