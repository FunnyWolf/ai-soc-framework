# 开始之前

- ASF不是一个开箱即用的产品,而是一个框架.
- ASF需要使用者有一定的Python编程能力(在Cursor/Claude Code/Github Copilot帮助下很简单).

# 服务器资源

- 如果需要使用AI SOAR作为SIRP平台,则需要一台8核32G内存40G硬盘的Ubuntu24.04服务器
- 如果已经有其他SIRP/SOAR平台,只需要使用ASF的自动化功能,则需要一台2核4G内存40G硬盘的Ubuntu24.04服务器,可满足绝大多数自动化需求
- 如果需要使用本地化的LLM,则需要可以稳定运行支持格式化输出和函数调用的模型

# 环境部署

克隆项目到本地

```bash
git clone https://github.com/FunnyWolf/ai-soc-framework
```

## AI SOAR

> 如果不需要AI SOAR,可跳过此步骤

- 参考 [Nocoly官方文档](https://docs-pd.nocoly.com/zh-Hans/deployment/docker-compose/standalone/quickstart/)
  ,私有部署安装Nocoly
- 将`ai-soc-framework/Docker/nocoly/AI SOAR.mdy`导入Nocoly
  ![img.png](img.png)

## AI SOC Framework

- 安装Docker和Docker Compose,可参考 [Docker安装文档](https://github.com/docker/docker-install/)
- 上传ASF代码到服务器,例如/root/asf
- 修改/root/asf/Docker/redis_stack/docker-compose.yml的`redis-stack-password-for-ai-soc-framework`为你自己的密码
- 同步修改/root/asf/CONFIG.example.py的`REDIS_URL`
- 使用uvicorn --config uvicorn.toml

## AI SOC Framework

* Python 3.12+
* Docker 和 Docker Compose (用于运行 Redis Stack) [Docker安装文档](https://github.com/docker/docker-install/)

- **克隆项目**
   ```bash
   git clone https://github.com/FunnyWolf/ai-soc-framework
   cd ai-soc-framework
   ```

- **启动Redis Stack**

   ```bash
   cd Docker/redis_stack
   docker compose up -d
   ```

- **安装依赖**

  建议在虚拟环境中使用 pip 安装依赖
   ```bash
   python -m venv venv
   source venv/bin/activate  
   pip install -r requirements.txt
   ```

- **配置**

  复制配置文件模板，并根据您的环境修改 `CONFIG.py` 文件，填入各个服务的 API 密钥、URL 和其他必要参数。
   ```bash
   cp CONFIG.example.py CONFIG.py
   ```

- **运行**

  完成上述步骤后，在项目根目录运行主程序：

    ```bash
    python manage.py runserver 0.0.0.0:7000
    ```

## 模块开发

您可以参考 `MODULES` 目录下的现有模块，开发自己的自动化流程。每个模块都是一个独立的 Python 文件，框架会自动加载并运行它。
