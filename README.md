# AI SOC Framework (ASF)

基于 AI Agent 的 SOC 自动化框架. 开源, 灵活, 强大, 私有部署.

## 功能

- 基于 Webhook + Redis Stream 的告警流水线, 支持主流 SIEM 平台
- 提供 Langchain/Langgraph/Dify 等 AI Agent 模块模板, 快速开发 Pre Automation/Post Automation 模块
- 内置功能齐全的 SIRP 平台(AI SOAR), 支持 Artifact/Alert/Case 网络安全告警数据模型
- AI SOAR 内置简单易用的告警聚合功能, 支持默认规则和自定义规则
- 框架代码皆为 Python 编写, 易于二次开发和扩展

## 为什么使用 ASF & ASF 解决哪些问题

- 预算 / 资源有限无法购买商用 SOAR 产品

> ASF 完全开源免费, 且支持对接社区版的 ELK(SIEM), 企业只需有基础的安全设备和日志采集能力即可构建完整的 SOC 基础设施

- 所有网络安全相关数据不允许离开企业内网

> ASF 所有组件 (AI SOAR/Redis Stack/Module Framework) 均可本地部署,
> 通过 vllm/ollama 等部署本地化的 LLM, 实现完全本地化的 AI Agent 能力

- 对于 SIRP 有大量定制化需求, 不限于个性化 UI, 定制化流程, 自定义数据模型, 数据报表等

> AI SOAR 基于 [Nocoly](https://www.nocoly.com/) 构建, 无需编写代码即可实现定制化 UI 修改, 自定义工作流, 自定义报表等

- 出于特定的安全业务需求或提高效率, 需要定制化的 AI Agent 分析告警

> ASF 提供模块模板及样例模块, 用户可根据自身需求快速开发定制化的 AI Agent 模块, 支持多框架(Langchain/Langgraph/Dify 等)

- 内部系统 / 设备接口众多, 需要额外的数据处理及转化, 主流的 SOAR(如 Swimlane/Splunk SOAR)或可视化编排产品 (n8n) 等无法满足需求

> ASF 的模块开发完全基于 Python, 用户可以使用任何 Python 库, 并且可以灵活地对接任何 API 或设备

- SOAR 的自动化剧本和自定义的自动化脚本无法调试

> ASF 中有用于调试的适配性代码, 用户可单独运行模块对指定告警 (Redis Insight 检索查看) 进行调试, 而无需启动整个框架

## 不适用于哪些场景

- 安全团队没有基础的 Python 开发能力

> ASF 不是开箱即用平台, 需要一定的 Python 开发能力来进行模块开发和定制化

- 企业使用单独厂商一揽子解决方案(如 XDR/MDR/MSS 等)

> ASF 需要告警数据或日志来进行自动化分析,XDR/MDR/MSS 等封闭系统无法实现

- 企业没有基础的安全设备和日志采集能力

> 没有设备就没有日志和告警, 那也就不需要自动化

## 许可证

该项目采用 [MIT](https://choosealicense.com/licenses/mit/) 许可证。

