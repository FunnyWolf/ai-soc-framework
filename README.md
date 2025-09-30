# AI SOC Framework (ASF)

基于AI Agent的SOC自动化框架.灵活,强大,本地部署.

## 功能

- 基于Webhook + Redis Stream的告警流水线,支持主流SIEM平台
- 提供Langchain/Langgraph/Dify等AI Agent模块模板,快速开发Pre Automation/Post Automation模块
- 内置功能齐全的工单平台(AI SOAR),支持Artifact->Alert->Case网络安全告警数据模型
- AI SOAR内置简单易用的告警聚合功能,支持默认规则和自定义规则
- 框架代码皆为Python编写,易于二次开发和扩展

### AI SOAR Dashboard

![img.png](Static/img.png)

![img_1.png](Static/img_1.png)

### AI SOAR Case Table

![img_2.png](Static/img_2.png)

![img_3.png](Static/img_3.png)

![img_4.png](Static/img_4.png)

![img_5.png](Static/img_5.png)

### AI SOAR Alert Table

![img_6.png](Static/img_6.png)

![img_7.png](Static/img_7.png)

![img_8.png](Static/img_8.png)

![img_9.png](Static/img_9.png)

### AI SOAR Artifact Table

![img_10.png](Static/img_10.png)

![img_11.png](Static/img_11.png)

### Redis Alert Stream

![img_12.png](Static/img_12.png)

## 为什么使用ASF & ASF解决哪些问题

- 预算/资源有限无法购买商用SOAR产品

> ASF完全开源免费,且支持对接社区版的ELK(SIEM),企业只需有基础的安全设备和日志采集能力即可构建完整的SOC基础设施

- 所有网络安全相关数据不允许离开企业内网

> ASF所有组件(AI SOAR/Redis Stack/Module Framework)均可本地部署,可以通过vllm/ollama等部署本地化的LLM,实现完全本地化的AI
> Agent能力

- 对于工单管理有大量定制化需求,不限于个性化UI,定制化流程,自定义数据模型,数据报表等

> ASF的AI SOAR基于[Nocoly](https://www.nocoly.com/)构建,无需编写代码即可实现定制化UI修改,自定义工作流,自定义报表等

- 出于特定的安全业务需求或提高效率,需要定制化的AI Agent分析告警

> ASF提供模块模板及样例模块,用户可根据自身需求快速开发定制化的AI Agent模块,支持多框架(Langchain/Langgraph/Dify等)

- 内部系统/设备接口众多,需要额外的数据处理及转化,主流的SOAR(如Swimlane/Splunk SOAR)或可视化编排产品(n8n)等无法满足需求

> ASF的模块开发完全基于Python,用户可以使用任何Python库,并且可以灵活地对接任何API或设备

- SOAR的自动化剧本和自定义的自动化脚本无法调试

> ASF中有用于调试的适配性代码,用户可单独运行模块对指定告警(Redis Insight检索查看)进行调试,而无需启动整个框架

## 不适用于哪些场景

- 安全团队没有基础的Python开发能力

> ASF不是开箱即用平台,需要一定的Python开发能力来进行模块开发和定制化

- 企业使用单独厂商一揽子解决方案(如XDR/MDR/MSS等)

> ASF需要告警数据或日志来进行自动化分析,XDR/MDR/MSS等封闭系统无法实现

- 企业没有基础的安全设备和日志采集能力

> 没有设备就没有日志和告警,那也就不需要自动化

## 架构图

![img.png](Static/img_arch.png)


## TODO

- 详细的安装和使用文档

> nocoly的部署,redis stack的部署

- 各个部分的设计思想
- uwsgi配置
- 通过case_id/alert_id/artifact_id获取数据的api接口

## 许可证

该项目采用 [MIT](https://choosealicense.com/licenses/mit/) 许可证。

