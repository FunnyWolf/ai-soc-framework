## Design

- Nocoly有很大的灵活性,可以根据业务需求定制前端,界面,数据库等.无需编写代码.
- SOAR的可视化编排功能受限,调试困难,如果由于各种限制确实需要可视化编排,也可以使用n8n,dify等专业的可视化编排工具.
- 成熟稳定的自动化部分还是需要使用代码来实现,考虑到社区生态,python是最好的选择,而且还可以利用AI Coding,并使用git进行版本管理.
- 也就是利用Nocoly的APass能力,使用者可以根据业务需求定制Case Management,因为这部分是直接给应急人员使用的,所以需要高度定制化,保证灵活性及易用性.
- 自动化部分,比如告警分析,情报查询等,使用python实现,并将各个功能模块化,确保快速开发和稳定运行.


AI Agent SOC Automation Framework.Open Source, Flexible, Powerful, Private Deployment.



企业运营SOC 自动化是必不可少的,因为需要提升效率
当前的SOAR不是图灵完备的,无法实现真正的自动化,只能实现半自动化,需要大量的人工干预.



	http://192.168.241.1:7000/api/v1/automation/playbook
	nocoly_token_for_playbook
	Threat_Intelligence_Query
	Artifact
	12312-123123-1231231-3123123