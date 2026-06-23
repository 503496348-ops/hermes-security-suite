1|---
2|name: hermes-security-suite
3|description: "Hermes Agent安全五件套 — 检测(Detector: 830+规则/17层) + 诊断(Doctor: 自诊断自愈) + 防护(Hooks: 实时拦截) + 红队(RedTeam: Agent演习) + 流水线(Pipeline: 三阶段扫描)。当需要扫描AI Agent安全威胁、运行安全诊断、配置实时防护策略、进行安全演习、执行自动化扫描时使用。"
4|version: 2.3.0
5|author: 奇点造物
6|license: MIT
7|metadata:
8|  hermes:
9|    tags: [security, ai-agent, prompt-injection, detection, diagnosis, hooks, redteam, agent-snooping, pipeline, owasp-asi]
10|    related_skills: [agent-security-hardening, kingdom-shield-hooks, group-chat-survival]
11|triggers:
12|  - 安全扫描
13|  - 安全检测
14|  - Agent安全
15|  - prompt injection检测
16|  - security scan
17|  - 奇点造物
18|  - hermes-security
19|---

> 📖 详细技术文档见 references/ 目录
20|
21|# Hermes Security Suite — Agent安全五件套
22|
23|> 检测 · 诊断 · 防护 · 红队 · 流水线 — AI Agent 全链路安全框架
24|
25|## When to Use
26|
27|- 扫描用户输入/Agent输出中的安全威胁
28|- 运行Agent健康诊断
29|- 配置实时安全拦截策略
30|- 安全事件告警和响应
31|- **Agent Snooping行为检测**（NEW）
32|- **三阶段自动化扫描**（NEW）
33|- 安全演习和红队测试
34|
35|## Quick Start
36|
37|```python
38|from detector.genesisix_detector import GenesisixDetector
39|from detector.modules.agent_snooping import scan_agent_snooping
40|from detector.modules.agent_scan_pipeline import AgentScanPipeline
41|
42|# 安全检测
43|detector = GenesisixDetector()
44|result = detector.scan("用户输入内容")
45|
46|# Agent Snooping检测
47|findings = scan_agent_snooping("/path/to/skill")
48|for f in findings:
49|    print(f"[{f.rule_id}] {f.description}")
50|
51|# 三阶段自动化扫描
52|pipeline = AgentScanPipeline(max_workers=4)
53|result = pipeline.scan("/path/to/skill")
54|print(f"风险评分: {result.summary['risk_score']}/100")
55|print(f"建议: {result.summary['recommendation']}")
56|```
57|
58|## Architecture
59|
60|```
61|Input → [Detector: 830+ rules/17 layers] → [Doctor: diagnose] → [Hooks: intercept] → Safe Output
62|Agent → [RedTeam: Agent-Scan + MCP-Scan + Agent-RT + PromptSec]
63|Skill → [Pipeline: Stage1(信息收集) → Stage2(并行检测) → Stage3(漏洞审查)]
64|```
65|
66|## Modules
67|
68|1. **Detector** — 830+条安全规则，17层防护，自学习循环
69|   - **NEW**: Agent Snooping层（AS1-AS3）检测配置窥探行为
70|2. **Doctor** — Agent自诊断、药方匹配、修复计划
71|3. **Hooks** — 实时拦截、策略热更、违规阻断
72|4. **RedTeam** — 安全演习、MCP审计、越狱测试
73|5. **Agent Scan Pipeline** — 三阶段自动化扫描流水线（NEW）
74|
75|## Agent Snooping Detection (NEW)
76|
77|检测技能中的Agent配置窥探行为：
78|
79|| 规则 | 描述 | 严重程度 |
80||------|------|----------|
81|| AS1 | Agent配置目录访问（.claude/, .codex/, .gemini/） | HIGH |
82|| AS2 | MCP配置文件访问（mcp.json, mcp_config.json） | HIGH |
83|| AS3 | 技能枚举/窥探（枚举其他已安装技能） | HIGH |
84|
85|Framework: OWASP LLMT09 (Misinformation), ASI-SR-003 (Least Knowledge)
86|
87|## Agent Scan Pipeline (NEW)
88|
89|三阶段自动化扫描流水线，融合自 Tencent AI-Infra-Guard v4.1.14：
90|
91|1. **信息收集** — 收集目标配置、能力和暴露的端点
92|2. **并行漏洞检测** — 每个检测技能一个轻量级worker，并发执行
93|3. **漏洞审查** — 合并结果，映射到OWASP ASI，分配最终严重程度
94|
95|**OWASP ASI 映射**:
96|- AS1-AS3 → ASI-05 (Agent Snooping)
97|- SC1-SC6 → ASI-06 (Supply Chain)
98|- E1-E2 → ASI-02 (Data Leakage)
99|- TM1-TM2 → ASI-04 (Tool Abuse)
100|- MP1-MP2 → ASI-10 (Memory Poisoning)
101|- AST1-AST2 → ASI-07 (Excessive Agency)
102|
---

## 工作流

使用此技能时，按以下步骤执行：

- [ ] 1. 确认用户需求和使用场景
- [ ] 2. 加载相关代码和配置
- [ ] 3. 执行核心功能
- [ ] 4. 验证输出结果
