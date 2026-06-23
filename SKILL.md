---
name: hermes-security-suite
description: "Hermes Agent安全五件套 — 检测(Detector: 830+规则/17层) + 诊断(Doctor: 自诊断自愈) + 防护(Hooks: 实时拦截) + 红队(RedTeam: Agent演习) + 流水线(Pipeline: 三阶段扫描)。当需要扫描AI Agent安全威胁、运行安全诊断、配置实时防护策略、进行安全演习、执行自动化扫描时使用。"
version: 2.3.0
author: 奇点造物
license: MIT
metadata:
  hermes:
    tags: [security, ai-agent, prompt-injection, detection, diagnosis, hooks, redteam, agent-snooping, pipeline, owasp-asi]
    related_skills: [agent-security-hardening, kingdom-shield-hooks, group-chat-survival]
triggers:
  - 安全扫描
  - 安全检测
  - Agent安全
  - prompt injection检测
  - security scan
  - 奇点造物
  - hermes-security
---

> 📖 详细技术文档见 references/ 目录

# Hermes Security Suite — Agent安全五件套

> 检测 · 诊断 · 防护 · 红队 · 流水线 — AI Agent 全链路安全框架

## When to Use

- 扫描用户输入/Agent输出中的安全威胁
- 运行Agent健康诊断
- 配置实时安全拦截策略
- 安全事件告警和响应
- **Agent Snooping行为检测**（NEW）
- **三阶段自动化扫描**（NEW）
- 安全演习和红队测试

## Quick Start

```python
from detector.genesisix_detector import GenesisixDetector
from detector.modules.agent_snooping import scan_agent_snooping
from detector.modules.agent_scan_pipeline import AgentScanPipeline

# 安全检测
detector = GenesisixDetector()
result = detector.scan("用户输入内容")

# Agent Snooping检测
findings = scan_agent_snooping("/path/to/skill")
for f in findings:
    print(f"[{f.rule_id}] {f.description}")

# 三阶段自动化扫描
pipeline = AgentScanPipeline(max_workers=4)
result = pipeline.scan("/path/to/skill")
print(f"风险评分: {result.summary['risk_score']}/100")
print(f"建议: {result.summary['recommendation']}")
```

## Architecture

```
Input → [Detector: 830+ rules/17 layers] → [Doctor: diagnose] → [Hooks: intercept] → Safe Output
Agent → [RedTeam: Agent-Scan + MCP-Scan + Agent-RT + PromptSec]
Skill → [Pipeline: Stage1(信息收集) → Stage2(并行检测) → Stage3(漏洞审查)]
```

## Modules

1. **Detector** — 830+条安全规则，17层防护，自学习循环
   - **NEW**: Agent Snooping层（AS1-AS3）检测配置窥探行为
2. **Doctor** — Agent自诊断、药方匹配、修复计划
3. **Hooks** — 实时拦截、策略热更、违规阻断
4. **RedTeam** — 安全演习、MCP审计、越狱测试
5. **Agent Scan Pipeline** — 三阶段自动化扫描流水线（NEW）

## Agent Snooping Detection (NEW)

检测技能中的Agent配置窥探行为：

| 规则 | 描述 | 严重程度 |
|------|------|----------|
| AS1 | Agent配置目录访问（.claude/, .codex/, .gemini/） | HIGH |
| AS2 | MCP配置文件访问（mcp.json, mcp_config.json） | HIGH |
| AS3 | 技能枚举/窥探（枚举其他已安装技能） | HIGH |

Framework: OWASP LLMT09 (Misinformation), ASI-SR-003 (Least Knowledge)

## Agent Scan Pipeline (NEW)

三阶段自动化扫描流水线，融合自 Tencent AI-Infra-Guard v4.1.14：

1. **信息收集** — 收集目标配置、能力和暴露的端点
2. **并行漏洞检测** — 每个检测技能一个轻量级worker，并发执行
3. **漏洞审查** — 合并结果，映射到OWASP ASI，分配最终严重程度

**OWASP ASI 映射**:
- AS1-AS3 → ASI-05 (Agent Snooping)
- SC1-SC6 → ASI-06 (Supply Chain)
- E1-E2 → ASI-02 (Data Leakage)
- TM1-TM2 → ASI-04 (Tool Abuse)
- MP1-MP2 → ASI-10 (Memory Poisoning)
- AST1-AST2 → ASI-07 (Excessive Agency)

---

## 工作流

使用此技能时，按以下步骤执行：

- [ ] 1. 确认用户需求和使用场景
- [ ] 2. 加载相关代码和配置
- [ ] 3. 执行核心功能
- [ ] 4. 验证输出结果
