---
name: hermes-security-suite
description: "Hermes Agent安全四件套 — 检测(Detector: 830+规则/17层) + 诊断(Doctor: 自诊断自愈) + 防护(Hooks: 实时拦截) + 红队(RedTeam: Agent演习)。当需要扫描AI Agent安全威胁、运行安全诊断、配置实时防护策略、进行安全演习时使用。"
version: 2.2.0
author: 奇点造物
license: MIT
metadata:
  hermes:
    tags: [security, ai-agent, prompt-injection, detection, diagnosis, hooks, redteam, agent-snooping]
    related_skills: [agent-security-hardening, kingdom-shield-hooks, group-chat-survival]
---

# Hermes Security Suite — Agent安全四件套

> 检测 · 诊断 · 防护 · 红队 — AI Agent 全链路安全框架

## When to Use

- 扫描用户输入/Agent输出中的安全威胁
- 运行Agent健康诊断
- 配置实时安全拦截策略
- 安全事件告警和响应
- **Agent Snooping行为检测**（NEW）
- 安全演习和红队测试

## Quick Start

```python
from detector.genesisix_detector import GenesisixDetector
from detector.modules.agent_snooping import scan_agent_snooping

# 安全检测
detector = GenesisixDetector()
result = detector.scan("用户输入内容")

# Agent Snooping检测
findings = scan_agent_snooping("/path/to/skill")
for f in findings:
    print(f"[{f.rule_id}] {f.description}")
```

## Architecture

```
Input → [Detector: 830+ rules/17 layers] → [Doctor: diagnose] → [Hooks: intercept] → Safe Output
Agent → [RedTeam: Agent-Scan + MCP-Scan + Agent-RT + PromptSec]
```

## Modules

1. **Detector** — 830+条安全规则，17层防护，自学习循环
   - **NEW**: Agent Snooping层（AS1-AS3）检测配置窥探行为
2. **Doctor** — Agent自诊断、药方匹配、修复计划
3. **Hooks** — 实时拦截、策略热更、违规阻断
4. **RedTeam** — 安全演习、MCP审计、越狱测试

## Agent Snooping Detection (NEW)

检测技能中的Agent配置窥探行为：

| 规则 | 描述 | 严重程度 |
|------|------|----------|
| AS1 | Agent配置目录访问（.claude/, .codex/, .gemini/） | HIGH |
| AS2 | MCP配置文件访问（mcp.json, mcp_config.json） | HIGH |
| AS3 | 技能枚举/窥探（枚举其他已安装技能） | HIGH |

Framework: OWASP LLMT09 (Misinformation), ASI-SR-003 (Least Knowledge)
