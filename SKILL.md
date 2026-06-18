---
name: hermes-security-suite
description: "Hermes Agent安全三件套 — 检测(Detector: 825条规则/13层) + 诊断(Doctor: 自诊断自愈) + 防护(Hooks: 实时拦截)。当需要扫描AI Agent安全威胁、运行安全诊断、配置实时防护策略时使用。"
version: 2.1.0
author: 奇点造物
license: MIT
metadata:
  hermes:
    tags: [security, ai-agent, prompt-injection, detection, diagnosis, hooks]
    related_skills: [agent-security-hardening, kingdom-shield-hooks, group-chat-survival]
---

# Hermes Security Suite — Agent安全三件套

> 检测 · 诊断 · 防护 — AI Agent 全链路安全框架

## When to Use

- 扫描用户输入/Agent输出中的安全威胁
- 运行Agent健康诊断
- 配置实时安全拦截策略
- 安全事件告警和响应

## Quick Start

```python
from detector.genesisix_detector import GenesisixDetector

detector = GenesisixDetector()
result = detector.scan("用户输入内容")
```

## Architecture

```
Input → [Detector: 825 rules/13 layers] → [Doctor: diagnose] → [Hooks: intercept] → Safe Output
```

## Modules

1. **Detector** — 825条安全规则，13层防护，自学习循环
2. **Doctor** — Agent自诊断、药方匹配、修复计划
3. **Hooks** — 实时拦截、策略热更、违规阻断
