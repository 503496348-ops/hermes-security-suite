# 🛡️ Hermes Security Suite — Agent安全三件套

> **检测 · 诊断 · 防护** — AI Agent 全链路安全框架

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hermes Agent](https://img.shields.io/badge/Hermes-Agent-blue)](https://github.com/503496348-ops/hermes-agent)

---

## 🎯 定位

**对标**: NVIDIA SkillSpector (7.4K⭐) · Tencent AI-Infra-Guard (3.9K⭐) · agentic_security (1.9K⭐)

**差异化**: 不是通用AI安全工具，而是 **Agent行为层** 的安全检测——专为自主Agent设计，覆盖从输入到输出的全链路。

```
┌─────────────────────────────────────────────────┐
│            Hermes Security Suite                 │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Detector │  │  Doctor  │  │  Hooks   │      │
│  │ (检测)   │  │ (诊断)   │  │ (防护)   │      │
│  │          │  │          │  │          │      │
│  │ 825条规则│  │ 自诊断   │  │ Hook拦截 │      │
│  │ 13层防护 │  │ 药方匹配 │  │ 实时阻断 │      │
│  │ 自学习   │  │ 病历沉淀 │  │ 策略热更 │      │
│  └──────────┘  └──────────┘  └──────────┘      │
│                                                  │
│  Input → [Detector] → [Doctor] → [Hooks] → Safe │
└─────────────────────────────────────────────────┘
```

## 📦 三大模块

### 1. Detector — 安全检测引擎 (`detector/`)

825条规则，13层防护：

| 层 | 覆盖范围 | 规则数 |
|---|---------|-------|
| LLM层 | 提示注入、越狱、多轮攻击、多语言注入 | 120+ |
| API层 | 认证、JWT、GraphQL、OAuth、密钥泄露 | 80+ |
| Web层 | XSS、SSRF、XXE、SQL注入、路径遍历 | 100+ |
| 内存层 | 记忆注入、Checkpoint篡改 | 40+ |
| 部署层 | 源码泄露、Docker泄露、CI/CD安全 | 60+ |
| 供应链层 | 恶意依赖、Typosquat、Skill完整性 | 50+ |
| 编码层 | Trojan Source、Homoglyph、零宽字符 | 30+ |
| MCP层 | 工具Schema验证、输出安全 | 40+ |
| 多轮层 | 上下文累积攻击、渐进式越狱 | 30+ |
| 资源层 | SSRF、文件泄露、路径穿越 | 50+ |
| 数据层 | PII泄露、敏感信息外泄 | 80+ |
| 自学习层 | 误报/漏报自动优化 | 持续增长 |
| Hook层 | 实时拦截、策略执行 | 40+ |

```python
from detector.genesisix_detector import GenesisixDetector

detector = GenesisixDetector()
result = detector.scan("用户输入内容")

# 分层扫描
result = detector.scan_llm("prompt内容")
result = detector.scan_outbound("https://example.com")
result = detector.scan_mcp(tool_schema, tool_output)
result = detector.scan_multiturn(message_history)
```

### 2. Doctor — 自诊断与自愈 (`doctor/`)

Agent健康体检 + 药方匹配 + 修复计划 + 病历沉淀。

```bash
# 运行诊断
python3 doctor/doctor.py --full-check

# 输出: 症状 → 药方 → 修复计划 → 飞书通知
```

### 3. Hooks — 实时防护 (`hooks/`)

基于 `.kingdom/` hook 的实时拦截器，让违规操作**物理不可能发生**。

```yaml
# hooks/policy.yaml
rules:
  - name: "block-credential-leak"
    trigger: "before_file_write"
    pattern: "(sk-|AKIA|ghp_)[a-zA-Z0-9]+"
    action: "block_and_alert"
```

## 🏃 Quick Start

```bash
# 安装
git clone https://github.com/503496348-ops/hermes-security-suite
cd hermes-security-suite

# 运行测试
python3 detector/test_genesisix.py

# 在Hermes Agent中使用
# 技能自动加载: genesisix-hermes, hermes-doctor, kingdom-shield-hooks
```

## 📊 竞品对比

| 维度 | SkillSpector (NVIDIA) | AI-Infra-Guard (Tencent) | agentic_security | **Hermes Security Suite** |
|------|----------------------|-------------------------|-----------------|--------------------------|
| **Stars** | 7.4K | 3.9K | 1.9K | 起步期 |
| **定位** | Skill安全审计 | AI基础设施安全 | 通用Agent安全 | **Agent行为层全链路** |
| **检测层** | 模型层 | 基础设施层 | 模型层 | **Agent层(输入→推理→输出→记忆→部署)** |
| **自学习** | ❌ | ❌ | ❌ | ✅ 误报/漏报自动优化 |
| **自愈能力** | ❌ | ❌ | ❌ | ✅ Doctor诊断+修复 |
| **实时防护** | ❌ | ❌ | ❌ | ✅ Hook拦截+阻断 |
| **Hermes集成** | ❌ | ❌ | ❌ | ✅ 原生集成 |
| **飞书通知** | ❌ | ❌ | ❌ | ✅ 安全事件飞书推送 |
| **规则数** | ~200 | ~100 | ~50 | **825** |
| **覆盖层数** | 3 | 5 | 3 | **13** |

## 📁 目录结构

```
hermes-security-suite/
├── detector/          # 安全检测引擎
│   ├── genesisix_detector.py  # 核心检测器
│   ├── self_loop.py           # 自学习循环
│   ├── rules/                 # 825条安全规则
│   │   ├── llm/              # LLM安全规则
│   │   ├── api/              # API安全规则
│   │   ├── web/              # Web安全规则
│   │   ├── memory/           # 内存安全规则
│   │   ├── deploy/           # 部署安全规则
│   │   └── supply_chain/     # 供应链安全规则
│   └── test_genesisix.py      # 测试套件
├── doctor/            # 自诊断与自愈
│   └── doctor.py              # 诊断引擎
├── hooks/             # 实时防护
│   └── policy.yaml            # 拦截策略
├── docs/              # 文档
│   └── COMPETITIVE_ANALYSIS.md
└── README.md
```

## 🛣️ Roadmap

- [x] v1.0: 825条规则 + 13层检测
- [x] v2.0: 自学习循环 + Hermes原生集成
- [ ] v2.1: Doctor诊断 + 飞书告警
- [ ] v2.2: Hook实时防护 + 策略热更
- [ ] v3.0: Skill安全市场 + 社区规则贡献

## 📄 License

MIT — 自由使用，共同守护Agent安全。

---

> **一句话**: SkillSpector检测Skill安全，AI-Infra-Guard保护基础设施，我们保护**Agent本身**——从输入到输出，从记忆到部署，13层825条规则，自学习，自诊断，自愈。
