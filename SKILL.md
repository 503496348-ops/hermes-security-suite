---
name: hermes-security-suite
description: "Hermes Agent安全五件套 — 检测(Detector: 830+规则/17层) + 诊断(Doctor: 自诊断自愈) + 防护(Hooks: 实时拦截) + 红队(RedTeam: Agent演习) + 流水线(Pipeline: 三阶段扫描)。当需要扫描AI Agent安全威胁、运行安全诊断、配置实时防护策略、进行安全演习、执行自动化扫描时使用。"
version: 2.5.0
author: 奇点造物
license: MIT
metadata:
  hermes:
    tags: [security, ai-agent, prompt-injection, detection, diagnosis, hooks, redteam, agent-snooping, pipeline, owasp-asi, mcp-security, osv]
    related_skills: [agent-security-hardening, kingdom-shield-hooks, group-chat-survival]
triggers:
  - 安全扫描
  - 安全检测
  - Agent安全
  - prompt injection检测
  - security scan
  - 奇点造物
  - hermes-security
  - MCP安全审计
  - OSV漏洞查询
  - 最小权限检查
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
- **MCP最小权限/工具投毒检测**（NEW）
- **OSV.dev实时依赖漏洞查询**（NEW）
- 安全演习和红队测试

## 快速开始

```python
from detector.genesisix_detector import GenesisixDetector
from detector.modules.agent_snooping import scan_agent_snooping
from detector.modules.agent_scan_pipeline import AgentScanPipeline
from detector.modules.mcp_analyzer import scan_mcp_manifest, build_least_privilege_profile
from detector.modules.supply_chain import scan_with_osv_lookup

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

# MCP最小权限与工具投毒检测
manifest = {"name": "report-tool", "capabilities": ["file_write"], "permissions": ["files:write:/workspace/reports/*.md"]}
threats = scan_mcp_manifest(manifest)
profile = build_least_privilege_profile(manifest)

# 依赖漏洞实时查询（联网时使用OSV.dev，离线时优雅降级）
supply_chain_findings = scan_with_osv_lookup("/path/to/project")
```

## Architecture

```
Input → [Detector: 830+ rules/17 layers] → [Doctor: diagnose] → [Hooks: intercept] → Safe Output
Agent → [RedTeam: Agent-Scan + MCP-Scan + Agent-RT + PromptSec]
Skill → [Pipeline: Stage1(信息收集) → Stage2(并行检测) → Stage3(漏洞审查)]
MCP → [TP1-TP4工具投毒检测 + LP1/LP2最小权限收敛]
Dependencies → [SC1-SC6供应链扫描 + SC4 OSV.dev批量漏洞查询]
```

## Modules

1. **Detector** — 830+条安全规则，17层防护，自学习循环
   - **NEW**: Agent Snooping层（AS1-AS3）检测配置窥探行为
2. **Doctor** — Agent自诊断、药方匹配、修复计划
3. **Hooks** — 实时拦截、策略热更、违规阻断
4. **RedTeam** — 安全演习、MCP审计、越狱测试
5. **Agent Scan Pipeline** — 三阶段自动化扫描流水线（NEW）
6. **MCP Security Analyzer** — 工具投毒、同形字、隐藏指令、最小权限与权限范围审计
7. **Supply Chain + OSV** — 依赖解析、typosquat、恶意包、版本锁定、OSV实时漏洞查询

## Agent Snooping Detection (NEW)

检测技能中的Agent配置窥探行为：

| 规则 | 描述 | 严重程度 |
|------|------|----------|
| AS1 | Agent配置目录访问（.claude/, .codex/, .gemini/） | HIGH |
| AS2 | MCP配置文件访问（mcp.json, mcp_config.json） | HIGH |
| AS3 | 技能枚举/窥探（枚举其他已安装技能） | HIGH |

Framework: OWASP LLMT09 (Misinformation), ASI-SR-003 (Least Knowledge)

## Agent Scan Pipeline (NEW)


1. **信息收集** — 收集目标配置、能力和暴露的端点
2. **并行漏洞检测** — 每个检测技能一个轻量级worker，并发执行
3. **漏洞审查** — 合并结果，映射到OWASP ASI，分配最终严重程度

**OWASP ASI 映射**:
- AS1-AS3 → ASI-05 (Agent Snooping)
- SC1-SC6 → ASI-06 (Supply Chain)
- TP1-TP4 / LP1-LP2 → ASI-04 (Tool Abuse)
- E1-E2 → ASI-02 (Data Leakage)
- TM1-TM2 → ASI-04 (Tool Abuse)
- MP1-MP2 → ASI-10 (Memory Poisoning)
- AST1-AST2 → ASI-07 (Excessive Agency)

---

## MCP/OSV安全能力

| 能力 | 入口 | 输出 |
|---|---|---|
| 工具投毒检测 | `scan_mcp_manifest(manifest)` | TP1隐藏指令、TP2同形字、TP3超长描述、TP4工具名仿冒 |
| 最小权限画像 | `build_least_privilege_profile(manifest)` | 高危能力、通配权限、推荐收敛权限、风险分 |
| 依赖漏洞查询 | `scan_with_osv_lookup(project_path)` | SC4漏洞发现、严重程度、修复版本建议 |

## 工作流

使用此技能时，按以下步骤执行：

- [ ] 1. 确认用户需求和使用场景
- [ ] 2. 加载相关代码和配置
- [ ] 3. 对MCP manifest执行工具投毒与最小权限扫描
- [ ] 4. 对项目依赖执行供应链与OSV漏洞查询
- [ ] 5. 验证输出结果并按严重程度给出修复建议

## 2026-07-03 运行时增强

- 新增运行时权限守卫与漏洞批次汇总：检测过宽工具权限、敏感工具缺 scope、供应链高风险密度阻断。
- 验证：新增模块通过 py_compile 和定向 pytest，代码不依赖外部服务。

## 2026-07-03 产品收敛门禁

- 新增 `scripts/product_convergence_gate.py`：从远端干净 clone 后可运行 `python3 scripts/product_convergence_gate.py --json`，检查 SKILL/README、入口文件、smoke 目标、测试与外部融合引用是否自洽。
- 新增 `tests/test_product_convergence_gate.py`：确保门禁在产品仓库中真实可执行，避免后续增强只停留在孤岛模块。

## 一键开箱交付

本仓库提供标准一键入口：

- `install.sh`：用户的一条命令安装与冒烟入口。
- `scripts/setup.py`：安装声明依赖并串联 doctor。
- `scripts/doctor.py`：检查 README、SKILL、入口脚本、package scripts 与产品收敛门禁。
- `scripts/smoke.py`：运行 doctor、产品收敛门禁与 Python 编译级冒烟。
- `tests/test_one_click_open_box.py`：契约测试，防止 README 写了但脚本缺失。


## Lark Coding Agent Bridge 融合增强

- 奇点造物新增 Bridge Security Invariants：prompt secret redaction、workspace allowlist、callback nonce 安全门禁。
- 新增模块：`core/bridge_security_invariants.py`
- 来源模式：飞书/Lark 消息入口、本地 Claude/Codex 执行、会话 fingerprint、profile 隔离与安全门禁。

## Generic orchestration security invariants

Adds controls for high-risk action confirmation, operator-only model changes, webhook URL allowlists, HTTPS enforcement, and wildcard CORS rejection.
