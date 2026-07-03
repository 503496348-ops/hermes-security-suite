## 一键安装 / One-click Quickstart

```bash
bash install.sh
python3 scripts/doctor.py
python3 scripts/smoke.py
```

- `bash install.sh`：自动执行 setup + smoke，适合第一次使用。
- `python3 scripts/doctor.py`：检查环境、入口文件和产品门禁，失败时给出修复建议。
- `python3 scripts/smoke.py`：执行产品收敛门禁和轻量核心冒烟验证。

# 🛡️ Hermes Security Suite — Agent安全五件套

> **检测 · 诊断 · 防护 · 红队 · 流水线** — AI Agent 全链路安全框架

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Hermes Agent](https://img.shields.io/badge/Hermes-Agent-blue)](https://github.com/503496348-ops/hermes-agent)

---

## 🎯 定位

定位: Agent行为层安全检测——专为自主Agent设计，覆盖从输入到输出的全链路。

**差异化**: 不是通用AI安全工具，而是 **Agent行为层** 的安全检测——专为自主Agent设计，覆盖从输入到输出的全链路。集成红队能力，提供 Agent 安全演习、MCP 审计、提示词越狱测试等攻击面评估。

```
┌──────────────────────────────────────────────────────────────────┐
│                    Hermes Security Suite                           │
│                                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐      │
│  │ Detector │  │  Doctor  │  │  Hooks   │  │   RedTeam    │      │
│  │ (检测)   │  │ (诊断)   │  │ (防护)   │  │   (红队)     │      │
│  │          │  │          │  │          │  │              │      │
│  │ 825条规则│  │ 自诊断   │  │ Hook拦截 │  │ Agent演习    │      │
│  │ 13层防护 │  │ 药方匹配 │  │ 实时阻断 │  │ MCP审计      │      │
│  │ 自学习   │  │ 病历沉淀 │  │ 策略热更 │  │ 越狱测试     │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘      │
│                                                                    │
│  Input → [Detector] → [Doctor] → [Hooks] → Safe                   │
│  Agent → [RedTeam: Agent-Scan + MCP-Scan + Agent-RT + PromptSec]  │
└──────────────────────────────────────────────────────────────────┘
```

## 📦 四大模块

### 1. Detector — 安全检测引擎 (`detector/`)

830+条规则，17层防护（含AST行为分析、数据流污点追踪、YARA签名扫描、MCP最小权限与OSV查询）：

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
| AST行为分析层 | Python AST解析检测危险执行模式（exec/eval/subprocess链） | 8规则 |
| 污点追踪层 | Source→Sink数据流分析（凭据泄露/RCE/数据外泄） | 5规则 |
| Agent Snooping层 | Agent配置窥探、MCP配置窃取、技能枚举 | 3规则（AS1-AS3） |
| YARA签名层 | 恶意软件/Webshell/挖矿/黑客工具签名扫描 | 20+规则 |
| MCP最小权限层 | 工具投毒、权限通配、能力/描述不一致、工具名仿冒 | 6规则 |
| OSV漏洞层 | OSV.dev批量漏洞查询、版本感知修复建议 | 实时查询 |

```python
from detector.genesisix_detector import GenesisixDetector

detector = GenesisixDetector()
result = detector.scan("用户输入内容")

# 分层扫描
result = detector.scan_llm("prompt内容")
result = detector.scan_outbound("https://example.org")
result = detector.scan_mcp(tool_schema, tool_output)
result = detector.scan_multiturn(message_history)
# 新增: AST行为分析 / 污点追踪 / YARA签名扫描
result = detector.scan_code_ast(source_code, "plugin.py")
result = detector.scan_code_taint(source_code, "plugin.py")
result = detector.scan_yara(file_content, "script.sh")

from detector.modules.mcp_analyzer import scan_mcp_manifest, build_least_privilege_profile
from detector.modules.supply_chain import scan_with_osv_lookup
threats = scan_mcp_manifest({"name": "report-tool", "capabilities": ["file_write"]})
profile = build_least_privilege_profile({"name": "report-tool", "capabilities": ["file_write"]})
vulns = scan_with_osv_lookup("/path/to/project")
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

### 4. RedTeam — AI红队安全评估 (`redteam/`)

整合红队能力，提供全方位 AI 安全攻击面评估。包含四个子模块：

| 子模块 | 能力 | 入口 |
|--------|------|------|
| **Agent-Scan** | AI Agent 驱动的代码扫描和漏洞检测 | `redteam/agent-scan/main.py` |
| **MCP-Scan** | MCP Server 安全审计和动态分析 | `redteam/mcp-scan/main.py` |
| **Agent RedTeam** | 一键式 Agent 安全演习 Skill | `redteam/agent-redteam/SKILL.md` |
| **Prompt Security** | 提示词安全评估和越狱测试 | `redteam/prompt-security/cli_run.py` |

**Agent RedTeam 核心能力**:
- 🔍 **基础设施扫描**: 80+ AI服务指纹识别 + CVE匹配（覆盖本地模型服务、推理网关与工作流服务器）
- 📝 **代码审计**: Skill源码分析、MCP Server审计、供应链检查
- 🎯 **动态测试**: 30+ 提示注入载荷，自适应变异
- 🔓 **越狱评估**: LLM边界测试，18+ 单轮攻击 + 6+ 多轮攻击算子
- 🔗 **工作流攻击**: 多步任务链滥用、RAG间接注入

```bash
# MCP Server 安全扫描
cd redteam/mcp-scan && python main.py --repo /path/to/project

# 提示词越狱测试
cd redteam/prompt-security && python cli_run.py --model "gpt-3.5-turbo" \
  --base_url "https://api.openai.com/v1" --api_key "key" \
  --scenarios Bias --techniques PromptInjection
```

## 🏃 Quick Start

```bash
# 安装
git clone https://github.com/503496348-ops/hermes-security-suite
cd hermes-security-suite

# 运行测试
python3 detector/test_genesisix.py

# Agent 安全演习
cd redteam/agent-redteam && python3 scripts/run.py

# 在Hermes Agent中使用
# 技能自动加载: genesisix-hermes, hermes-doctor, kingdom-shield-hooks, aig-agent-redteam
```
## 📁 目录结构

```
hermes-security-suite/
├── detector/              # 安全检测引擎
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
├── doctor/                # 自诊断与自愈
│   └── doctor.py              # 诊断引擎
├── hooks/                 # 实时防护
│   └── policy.yaml            # 拦截策略
├── redteam/               # AI红队安全评估 (红队能力)
│   ├── agent-scan/        # Agent代码扫描
│   ├── mcp-scan/          # MCP Server安全审计
│   ├── agent-redteam/     # Agent安全演习Skill
│   └── prompt-security/   # 提示词安全评估
├── core/                  # 核心框架
├── docs/                  # 文档
│   └── COMPETITIVE_ANALYSIS.md
└── README.md
```

## 🛣️ Roadmap

- [x] v1.0: 825条规则 + 13层检测
- [x] v2.0: 自学习循环 + Hermes原生集成
- [x] v2.1: RedTeam模块 — Agent演习 + MCP审计 + 越狱测试 (整合红队能力)
- [x] v2.4: MCP最小权限 + OSV实时漏洞查询
- [ ] v2.5: Doctor诊断 + 飞书告警
- [ ] v2.6: Hook实时防护 + 策略热更
- [ ] v3.0: Skill安全市场 + 社区规则贡献

## 📄 License

MIT — 自由使用，共同守护Agent安全。

---

> **一句话**: 我们保护**Agent本身**——从输入到输出，从记忆到部署，13层825条规则，自学习，自诊断，自愈，外加红队演习能力。

> **AtomCollide-智械工坊** — 让AI安全可见、可测、可防

---



---

## 🚀 加入AtomCollide-AI智能体实验室

**元素碰撞-AtomCollide-AI 智能体实验室** 是一个专注于AI领域的开源组织，汇聚了众多优秀学习者。

### 核心价值

**找工作：更省力，也更精准**
- 一线大厂内推通道（字节、阿里、腾讯等）
- 全链路求职赋能包（面试题库、简历优化、晋升指导）
- 线下技术沙龙 & 人脉网络

**学AI测试：真正落地，拒绝空谈**
- 从0到1实战落地体系（Skills、MCP、RAG、AI IDE等）
- 独家自研资料与工具矩阵
- 前沿技术同步与提效方案

### 知识库

- [踩坑合集](https://vcnvmnln7wit.feishu.cn/wiki/CjV9wG8IHiIpWikCdFEcxfErnne)
- [商业化案例库](https://vcnvmnln7wit.feishu.cn/wiki/LdIxwlrKGibFEVkWMocc2K9KnBh)
- [科普专栏](https://vcnvmnln7wit.feishu.cn/wiki/K1RPwM8zji9ZchkxlOmcivUgnJe)
- [Open Build](https://vcnvmnln7wit.feishu.cn/wiki/CThswol0PiNJJbkhgT1cZIxanLb)
- [LLM/Agent/研究报告知识库](https://vcnvmnln7wit.feishu.cn/wiki/KwGQwS2TciT2EdkSBBtcYnbsnSd)
- [Skill封装合集](https://vcnvmnln7wit.feishu.cn/wiki/PDfpwqJZUibTyBkUa7TcZZ6Onpd)
- [社区治理运营知识库](https://vcnvmnln7wit.feishu.cn/wiki/MSEGwrdnTiiF9Dk8qCVcNW6InJg)

### 加入社群

| 社群 | 链接 |
|------|------|
| AI探索交流1区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=074vd565-6084-455c-ac52-9703e89a0697) |
| AI探索交流2区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=60bj94f0-1a67-48a7-abbb-9172b161c2b0) |
| AI探索交流3区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=13do1920-db46-4444-b635-005680beaf58) |
| AI探索交流4区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=f17o1b86-06f6-4f10-911a-69a299a25fe3) |
| AI探索交流5区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=2bbh6ab6-22c2-4753-b973-74bb1a2edcc9) |
| AI探索交流6区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=d19r19f7-2f47-42ba-b1ec-cb0342cf2e80) |
| AI探索交流7区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=fe9vdacc-7316-4b4d-ae4a-fdbcf56315e6) |
| AI探索交流8区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=103kfae8-1fd7-424f-984f-d66c210e42d1) |
| AI探索交流9区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=239p3cad-2f83-4baa-a230-f40386067548) |
| AI探索交流10区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=880r7cf5-3638-45ff-afb9-7944de991872) |
| AI探索交流-网文作家 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=6a3v579b-ab43-4e1a-87f9-be63bab88da7) |
| AI探索交流群-音乐达人 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=76at299e-73da-4eeb-9eba-32161e98f2f8) |
| AI探索交流群-微笑驿站 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=f2av73d0-6bb4-4a9f-9095-5fbbe83e49ec) |

---

*AtomCollide-智械工坊团队出品*


### 5. Agent Scan Pipeline — 三阶段扫描流水线 (`detector/modules/agent_scan_pipeline.py`)


**三阶段流水线**:
1. **信息收集** — 收集目标配置、能力和暴露的端点
2. **并行漏洞检测** — 每个检测技能一个轻量级worker，并发执行
3. **漏洞审查** — 合并结果，映射到OWASP ASI，分配最终严重程度

**OWASP ASI 映射**:
| 规则ID | OWASP ASI | 描述 |
|--------|-----------|------|
| AS1-AS3 | ASI-05 | Agent Snooping |
| SC1-SC6 | ASI-06 | Supply Chain |
| E1-E2 | ASI-02 | Data Leakage |
| TM1-TM2 | ASI-04 | Tool Abuse |
| MP1-MP2 | ASI-10 | Memory Poisoning |
| AST1-AST2 | ASI-07 | Excessive Agency |
| TT1-TT3 | ASI-02/ASI-07 | Taint Tracking |
| YR1-YR2 | ASI-06 | YARA Signatures |
| LP1-LP2 | ASI-04 | MCP Least Privilege |
| TP1-TP2 | ASI-04 | MCP Tool Poisoning |

```python
from detector.modules.agent_scan_pipeline import AgentScanPipeline

pipeline = AgentScanPipeline(max_workers=4)
result = pipeline.scan("/path/to/skill")

print(f"风险评分: {result.summary['risk_score']}/100")
print(f"建议: {result.summary['recommendation']}")
```

---

## 组织与社群入口

**元素碰撞 · AtomCollide-AI 智能体实验室**：面向学习者、创作者与自动化实践者，持续沉淀可复用的 AI Agent 产品、工作流与工程经验。使命：**for the learner**。

> 请选择 1 个常用社群加入，内容全域同步，无需重复加入。

### 知识库

| 知识库 | 链接 |
|---|---|
| 踩坑合集 | [进入](https://vcnvmnln7wit.feishu.cn/wiki/CjV9wG8IHiIpWikCdFEcxfErnne) |
| 商业化案例库 | [进入](https://vcnvmnln7wit.feishu.cn/wiki/LdIxwlrKGibFEVkWMocc2K9KnBh) |
| 科普专栏 | [进入](https://vcnvmnln7wit.feishu.cn/wiki/K1RPwM8zji9ZchkxlOmcivUgnJe) |
| Open Build | [进入](https://vcnvmnln7wit.feishu.cn/wiki/CThswol0PiNJJbkhgT1cZIxanLb) |
| LLM / Agent / 研究报告 | [进入](https://vcnvmnln7wit.feishu.cn/wiki/KwGQwS2TciT2EdkSBBtcYnbsnSd) |
| Skill 封装合集 | [进入](https://vcnvmnln7wit.feishu.cn/wiki/PDfpwqJZUibTyBkUa7TcZZ6Onpd) |
| 社区治理运营 | [进入](https://vcnvmnln7wit.feishu.cn/wiki/MSEGwrdnTiiF9Dk8qCVcNW6InJg) |

### 社群邀请

| 社群 | 链接 |
|---|---|
| AI 探索交流 1 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=074vd565-6084-455c-ac52-9703e89a0697) |
| AI 探索交流 2 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=60bj94f0-1a67-48a7-abbb-9172b161c2b0) |
| AI 探索交流 3 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=13do1920-db46-4444-b635-005680beaf58) |
| AI 探索交流 4 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=f17o1b86-06f6-4f10-911a-69a299a25fe3) |
| AI 探索交流 5 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=2bbh6ab6-22c2-4753-b973-74bb1a2edcc9) |
| AI 探索交流 6 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=d19r19f7-2f47-42ba-b1ec-cb0342cf2e80) |
| AI 探索交流 7 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=fe9vdacc-7316-4b4d-ae4a-fdbcf56315e6) |
| AI 探索交流 8 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=103kfae8-1fd7-424f-984f-d66c210e42d1) |
| AI 探索交流 9 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=239p3cad-2f83-4baa-a230-f40386067548) |
| AI 探索交流 10 区 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=880r7cf5-3638-45ff-afb9-7944de991872) |
| AI 探索交流 — 网文作家 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=6a3v579b-ab43-4e1a-87f9-be63bab88da7) |
| AI 探索交流群 — 音乐达人 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=76at299e-73da-4eeb-9eba-32161e98f2f8) |
| AI 探索交流群 — 微笑驿站 | [加入](https://applink.feishu.cn/client/chat/chatter/add_by_link?link_token=f2av73d0-6bb4-4a9f-9095-5fbbe83e49ec) |

---

AtomCollide-智械工坊团队出品。更多产品见：[AtomCollide Product Matrix](https://503496348-ops.github.io/atomcollide-product-matrix/)。

## Governance Links

- [LICENSE](LICENSE)
- [CHANGELOG](CHANGELOG.md)
- [SECURITY](SECURITY.md)
- [CONTRIBUTING](CONTRIBUTING.md)



## 2026-07-03 运行时增强

- 新增运行时权限守卫与漏洞批次汇总：检测过宽工具权限、敏感工具缺 scope、供应链高风险密度阻断。
- 交付物包含可导入模块与定向单元测试。

## 2026-07-03 产品收敛门禁

- 新增 `scripts/product_convergence_gate.py`：从远端干净 clone 后可运行 `python3 scripts/product_convergence_gate.py --json`，检查 SKILL/README、入口文件、smoke 目标、测试与外部融合引用是否自洽。
- 新增 `tests/test_product_convergence_gate.py`：确保门禁在产品仓库中真实可执行，避免后续增强只停留在孤岛模块。


## Lark Coding Agent Bridge 融合增强

- 奇点造物新增 Bridge Security Invariants：prompt secret redaction、workspace allowlist、callback nonce 安全门禁。
- 新增模块：`core/bridge_security_invariants.py`
- 来源模式：飞书/Lark 消息入口、本地 Claude/Codex 执行、会话 fingerprint、profile 隔离与安全门禁。
