# 🗡️ RedTeam — AI红队安全评估模块

> **Agent安全 · MCP安全 · 提示词安全 · 基础设施安全** — 全方位AI红队攻击面覆盖

---

## 🎯 定位

RedTeam 模块整合了 AI Agent 生态的红队攻击能力，覆盖从 Agent 本身到其依赖的 MCP Server、Prompt、底层基础设施的完整攻击面。基于第一性原理推理，而非机械跑 payload 库。

## 📦 四大子模块

### 1. Agent-Scan (`agent-scan/`)

AI Agent 驱动的自动化代码扫描和漏洞检测工具。支持多阶段扫描流程，自动识别项目结构、技术栈和潜在安全漏洞。

```bash
python main.py -m deepseek/deepseek-v3.2 -k sk-xxx --agent_provider demo_dify.yaml
```

**能力**: 代码审计 · 漏洞检测 · Skill一致性审计 · Agent行为分析

### 2. MCP-Scan (`mcp-scan/`)

MCP (Model Context Protocol) Server 安全扫描工具。模仿 Claude Code / Gemini CLI 的工作方式，进行深度代码分析和安全评估。

```bash
python main.py --repo /path/to/project
python main.py --server_url "http://localhost:8000/sse"  # 动态分析
```

**能力**: MCP工具Schema审计 · 代码安全扫描 · Skill一致性验证 · 动态MCP分析

### 3. Agent RedTeam (`agent-redteam/`)

一键式 Agent 安全演习 Skill。安装到 Agent 客户端后，让 Agent 自己攻击自己——测试提示注入、工具滥用、数据泄露、权限提升、SSRF、供应链风险和基础设施暴露。

```bash
# 安装到 Agent
npx skills add https://github.com/503496348-ops/hermes-security-suite.git --skill agent-redteam
# 使用
帮我进行安全演习
```

**能力**:
- 🔍 **基础设施扫描**: AI服务指纹识别 + CVE匹配 (Ollama, vLLM, Dify 等 80+ 指纹)
- 📝 **代码审计**: Skill源码静态分析、MCP Server代码审计、依赖供应链检查
- 🎯 **动态测试**: 30+ 提示注入载荷，自适应变异（角色扮演、编码、多轮升级）
- 🔓 **越狱评估**: Parseltongue 编码引擎的 LLM 边界测试
- 🔗 **工作流攻击**: 多步任务链滥用、文档/RAG 间接注入
- 📊 **完整报告**: 严重性分级发现 + 证据链 + 防御验证 + 修复建议

### 4. Prompt Security (`prompt-security/`)

基于 DeepTeam 框架的提示词安全评估系统，支持模型API评估和一键越狱测试。

```bash
python cli_run.py --model "gpt-3.5-turbo" --base_url "https://api.openai.com/v1" \
  --api_key "your-key" --scenarios Bias --techniques PromptInjection
```

**能力**:
- 🧪 **13+ 评估场景**: Bias、Toxicity、Misinformation、PIILeakage、UnauthorizedAccess 等
- ⚔️ **18+ 单轮攻击算子**: Base64、ROT-13、Leetspeak、Emoji、Roleplay、Multilingual 等
- 🔄 **6+ 多轮攻击算子**: LinearJailbreaking、TreeJailbreaking、CrescendoJailbreaking 等
- 📊 **自定义数据集**: 支持 CSV/JSON/JSONL/TXT 格式

---

## 🏗️ 架构

```
┌──────────────────────────────────────────────────────┐
│                    RedTeam Module                      │
│                                                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐      │
│  │ Agent-Scan │  │  MCP-Scan  │  │ Agent-RT   │      │
│  │ 代码扫描   │  │ MCP审计    │  │ 一键演习   │      │
│  └────────────┘  └────────────┘  └────────────┘      │
│                                                        │
│  ┌────────────────────────────────────────────┐       │
│  │          Prompt Security                    │       │
│  │   模型评估 · 越狱测试 · 攻击算子库         │       │
│  └────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────┘
```

## 📁 目录结构

```
redteam/
├── agent-scan/          # Agent代码扫描工具
│   ├── main.py          # 入口
│   ├── core/            # 核心扫描引擎
│   ├── prompt/          # 提示词模板
│   └── tools/           # 扫描工具集
├── mcp-scan/            # MCP Server安全扫描
│   ├── main.py          # 入口
│   ├── agent/           # Agent核心实现
│   ├── tools/           # 工具模块
│   └── prompt/          # 提示词模板
├── agent-redteam/       # Agent安全演习Skill
│   ├── SKILL.md         # Skill定义
│   ├── modules/         # 攻击模块
│   │   ├── infra-attack/    # 基础设施攻击
│   │   ├── model-attack/    # 模型攻击
│   │   └── workflow-attack/ # 工作流攻击
│   ├── scripts/         # 辅助脚本
│   └── phases/          # 演习阶段定义
├── prompt-security/     # 提示词安全评估
│   ├── cli_run.py       # CLI入口
│   ├── deepteam/        # DeepTeam框架
│   ├── plugin/          # 插件系统
│   └── tests/           # 测试套件
└── README.md            # 本文档
```

## 🔗 数据源

RedTeam 模块复用以下数据源：
- **基础设施指纹**: 80+ AI服务指纹 (Ollama, vLLM, Dify, LangChain, Flowise 等)
- **漏洞规则**: CVE匹配 + 中英文漏洞规则库
- **评估数据集**: JailBench, JADE 3.0, ChatGPT-Jailbreak-Prompts 等公开benchmark
- **攻击算子**: 18+ 单轮 + 6+ 多轮攻击技术

---

> **AtomCollide-智械工坊** — 让AI安全可见、可测、可防
