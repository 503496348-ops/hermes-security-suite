# 【T0-学习文档-技能智造】白龙马医生（Hermes Doctor）技能设计手册 v1.0

> **版本**：v1.0 Hermes 框架重构版
>
> **生成日期**：2026-06-06
>
> **状态**：技能设计手册
>
> **定位**：面向 Hermes Agent 小白用户的智能体自诊断自愈 Skill 产品
>
> **设计哲学**：让 Hermes Agent 学会自己看病，像一位可靠、稳重、守边界的私人医生一样，先体检、再诊断、开药方、确认后修复、最后复盘沉淀
>
> **框架基础**：Hermes 插件框架、`.hermes-skill` manifest、主 `SKILL.md`、子 `skills/`、`agents/`、本地 CLI、药方库、病历库
>
> **设计参照**：Kubernetes 控制器模式、AWS Well-Architected Framework、Netflix Hystrix、Prometheus 告警体系、Git 版本化病历、TDD 红-绿-重构循环、Hermes Skill 插件化交付规范

## 一、产品概述

### 1.1 产品定位

白龙马医生（Hermes Doctor）是面向 Hermes Agent 用户的自诊断自愈 Skill 产品。

它不是皮皮虾医生的换皮，也不是 OpenClaw Doctor 的附属模块，而是基于 Hermes 自身框架重构的独立医生型 Skill。它负责诊断 Hermes 插件、Agent、工具调用、运行时、配置、日志、飞书消息路由等问题，并用小白能理解的方式输出健康报告、药方和修复计划。

**核心理念**：“让 Hermes 学会自己看病”。

白龙马医生不追求一上来就自动乱修，而是遵循一套稳定闭环：

```text
只读体检 → 结构化分诊 → 药方匹配 → 风险确认 → 最小修复 → 验证复查 → 病历沉淀
```

### 1.2 核心用户画像

| 维度 | 描述 |
|-|-|
| **技术背景** | 非开发者或轻技术用户，能复制命令、看懂简单报告，但不擅长读日志和配置 |
| **核心诉求** | “我的 Hermes Agent 出问题了，怎么知道哪里坏了、能不能安全修？” |
| **使用场景** | Hermes 插件安装、Skill 调试、工具调用失败、网页数据获取失败、飞书消息路由、日常巡检 |
| **典型痛点** | 看不懂报错、不知道目标目录、工具注册不清楚、怕修坏、同类问题反复出现 |
| **交付期待** | 一键体检、明确结论、药方步骤、风险说明、可验证结果、历史病历可查 |

### 1.3 四大核心特性

| 特性 | 说明 | 设计参照 |
|-|-|-|
| **自主化** | 主动发现 Hermes 插件结构、运行线索、日志和工具问题 | Kubernetes 控制器“观察-判断-行动”调和循环 |
| **自动化** | 自动匹配药方、生成修复计划、记录脱敏病历 | TDD 红-绿-重构循环的经验沉淀 |
| **自闭环** | 体检、诊断、处方、确认、验证、复盘一套走完 | AWS Well-Architected 持续改进闭环 |
| **零门槛** | 用小白语言解释严重度、影响范围、证据、风险和下一步 | 渐进式披露 UX 原则 |

### 1.4 为什么是现在做

白龙马医生必须回答“为什么现在立项”，否则评审会把它看成皮皮虾医生或 OpenClaw Doctor 的重复建设。当前立项窗口成立，来自三个触发条件：

| 触发条件 | 当前变化 | 立项意义 |
|-|-|-|
| **Hermes 框架成熟度** | Hermes 已形成插件化交付形态：`.hermes-skill`、主 `SKILL.md`、子 `skills/`、`agents/`、`scripts/`、`references/` 可以组合成完整技能包 | 医生能力可以直接嵌入 Hermes 框架，而不是靠外部文档或人工排查 |
| **用户痛点强度** | 小白用户开始真正使用 Hermes Agent，但最常见的问题集中在安装、路径、工具调用、日志、网页数据、飞书路由和权限确认 | 这些问题高频、可模式化、可药方化，适合先做自诊断自愈 |
| **竞品进度窗口** | 皮皮虾医生解决的是通用/ OpenClaw 医生形态，OpenClaw Doctor 偏 OpenClaw 生态；Hermes 缺少一个按自身框架组织的医生 Skill | 现在补位可以建立 Hermes 原生诊断标准，避免后续每个 Hermes 插件各自发明一套排障方式 |

结论：白龙马医生的必要性不在于“又做一个医生”，而在于把医生能力嵌进 Hermes 自己的插件生命周期里，形成 Hermes 原生的体检、药方、修复计划和病历标准。

## 二、能力架构

### 2.1 白龙马医生核心能力矩阵

| # | 能力模块 | 对标功能 | 优先级 | Hermes 实现形态 | 设计参照 |
|-|-|-|-|-|-|
| 1 | **全面体检** | Hermes 结构与运行状态检查 | P0 | `skills/hermes-check` + `scripts/hermes_doctor.py check` | AWS Well-Architected 五维评估 |
| 2 | **自动预警** | 日志/状态异常感知 | P0 | 读取日志关键词、健康评分、降级提示 | Prometheus Alertmanager 分级告警 |
| 3 | **药方库** | 高频故障点检索 | P0 | `references/prescriptions.md` + `match` 命令 | Stack Overflow 知识沉淀 |
| 4 | **自我修复** | 修复计划与确认门禁 | P0 | `skills/repair-plan` + 风险等级 L0-L3 | Kubernetes Reconcile Loop |
| 5 | **病历管理** | 诊断/修复记录沉淀 | P0 | `.doctor/cases` + `record/search` | Git 版本化记录 |
| 6 | **安全红线** | 防止越权与误修 | P1 | `references/safety_policy.md` | eBPF 动态安全检查思想 |
| 7 | **诊断逻辑** | 结构化排查路径 | P1 | `agents/diagnosis-agent.md` | 医学鉴别诊断 |
| 8 | **权限管控** | 授权、重启、安装、写入确认 | P1 | L0/L1/L2/L3 风险策略 | AWS IAM 最小权限 |
| 9 | **经验封装** | 将重复问题沉淀为 Skill/药方 | P1 | `skills/` 子能力 + 药方扩展 | Hermes Skill 插件规范 |
| 10 | **日常保健** | 定期体检与维护建议 | P1 | `check` + 基线评分 + 周期复查 | 预防性维护模式 |

### 2.2 Hermes 技能项目结构

白龙马医生必须遵循 Hermes 自身框架，而不是 OpenClaw/Codex Skill 的单一结构。

```text
hermes-doctor/
├── .hermes-skill/
│   ├── plugin.json              # Hermes 插件身份
│   └── marketplace.json         # Hermes 市场安装入口
├── SKILL.md                     # 主技能入口
├── README.md                    # 团队交付说明
├── USER_MANUAL.md               # 小白用户手册
├── agents/
│   ├── diagnosis-agent.md       # 诊断角色
│   ├── repair-agent.md          # 修复计划角色
│   └── case-agent.md            # 病历沉淀角色
├── skills/
│   ├── hermes-check/
│   ├── prescription-match/
│   ├── repair-plan/
│   ├── case-record/
│   ├── case-search/
│   └── feishu-route/
├── scripts/
│   └── hermes_doctor.py         # 本地 CLI 总入口
└── references/
    ├── prd_summary.md
    ├── prescriptions.md
    ├── safety_policy.md
    ├── output_formats.md
    ├── test_cases.md
    └── beginner_guide.md
```

## 三、工程执行框架

### 3.0 与同类产品对比表

为了避免评审者误解“白龙马医生 = 皮皮虾医生换皮”，本节明确三者边界。

| 对比维度 | 皮皮虾医生 | OpenClaw Doctor | 白龙马医生（Hermes Doctor） |
|-|-|-|-|
| **产品定位** | 面向小白用户的智能体医生概念与 PRD 样板 | 面向 OpenClaw/Codex/local agent 的自诊断 Skill 包 | 面向 Hermes Agent 的原生医生 Skill |
| **目标用户** | 泛智能体小白用户、社群试用者 | OpenClaw 使用者、Codex Skill 测试者、本地 agent 维护者 | Hermes 插件使用者、Hermes Agent 维护者、需要飞书路由的团队 |
| **技术框架** | 产品设计文档为主 | `openclaw-doctor/`，Codex Skill 风格：`SKILL.md` + `agents/openai.yaml` + scripts | `hermes-doctor/`，Hermes 框架：`.hermes-skill` + 主 `SKILL.md` + `skills/` + `agents/` + scripts |
| **诊断对象** | Agent 问题的抽象范式 | OpenClaw、Codex、Skill 包、Lark/Feishu、本地日志和依赖 | Hermes 插件 manifest、子 skills、agents、工具调用、运行时、日志、飞书消息路由 |
| **交付物** | PRD、手册、测试思路 | 可运行 Skill 包、README、USER_MANUAL、药方库、测试脚本 | Hermes 原生插件包、marketplace manifest、子 Skill、CLI、药方库、病历、飞书路由 |
| **核心差异** | 讲清“医生应该是什么” | 验证 OpenClaw/Codex 场景能跑通 | 建立 Hermes 生态自己的诊断与自愈标准 |
| **不能越界** | 不直接假设 Hermes 框架细节 | 不替 Hermes 插件定义框架规范 | 不伪装成 OpenClaw Doctor，不处理 OpenClaw 专属网关问题 |

白龙马医生的存在理由：Hermes 用户的问题不是抽象“Agent 坏了”，而是“这个 Hermes 插件为什么无法安装、触发、调用工具、读取数据、路由飞书消息”。因此它需要 Hermes 原生目录、命令、风险门禁和验收标准。

### 3.1 工程三要素 v2.0（五步门禁）

这是白龙马医生开发和交付的质量宪法。任何版本发布前，都必须逐项通过。

| 步骤 | 内容 | 通过标准 |
|-|-|-|
| **第一步** | Hermes 框架完整性验证 | `.hermes-skill`、`SKILL.md`、`agents/`、`skills/`、`scripts/`、`references/` 全部存在 |
| **第二步** | 测试环境三次验证 | `validate`、`check`、`match`、`plan`、`record/search`、`route` 均可重复通过 |
| **第三步** | 战场清扫 | 无 `__pycache__`、`.DS_Store`、临时授权图、明文 token、无关测试残留进入包 |
| **第四步** | PRD 交付规范 | 十大模块 + 第十一模块完整，P0/P1 功能和验收项写清楚 |
| **第五步** | 架构预见性检查 | 能支持未来 18 个月内的药方扩展、子 Skill 增加、飞书路由和自动巡检演进 |

### 3.2 三层质量防线

| 防线 | 执行动作 | 通过标准 | 设计参照 |
|-|-|-|-|
| **第一层：语法门** | Python CLI 语法与 import 自检 | 无 SyntaxError，无第三方依赖阻塞 | TDD 红阶段 |
| **第二层：API/外部调用门** | 所有外部调用必须有 timeout 或确认流程 | 不能无超时阻塞；不能静默联网安装 | Kubernetes Liveness/Readiness Probe |
| **第三层：功能门** | 运行 smoke tests 和结构化输出 | 产生报告、JSON、药方、修复计划、病历和路由结果 | Prometheus 指标暴露规范 |

### 3.3 健康评分与自适应阈值机制

白龙马医生的健康评分不是展示用数字，必须可复算、可解释、可回溯。

**评分公式：**

```text
Health Score = max(0, 100 - fail_count × 22 - warn_count × 10 - info_count × 2)
```

| 问题等级 | 扣分 | 判定示例 |
|-|-|-|
| `fail` | 22 分 | 缺少 `.hermes-skill/plugin.json`、manifest JSON 不合法、目标路径不存在 |
| `warn` | 10 分 | 缺少 marketplace、缺少子 Skill、命令不可用、日志含错误 |
| `info` | 2 分 | 配置提示、无日志、可选文档缺失、非阻塞建议 |

**状态判断：**

| 分数/条件 | 状态 | 行动 |
|-|-|-|
| 存在 `fail` 或分数 <60 | 严重异常 | 只报告，不自动修；优先生成修复计划 |
| 存在 `warn` 或分数 <90 | 需要处理 | 给出药方和下一步 |
| 无 `fail/warn` 且分数 ≥90 | 健康 | 保持当前状态，允许记录正反馈 |

**基线初始化：**

| 阶段 | 规则 |
|-|-|
| 首次运行，无历史数据 | 基线 = 当前第一次 `check` 分数，仅作为初始参考，不触发降级 |
| 历史样本 <3 次 | 基线 = 已有样本均值，预警只提示，不熔断 |
| 历史样本 3-9 次 | 基线 = 最近样本均值，可触发“需要关注”但不自动 blocked |
| 历史样本 ≥10 次 | 基线 = 最近 10 次同类体检均值，正式启用自适应阈值 |

| 指标 | 规则 | 设计参照 |
|-|-|-|
| **Health Score 基线** | 最近 10 次同类体检 HS 均值作为基线 | 移动平均线 |
| **异常信号** | 当前 HS 比基线低 ≥15 分，降级为只报告不自动修 | Netflix Hystrix 熔断 |
| **超出预期** | 当前 HS 比基线高 ≥10 分，记录正反馈病历 | 正向强化学习 |
| **故障重复度** | 同类修复连续失败 ≥3 次，标记 `blocked` | 熔断保护 |
| **药方封装阈值** | 同类问题重复出现 ≥3 次，进入药方库候选 | Skill 工程化沉淀 |

### 3.4 Skill 封装规范

| 触发条件 | 执行动作 | 设计参照 |
|-|-|-|
| 单次问题需要 ≥5 次工具调用 | 写入病历，标记 `[可封装]` 和 `[触发场景]` | Hermes Skill 子能力拆分 |
| 成功修复复杂错误 | 同步写入 `references/prescriptions.md` 候选药方 | Git commit/tag 机制 |
| 每周例行检查 | 检查 blocked/partial 病历，整理高频问题 | CronJob 定时巡检 |
| 用户反复问同一问题 | 优先查病历，再决定是否新增 Skill | 知识库检索模式 |

“反复问”判定阈值：同一用户或同一项目在 7 天内出现 ≥3 次相同药方 ID，或相同错误关键词相似度 ≥80% 且出现 ≥3 次，即视为重复问题；进入药方扩展或子 Skill 封装候选。

## 四、功能详细设计

### 4.1 P0 核心功能（必须实现）

**功能 1：全面体检**

- **入口**：`Hermes Doctor 体检`、`看看状态`、`health check`
- **执行**：检查 Hermes 插件 manifest、主 SKILL、子 skills、agents、scripts、references、日志、基础命令
- **输出**：结构化健康报告，包含通过项、警告项、异常项、药方、风险和下一步
- **命令**：

```bash
python3 scripts/hermes_doctor.py check --target . --format markdown
```

- **验收标准**：5 秒内返回；JSON 输出必须包含 `score`、`status`、`findings`、`passed_checks`
- **设计参照**：AWS Well-Architected Framework

**功能 2：自动预警**

- **触发**：体检发现日志错误、结构缺失、工具不可用、连续失败或低于健康基线
- **执行**：异常感知 → 分级 → 输出下一步
- **输出**：健康报告中的 warning/fail，以及飞书路由可转发的摘要
- **熔断**：同类问题连续 3 次修复失败，降级为仅报告 + 人工复核
- **设计参照**：Prometheus Alertmanager、Netflix Hystrix

**功能 3：药方库查询**

- **入口**：`报错了`、`出错了`、`fetch failed`、`unknown tool`、`找不到模块`
- **执行**：检索 Hermes 高频故障药方
- **输出**：问题定位、小白解释、修复步骤、风险等级
- **命令**：

```bash
python3 scripts/hermes_doctor.py match --text "Hermes fetch failed timeout 访问不到网页"
```

- **首期药方覆盖**：首期必须落地具体药方，而不是只列类目。P0 首期至少包含以下 12 条：

| 药方 ID | 症状关键词 | 小白诊断 | 安全处方 | 风险 |
|-|-|-|-|-|
| RX-HERMES-001 | `.hermes-skill`, `plugin.json`, `manifest missing` | Hermes 插件身份文件缺失，项目无法被 Hermes 识别。 | 补充 `.hermes-skill/plugin.json`，写入前展示内容。 | L1 |
| RX-HERMES-002 | `JSONDecodeError`, `invalid json` | manifest 格式坏了，不是 Hermes 本身坏了。 | 用 JSON 解析定位行列，最小修改修复格式。 | L1 |
| RX-HERMES-003 | `缺少 agents`, `角色边界不清` | 诊断、修复、病历角色没拆开，后续容易乱修。 | 补充 diagnosis/repair/case agent 文档。 | L1 |
| RX-HERMES-004 | `缺少 skills`, `子 Skill`, `触发失败` | 子能力没有拆分，Hermes 不知道什么时候调用哪项能力。 | 补齐 `skills/<name>/SKILL.md`。 | L1 |
| RX-HERMES-005 | `scripts`, `CLI`, `command not found` | 缺少本地执行入口或命令不可用。 | 补充 CLI；安装依赖前必须确认。 | L1/L2 |
| RX-RUNTIME-001 | `fetch failed`, `访问不到`, `timeout` | 网页数据获取链路失败，可能是网络、代理、平台限制或解析问题。 | 区分“访问不到”和“打开了但取不到”；不绕过登录、验证码、反爬或限流。 | L0/L2 |
| RX-RUNTIME-002 | `playwright`, `chromium`, `screenshot`, `vision` | 浏览器或视觉链路异常。 | 只读检查依赖和截图日志；安装浏览器依赖前确认。 | L2 |
| RX-TOOL-001 | `unknown tool`, `tool not found`, `工具调用失败` | Hermes 调用了未注册或名称不一致的工具。 | 对照工具注册表和调用名；修配置或代码前展示 diff。 | L1/L2 |
| RX-DEP-001 | `ModuleNotFoundError`, `No module named`, `找不到模块` | Python 依赖缺失或解释器环境不对。 | 确认解释器和环境；安装前展示命令并确认。 | L2 |
| RX-FILE-001 | `No such file`, `ENOENT`, `找不到路径` | 命令找不到目标路径。 | 先确认当前目录和绝对路径；创建目录前确认。 | L0/L1 |
| RX-SAFETY-001 | `token`, `cookie`, `password`, `private key` | 输入或日志含敏感信息。 | 立即脱敏；不写入群聊或病历原文。 | L3 |
| RX-FEISHU-003 | `帮我修一下`, `自愈`, `飞书消息` | 飞书消息涉及修复，不能直接执行。 | 生成修复计划，等待用户确认。 | L2 |

- **设计参照**：Stack Overflow 知识沉淀与检索

**功能 4：自我修复（PCEC 引擎）**

- **触发**：用户说 `帮我修一下`、`自愈`、`怎么修`
- **执行**：Perceive → Classify → Execute Plan → Check
- **注意**：P0 阶段只生成修复计划，不直接执行修复
- **命令**：

```bash
python3 scripts/hermes_doctor.py plan --text "unknown tool 工具调用失败"
```

- **安全**：写文件、安装依赖、授权、重启、修改配置前必须确认；删除、覆盖、reset、读取秘密信息默认 L3，不自动执行
- **设计参照**：Kubernetes 控制器调和循环

**功能 5：病历管理**

- **存储**：`.doctor/cases/*.md`
- **写入入口**：修复尝试后、诊断有价值时、问题被阻塞时
- **查询入口**：`上次这个问题怎么处理的？`
- **命令**：

```bash
python3 scripts/hermes_doctor.py record --title "fetch failed" --status partial --summary "diagnosis summary"
python3 scripts/hermes_doctor.py search --query "fetch"
```

- **安全**：写入前自动脱敏 token、cookie、password、private key。这里的“脱敏”只处理用户主动贴出的报错、日志摘要或修复总结；不得主动读取 `.env`、浏览器 session、cookie 文件、私钥文件或系统钥匙串。
- **设计参照**：Git 版本化病历

### 4.2 P1 增强功能（逐步实现）

P1 默认安全策略：所有增强功能默认按 **L0 只读/只报告** 执行。只有当用户明确说“动手修”“帮我改”“执行这个修复”时，才允许升级到 L1+；升级后必须展示影响范围、目标文件/命令、验证方式和回滚方式。

**全局风险等级矩阵：**

| 风险等级 | 定义 | 允许动作 | 必须确认 | 禁止事项 |
|-|-|-|-|-|
| **L0 只读** | 不写文件、不联网安装、不授权、不重启 | 读取公开项目文件、列目录、解析非敏感日志、生成报告 | 否 | 读取 `.env` 内容、读取 cookie/token/private key |
| **L1 低风险写入** | 写入医生项目自身文档、药方、病历、非敏感配置 | 新增/修改 README、references、case note、子 Skill 文档 | 是，需展示路径和内容摘要 | 覆盖用户业务文件、写入明文秘密 |
| **L2 中风险操作** | 安装依赖、授权、重启、改运行配置、修改工具注册 | pip/npm 安装、auth login、修改 manifest、重启本地服务 | 是，需展示命令、影响范围、验证方式、回滚方案 | 静默执行、无 timeout 外部调用 |
| **L3 高风险操作** | 删除、覆盖、reset、读取秘密、绕过平台保护 | 默认只给人工计划 | 必须精确确认动作；通常不执行 | `rm -rf`、`git reset --hard`、读取密钥、绕过登录/验证码/限流 |
 
**升级冲突仲裁规则：** 同一动作被多个规则命中时，取最高风险等级。例如“写入药方”是 L1，但如果药方内容包含 token 原文，则升级 L3 并禁止写入原文；“日常保健”默认 L0，但创建 cron 任务升级 L2。

| 功能 | 入口关键词 | 核心价值 | 默认风险 | 升级条件 | 设计参照 |
|-|-|-|-|-|-|
| **安全红线** | `安全吗？`、`有没有风险？` | 防止自我损坏、越权、泄密 | L0 | 用户要求写入安全策略或更新规则时升级 L1 | eBPF 动态安全检查 |
| **诊断逻辑** | `帮我分析一下`、`什么情况？` | 结构化排查 Hermes 运行链路 | L0 | 用户要求修改诊断脚本或配置时升级 L1/L2 | 医学鉴别诊断 |
| **权限管控** | `谁能做？`、`需要授权吗？` | 区分只读、写入、安装、授权、重启、删除 | L0 | 用户要求发起授权、改权限或重启服务时升级 L2 | AWS IAM 最小权限 |
| **经验封装** | `这个能不能做成 Skill？` | 高频修复流程工程化 | L0 | 用户确认写入新子 Skill 或药方时升级 L1 | Hermes Skill 规范 |
| **日常保健** | `日常怎么维护？`、`怎么保养？` | 定期体检、药方更新、病历复盘 | L0 | 用户要求创建定时任务、安装依赖或修改配置时升级 L2 | 预防性维护 |
| **专科门诊** | `复杂问题`、`疑难杂症` | 深入日志、工具链、浏览器链路、飞书路由排查 | L0 | 用户要求执行修复、安装浏览器依赖、改工具注册时升级 L2/L3 | 医院专科会诊 |

## 五、工程执行计划

| Phase | 内容 | 输入 | 输出 |
|-|-|-|-|
| **Phase 1** | P0 核心功能开发 | 本设计手册评审通过 | Hermes manifest + 6 个子 Skill + CLI + 药方库 + 测试日志 |
| **Phase 2** | P1 增强功能开发 | Phase 1 smoke tests 通过 | 安全红线、权限管控、经验封装、日常保健模块 |
| **Phase 3** | 飞书/Lark 接入与团队试用 | Phase 2 验证通过 | 飞书消息路由、团队试用包、病历样例、生产验证报告 |
| **Phase 4** | 自动巡检与药方扩展 | 试用反馈和病历库 | 高频故障药方扩展、健康基线、预警策略 |

Phase 1 必须额外通过“小白可用性门禁”：邀请 5 个非开发者或轻技术用户，在不看开发者说明的前提下完成 5 个核心场景，整体完成率 ≥80%。核心场景包括：体检、报错匹配、生成修复计划、查询病历、飞书消息路由。

### 5.1 系统接入层定位

白龙马医生分为三层，避免“小白入口”和“开发者命令”混在一起。

| 层级 | 职责 | 用户 |
|-|-|-|
| **自然语言入口层** | 接收“体检、报错了、帮我修、查病历”等自然语言，负责意图识别 | 小白用户、飞书群用户 |
| **系统接入层** | 将自然语言转换为 Hermes Doctor CLI 命令，处理路径、Python 环境、Windows 编码、中文引号、权限确认 | Hermes Agent / Feishu Bot / 包装命令 |
| **CLI 执行层** | 执行 `check/match/plan/record/search/route/validate/test`，输出结构化结果 | 开发者、测试人员、接入层 |

边界：小白用户不应该直接面对 `python3 scripts/hermes_doctor.py ...`；这类命令用于开发验证和系统接入层调用。正式交互应是“白龙马医生，帮我体检”。

### 5.2 边界判定规则

| 问题类型 | 是否归白龙马医生 | 处理方式 |
|-|-|-|
| Hermes 插件 manifest、skills、agents、scripts、references 缺失 | 是 | 体检 + 药方 + 修复计划 |
| Hermes 工具调用失败、unknown tool、路由失败 | 是 | 药方匹配 + 工具注册检查 |
| Hermes 网页数据获取失败 | 是 | 区分网络、平台限制、浏览器链路、解析链路 |
| OpenClaw 网关、OpenClaw Core API 专属问题 | 否 | 转给 OpenClaw Doctor |
| 皮皮虾医生 PRD 或产品文档问题 | 否 | 转给皮皮虾医生文档维护流程 |
| 用户要求绕过登录、验证码、反爬、限流 | 否 | 拒绝绕过，只给合规排查建议 |
| 用户粘贴 token/cookie/password/private key | 只处理脱敏 | 立即脱敏，不写入原文，不回显 |

### 5.3 技术可行性说明

| 能力 | 当前可行性 | 依据 | 风险 |
|-|-|-|-|
| Hermes 插件结构体检 | 高 | 文件系统可读，manifest JSON 可解析 | 目标目录选错会误报 |
| 药方匹配 | 高 | 文本关键词和药方库可本地匹配 | 未知错误需要人工补药方 |
| 修复计划生成 | 高 | 只生成计划，不执行修复 | 计划质量依赖药方准确度 |
| 病历记录/搜索 | 高 | 本地 Markdown 文件即可实现 | 必须严格脱敏 |
| 飞书消息路由 | 中 | 文本路由本地可做，真实飞书事件接入需独立 Bot 层 | 权限、身份、群消息隐私 |
| 自动预警 | 中 | 可基于体检和日志实现，长期定时需要调度器 | 误报、频率控制 |
| 自动修复 | 低到中 | L1 可控，L2/L3 需确认和回滚 | 越权、破坏、环境差异 |

## 六、用户交互设计

### 6.1 触发方式

| 触发类型 | 示例 | 处理方式 |
|-|-|-|
| **主动触发** | `Hermes Doctor 体检一下`、`看看状态` | 执行全面检查，输出健康报告 |
| **被动触发** | `报错了`、`出问题了`、贴日志 | 检索药方库，给出诊断与修复建议 |
| **修复触发** | `帮我修一下`、`自愈` | 生成修复计划，不直接执行 |
| **询问触发** | `上次这个问题怎么处理的？` | 查询病历，返回历史处理记录 |
| **飞书触发** | `Hermes Doctor 帮我修一下：fetch failed` | 路由为本地 CLI 动作，涉及修复时要求确认 |

### 6.2 输出示例

```text
🐉 白龙马医生 - Hermes 健康报告

✅ 通过项（6）
  - Hermes plugin manifest：正常
  - marketplace.json：正常
  - 主 SKILL.md：存在
  - 子 skills：完整
  - agents：完整
  - 本地 CLI：可执行

⚠️ 警告项（1）
  - 最近日志出现 fetch failed timeout
  → 药方：RX-RUNTIME-001
  → 建议：先区分“访问不到”和“打开了但取不到”

❌ 异常项（0）
  - 暂无

📊 健康评分：90/100
状态：需要关注
下一步：运行药方匹配并生成修复计划；涉及配置修改前先确认。
```

### 6.3 飞书消息路由示例

```bash
python3 scripts/hermes_doctor.py route \
  --text "Hermes Doctor 帮我修一下：fetch failed timeout" \
  --format json
```

注意：上面的命令用于开发者验证，不应作为小白用户的第一交互入口。小白用户优先使用自然语言：

```text
白龙马医生，帮我修一下：fetch failed timeout
```

系统接入层负责处理 Python 命令路径、Windows/Python Launcher 差异、中文引号和编码问题。若必须让小白本地执行命令，安装脚本应提供 `bailongma-doctor` 或 `hermes-doctor` 包装命令，避免暴露 `python3 hermes-doctor/scripts/hermes_doctor.py ...` 这种路径细节。

预期输出：

```json
{
  "intent": "repair_plan",
  "action": "generate_repair_plan",
  "confirmation_required": true
}
```

## 七、安装与零门槛配置

### 7.1 一键初始化流程

用户只需说：

```text
白龙马医生，我要体检
```

系统自动执行：

```text
解析目标 Hermes 项目 → 读取 .hermes-skill/plugin.json → 检查 SKILL.md/skills/agents/scripts/references → 扫描日志 → 输出健康报告
```

本地命令：

```bash
python3 hermes-doctor/scripts/hermes_doctor.py validate --target hermes-doctor
python3 hermes-doctor/scripts/hermes_doctor.py check --target hermes-doctor
python3 hermes-doctor/scripts/hermes_doctor.py test --target hermes-doctor
```

### 7.1.1 包装命令安装方法

为避免小白用户处理 `python3`、路径、中文引号和 Windows 编码问题，正式包应提供包装命令。

**macOS / Linux：**

```bash
cd hermes-doctor
chmod +x scripts/hermes_doctor.py
ln -s "$(pwd)/scripts/hermes_doctor.py" /usr/local/bin/bailongma-doctor
```

使用：

```bash
bailongma-doctor check --target .
bailongma-doctor match --text "fetch failed timeout"
```

**Windows：**

提供 `bailongma-doctor.cmd`：

```bat
@echo off
py "%~dp0scripts\hermes_doctor.py" %*
```

使用：

```bat
bailongma-doctor check --target .
```

验收标准：包装命令存在时，小白文档优先展示 `bailongma-doctor`，开发者文档才展示 `python3 scripts/hermes_doctor.py`。

### 7.2 小白引导文案（严格按 P0 功能编写）

```text
🐉 白龙马医生已上线！我是你的 Hermes Agent 医生。

以后你可以这样叫我：

"体检" → 全面检查你的 Hermes 插件
"报错了" → 我帮你找原因、匹配药方
"帮我修一下" → 我先给修复计划，等你确认再动手
"上次怎么处理" → 我帮你查历史病历

我不会偷看 token、cookie、密码或私钥。
涉及写文件、安装依赖、授权、重启、改配置，我都会先问你。
```

## 八、子 Agent 质量监控机制

### 8.1 五大门禁检查项

| 门禁 | 检查内容 | 通过条件 |
|-|-|-|
| **G1：PRD 评审门禁** | 十大模块 + 第十一模块完整性 | 全部模块有实质内容 |
| **G2：Hermes 框架门禁** | `.hermes-skill`、`SKILL.md`、`skills/`、`agents/`、`scripts/`、`references/` | 结构完整，manifest JSON 合法 |
| **G3：功能验证门禁** | validate/check/match/plan/record/search/route/test | 一键 smoke tests 全部通过 |
| **G4：安全边界门禁** | `.env` 不读取、病历脱敏、L3 不自动执行 | 不泄密、不越权、不绕过平台保护 |
| **G5：小白可用性门禁** | 5 个非开发者实测 5 个核心场景 | 无开发者引导时完成率 ≥80%，失败点必须写入改进清单 |

### 8.2 质量预警信号

- 单次测试失败 → 记录病历 + 输出告警
- 连续三次失败 → 熔断 + 标记 blocked
- 发现明文 token/cookie/password/private key → 立即脱敏，不写入群聊
- `check` 健康评分低于基线 15 分 → 降级为只报告
- `check` 健康评分高于基线 10 分 → 记录正反馈

## 九、系统能力演进概览

| 时间维度 | 过去（v0.x） | 现在（v1.0） | 未来（v2.0） |
|-|-|-|-|
| **诊断能力** | 靠人工读日志 | Hermes 框架体检 + 药方匹配 + 结构化报告 | 预测性维护和自动巡检 |
| **自愈能力** | 无安全门禁 | 修复计划 + L0-L3 风险确认 | 低风险自动修复，高风险人工批准 |
| **知识沉淀** | 零散记录 | 脱敏病历 + 药方库 | 药方自扩展和团队知识库同步 |
| **用户体验** | 命令分散、文档复杂 | 小白引导 + 飞书路由 + 一键测试 | 自然语言全流程交互 |
| **药方库规模** | 无 | 首期覆盖 Hermes 高频问题 | 扩展到 100+ Hermes/工具链故障点 |
| **安全性** | 靠用户谨慎 | `.env` 不读、秘密脱敏、L3 禁止自动执行 | 自适应安全策略和权限审计 |
| **工程交付** | 手工散件 | Hermes 插件包 + zip 验证 | 市场化安装和版本升级机制 |

## 十、验收分级与改进清单

本项目只使用一套优先级命名，避免“必改/建议改/小问题”和 P0/P1/P2 混用。

| 优先级 | 定义 | 处理时限 | 当前状态 |
|-|-|-|-|
| **P0 必改** | 不补会影响立项、评审通过或安全边界 | 进入评审前必须完成 | 已补齐 6 项 |
| **P1 应改** | 不补会影响可落地性、可测试性或团队接入 | Phase 1 结束前完成 | 已补齐 4 项 |
| **P2 可改** | 不影响立项，但影响小白体验或长期维护 | Phase 2 前完成 | 已补齐 2 项 |

### 10.1 P0 必改闭环

| # | 问题 | 修正位置 | 状态 |
|-|-|-|-|
| 1 | 第十一模块位置错乱 | `十一、系统能力演进分析（第十一模块）` | ✅ 已补独立章节 |
| 2 | 健康评分公式没写 | `3.3 健康评分与自适应阈值机制` | ✅ 已补公式、扣分、状态、基线初始化 |
| 3 | 首期药方只列类目 | `4.1 功能 3：药方库查询` | ✅ 已补 12 条具体药方 |
| 4 | L0/L1/L2/L3 风险矩阵缺失 | `4.2 全局风险等级矩阵` | ✅ 已补定义、动作、确认、禁止事项 |
| 5 | 自动脱敏和 `.env` 不读取边界冲突 | `4.1 功能 5：病历管理` | ✅ 已说明只脱敏用户主动贴出的文本，不主动读秘密文件 |
| 6 | 三审三校审计方法空 | `三审三校最终审计报告` | ✅ 已补审计证据列 |

### 10.2 P1 应改闭环

| # | 问题 | 修正位置 | 状态 |
|-|-|-|-|
| 1 | 系统接入层定位模糊 | `5.1 系统接入层定位` | ✅ 已补三层结构 |
| 2 | 边界判定规则缺 | `5.2 边界判定规则` | ✅ 已补归属/转诊/拒绝规则 |
| 3 | 技术可行性没写 | `5.3 技术可行性说明` | ✅ 已补能力、可行性、依据、风险 |
| 4 | 反复问判定阈值缺 | `3.4 Skill 封装规范` | ✅ 已补 7 天 3 次或相似度 ≥80% 规则 |

### 10.3 P2 可改闭环

| # | 问题 | 修正位置 | 状态 |
|-|-|-|-|
| 1 | 包装命令安装方法缺 | `7.1.1 包装命令安装方法` | ✅ 已补 macOS/Linux 与 Windows 方案 |
| 2 | 升级冲突仲裁缺 | `4.2 升级冲突仲裁规则` | ✅ 已补多规则命中取最高风险 |

## 十一、系统能力演进分析（第十一模块）

第十一模块是独立的架构预见性检查，不等同于第九章的概览表。它回答：白龙马医生未来 18 个月会怎样扩展，哪些设计今天必须预留。

| 维度 | 当前 v1.0 设计 | 未来 6 个月 | 未来 18 个月 | 当前必须预留 |
|-|-|-|-|-|
| **药方库** | 首期 12 条 P0 药方 | 扩展到 50 条 Hermes 高频故障 | 扩展到 100+ 条跨插件故障 | 药方 ID、症状、诊断、处方、风险字段必须稳定 |
| **病历库** | 本地 `.doctor/cases/*.md` | 支持按项目/用户/药方 ID 归档 | 支持同步团队知识库 | 病历必须脱敏、可迁移、可搜索 |
| **飞书接入** | 本地 route 文本路由 | 接入真实 Feishu Bot 事件 | 支持群/私聊分级权限 | 路由输出必须结构化，修复意图必须带确认标记 |
| **自动修复** | 只生成计划 | L1 低风险写入可半自动 | L2 需确认后执行，L3 默认人工计划 | 风险矩阵和升级仲裁必须在 v1.0 固化 |
| **小白体验** | 文档和自然语言入口 | 包装命令 + 安装脚本 | 完全自然语言交互 | 系统接入层不能把 CLI 复杂度暴露给小白 |
| **安全策略** | 不读 `.env`，不回显秘密 | 增加 secret scanner | 增加权限审计和操作留痕 | 脱敏边界必须清楚，不能主动读取秘密文件 |
| **生态边界** | 区分皮皮虾/OpenClaw/Hermes | 建立跨医生转诊规则 | 形成医生 Skill 生态 | 边界判定表必须进入 PRD |

第十一模块通过标准：未来扩展不能推翻当前 Hermes 目录结构、药方字段、风险等级、病历格式和飞书路由结构；如果未来需要改动，必须提供兼容迁移方案。

## 十二、交付物清单

| 文件/目录 | 状态 | 说明 |
|-|-|-|
| `.hermes-skill/plugin.json` | ✅ 已设计 | Hermes 插件身份 |
| `.hermes-skill/marketplace.json` | ✅ 已设计 | Hermes 市场入口 |
| `SKILL.md` | ✅ 已设计 | 主技能入口 |
| `agents/diagnosis-agent.md` | ✅ 已设计 | 诊断角色 |
| `agents/repair-agent.md` | ✅ 已设计 | 修复计划角色 |
| `agents/case-agent.md` | ✅ 已设计 | 病历角色 |
| `skills/hermes-check/` | ✅ 已设计 | 全面体检 |
| `skills/prescription-match/` | ✅ 已设计 | 药方匹配 |
| `skills/repair-plan/` | ✅ 已设计 | 修复计划 |
| `skills/case-record/` | ✅ 已设计 | 病历写入 |
| `skills/case-search/` | ✅ 已设计 | 病历查询 |
| `skills/feishu-route/` | ✅ 已设计 | 飞书消息路由 |
| `scripts/hermes_doctor.py` | ✅ 已设计 | 本地 CLI |
| `references/prescriptions.md` | ✅ 已设计 | 药方库 |
| `references/safety_policy.md` | ✅ 已设计 | 安全策略 |
| `references/test_cases.md` | ✅ 已设计 | 验收清单 |
| `README.md` | ✅ 已设计 | 团队交付说明 |
| `USER_MANUAL.md` | ✅ 已设计 | 小白使用说明 |
| `hermes-doctor-v0.1.1.zip` | ✅ 已产出 | 团队测试包 |

## 三审三校最终审计报告

### 审计结论：✅ 通过，已达到 Hermes Skill v1.0 可交付设计标准

| 审计项 | 结论 | 审计证据 | 说明 |
|-|-|-|-|
| **格式复刻** | ✅ 通过 | 标题元信息 + 一至十二章 + 三审三校报告 | 已按皮皮虾医生 PRD 的模块结构重写，并补独立第十一模块 |
| **产品边界** | ✅ 通过 | `3.0 与同类产品对比表` | 明确白龙马医生是 Hermes 独立 Skill，不是皮皮虾医生附属模块 |
| **市场时机** | ✅ 通过 | `1.4 为什么是现在做` | 补充 Hermes 框架成熟度、用户痛点强度、竞品进度三项理由 |
| **P0 功能完整性** | ✅ 通过 | `4.1 P0 核心功能` | 体检、预警、药方、自愈计划、病历全部覆盖 |
| **具体药方** | ✅ 通过 | `4.1 功能 3` 的 12 条药方表 | 不再只列类目，已给 ID、症状、诊断、处方、风险 |
| **健康评分** | ✅ 通过 | `3.3 健康评分与自适应阈值机制` | 已给扣分公式、状态判断、基线初始化 |
| **Hermes 框架适配** | ✅ 通过 | `2.2 Hermes 技能项目结构` | 使用 `.hermes-skill`、`SKILL.md`、`skills/`、`agents/`、`scripts/`、`references/` |
| **风险等级矩阵** | ✅ 通过 | `4.2 全局风险等级矩阵` | 已列 L0/L1/L2/L3 定义、动作、确认、禁止事项 |
| **脱敏边界** | ✅ 通过 | `4.1 功能 5` + `8.1 G4` | 脱敏仅处理用户主动贴出的文本，不主动读取 `.env` 或秘密文件 |
| **系统接入层** | ✅ 通过 | `5.1 系统接入层定位` | 小白入口、接入层、CLI 层分离 |
| **边界判定规则** | ✅ 通过 | `5.2 边界判定规则` | 明确 Hermes / OpenClaw / 皮皮虾 / 平台保护的转诊边界 |
| **技术可行性** | ✅ 通过 | `5.3 技术可行性说明` | 已列能力、可行性、依据和风险 |
| **反复问阈值** | ✅ 通过 | `3.4 Skill 封装规范` | 7 天内 ≥3 次同药方或相似度 ≥80% 视为重复问题 |
| **包装命令安装** | ✅ 通过 | `7.1.1 包装命令安装方法` | 已补 macOS/Linux 和 Windows 包装方式 |
| **升级冲突仲裁** | ✅ 通过 | `4.2 升级冲突仲裁规则` | 多规则命中时取最高风险等级 |
| **小白可用性** | ✅ 通过 | `8.1 G5` | 要求 5 人 5 场景，无开发者引导完成率 ≥80% |
| **工程验收** | ✅ 通过 | `十二、交付物清单` + 命令验收路径 | 包含 validate/check/match/plan/record/search/route/test |

最终判断：白龙马医生（Hermes Doctor）v1.0 可以作为 Hermes Agent 自诊断自愈 Skill 的正式设计手册，用于团队评审、后续开发、测试包交付和飞书文档发布。
