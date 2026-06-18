# Hermes Doctor v0.1.3

Hermes Doctor 是一个基于 Hermes 自身插件框架重构的 Agent 自诊断与安全自愈项目。它的功能目标对齐皮皮虾医生 PRD：体检、分诊、药方、修复计划、确认、验证、病历沉淀。

---

## 🚀 快速开始（小白版 · 5 步走通）

> 如果你第一次用 Hermes Doctor，**按顺序**跑完这 5 步就行。每步有预期输出，对得上就过。

### Step 1：下载

二选一：

**A. 下载 zip（推荐给非开发者）**

打开 https://github.com/503496348-ops/hermes-doctor/releases ，下载最新的 `hermes-doctor-*.zip` 到 `~/Downloads/`，**双击解压**。

> ⚠️ 不要用命令行 `unzip` —— macOS 自带 unzip 对中文文件名有 bug，请用系统 Archive Utility（双击 zip 就是）。

**B. git clone（推荐给开发者）**

```bash
git clone --branch v0.1.3 https://github.com/503496348-ops/hermes-doctor.git
```

解压或 clone 完之后，**目录里会有一个 `hermes-doctor-0.1.3/`（zip 解压） 或 `hermes-doctor/`（git clone）文件夹**。

### Step 2：进入项目目录

```bash
cd ~/Downloads/hermes-doctor-0.1.3   # 如果是 zip 解压
# 或者
cd ~/hermes-doctor                   # 如果是 git clone
```

**怎么验证进对了？** 跑 `ls` 应该能看到 `SKILL.md`、`scripts/`、`references/` 等文件。

### Step 3：第一次体检

**macOS / Linux**：

```bash
python3 scripts/hermes_doctor.py check --target .
```

**Windows**：

```bat
python scripts\hermes_doctor.py check --target .
```

**预期输出**（截取关键行）：

```text
Hermes Doctor 诊断报告

健康评分：100/100
状态：健康
```

看到 `100/100` 就说明体检通过 ✅。

> ⚠️ 如果提示 `python3: command not found`（macOS 自带 Python 2 时常见）：改用 `python scripts/hermes_doctor.py ...`。
> ⚠️ 如果提示 `No such file or directory`：说明没在项目目录里，回去看 Step 2。

### Step 4：装全局命令 `bailongma-doctor`（可选但推荐）

跑完 Step 3 后，你还要每次都 `cd` 到项目目录才能用命令，太麻烦。把 `bailongma-doctor` 装到全局，**以后任何目录都能直接用**：

**macOS / Linux**：

```bash
chmod +x scripts/bailongma-doctor scripts/hermes_doctor.py
ln -s "$(pwd)/scripts/bailongma-doctor" /usr/local/bin/bailongma-doctor
```

**Windows**（以管理员身份运行 PowerShell）：

```powershell
# 把 hermes-doctor 路径加到系统 PATH 环境变量
# 或者把 scripts\bailongma-doctor.cmd 复制到 C:\Windows\
```

装完后，**新开一个终端**（必须！），跑：

```bash
bailongma-doctor check --target .
```

应该跟 Step 3 输出一模一样。✅

### Step 5：飞书怎么用（如果你用飞书跟 Hermes 沟通）

Hermes Doctor 监听**自然语言触发词**，在飞书 bot 里说：

```text
白龙马医生 体检一下
白龙马医生 报错了：fetch failed timeout
白龙马医生 帮我修一下：unknown tool
白龙马医生 上次这个问题怎么处理
```

**白龙马医生** 就是 Hermes Doctor 的飞书 bot 名字。直接跟它说话就行，**不用**自己跑命令。

> 飞书触发前缀支持：`白龙马医生` / `@白龙马医生` / `Hermes Doctor` / `hermes doctor` / `Hermes医生` / `hermes医生` / `@Hermes Doctor`，大小写都行。

---

## 📋 常用命令速查

| 你想做什么 | 跑这个（macOS / Linux）| 跑这个（Windows） |
|---|---|---|
| 体检当前项目 | `bailongma-doctor check --target .` | `bailongma-doctor.cmd check --target .` |
| 把报错贴上去匹配药方 | `bailongma-doctor match --text "你的报错"` | `bailongma-doctor.cmd match --text "你的报错"` |
| 生成修复计划（不直接执行） | `bailongma-doctor plan --text "你的问题"` | `bailongma-doctor.cmd plan --text "你的问题"` |
| 验证安装是否正确 | `bailongma-doctor validate --target .` | `bailongma-doctor.cmd validate --target .` |
| 跑一键 smoke tests | `bailongma-doctor test --target .` | `bailongma-doctor.cmd test --target .` |

**预期输出格式**：见 `references/output_formats.md`。

---

## ❓ 踩坑 FAQ

### Q1: `python3: command not found` 怎么办？
macOS 上常见。改用 `python`（不带 3）试一次。如果还不行，确认 Python 3.8+ 已安装：终端跑 `python3 --version`，应该输出 `Python 3.x.x`。

### Q2: 双击 zip 解压后，跑命令提示 "找不到 hermes-doctor 文件"？
你可能没在解压出来的目录里跑。`cd` 到解压目录（名字一般是 `hermes-doctor-0.1.3`）。

### Q3: `bailongma-doctor check --target .` 报 "Permission denied"？
需要先 `chmod +x`（macOS / Linux）。看 Step 4 第一条命令。

### Q4: `bailongma-doctor: command not found` 装完全局后还是报这个？
**新开一个终端**再试。环境变量是会话级的，老终端看不到 `ln -s` 的效果。

### Q5: 体检 100/100 之后我该做什么？
**什么都不用做**。100/100 表示项目健康。但建议**保留体检报告**，对比下次体检看是否有回退。

### Q6: 体检分数 < 100 但不是 fail 怎么办？
看 `发现的问题` 列表。按每条 `药方` 的 `建议修复` 走。涉及 `L1/L2/L3`（写入/安装/重启/删除）的动作，doctor **不会自动做**——会先给计划，等你确认。

### Q7: 飞书里跟白龙马医生说话没反应？
检查：1) bot 是否在群里被 @了；2) 触发词是否完整（必须以"白龙马医生"或"Hermes Doctor"开头）；3) 群是否启用了 bot。

### Q8: `validate` 报 `FAIL missing required files` 怎么办？
**别慌**。这说明目录结构不完整，**不要手动补文件**。重新解压 / 重新 clone 一遍。

### Q9: macOS 命令行 `unzip hermes-doctor.zip` 报 "write error / fchmod error"？
**不要用命令行 unzip**！macOS 的命令行 unzip 对中文文件名有 bug。请用**双击 zip**（系统 Archive Utility）解压。

### Q10: 想看完整药方库和风险策略？
- 药方库：`references/prescriptions.md`（21 条）
- 风险等级矩阵：`references/safety_policy.md`（L0-L3）
- PRD 摘要：`references/prd_summary.md`

---

## 📁 目录结构

```text
hermes-doctor/
  .hermes-skill/
    plugin.json                    # Hermes 插件身份
    marketplace.json               # Hermes 市场入口
  SKILL.md                         # 主技能入口
  agents/
    diagnosis-agent.md             # 诊断角色
    repair-agent.md                # 修复计划角色
    case-agent.md                  # 病历角色
  skills/
    hermes-check/                  # 全面体检
    prescription-match/            # 药方匹配
    repair-plan/                   # 修复计划
    case-record/                   # 病历写入
    case-search/                   # 病历查询
    feishu-route/                  # 飞书消息路由
  scripts/
    hermes_doctor.py               # 本地 CLI 总入口
    bailongma-doctor               # macOS/Linux 包装命令
    bailongma-doctor.cmd           # Windows 包装命令
  references/
    prd_summary.md                 # PRD 摘要
    prescriptions.md               # 药方库（21 条）
    safety_policy.md               # 风险等级 + 脱敏规则
    test_cases.md                  # 验收清单（11 条 TC-P0）
    beginner_guide.md              # 3 步基础引导
    output_formats.md              # 输出格式说明
```

---

## 🛠 Hermes 安装形态

参考 Hermes 插件框架，插件身份由 `.hermes-skill/plugin.json` 和 `.hermes-skill/marketplace.json` 声明；能力由 `SKILL.md`、`skills/`、`agents/`、`scripts/` 和 `references/` 承载。

安装到 Hermes profile 时，可放入：

```text
~/.hermes/profiles/<profile>/skills/hermes-doctor
```

放完后 Hermes 会自动发现，下次启动 hermes 时就能用。

---

## 📊 健康评分

```text
Health Score = max(0, 100 - fail_count × 22 - warn_count × 10 - info_count × 2)
```

| 等级 | 扣分 | 例子 |
|---|---|---|
| `fail` | 22 分/条 | 缺少 manifest、JSON 非法、目标路径不存在 |
| `warn` | 10 分/条 | 缺少 marketplace、缺少子 Skill、命令不可用 |
| `info` | 2 分/条 | 配置提示、可选文档缺失 |

**状态判断**：
- 有 `fail` 或分数 < 60 → 严重异常
- 有 `warn` 或分数 < 90 → 需要处理
- 无 `fail/warn` 且分数 ≥ 90 → 健康

首次运行无历史基线时，只展示当前分数，不触发熔断。历史样本达到 10 次后，使用最近 10 次均值作为正式基线。

---

## 🔒 安全边界

- 只读体检可以自动执行。
- 写文件、安装依赖、授权、重启、改配置前必须确认。
- 删除、覆盖、reset、读取敏感信息属于高风险，不自动执行。
- 不收集 cookie、token、密码、私钥或无关个人数据。
- `.env` 只能检测存在，不能读取内容；病历脱敏只处理用户主动贴出的文本。
- 病历脱敏覆盖：`cookie / token / password / private key / 私钥 / 密码 / client_secret / bearer / api_key / jwt / authorization / secret / access_key / session_id / csrf_token / xsrf_token`

---

## 🧪 开发者快速验证

如果你想跑完所有 P0 验收（11 条 TC-P0）：

```bash
bailongma-doctor validate --target .        # 预期: OK
bailongma-doctor check --target .           # 预期: 包含 "Hermes Doctor 诊断报告"
bailongma-doctor match --text "fetch failed timeout"  # 预期: 命中 RX-RUNTIME-001
bailongma-doctor test --target .            # 预期: summary: 14/14 passed
```

详细验收清单见 `references/test_cases.md`。

---

## 📚 更多文档

- `SKILL.md` — 主技能入口（Hermes 框架用）
- `USER_MANUAL.md` — 简版用户手册
- `references/beginner_guide.md` — 3 步基础引导
- `references/prd_summary.md` — PRD 摘要
- `references/prescriptions.md` — 药方库完整列表
- `references/safety_policy.md` — 风险等级 + 脱敏策略
- `references/test_cases.md` — 验收清单
- `references/output_formats.md` — 命令输出格式规范
