# G5 门禁测试指南（5 个非开发者实测）

> **目的**：验证 Hermes Doctor 在"无开发者引导"下，小白能不能完成 5 个核心场景
> **PRD 8.1 G5 要求**：5 个非开发者 × 5 个核心场景，**完成率 ≥ 80%**
> **测试方式**：把这份指南发给 5 个**没看过 Hermes Doctor 源码/文档**的人，让他们自己跑，记录结果

---

## 准备工作（你只做一次）

把 `hermes-doctor-bugfix-patch.zip` 发给 5 个测试者，让他们：

1. 双击 zip 解压到 `~/Downloads/hermes-doctor-0.1.3/`
2. 打开终端，跑：

```bash
cd ~/Downloads/hermes-doctor-0.1.3
python3 scripts/hermes_doctor.py check --target .
```

如果看到 `健康评分：100/100 状态：健康`，说明装好了。✅

如果看不到，检查 README.md 里的"踩坑 FAQ"。

---

## 5 个核心场景（让测试者按顺序跑）

### 场景 1：体检

**任务**：用 Hermes Doctor 给当前项目做一次体检。

**指令**：
```bash
cd ~/Downloads/hermes-doctor-0.1.3
python3 scripts/hermes_doctor.py check --target .
```

**成功标准**：
- ✅ 看到 `Hermes Doctor 诊断报告` 标题
- ✅ 看到 `健康评分：100/100`
- ✅ 看到 `状态：健康`

**失败标准**：
- ❌ 命令报"找不到文件"（说明没在项目目录）
- ❌ 报"Permission denied"（说明没 chmod）

---

### 场景 2：报错匹配

**任务**：把一段报错贴给 Hermes Doctor，让它告诉你是哪类问题。

**指令**：
```bash
python3 scripts/hermes_doctor.py match --text "Hermes fetch failed timeout 访问不到网页"
```

**成功标准**：
- ✅ 看到 `1. 药方：RX-RUNTIME-001`（或类似格式）
- ✅ 看到 `匹配分：60+` 的数字
- ✅ 看到"小白解释"和"修复步骤"

---

### 场景 3：生成修复计划

**任务**：遇到一个工具调用失败的问题，让 Hermes Doctor 给一个修复计划。

**指令**：
```bash
python3 scripts/hermes_doctor.py plan --text "unknown tool 工具调用失败"
```

**成功标准**：
- ✅ 看到 `Hermes Doctor 修复计划`
- ✅ 看到 `是否需要确认：是`（说明没自动执行修复）
- ✅ 看到"执行前检查"列表

---

### 场景 4：查询病历

**任务**：写一条病历，然后搜索它。

**先写一条病历**（注意：先 `mkdir -p /tmp/cases`）：

```bash
mkdir -p /tmp/cases
python3 scripts/hermes_doctor.py record   --case-dir /tmp/cases   --title "我的测试问题"   --status blocked   --summary "这是测试摘要"
```

**预期**：输出一个 `.md` 文件路径。

**再搜索这条病历**：

```bash
python3 scripts/hermes_doctor.py search --case-dir /tmp/cases --query "测试"
```

**成功标准**：
- ✅ 看到 `Hermes Doctor 病历查询`
- ✅ 看到列表里有刚才写的"我的测试问题"

---

### 场景 5：飞书消息路由（如果没用飞书可跳过）

**任务**：模拟在飞书跟 Hermes Doctor 说一句话，看它路由成什么命令。

**指令**：
```bash
python3 scripts/hermes_doctor.py route --text "白龙马医生 体检" --format json
```

**成功标准**：
- ✅ 看到 JSON 输出
- ✅ 看到 `"intent": "health_check"`
- ✅ 看到 `"action": "run_health_check"`

---

## 记录模板

每个测试者跑完后，**让他自己**填这个表（不要引导）：

```markdown
# G5 门禁测试报告

## 测试者信息
- 姓名/ID: __________
- 技术背景: □ 完全没有编程经验  □ 看过 Python 教程  □ 写过简单脚本  □ 其他: ____
- 用过 Hermes Agent 吗: □ 是  □ 否
- 用过终端吗: □ 从来没用过  □ 用过一两次  □ 经常用

## 5 个场景结果

| # | 场景 | 完成情况 | 遇到的问题（如果有） |
|---|---|---|---|
| 1 | 体检 | □ 成功  □ 失败  □ 跳过 | |
| 2 | 报错匹配 | □ 成功  □ 失败  □ 跳过 | |
| 3 | 生成修复计划 | □ 成功  □ 失败  □ 跳过 | |
| 4 | 查询病历 | □ 成功  □ 失败  □ 跳过 | |
| 5 | 飞书消息路由 | □ 成功  □ 失败  □ 跳过 | |

## 总体反馈
- 最难的一步是: __________
- 最不清楚的一个命令: __________
- 建议改进的地方: __________
```

## 通过标准

- 5 个测试者 × 5 个场景 = 25 个样本
- 完成数 ≥ 25 × 0.8 = **20 个** = 门禁通过
- 完成数 < 20 = 需要改进文档/命令，**不通过 G5 门禁**

## 收集到反馈后的处理

1. 把 5 份报告的"遇到的问题"汇总
2. 按"卡了几个人"排序（卡 3+ 人的 = 高优先级）
3. 改 README/USER_MANUAL/beginner_guide.md
4. 重新跑 5 人实测，确认通过
