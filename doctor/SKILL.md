---
name: hermes-doctor
description: Hermes Agent 自诊断与安全自愈插件。用于 Hermes 插件、Agent、工具调用、运行时、配置、日志、飞书消息路由的体检、药方匹配、修复计划、病历记录和问题复盘。
version: 0.1.2
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, diagnosis, self-healing, agent]
requires_tools: [read_file, write_file, patch, search_files, terminal, clarify]
requires_toolsets: [file, terminal]
---

# Hermes Doctor

Hermes Doctor 是基于 Hermes 自身插件框架重构的 Agent 医生。功能目标对齐皮皮虾医生 PRD，但实现形态属于 Hermes：`.hermes-skill` 插件 manifest、主 `SKILL.md`、子 `skills/`、`agents/`、本地 CLI 和 references 文档。

## When To Use

激活此插件的场景：

- 用户说 `Hermes Doctor 体检`、`看看状态`、`自诊断`
- 用户贴 Hermes 报错、日志、工具调用失败、配置失败、依赖失败
- 用户说 `帮我修一下`、`自愈`、`怎么修`
- 用户需要查询或写入历史处理记录
- 用户要把飞书消息路由到本地 Hermes Doctor 动作

不激活的场景：

- 普通聊天或泛化技术科普
- 用户要修的是 OpenClaw Doctor/皮皮虾医生本体
- 需要绕过登录、验证码、反爬或限流保护

## Core Loop

1. Inspect: 只读收集证据。
2. Triage: 判断严重度、影响范围和风险。
3. Prescribe: 匹配药方。
4. Confirm: 写入、安装、授权、重启、删除前确认。
5. Verify: 运行最小验证。
6. Record: 写入脱敏病历。

## Commands

```bash
python3 scripts/hermes_doctor.py check --target . --format markdown
python3 scripts/hermes_doctor.py match --text "Hermes fetch failed timeout"
python3 scripts/hermes_doctor.py plan --text "unknown tool 工具调用失败"
python3 scripts/hermes_doctor.py record --title "fetch failed" --status partial --summary "what happened"
python3 scripts/hermes_doctor.py search --query "fetch"
python3 scripts/hermes_doctor.py route --text "Hermes Doctor 帮我修一下：fetch failed" --format json
python3 scripts/hermes_doctor.py validate --target .
python3 scripts/hermes_doctor.py test --target .
```

## Subskills

| 子 Skill | 功能 |
|-|-|
| `hermes-check` | 只读体检 Hermes 插件结构、运行线索、日志和工具 |
| `prescription-match` | 把错误文本映射到药方库 |
| `repair-plan` | 生成修复计划，不执行修复 |
| `case-record` | 写入脱敏病历 |
| `case-search` | 查询历史病历 |
| `feishu-route` | 把飞书/Lark 文本路由成本地动作 |

## Safety

- `.env` 只能检测存在，不能读取或回显内容。
- 不收集 cookie、token、password、private key、session storage。
- 不绕过登录、验证码、反爬或限流。
- 删除、覆盖、reset、读取秘密信息属于 L3，默认只给人工计划。
