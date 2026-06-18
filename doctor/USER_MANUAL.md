# Hermes Doctor 用户手册 v0.1.3

> 简版用户手册。如果你是第一次用，**先看 README.md 的"快速开始 5 步走"**。

## 它能做什么

Hermes Doctor 可以帮你：

- 看 Hermes 插件是不是完整
- 看最近日志有没有明显错误
- 把报错翻译成小白能懂的解释
- 给出安全修复计划
- 查询上次类似问题怎么处理
- 把处理结果写成病历，方便团队复用

## 常用说法（飞书 / Hermes 对话框）

在飞书里跟"白龙马医生"说，或者在 Hermes 对话框里说：

```text
白龙马医生 体检
白龙马医生 报错了：fetch failed timeout
白龙马医生 帮我修一下：unknown tool
白龙马医生 上次这个问题怎么处理
白龙马医生 带我上手
```

**触发前缀**（大小写都行）：`白龙马医生` / `@白龙马医生` / `Hermes Doctor` / `hermes doctor` / `Hermes医生` / `hermes医生` / `@Hermes Doctor`

## 重要提醒

Hermes Doctor 不会直接乱修。只读检查可以直接跑；涉及写文件、安装依赖、授权、重启或改配置时，会先给你计划并等你确认。

## 5 个核心场景

1. **体检**：`白龙马医生 体检` → 跑完看到健康评分和发现的问题
2. **报错匹配**：`白龙马医生 报错了：<你的报错>` → 命中药方
3. **生成修复计划**：`白龙马医生 帮我修一下：<你的问题>` → 给计划，等你确认
4. **查询病历**：`白龙马医生 上次这个问题怎么处理` → 查历史
5. **新手上路**：`白龙马医生 带我上手` → 读小白引导文档

## 详细文档

- README.md — 完整使用说明 + FAQ
- references/beginner_guide.md — 3 步基础引导
- references/prd_summary.md — PRD 摘要
- references/prescriptions.md — 药方库（21 条）
- references/safety_policy.md — 风险等级 + 脱敏策略
- references/test_cases.md — 验收清单
