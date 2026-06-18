---
name: feishu-route
description: Route Feishu or Lark message text into Hermes Doctor local actions.
version: 0.1.3
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, feishu]
requires_tools: [terminal, read_file]
requires_toolsets: [terminal, file]
---


# Feishu Route

Use when integrating Hermes Doctor with Feishu/Lark messages.

Run:

```bash
python3 scripts/hermes_doctor.py route --text "Hermes Doctor 报错了：fetch failed" --format json
```

The router maps:

- `体检` -> health check
- `报错了` -> prescription match
- `帮我修一下` -> repair plan
- `上次/病历` -> case search
- `带我上手` -> beginner guide

Repair routes must return `confirmation_required: true`.
