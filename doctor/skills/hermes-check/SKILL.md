---
name: hermes-check
description: Run read-only Hermes Doctor health checks for Hermes plugin structure, manifest validity, subskills, agents, scripts, references, logs, and required local commands.
version: 0.1.3
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, diagnosis]
requires_tools: [terminal, read_file]
requires_toolsets: [terminal, file]
---


# Hermes Check

Use when the user says `体检`, `看看状态`, `health check`, `Hermes 插件是否完整`, or wants a read-only diagnosis report.

Run:

```bash
python3 scripts/hermes_doctor.py check --target . --format markdown
```

For structured output:

```bash
python3 scripts/hermes_doctor.py check --target . --format json
```

Never read `.env` contents or secrets. Report only evidence, impact, prescription, risk, and next step.
