---
name: repair-plan
description: Generate confirmation-ready Hermes Doctor repair plans without executing repairs.
version: 0.1.3
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, repair]
requires_tools: [terminal, read_file]
requires_toolsets: [terminal, file]
---


# Repair Plan

Use when the user says `帮我修一下`, `自愈`, `怎么修`, or needs a safe recovery plan.

Run:

```bash
python3 scripts/hermes_doctor.py plan --text "symptom or error"
```

Or with an explicit prescription:

```bash
python3 scripts/hermes_doctor.py plan --rx-id RX-RUNTIME-001
```

Do not execute writes, installs, auth changes, restarts, deletes, or config edits from this skill. Generate the plan and wait for confirmation.
