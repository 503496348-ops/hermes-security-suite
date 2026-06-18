---
name: case-record
description: Record redacted Hermes Doctor case notes after a diagnosis or repair attempt.
version: 0.1.3
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, case]
requires_tools: [terminal, read_file]
requires_toolsets: [terminal, file]
---


# Case Record

Use when the user says `记录病历`, `记一下`, `save case`, or after a repair attempt, useful diagnosis, or blocked incident.

Run:

```bash
python3 scripts/hermes_doctor.py record --title "short title" --status fixed --summary "what happened"
```

Valid status values:

- `fixed`
- `partial`
- `blocked`

Secrets are redacted before writing. Do not store tokens, cookies, passwords, private keys, or unrelated personal data.
