---
name: prescription-match
description: Match pasted Hermes errors, logs, or symptoms to the Hermes Doctor prescription library.
version: 0.1.3
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, prescription]
requires_tools: [terminal, read_file]
requires_toolsets: [terminal, file]
---


# Prescription Match

Use when the user says `报错了`, `出错了`, pastes logs, or asks what an error means.

Run:

```bash
python3 scripts/hermes_doctor.py match --text "paste error text here"
```

Return the top prescription in plain Chinese. If no match is found, ask for the most relevant 20 log lines and suggest a read-only health check.
