---
name: case-search
description: Search prior Hermes Doctor case notes by keyword.
version: 0.1.3
author: AtomCollide-AI-陈宇锋团队
tags: [hermes, doctor, case]
requires_tools: [terminal, read_file]
requires_toolsets: [terminal, file]
---


# Case Search

Use when the user asks `上次怎么处理`, `查病历`, `历史记录`, or repeats a known issue.

Run:

```bash
python3 scripts/hermes_doctor.py search --query "keyword"
```

Return matching case filenames and short summaries. If no case exists, suggest running health check or prescription match first.
