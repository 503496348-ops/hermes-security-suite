# Team Test Cases

## P0

| ID | Command | Expected |
|-|-|-|
| TC-P0-001 | `python3 hermes-doctor/scripts/hermes_doctor.py validate --target hermes-doctor` | `OK` |
| TC-P0-002 | `python3 hermes-doctor/scripts/hermes_doctor.py check --target hermes-doctor` | `Hermes Doctor 诊断报告` |
| TC-P0-003 | `python3 hermes-doctor/scripts/hermes_doctor.py check --target hermes-doctor --format json` | `passed_checks` |
| TC-P0-004 | `python3 hermes-doctor/scripts/hermes_doctor.py check --target /no/such/path` | `RX-FILE-001` |
| TC-P0-005 | `python3 hermes-doctor/scripts/hermes_doctor.py match --text "Hermes fetch failed timeout 访问不到网页"` | `RX-RUNTIME-001` |
| TC-P0-006 | `python3 hermes-doctor/scripts/hermes_doctor.py plan --text "unknown tool 工具调用失败"` | `修复计划` |
| TC-P0-007 | `python3 hermes-doctor/scripts/hermes_doctor.py route --text "白龙马医生 体检" --format json` | `health_check` |
| TC-P0-008 | `python3 hermes-doctor/scripts/hermes_doctor.py test --target hermes-doctor` | `summary:` |
| TC-P0-009 | `hermes-doctor/scripts/bailongma-doctor match --text "unknown tool 工具调用失败"` | `RX-TOOL-001` |
| TC-P0-010 | `python3 hermes-doctor/scripts/hermes_doctor.py match --text "token=abc123 cookie=xyz password=hello"` | `RX-SAFETY-001` |
| TC-P0-011 | `python3 hermes-doctor/scripts/hermes_doctor.py match --text "Authorization: Bearer eyJhbGc... client_secret=xxx"` | `RX-SAFETY-001` (covers M-2 JWT/Bearer/client_secret redaction) |

## Acceptance Gate

- Hermes manifest valid.
- Main SKILL.md present.
- Subskills present.
- Health report includes passed checks.
- Prescription match covers runtime/tool/safety cases.
- Repair plan never executes repair commands.
- Case records are redacted.
- Health JSON includes scoring_formula, severity_counts, and baseline.
- At least 12 P0 prescriptions are present.
- Wrapper command exists for non-developer usage.
