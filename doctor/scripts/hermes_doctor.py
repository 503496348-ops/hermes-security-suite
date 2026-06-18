#!/usr/bin/env python3
"""Hermes Doctor CLI.

Dependency-free implementation for Hermes Agent diagnosis and safe repair
planning. It follows the PRD behavior: inspect first, explain clearly,
prescribe safely, confirm before changes, verify, and record cases.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCORING_FORMULA = "Health Score = max(0, 100 - fail_count × 22 - warn_count × 10 - info_count × 2)"
REQUIRED_PRESCRIPTIONS = {
    "RX-HERMES-001",
    "RX-HERMES-002",
    "RX-HERMES-003",
    "RX-HERMES-004",
    "RX-HERMES-005",
    "RX-RUNTIME-001",
    "RX-RUNTIME-002",
    "RX-TOOL-001",
    "RX-DEP-001",
    "RX-FILE-001",
    "RX-SAFETY-001",
    "RX-FEISHU-003",
}


@dataclass
class Finding:
    level: str
    title: str
    evidence: str
    impact: str
    prescription: str
    risk: str
    next_step: str


@dataclass
class Prescription:
    rx_id: str
    symptoms: str
    diagnosis: str
    prescription: str
    risk: str


@dataclass
class Route:
    intent: str
    action: str
    command: list[str]
    confirmation_required: bool
    reply_hint: str


def read_text(path: Path, limit: int = 20000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception as exc:  # noqa: BLE001 - doctor should report, not crash
        return f"<<read failed: {exc}>>"


def split_markdown_row(line: str) -> list[str]:
    text = line.strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|"):
        text = text[:-1]
    cells: list[str] = []
    current: list[str] = []
    in_code = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == "`":
            in_code = not in_code
            current.append(char)
            continue
        if char == "|" and not in_code:
            cells.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    cells.append("".join(current).strip())
    return cells


def load_prescriptions(path: Path | None = None) -> list[Prescription]:
    """v0.1.3 改进：跳过坏行而非整表 fail（架构评审 #14）。"""
    path = path or ROOT / "references" / "prescriptions.md"
    rows: list[Prescription] = []
    skipped: list[str] = []
    for line in read_text(path, 200000).splitlines():
        if not line.startswith("| RX-"):
            continue
        cells = split_markdown_row(line)
        if len(cells) != 5:
            skipped.append(line[:80])
            print(f"[warn] prescriptions.md 跳过坏行 ({len(skipped)}): {line[:60]}", file=sys.stderr)
            continue
        try:
            rows.append(Prescription(*cells))
        except (ValueError, TypeError) as e:
            skipped.append(line[:80])
            print(f"[warn] prescriptions.md 字段解析失败: {e}", file=sys.stderr)
            continue
    if skipped:
        print(f"[info] prescriptions.md 加载完成: {len(rows)} 条有效, {len(skipped)} 条跳过", file=sys.stderr)
    return rows


STOPWORDS = {"and", "the", "with", "none", "not", "fail", "failed", "error", "missing", "invalid"}


def tokens(text: str) -> list[str]:
    raw = re.findall(r"`([^`]+)`|([A-Za-z0-9_:/.-]{3,})|([\u4e00-\u9fff]{2,})", text)
    result: list[str] = []
    for quoted, bare, chinese in raw:
        value = (quoted or bare or chinese).strip().lower()
        if value and value not in STOPWORDS:
            result.append(value)
    return result


def score_match(query: str, item: Prescription) -> tuple[int, list[str]]:
    haystack = f"{item.rx_id} {item.symptoms} {item.diagnosis} {item.prescription}".lower()
    query_l = query.lower()
    query_tokens = set(tokens(query))
    matched: list[str] = []
    score = 0
    if item.rx_id.lower() in query_l:
        score += 100
        matched.append(item.rx_id)
    for token in tokens(item.symptoms):
        if token in query_l or token in query_tokens:
            score += 22 if len(token) > 6 else 12
            matched.append(token)
    for token in tokens(query):
        if token in haystack:
            score += 4
    return score, sorted(set(matched))


def match_prescriptions(query: str, prescriptions: list[Prescription]) -> list[tuple[int, list[str], Prescription]]:
    matches = sorted(
        ((score_match(query, item)[0], score_match(query, item)[1], item) for item in prescriptions),
        key=lambda row: row[0],
        reverse=True,
    )
    matches = [row for row in matches if row[0] >= 8]
    if matches:
        threshold = max(8, int(matches[0][0] * 0.35))
        matches = [row for row in matches if row[0] >= threshold]
    return matches


def redacted(value: str) -> str:
    result = value
    # Rule 1: generic key=value pairs (token, cookie, password, secret, api_key, etc.)
    result = re.sub(
        r"(?i)(token|cookie|password|passwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|"
        r"csrf[_-]?token|xsrf[_-]?token|session[_-]?id|session[_-]?token|auth[_-]?token|"
        r"bearer|aws[_-]?(?:access|secret)[_-]?key|private[_-]?key)\s*[:=]\s*['\"]?[^'\"\s,;]+",
        lambda match: f"{match.group(1)}=[REDACTED]",
        result,
        flags=re.S,
    )
    # Rule 2: Authorization header (Bearer/JWT) and Set-Cookie
    # Match any non-whitespace, non-quote, non-angle-bracket characters after the scheme
    # (intentionally no min-length: real tokens may be short after unicode normalization,
    #  or use em-dash separators; false positive on short literals is preferable to leak)
    result = re.sub(
        r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)[^\s'\"<>]+",
        r"\1[REDACTED]",
        result,
    )
    result = re.sub(
        r"(?i)(set-cookie\s*:\s*[^=\s;]+=)[^;\s]+",
        r"\1[REDACTED]",
        result,
    )
    # Rule 3: JWT (eyJ...eyJ....)
    result = re.sub(
        r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_\-+/=]+",
        "[REDACTED_JWT]",
        result,
    )
    # Rule 4: PEM private keys
    result = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        result,
        flags=re.S,
    )
    # Rule 5: database connection strings with embedded credentials
    result = re.sub(
        r"(?i)(?P<proto>mysql|postgresql|postgres|mongodb|redis|amqp)://[^:\s]+:[^@\s]+@",
        r"\g<proto>://[REDACTED_USER]:[REDACTED_PASS]@",
        result,
    )
    return result


def collect_files(target: Path, limit: int = 500) -> list[Path]:
    ignored = {".git", "node_modules", ".venv", "venv", "__pycache__", ".doctor", ".pytest_cache"}
    target_resolved = target.resolve()
    files: list[Path] = []
    for root, dirs, names in os.walk(target, followlinks=False):  # L-2: don't follow symlinks
        # L-2: filter out symlinked dirs that resolve outside target
        safe_dirs = []
        for d in dirs:
            if d in ignored:
                continue
            d_path = Path(root) / d
            try:
                if d_path.is_symlink():
                    resolved = d_path.resolve()
                    if not str(resolved).startswith(str(target_resolved)):
                        continue  # skip symlinked dirs pointing outside target
            except OSError:
                continue
            safe_dirs.append(d)
        dirs[:] = safe_dirs
        for name in names:
            p = Path(root) / name
            # L-2: skip symlinked files that resolve outside target
            try:
                if p.is_symlink() and not str(p.resolve()).startswith(str(target_resolved)):
                    continue
            except OSError:
                continue
            files.append(p)
            if len(files) >= limit:
                return files
    return files


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def check_project(target: Path) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    passed: list[str] = []
    files = collect_files(target)
    names = [rel(path, target) for path in files]
    lower_names = [name.lower() for name in names]

    manifest = target / ".hermes-skill" / "plugin.json"
    marketplace = target / ".hermes-skill" / "marketplace.json"
    if manifest.exists():
        try:
            data = json.loads(read_text(manifest))
            if data.get("name"):
                passed.append(f"Hermes plugin manifest 可读取：{data.get('name')}")
            else:
                findings.append(Finding("warn", "plugin.json 缺少 name", rel(manifest, target), "Hermes 市场安装和识别可能失败。", "RX-HERMES-001", "L1", "补齐 name/version/description。"))
        except json.JSONDecodeError as exc:
            findings.append(Finding("fail", "plugin.json 不是合法 JSON", f"{rel(manifest, target)}: {exc}", "Hermes 插件无法被识别。", "RX-HERMES-002", "L1", "修复 JSON 格式后重新 validate。"))
    else:
        findings.append(Finding("fail", "缺少 Hermes plugin.json", ".hermes-skill/plugin.json", "这不是完整 Hermes 插件项目。", "RX-HERMES-001", "L1", "按 Hermes 框架补充 .hermes-skill/plugin.json。"))

    if marketplace.exists():
        passed.append("Hermes marketplace.json 存在")
    else:
        findings.append(Finding("warn", "缺少 marketplace.json", ".hermes-skill/marketplace.json", "团队分发和安装说明不完整。", "RX-HERMES-001", "L1", "补充 marketplace.json。"))

    for directory, rx_id, impact in [
        ("agents", "RX-HERMES-003", "诊断/修复/病历角色边界不清。"),
        ("skills", "RX-HERMES-004", "Hermes 子能力无法按命令拆分触发。"),
        ("scripts", "RX-HERMES-005", "缺少可验证的本地执行入口。"),
        ("references", "RX-HERMES-006", "PRD、安全策略、药方和验收无法沉淀。"),
    ]:
        if (target / directory).is_dir():
            passed.append(f"目录存在：{directory}/")
        else:
            findings.append(Finding("warn", f"缺少 {directory}/", directory, impact, rx_id, "L1", f"按 Hermes 项目结构补齐 {directory}/。"))

    if any(name == "skill.md" for name in lower_names):
        passed.append("主 SKILL.md 存在")
    else:
        findings.append(Finding("warn", "缺少主 SKILL.md", "SKILL.md", "Hermes Agent 不容易理解插件何时触发。", "RX-HERMES-004", "L1", "补充主入口和触发规则。"))

    env_files = [name for name in lower_names if name in {".env", ".env.local"}]
    if env_files:
        passed.append("发现 env 文件，但已按安全策略跳过读取内容")
    if any(name in lower_names for name in [".env.example", "env.example", "config.example.json"]):
        passed.append("发现示例配置文件，可用于小白引导")

    logs = [path for path in files if path.suffix in {".log", ".err", ".out"}]
    log_findings = 0
    log_size_limit = 5 * 1024 * 1024  # M-1: skip log files larger than 5MB to prevent DoS
    for path in sorted(logs, key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)[:8]:
        # M-1: size check before reading
        try:
            if path.stat().st_size > log_size_limit:
                findings.append(Finding(
                    "info", f"日志文件过大已跳过：{path.name}",
                    rel(path, target),
                    f"文件大小 {path.stat().st_size // (1024*1024)}MB 超过 5MB 限制，未读取。",
                    "RX-LOG-001", "L0", "如需查看请手动分页或过滤。"
                ))
                continue
        except OSError:
            continue
        text = read_text(path)
        lower = text.lower()
        if not any(word in lower for word in ["error", "failed", "exception", "timeout", "失败", "异常"]):
            continue
        rx_id = "RX-LOG-001"
        title = "最近日志包含错误"
        if re.search(r"fetch failed|failed to fetch|访问不到|取不到|timeout", text, re.I):
            rx_id, title = "RX-RUNTIME-001", "网页数据获取失败"
        elif re.search(r"unknown tool|tool .*not found|工具不存在|工具调用失败", text, re.I):
            rx_id, title = "RX-TOOL-001", "工具调用失败"
        elif re.search(r"captcha|rate limit|login required|验证码|请求太频繁|登录", text, re.I):
            rx_id, title = "RX-SAFETY-002", "平台限制或登录态问题"
        findings.append(Finding("warn", f"{title}：{path.name}", rel(path, target), "可能解释 Hermes 当前不可用或取不到数据。", rx_id, "L0", "先匹配药方，再生成修复计划。"))
        log_findings += 1
    if not logs:
        passed.append("未发现近期 .log/.err/.out 日志文件")
    elif log_findings == 0:
        passed.append(f"扫描 {min(len(logs), 8)} 个日志文件，未发现错误关键词")

    for tool in ["python3", "rg"]:
        if shutil.which(tool):
            passed.append(f"命令可用：{tool}")
        else:
            findings.append(Finding("warn", f"命令不可用：{tool}", f"{tool} not found in PATH", "本地诊断能力会受限。", "RX-DEP-001", "L2", "需要时再安装；安装前必须确认。"))
    return findings, passed


def health_score(findings: list[Finding]) -> int:
    value = 100
    for item in findings:
        if item.level == "fail":
            value -= 22
        elif item.level == "warn":
            value -= 10
        elif item.level == "info":
            value -= 2
    return max(0, value)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {
        "fail": sum(1 for item in findings if item.level == "fail"),
        "warn": sum(1 for item in findings if item.level == "warn"),
        "info": sum(1 for item in findings if item.level == "info"),
    }


def health_status(score: int, findings: list[Finding]) -> str:
    if any(item.level == "fail" for item in findings) or score < 60:
        return "严重异常"
    if any(item.level == "warn" for item in findings) or score < 90:
        return "需要处理"
    return "健康"


def baseline_status(score: int, baseline_file: Path | None = None) -> dict[str, object]:
    if baseline_file is None:
        return {
            "status": "not_configured",
            "sample_count": 0,
            "baseline_score": None,
            "delta": None,
            "action": "首次或未配置基线时，只展示当前分数，不触发熔断。",
        }
    if not baseline_file.exists():
        return {
            "status": "not_initialized",
            "sample_count": 0,
            "baseline_score": None,
            "delta": None,
            "action": "首次运行可将当前分数作为初始参考；只读体检不会自动写入基线。",
        }
    try:
        data = json.loads(read_text(baseline_file, 100000))
        samples = [int(item["score"]) for item in data.get("samples", []) if "score" in item]
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "invalid",
            "sample_count": 0,
            "baseline_score": None,
            "delta": None,
            "action": f"基线文件不可解析：{exc}",
        }
    recent = samples[-10:]
    if not recent:
        return {
            "status": "not_initialized",
            "sample_count": 0,
            "baseline_score": None,
            "delta": None,
            "action": "基线文件没有样本；只展示当前分数。",
        }
    baseline = round(sum(recent) / len(recent), 2)
    delta = round(score - baseline, 2)
    if len(recent) < 3:
        status = "warming_up"
        action = "样本少于 3 次，只提示不熔断。"
    elif len(recent) < 10:
        status = "partial"
        action = "样本少于 10 次，可提示风险，不自动 blocked。"
    elif delta <= -15:
        status = "downgrade"
        action = "当前分数低于基线 15 分以上，降级为只报告。"
    elif delta >= 10:
        status = "positive"
        action = "当前分数高于基线 10 分以上，可记录正反馈。"
    else:
        status = "normal"
        action = "当前分数在基线波动范围内。"
    return {
        "status": status,
        "sample_count": len(recent),
        "baseline_score": baseline,
        "delta": delta,
        "action": action,
    }


def render_check(target: Path, findings: list[Finding], passed: list[str], display_target: str | None = None) -> str:
    score = health_score(findings)
    state = health_status(score, findings)
    counts = severity_counts(findings)
    baseline = baseline_status(score)
    # When caller passes display_target, prefer it (avoids macOS hardlink path mangling).
    target_str = display_target or str(target)
    lines = [
        "Hermes Doctor 诊断报告",
        "",
        f"目标：{target_str}",
        f"时间：{datetime.now(timezone.utc).isoformat()}",
        f"健康评分：{score}/100",
        f"状态：{state}",
        f"评分公式：{SCORING_FORMULA}",
        f"计数：fail={counts['fail']}，warn={counts['warn']}，info={counts['info']}",
        f"基线状态：{baseline['status']}；{baseline['action']}",
        "",
        "主要结论：",
    ]
    if findings:
        lines.append(f"当前状态为{state}，发现 {len(findings)} 个问题。最需要关注：{findings[0].title}。")
    else:
        lines.append("未发现需要处理的问题，可以保持当前状态。")
    lines.extend(["", "发现的问题："])
    if findings:
        for index, item in enumerate(findings, 1):
            severity = {"fail": "高", "warn": "中", "info": "低"}.get(item.level, "低")
            lines.extend(
                [
                    f"{index}. {item.title}",
                    f"   严重度：{severity}",
                    f"   影响范围：{item.impact}",
                    f"   证据：{item.evidence}",
                    f"   药方：{item.prescription}",
                    f"   修复风险：{item.risk}",
                    f"   下一步：{item.next_step}",
                ]
            )
    else:
        lines.append("无")
    if passed:
        lines.extend(["", "已通过检查："])
        for item in passed:
            lines.append(f"- {item}")
    return "\n".join(lines)


def render_matches(query: str, matches: list[tuple[int, list[str], Prescription]]) -> str:
    if not matches:
        return "\n".join(
            [
                "Hermes Doctor 药方匹配",
                "",
                "未找到明确药方。",
                "",
                "下一步：先运行只读体检，摘取最关键的 20 行错误日志，再生成兜底诊断报告。",
                f"输入摘要：{query[:500]}",
            ]
        )
    lines = ["Hermes Doctor 药方匹配", ""]
    for rank, (score, matched, item) in enumerate(matches[:3], 1):
        lines.extend(
            [
                f"{rank}. 药方：{item.rx_id}",
                f"   匹配分：{score}",
                f"   命中症状：{', '.join(matched) if matched else '弱匹配'}",
                f"   小白解释：{item.diagnosis}",
                f"   修复步骤：{item.prescription}",
                f"   风险等级：{item.risk}",
                "",
            ]
        )
    lines.append("下一步：按最高匹配药方处理；涉及写入、安装、授权、重启或删除时先确认。")
    return "\n".join(lines)


RISK_POLICY = {
    "L0": "可自动执行，只读检查或报告生成。",
    "L1": "低风险写入，必须展示将写入的路径和内容摘要。",
    "L2": "中风险操作，必须展示命令、影响范围、验证方式，并等待确认。",
    "L3": "高风险操作，默认不执行；只提供人工计划，除非用户明确批准精确动作。",
}


def risk_level(risk: str) -> str:
    for level in ["L3", "L2", "L1", "L0"]:
        if level in risk:
            return level
    return "L2"


def build_plan(item: Prescription, source: str) -> dict[str, object]:
    level = risk_level(item.risk)
    return {
        "rx_id": item.rx_id,
        "risk": item.risk,
        "risk_policy": RISK_POLICY[level],
        "source": source[:1000],
        "diagnosis": item.diagnosis,
        "recommended_fix": item.prescription,
        "impact": "仅处理 Hermes Doctor 或目标 Hermes 项目的相关问题，不扩大到无关文件、凭证或用户数据。",
        "confirmation_required": level != "L0",
        "preflight": [
            "确认目标路径和当前工作区",
            "保留原始错误摘要",
            "确认没有未说明的删除、覆盖、重置、读取密钥动作",
        ],
        "execution": [
            item.prescription,
            "如涉及写入、安装、授权、重启或配置修改，先展示命令或 diff 并等待用户确认。",
        ],
        "verification": [
            "重新运行触发问题的最小命令",
            "重新运行 hermes_doctor.py check 或对应子能力测试",
            "如果失败，记录病历并降级为人工复核",
        ],
        "rollback": [
            "L0 无需回滚",
            "L1/L2 使用修改前备份或反向 diff",
            "L3 默认不执行，必须先定义回滚方案",
        ],
    }


def render_plan(plan: dict[str, object]) -> str:
    lines = [
        "Hermes Doctor 修复计划",
        "",
        f"药方：{plan['rx_id']}",
        f"风险：{plan['risk']}",
        f"是否需要确认：{'是' if plan['confirmation_required'] else '否'}",
        "",
        f"诊断：{plan['diagnosis']}",
        f"建议修复：{plan['recommended_fix']}",
        f"影响范围：{plan['impact']}",
        f"风险策略：{plan['risk_policy']}",
        "",
        "执行前检查：",
    ]
    for item in plan["preflight"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("执行步骤：")
    for item in plan["execution"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("验证方式：")
    for item in plan["verification"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("回滚方式：")
    for item in plan["rollback"]:
        lines.append(f"- {item}")
    if plan.get("circuit_breaker", {}).get("triggered"):
        cb = plan["circuit_breaker"]
        lines.extend([
            "",
            "⚠️ 熔断触发（Circuit Breaker）",
            f"原因：{cb.get('reason', 'unknown')}",
            f"连续失败次数：{cb.get('consecutive', 0)}",
            f"最后状态：{cb.get('last_status', 'unknown')}",
            "动作：降级为仅报告 + 人工复核；不再自动执行修复。",
            f"证据：{', '.join(cb.get('evidence', []))}",
        ])
    return "\n".join(lines)


def check_circuit_breaker(query: str, case_dir: Path | None = None) -> dict:
    """Check if the same issue has been blocked/partial 3 times in a row.

    Implements PRD 4.1 功能 2 ("同类问题连续 3 次修复失败，降级为仅报告 + 人工复核")
    and PRD 8.1 质量预警 ("连续三次失败 → 熔断 + 标记 blocked").
    """
    if case_dir is None:
        case_dir = Path(os.environ.get("HERMES_DOCTOR_CASE_DIR", ".doctor/cases"))
    if not case_dir.exists():
        return {"triggered": False, "reason": "no_history", "consecutive": 0}
    paths = sorted(case_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
    if len(paths) < 3:
        return {"triggered": False, "reason": "insufficient_history", "consecutive": len(paths)}
    cases = []
    for path in paths:
        body = read_text(path, 20000)
        title, status = "", ""
        for line in body.splitlines():
            if line.startswith("title:"):
                title = line.split(":", 1)[1].strip().lower()
            elif line.startswith("status:"):
                status = line.split(":", 1)[1].strip()
        cases.append({"path": str(path), "title": title, "status": status})
    titles = [c["title"] for c in cases]
    statuses = [c["status"] for c in cases]
    query_norm = (query or "").strip().lower()
    same_title = (
        len(set(titles)) == 1
        and titles[0] != ""
        and (query_norm == "" or query_norm in titles[0] or titles[0] in query_norm)
    )
    all_failed = all(s in ("blocked", "partial") for s in statuses)
    if same_title and all_failed:
        return {
            "triggered": True,
            "reason": "3_consecutive_failures_same_title",
            "consecutive": 3,
            "last_status": statuses[0],
            "evidence": [c["path"] for c in cases],
        }
    return {"triggered": False, "reason": "no_pattern", "consecutive": 0, "recent": cases}


def route_text(text: str) -> Route:
    """飞书/Lark 文本 → 路由意图。
    
    v0.1.3 改进：用置信度评分替代硬编码顺序（修复架构评审 #10）
    规则：每条规则的关键词打分，主关键词权重 = 2，普通关键词 = 1，取最高分且 ≥ 2 才确定
    修复/写入类意图始终 confirmation_required=True
    """
    normalized = text.strip()
    for prefix in ["白龙马医生", "@白龙马医生", "Hermes Doctor", "hermes doctor", "Hermes医生", "hermes医生", "@Hermes Doctor"]:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :].strip(" ：:")
            break

    # 置信度评分：(route_name, confirmation_required, score, kwargs_builder)
    candidates = []
    # health_check: 强关键词 体检/看看状态/health check 各 2 分
    health_score = sum(2 for kw in ["体检", "看看状态", "health check"] if kw in normalized) + (1 if "check" in normalized.lower() and "health" not in normalized.lower() else 0)
    if health_score > 0:
        candidates.append(("health_check", False, health_score, lambda: ["python3", "scripts/hermes_doctor.py", "check", "--target", "."]))
    # repair_plan: 强关键词 帮我修/自愈/修一下 各 2 分
    repair_score = sum(2 for kw in ["帮我修", "自愈", "修一下"] if kw in normalized) + (1 if "repair" in normalized.lower() else 0)
    if repair_score > 0:
        candidates.append(("repair_plan", True, repair_score, lambda: ["python3", "scripts/hermes_doctor.py", "plan", "--text", normalized.split("：", 1)[-1] if "：" in normalized else normalized]))
    # case_search: 上次/病历 各 1 分（弱化，避免抢 repair_plan 关键词）
    case_score = sum(1 for kw in ["病历", "历史"] if kw in normalized) + (1 if "上次" in normalized and "修" not in normalized else 0)
    if case_score > 0:
        candidates.append(("case_search", False, case_score, lambda: ["python3", "scripts/hermes_doctor.py", "search", "--query", normalized.split("：", 1)[-1] if "：" in normalized else normalized]))
    # prescription_match: 报错/出错/failed 各 1 分
    rx_score = sum(1 for kw in ["报错", "出错", "failed", "异常"] if kw in normalized) + (1 if "error" in normalized.lower() else 0)
    if rx_score > 0:
        candidates.append(("prescription_match", False, rx_score, lambda: ["python3", "scripts/hermes_doctor.py", "match", "--text", normalized.split("：", 1)[-1] if "：" in normalized else normalized]))

    if candidates:
        # 取最高分
        candidates.sort(key=lambda x: x[2], reverse=True)
        name, conf, _, builder = candidates[0]
        if name == "health_check":
            return Route(name, "run_health_check", builder(), conf, "返回 Hermes Doctor 健康报告。")
        if name == "repair_plan":
            return Route(name, "generate_repair_plan", builder(), conf, "先返回修复计划，等待用户确认。")
        if name == "case_search":
            return Route(name, "search_cases", builder(), conf, "返回匹配病历。")
        if name == "prescription_match":
            return Route(name, "match_prescription", builder(), conf, "返回匹配药方。")
        return Route("prescription_match", "match_prescription", ["python3", "scripts/hermes_doctor.py", "match", "--text", symptom], False, "返回药方卡。")
    if any(word in normalized for word in ["带我上手", "不会用", "开始"]):
        return Route("onboarding", "read_reference", ["read_file", "references/beginner_guide.md"], False, "按小白引导回复，不直接执行外部操作。")
    return Route("fallback", "fallback_health_check", ["python3", "scripts/hermes_doctor.py", "check", "--target", "."], False, "未识别明确意图，先做只读体检或请用户贴报错。")


def command_check(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    findings: list[Finding] = []
    passed: list[str] = []
    if not target.exists():
        findings.append(Finding("fail", "目标路径不存在", str(target), "无法执行体检。", "RX-FILE-001", "L0", "确认路径后重试。"))
    else:
        findings, passed = check_project(target)
    score = health_score(findings)
    baseline_file = Path(args.baseline_file).expanduser().resolve() if args.baseline_file else None
    if args.format == "json":
        # Use args.target (user's input) rather than target.resolve() so the displayed
        # path matches what the user typed, even when macOS directory hardlinks cause
        # resolve() to return a sibling path.
        display_target = str(Path(args.target).expanduser())
        print(json.dumps({"target": display_target, "score": score, "status": health_status(score, findings), "scoring_formula": SCORING_FORMULA, "severity_counts": severity_counts(findings), "baseline": baseline_status(score, baseline_file), "findings": [asdict(item) for item in findings], "passed_checks": passed}, ensure_ascii=False, indent=2))
    else:
        print(render_check(target, findings, passed, display_target=str(Path(args.target).expanduser())))
    return 0 if not any(item.level == "fail" for item in findings) else 2


def command_match(args: argparse.Namespace) -> int:
    query = args.text
    if args.file:
        query = read_text(Path(args.file), 100000)
    matches = match_prescriptions(query, load_prescriptions())
    if args.format == "json":
        print(json.dumps({"query": query[:1000], "matches": [{"score": s, "matched": m, **asdict(p)} for s, m, p in matches[:5]]}, ensure_ascii=False, indent=2))
    else:
        print(render_matches(query, matches))
    return 0


def command_plan(args: argparse.Namespace) -> int:
    prescriptions = load_prescriptions()
    item: Prescription | None = None
    if args.rx_id:
        item = next((p for p in prescriptions if p.rx_id == args.rx_id), None)
    else:
        matches = match_prescriptions(args.text, prescriptions)
        item = matches[0][2] if matches else None
    # Circuit breaker check runs regardless of match outcome — if the same query
    # has been blocked/partial 3 times, surface the warning even when no
    # prescription matches (otherwise an unrecognised failure pattern would
    # silently bypass the breaker).
    cb = check_circuit_breaker(args.text or args.rx_id)
    if not item:
        if cb.get("triggered"):
            print("⚠️ 熔断触发（Circuit Breaker）— 未匹配到药方但同类问题已连续失败 3 次")
            print(f"原因：{cb.get('reason')}")
            print(f"连续失败次数：{cb.get('consecutive', 0)}")
            print(f"最后状态：{cb.get('last_status', 'unknown')}")
            print("动作：停止生成新方案，降级为仅报告 + 人工复核。")
            return 1
        print("未找到可生成修复计划的药方。请先运行 match。")
        return 1
    plan = build_plan(item, args.text or args.rx_id)
    if cb.get("triggered"):
        plan["circuit_breaker"] = cb
        plan["confirmation_required"] = True
    if args.format == "json":
        print(json.dumps({"prescription": asdict(item), "plan": plan, "circuit_breaker": cb}, ensure_ascii=False, indent=2))
    else:
        print(render_plan(plan))
    return 0


def command_record(args: argparse.Namespace) -> int:
    # L-1: resolve and sandbox case_dir to user home / cwd / system temp only
    case_dir = Path(args.case_dir).expanduser().resolve()
    cwd = Path.cwd().resolve()
    home = Path.home().resolve()
    temp_dir = Path(tempfile.gettempdir()).resolve()
    allowed_roots = [home, cwd, temp_dir, Path("/tmp").resolve(), Path("/private/tmp").resolve()]
    if not any(str(case_dir).startswith(str(root)) for root in allowed_roots):
        print(f"REFUSED: case_dir {case_dir} must be under HOME, cwd, or system temp.")
        return 2
    case_dir.mkdir(parents=True, exist_ok=True)
    # Use microsecond precision so consecutive `record` calls in the same second
    # don't overwrite each other. The previous second-precision format made
    # writing 2+ cases within a single second silently clobber earlier files,
    # which broke any test or tool that relied on the count of stored cases
    # (notably the circuit breaker in check_circuit_breaker, which reads the
    # 3 most recent case files).
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", redacted(args.title).strip().lower()).strip("-") or "case"
    # L-1: ensure final path is still within case_dir (no path traversal via title)
    path = (case_dir / f"{timestamp}-{slug}.md").resolve()
    if not str(path).startswith(str(case_dir)):
        print(f"REFUSED: computed path {path} escapes case_dir {case_dir}.")
        return 2
    body = "\n".join(
        [
            "---",
            f"title: {redacted(args.title)}",
            f"status: {args.status}",
            f"created_at: {datetime.now(timezone.utc).isoformat()}",
            "---",
            "",
            "# Hermes Doctor Case",
            "",
            f"## Summary\n\n{redacted(args.summary)}",
        ]
    )
    path.write_text(body + "\n", encoding="utf-8")
    print(path)
    return 0


def command_search(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir).expanduser()
    query = args.query.lower()
    if not case_dir.exists():
        print("Hermes Doctor 病历查询\n\n暂无病历。")
        return 0
    matches = []
    for path in sorted(case_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
        text = read_text(path, 20000)
        if not query or query in text.lower() or query in path.name.lower():
            matches.append((path, text))
        if len(matches) >= 5:
            break
    lines = ["Hermes Doctor 病历查询", "", f"查询词：{args.query or '(最近病历)'}", ""]
    if not matches:
        lines.append("没有找到匹配病历。")
    for path, text in matches:
        first = next((line for line in text.splitlines() if line and not line.startswith("---")), path.name)
        lines.extend([f"- {path.name}", f"  摘要：{first[:160]}"])
    print("\n".join(lines))
    return 0


def command_route(args: argparse.Namespace) -> int:
    route = route_text(args.text)
    if args.format == "json":
        print(json.dumps(asdict(route), ensure_ascii=False, indent=2))
    else:
        print("\n".join(["Hermes Doctor 消息路由", "", f"意图：{route.intent}", f"动作：{route.action}", f"命令：{' '.join(route.command)}", f"是否需要确认：{'是' if route.confirmation_required else '否'}", f"回复提示：{route.reply_hint}"]))
    return 0


def command_validate(args: argparse.Namespace) -> int:
    target = Path(args.target).expanduser().resolve()
    # NOTE: "白龙马医生（Hermes）技能设计手册 v1.0.md" is the internal design doc
    # (kept in repo root for traceability). It is intentionally NOT in the required
    # list because macOS stock `unzip` fails on its UTF-8 Chinese filename with
    # "write error" / "fchmod error", which would cascade into a validate failure
    # and break every zip-based install. The design doc is optional content, not
    # a runtime dependency.
    required = [
        ".hermes-skill/plugin.json",
        ".hermes-skill/marketplace.json",
        "SKILL.md",
        "README.md",
        "scripts/hermes_doctor.py",
        "references/prd_summary.md",
        "references/prescriptions.md",
        "references/safety_policy.md",
        "references/test_cases.md",
        "scripts/bailongma-doctor",
        "scripts/bailongma-doctor.cmd",
        "skills/hermes-check/SKILL.md",
        "skills/prescription-match/SKILL.md",
        "skills/repair-plan/SKILL.md",
        "skills/case-record/SKILL.md",
        "skills/case-search/SKILL.md",
        "skills/feishu-route/SKILL.md",
    ]
    missing = [item for item in required if not (target / item).exists()]
    if missing:
        print("FAIL missing required files:")
        for item in missing:
            print(f"- {item}")
        return 1
    json.loads(read_text(target / ".hermes-skill" / "plugin.json"))
    json.loads(read_text(target / ".hermes-skill" / "marketplace.json"))
    prescription_ids = {item.rx_id for item in load_prescriptions(target / "references" / "prescriptions.md")}
    missing_prescriptions = sorted(REQUIRED_PRESCRIPTIONS - prescription_ids)
    if missing_prescriptions:
        print("FAIL missing required prescriptions:")
        for item in missing_prescriptions:
            print(f"- {item}")
        return 1
    if len(prescription_ids) < 12:
        print(f"FAIL prescription count < 12: {len(prescription_ids)}")
        return 1
    print("OK")
    return 0


def run_subprocess(command: list[str], cwd: Path, expect: str, exit_codes: tuple[int, ...] = (0,)) -> tuple[bool, str]:
    proc = subprocess.run(command, cwd=str(cwd), text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    output = proc.stdout.strip()
    return proc.returncode in exit_codes and expect in output, output


def command_test(args: argparse.Namespace) -> int:
    root = Path(args.target).expanduser().resolve()
    py = sys.executable
    case_dir = Path(tempfile.mkdtemp(prefix="hermes-doctor-tests-"))
    cases = [
        ("validate", [py, str(root / "scripts" / "hermes_doctor.py"), "validate", "--target", str(root)], "OK", (0,)),
        ("check", [py, str(root / "scripts" / "hermes_doctor.py"), "check", "--target", str(root)], "Hermes Doctor 诊断报告", (0, 2)),
        ("check-json", [py, str(root / "scripts" / "hermes_doctor.py"), "check", "--target", str(root), "--format", "json"], '"passed_checks"', (0, 2)),
        ("check-formula", [py, str(root / "scripts" / "hermes_doctor.py"), "check", "--target", str(root), "--format", "json"], '"scoring_formula"', (0, 2)),
        ("missing-path", [py, str(root / "scripts" / "hermes_doctor.py"), "check", "--target", "/no/such/path"], "RX-FILE-001", (2,)),
        ("rx-fetch", [py, str(root / "scripts" / "hermes_doctor.py"), "match", "--text", "Hermes fetch failed timeout 访问不到网页"], "RX-RUNTIME-001", (0,)),
        ("rx-tool", [py, str(root / "scripts" / "hermes_doctor.py"), "match", "--text", "unknown tool 工具调用失败"], "RX-TOOL-001", (0,)),
        ("rx-secret", [py, str(root / "scripts" / "hermes_doctor.py"), "match", "--text", "token=abc123 cookie=xyz password=hello"], "RX-SAFETY-001", (0,)),
        ("rx-jwt", [py, str(root / "scripts" / "hermes_doctor.py"), "match", "--text", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc csrf_token=xyz"], "RX-SAFETY-001", (0,)),  # M-2: JWT/Bearer/csrf redaction
        ("plan", [py, str(root / "scripts" / "hermes_doctor.py"), "plan", "--text", "login required captcha rate limit"], "是否需要确认：是", (0,)),
        ("record", [py, str(root / "scripts" / "hermes_doctor.py"), "record", "--case-dir", str(case_dir), "--title", "fetch failed", "--status", "partial", "--summary", "token=abc123"], str(case_dir), (0,)),
        ("search", [py, str(root / "scripts" / "hermes_doctor.py"), "search", "--case-dir", str(case_dir), "--query", "fetch"], "fetch", (0,)),
        ("route", [py, str(root / "scripts" / "hermes_doctor.py"), "route", "--text", "白龙马医生 帮我修一下：fetch failed", "--format", "json"], '"confirmation_required": true', (0,)),
        ("wrapper", [str(root / "scripts" / "bailongma-doctor"), "match", "--text", "unknown tool 工具调用失败"], "RX-TOOL-001", (0,)),
    ]
    failures = 0
    try:
        for name, command, expect, codes in cases:
            ok, output = run_subprocess(command, root.parent, expect, codes)
            print(f"{'OK' if ok else 'FAIL'} {name}")
            if not ok:
                failures += 1
                print(output[:1200])
        print(f"summary: {len(cases) - failures}/{len(cases)} passed")
    finally:
        # L-3: clean up the test tempdir so we don't leak /tmp entries
        shutil.rmtree(case_dir, ignore_errors=True)
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes Doctor CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="run read-only health check")
    p.add_argument("--target", default=".")
    p.add_argument("--baseline-file", help="optional read-only health baseline JSON file")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.set_defaults(func=command_check)

    p = sub.add_parser("match", help="match error text to prescriptions")
    p.add_argument("--text", default="")
    p.add_argument("--file")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.set_defaults(func=command_match)

    p = sub.add_parser("plan", help="generate confirmation-ready repair plan")
    p.add_argument("--text", default="")
    p.add_argument("--rx-id", default="")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.set_defaults(func=command_plan)

    p = sub.add_parser("record", help="write redacted case note")
    p.add_argument("--case-dir", default=os.environ.get("HERMES_DOCTOR_CASE_DIR", ".doctor/cases"))
    p.add_argument("--title", required=True)
    p.add_argument("--status", choices=["fixed", "partial", "blocked"], required=True)
    p.add_argument("--summary", required=True)
    p.set_defaults(func=command_record)

    p = sub.add_parser("search", help="search case notes")
    p.add_argument("--case-dir", default=os.environ.get("HERMES_DOCTOR_CASE_DIR", ".doctor/cases"))
    p.add_argument("--query", default="")
    p.set_defaults(func=command_search)

    p = sub.add_parser("route", help="route Feishu/Lark message text")
    p.add_argument("--text", required=True)
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.set_defaults(func=command_route)

    p = sub.add_parser("validate", help="validate Hermes Doctor package")
    p.add_argument("--target", default=str(ROOT))
    p.set_defaults(func=command_validate)

    p = sub.add_parser("test", help="run smoke tests")
    p.add_argument("--target", default=str(ROOT))
    p.set_defaults(func=command_test)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
