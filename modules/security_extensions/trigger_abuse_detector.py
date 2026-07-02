# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Trigger Abuse Detector
AtomCollide-智械工坊 · 2026

Detects trigger abuse patterns in AI agent skills — hidden triggers that
cause unintended behavior when specific conditions are met.

Trigger abuse detection patterns for agent security workflows.

Detection Patterns:
  TA1: Shadow Command Trigger — hidden commands activated by specific keywords
  TA2: Conditional Trigger — behavior changes based on environment/context
  TA3: Environment Trigger — activation based on system state detection

Usage:
    from modules.trigger_abuse_detector import scan_trigger_abuse
    threats = scan_trigger_abuse(text, filename="skill.md")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TriggerAbuseThreat:
    """A single trigger abuse threat."""
    rule_id: str
    pattern_name: str
    description: str
    severity: str
    confidence: float
    filename: str
    line: int
    matched_text: str
    mitigation: str = ""


# ============================================================
# TA1: Shadow Command Trigger
# ============================================================

_TA1_PATTERNS = [
    (re.compile(
        r"(?:if|when)\s+(?:input|message|text|query)\s*(?:==|contains?|matches?|equals?|is)\s*[\"\']",
        re.IGNORECASE
    ), "Keyword-gated behavior switch", 0.75),
    (re.compile(
        r"(?:secret|hidden|backdoor|magic|special)\s+(?:keyword|word|phrase|command|code|trigger)",
        re.IGNORECASE
    ), "Explicit shadow command reference", 0.90),
    (re.compile(
        r"(?:activate|enable|switch\s+to|enter)\s+(?:mode|debug|admin|root|sudo|god|jailbreak)",
        re.IGNORECASE
    ), "Privilege escalation trigger", 0.95),
    (re.compile(
        r"(?:when|if)\s+(?:the\s+)?(?:user|human)\s+(?:says?|types?|mentions?)\s+[\"\']\\w+[\"\']",
        re.IGNORECASE
    ), "User-utterance gated trigger", 0.70),
    (re.compile(
        r"(?:case|match|switch)\s*\(.*?(?:trigger|activate|execute|deploy)",
        re.IGNORECASE | re.DOTALL
    ), "Switch-case trigger dispatch", 0.80),
]

# ============================================================
# TA2: Conditional Trigger
# ============================================================

_TA2_PATTERNS = [
    (re.compile(
        r"(?:if|when|unless)\s+(?:running|deployed|hosted)\s+(?:on|in|at|from)\s+",
        re.IGNORECASE
    ), "Deployment environment check", 0.75),
    (re.compile(
        r"(?:detect|check|scan|probe)\s+(?:os|platform|hostname|ip|environment|provider)",
        re.IGNORECASE
    ), "Environment fingerprinting", 0.80),
    (re.compile(
        r"(?:if|when)\s+(?:user|caller|requester)\s+(?:is|has|owns?|belongs?)\s+(?:admin|root|owner|superuser)",
        re.IGNORECASE
    ), "Role-based conditional behavior", 0.85),
    (re.compile(
        r"(?:sandbox|container|vm|virtual|ci|cd|github|gitlab)\s+(?:is|was|detected|found|present)",
        re.IGNORECASE
    ), "Sandbox detection trigger", 0.85),
    (re.compile(
        r"(?:if|check|detect)\s+(?:.env|api.?key|token|secret|password|credential)\s+(?:exists?|is|present|available)",
        re.IGNORECASE
    ), "Credential presence trigger", 0.80),
]

# ============================================================
# TA3: Environment Trigger
# ============================================================

_TA3_PATTERNS = [
    (re.compile(
        r"(?:os\.environ|getenv|process\.env|ENV)\s*\[",
        re.IGNORECASE
    ), "Environment variable access", 0.60),
    (re.compile(
        r"(?:import|require)\s+(?:socket|platform|sys|os|subprocess)",
        re.IGNORECASE
    ), "System module import for fingerprinting", 0.50),
    (re.compile(
        r"(?:ip|hostname|machine.?id|device.?id|user.?agent)\s*(?:==|!=|contains?|matches?)",
        re.IGNORECASE
    ), "Hardware/network fingerprint gate", 0.85),
    (re.compile(
        r"(?:time|date|hour|day|month|year|weekday)\s*(?:==|!=|>=|<=|>|<)\s*\d",
        re.IGNORECASE
    ), "Time-based environment trigger", 0.70),
    (re.compile(
        r"(?:file|path|directory)\s+(?:exists?|is.?file|is.?dir|accessible)\s",
        re.IGNORECASE
    ), "Filesystem probe trigger", 0.65),
]


# ============================================================
# Scanner
# ============================================================

def scan_trigger_abuse(
    text: str,
    filename: str = "<string>",
) -> List[TriggerAbuseThreat]:
    """
    Scan text for trigger abuse patterns.

    Args:
        text: Source code or prompt text to scan.
        filename: Name of the file being scanned.

    Returns:
        List of TriggerAbuseThreat objects found.
    """
    threats: List[TriggerAbuseThreat] = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for pattern, desc, conf in _TA1_PATTERNS:
            m = pattern.search(line)
            if m:
                threats.append(TriggerAbuseThreat(
                    rule_id="TA1",
                    pattern_name="Shadow Command Trigger",
                    description=desc,
                    severity="high" if conf >= 0.85 else "medium",
                    confidence=conf,
                    filename=filename,
                    line=line_num,
                    matched_text=m.group(0)[:120],
                    mitigation="Remove hidden keyword-gated behavior switches.",
                ))

        for pattern, desc, conf in _TA2_PATTERNS:
            m = pattern.search(line)
            if m:
                threats.append(TriggerAbuseThreat(
                    rule_id="TA2",
                    pattern_name="Conditional Trigger",
                    description=desc,
                    severity="high" if conf >= 0.85 else "medium",
                    confidence=conf,
                    filename=filename,
                    line=line_num,
                    matched_text=m.group(0)[:120],
                    mitigation="Remove environment-dependent behavior changes.",
                ))

        for pattern, desc, conf in _TA3_PATTERNS:
            m = pattern.search(line)
            if m:
                threats.append(TriggerAbuseThreat(
                    rule_id="TA3",
                    pattern_name="Environment Trigger",
                    description=desc,
                    severity="high" if conf >= 0.80 else "medium",
                    confidence=conf,
                    filename=filename,
                    line=line_num,
                    matched_text=m.group(0)[:120],
                    mitigation="Remove environment fingerprinting and conditional activation.",
                ))

    return threats


def scan_trigger_abuse_dir(
    directory: str,
    extensions: tuple = (".md", ".txt", ".py", ".yaml", ".yml", ".json", ".js", ".ts"),
) -> List[TriggerAbuseThreat]:
    """Scan all text files in a directory for trigger abuse."""
    from pathlib import Path

    all_threats: List[TriggerAbuseThreat] = []
    dir_path = Path(directory)

    for ext in extensions:
        for fpath in dir_path.rglob(f"*{ext}"):
            if ".git" in str(fpath) or "__pycache__" in str(fpath):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                threats = scan_trigger_abuse(content, filename=str(fpath))
                all_threats.extend(threats)
            except Exception:
                continue

    return all_threats
