# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Memory Poisoning Detector
AtomCollide-智械工坊 · 2026

Detects memory/context poisoning attacks in AI agent skills and prompts.
Inspired by NVIDIA SkillSpector's memory poisoning category (3 patterns).

Detection Patterns:
  MP1: Persistent Context Injection — instructions that modify agent memory/state
  MP2: Session Data Manipulation — attempts to alter conversation history
  MP3: Temporal Attack — time-delayed or conditional payload activation

Usage:
    from modules.memory_poisoning_detector import scan_memory_poisoning
    threats = scan_memory_poisoning(text, filename="skill.md")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MemoryPoisoningThreat:
    """A single memory poisoning threat."""
    rule_id: str
    pattern_name: str
    description: str
    severity: str          # critical / high / medium / low
    confidence: float      # 0.0 - 1.0
    filename: str
    line: int
    matched_text: str
    mitigation: str = ""


# ============================================================
# Pattern Definitions
# ============================================================

_MP1_PATTERNS = [
    # Direct memory/state modification instructions
    (re.compile(
        r"(?:remember|store|save|cache|memorize|keep)\s+(?:this|the following|that)",
        re.IGNORECASE
    ), "Direct memory store instruction", 0.70),
    (re.compile(
        r"(?:always|from now on|forever|permanently)\s+(?:respond|answer|act|behave|treat)",
        re.IGNORECASE
    ), "Persistent behavior modification", 0.80),
    (re.compile(
        r"(?:update|modify|change|alter|overwrite)\s+(?:your|the)\s+(?:memory|context|state|profile|persona)",
        re.IGNORECASE
    ), "Memory overwrite instruction", 0.85),
    (re.compile(
        r"(?:system|global|persistent)\s+(?:prompt|instruction|rule|directive)\s*(?::|is|=)",
        re.IGNORECASE
    ), "System prompt injection via memory", 0.90),
    (re.compile(
        r"(?:forget|erase|clear|wipe|reset)\s+(?:your|all|previous|prior)\s+(?:instructions|rules|constraints|memory)",
        re.IGNORECASE
    ), "Memory erasure attack", 0.95),
]

_MP2_PATTERNS = [
    # Session/conversation history manipulation
    (re.compile(
        r"(?:prepend|append|insert|inject|add)\s+(?:to|into|before|after)\s+(?:the|your)\s+(?:conversation|history|context|messages)",
        re.IGNORECASE
    ), "Conversation history injection", 0.85),
    (re.compile(
        r"(?:previous|prior|above)\s+(?:message|instruction|prompt)\s+(?:was|is|should be|says)",
        re.IGNORECASE
    ), "Fake prior instruction reference", 0.80),
    (re.compile(
        r"(?:user|human|admin|developer)\s+(?:said|told|requested|confirmed)\s+(?:that|to|you should)",
        re.IGNORECASE
    ), "Fabricated user instruction", 0.75),
    (re.compile(
        r"\[(?:system|assistant|user)\]", re.IGNORECASE
    ), "Chat role tag injection", 0.90),
    (re.compile(
        r"(?:ignore|disregard|forget)\s+(?:the\s+)?(?:previous|above|earlier|prior)\s+(?:conversation|messages|context)",
        re.IGNORECASE
    ), "Context dismissal attack", 0.90),
]

_MP3_PATTERNS = [
    # Time-delayed or conditional activation
    (re.compile(
        r"(?:after|when|once|if)\s+(?:\d+|several|many|a few)\s+(?:messages?|turns?|interactions?|requests?)",
        re.IGNORECASE
    ), "Delayed activation trigger", 0.70),
    (re.compile(
        r"(?:on|after|when)\s+(?:the\s+)?(?:next|third|fifth|tenth|Nth)\s+(?:message|turn|request|interaction)",
        re.IGNORECASE
    ), "Nth-message trigger", 0.75),
    (re.compile(
        r"(?:if|when)\s+(?:you|the agent)\s+(?:has been|have been|are)\s+(?:running|active|online)\s+for",
        re.IGNORECASE
    ), "Time-based activation", 0.80),
    (re.compile(
        r"(?:activate|enable|trigger|execute)\s+(?:after|on|when)\s+(?:condition|threshold|count|timer)",
        re.IGNORECASE
    ), "Conditional payload activation", 0.85),
    (re.compile(
        r"(?:day|hour|minute|week)\s+\d+.*?(?:then|execute|activate|run|deploy)",
        re.IGNORECASE | re.DOTALL
    ), "Calendar-triggered payload", 0.75),
]


# ============================================================
# Scanner
# ============================================================

def scan_memory_poisoning(
    text: str,
    filename: str = "<string>",
) -> List[MemoryPoisoningThreat]:
    """
    Scan text for memory poisoning patterns.

    Args:
        text: Source code or prompt text to scan.
        filename: Name of the file being scanned (for reporting).

    Returns:
        List of MemoryPoisoningThreat objects found.
    """
    threats: List[MemoryPoisoningThreat] = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # MP1: Persistent Context Injection
        for pattern, desc, conf in _MP1_PATTERNS:
            m = pattern.search(line)
            if m:
                threats.append(MemoryPoisoningThreat(
                    rule_id="MP1",
                    pattern_name="Persistent Context Injection",
                    description=desc,
                    severity="high" if conf >= 0.85 else "medium",
                    confidence=conf,
                    filename=filename,
                    line=line_num,
                    matched_text=m.group(0)[:120],
                    mitigation="Remove persistent behavior modification instructions from skill content.",
                ))

        # MP2: Session Data Manipulation
        for pattern, desc, conf in _MP2_PATTERNS:
            m = pattern.search(line)
            if m:
                threats.append(MemoryPoisoningThreat(
                    rule_id="MP2",
                    pattern_name="Session Data Manipulation",
                    description=desc,
                    severity="high" if conf >= 0.85 else "medium",
                    confidence=conf,
                    filename=filename,
                    line=line_num,
                    matched_text=m.group(0)[:120],
                    mitigation="Sanitize conversation history injection attempts.",
                ))

        # MP3: Temporal Attack
        for pattern, desc, conf in _MP3_PATTERNS:
            m = pattern.search(line)
            if m:
                threats.append(MemoryPoisoningThreat(
                    rule_id="MP3",
                    pattern_name="Temporal Attack",
                    description=desc,
                    severity="high" if conf >= 0.80 else "medium",
                    confidence=conf,
                    filename=filename,
                    line=line_num,
                    matched_text=m.group(0)[:120],
                    mitigation="Remove time-delayed or conditional activation triggers.",
                ))

    return threats


def scan_memory_poisoning_dir(
    directory: str,
    extensions: tuple = (".md", ".txt", ".py", ".yaml", ".yml", ".json"),
) -> List[MemoryPoisoningThreat]:
    """Scan all text files in a directory for memory poisoning."""
    from pathlib import Path

    all_threats: List[MemoryPoisoningThreat] = []
    dir_path = Path(directory)

    for ext in extensions:
        for fpath in dir_path.rglob(f"*{ext}"):
            if ".git" in str(fpath) or "__pycache__" in str(fpath):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                threats = scan_memory_poisoning(content, filename=str(fpath))
                all_threats.extend(threats)
            except Exception:
                continue

    return all_threats
