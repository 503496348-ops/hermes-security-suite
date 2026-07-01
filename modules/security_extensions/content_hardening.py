"""Content hardening utilities for agent-facing research and browser content."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from html import unescape
import re
from typing import Iterable, List, Mapping
ACTIVE_TAG_RE = re.compile(r"<\s*(script|iframe|object|embed|style|meta|link|form|input|button)\b.*?><\s*/?\s*\1\s*>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
URL_RE = re.compile(r"https?://[^\s)\]}>\"']+", re.I)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
INSTRUCTION_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "system_override": re.compile(r"(?i)\b(ignore|override|bypass)\b.{0,40}\b(system|developer|previous|policy|instruction)s?\b"),
    "secret_exfiltration": re.compile(r"(?i)\b(api[_ -]?key|token|password|secret|credential|private key)\b.{0,60}\b(print|dump|show|return|exfiltrate)\b"),
    "tool_abuse": re.compile(r"(?i)\b(run|execute|call)\b.{0,50}\b(shell|bash|curl|wget|python|powershell|terminal)\b"),
    "role_confusion": re.compile(r"(?i)\b(you are now|act as|developer mode|jailbreak|godmode)\b"),
    "hidden_prompt": re.compile(r"(?i)\b(hidden|invisible|base64|rot13|zero[- ]?width|steganograph)\b.{0,50}\b(prompt|instruction|payload)\b"),
}
@dataclass(frozen=True)
class HardeningFinding:
    rule_id: str; severity: str; description: str; evidence: str
@dataclass(frozen=True)
class HardenedContent:
    text: str; urls: List[str]; findings: List[HardeningFinding]; risk_score: int; safe_for_context: bool
    def to_dict(self) -> dict:
        return {"text": self.text, "urls": self.urls, "findings": [asdict(f) for f in self.findings], "risk_score": self.risk_score, "safe_for_context": self.safe_for_context}
def _clip(value: str, limit: int = 120) -> str:
    value = " ".join(value.split()); return value[:limit] + ("…" if len(value) > limit else "")
def sanitize_markup(raw: str) -> str:
    text = unescape(raw or "")
    text = ACTIVE_TAG_RE.sub(" ", text); text = TAG_RE.sub(" ", text); text = CONTROL_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()
def detect_instruction_smuggling(text: str) -> List[HardeningFinding]:
    findings=[]
    for rule_id, pattern in INSTRUCTION_PATTERNS.items():
        for match in pattern.finditer(text):
            severity = "high" if rule_id in {"system_override", "secret_exfiltration"} else "medium"
            findings.append(HardeningFinding(rule_id, severity, "Untrusted content contains agent-directed instruction", _clip(match.group(0))))
    return findings
def harden_untrusted_content(raw: str, *, max_chars: int = 6000) -> HardenedContent:
    sanitized = sanitize_markup(raw); urls = sorted(set(URL_RE.findall(sanitized))); findings = detect_instruction_smuggling(sanitized)
    if len(raw or "") > max_chars:
        findings.append(HardeningFinding("oversized_context", "low", "Untrusted content exceeded context budget and was truncated", str(len(raw or ""))))
        sanitized = sanitized[:max_chars].rstrip()
    score = min(100, sum(45 if f.severity == "high" else 20 if f.severity == "medium" else 5 for f in findings))
    return HardenedContent(sanitized, urls, findings, score, score < 40)
def batch_harden(items: Iterable[str], *, max_chars: int = 6000) -> List[HardenedContent]:
    return [harden_untrusted_content(item, max_chars=max_chars) for item in items]
