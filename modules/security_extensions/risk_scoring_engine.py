# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Risk Scoring Engine
AtomCollide-智械工坊 · 2026

Unified risk scoring engine that aggregates threats from all detection modules
and produces a 0-100 risk score with severity labels and recommendations.

Product risk scoring system for agent security findings.

Scoring Formula:
  CRITICAL: +50 points each
  HIGH:     +25 points each
  MEDIUM:   +10 points each
  LOW:      +5 points each
  Executable scripts multiplier: 1.3x

Severity Levels:
  0-20:   LOW     → SAFE to install
  21-50:  MEDIUM  → CAUTION, review findings
  51-80:  HIGH    → DO NOT INSTALL without remediation
  81-100: CRITICAL → DO NOT INSTALL

Usage:
    from modules.risk_scoring_engine import RiskScorer
    scorer = RiskScorer()
    scorer.add_threats(ast_threats, source="ast_analyzer")
    scorer.add_threats(mcp_threats, source="mcp_analyzer")
    report = scorer.generate_report()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Score contribution per severity
_SEVERITY_SCORES = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
}

# Risk level thresholds
_RISK_THRESHOLDS = [
    (81, RiskLevel.CRITICAL),
    (51, RiskLevel.HIGH),
    (21, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
]

# Recommendations per risk level
_RECOMMENDATIONS = {
    RiskLevel.LOW: "SAFE — No significant issues found. Proceed with installation.",
    RiskLevel.MEDIUM: "CAUTION — Review flagged items before installation. Low-confidence findings may be false positives.",
    RiskLevel.HIGH: "DO NOT INSTALL — Significant security issues detected. Remediate before use.",
    RiskLevel.CRITICAL: "DO NOT INSTALL — Critical security vulnerabilities found. This skill may be malicious.",
}


@dataclass
class AggregatedThreat:
    """A threat from any detection module, normalized for scoring."""
    rule_id: str
    category: str
    severity: Severity
    confidence: float
    source_module: str
    description: str
    filename: str = ""
    line: int = 0
    matched_text: str = ""
    mitigation: str = ""


@dataclass
class RiskReport:
    """Final risk assessment report."""
    target: str
    score: int
    risk_level: RiskLevel
    recommendation: str
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    has_executable_scripts: bool
    executable_multiplier: float
    category_breakdown: Dict[str, int]
    source_breakdown: Dict[str, int]
    threats: List[Dict[str, Any]]
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "recommendation": self.recommendation,
            "total_threats": self.total_threats,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "has_executable_scripts": self.has_executable_scripts,
            "executable_multiplier": self.executable_multiplier,
            "category_breakdown": self.category_breakdown,
            "source_breakdown": self.source_breakdown,
            "threats": self.threats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary(self) -> str:
        emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
        e = emoji.get(self.risk_level.value, "⚪")
        lines = [
            f"{e} Risk Score: {self.score}/100 — {self.risk_level.value}",
            f"Threats: {self.total_threats} ({self.critical_count}C {self.high_count}H {self.medium_count}M {self.low_count}L)",
            f"Recommendation: {self.recommendation}",
        ]
        if self.has_executable_scripts:
            lines.append(f"⚠️  Executable scripts detected (1.3x multiplier applied)")
        return "\n".join(lines)


class RiskScorer:
    """
    Aggregates threats from multiple detection modules and computes
    a unified risk score.
    """

    def __init__(self, target: str = "<unknown>"):
        self.target = target
        self._threats: List[AggregatedThreat] = []
        self._has_executables = False

    def add_threats(self, threats: list, source: str = "unknown") -> None:
        """
        Add threats from any detection module.

        Accepts threats with attributes: rule_id, severity, confidence, description,
        filename, line, matched_text, mitigation. Works with dataclass threats from
        any Genesisix detection module.
        """
        for t in threats:
            sev_str = getattr(t, "severity", "medium").lower()
            try:
                sev = Severity(sev_str)
            except ValueError:
                sev = Severity.MEDIUM

            self._threats.append(AggregatedThreat(
                rule_id=getattr(t, "rule_id", "UNK"),
                category=getattr(t, "pattern_name", getattr(t, "category", "unknown")),
                severity=sev,
                confidence=getattr(t, "confidence", 0.5),
                source_module=source,
                description=getattr(t, "description", ""),
                filename=getattr(t, "filename", ""),
                line=getattr(t, "line", 0),
                matched_text=getattr(t, "matched_text", ""),
                mitigation=getattr(t, "mitigation", ""),
            ))

    def set_executable_flag(self, has_executables: bool) -> None:
        """Set whether the scanned target contains executable scripts."""
        self._has_executables = has_executables

    def compute_score(self) -> int:
        """Compute raw risk score (0-100, capped)."""
        if not self._threats:
            return 0

        raw = sum(
            _SEVERITY_SCORES[t.severity] * t.confidence
            for t in self._threats
        )

        multiplier = 1.3 if self._has_executables else 1.0
        score = int(min(100, raw * multiplier))
        return score

    def get_risk_level(self, score: int) -> RiskLevel:
        """Map numeric score to risk level."""
        for threshold, level in _RISK_THRESHOLDS:
            if score >= threshold:
                return level
        return RiskLevel.LOW

    def generate_report(self) -> RiskReport:
        """Generate the full risk report."""
        score = self.compute_score()
        risk_level = self.get_risk_level(score)

        cat_breakdown: Dict[str, int] = {}
        src_breakdown: Dict[str, int] = {}
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        threat_dicts = []
        for t in self._threats:
            sev_counts[t.severity.value] += 1
            cat_breakdown[t.category] = cat_breakdown.get(t.category, 0) + 1
            src_breakdown[t.source_module] = src_breakdown.get(t.source_module, 0) + 1
            threat_dicts.append({
                "rule_id": t.rule_id,
                "category": t.category,
                "severity": t.severity.value,
                "confidence": t.confidence,
                "source": t.source_module,
                "description": t.description,
                "filename": t.filename,
                "line": t.line,
                "matched_text": t.matched_text,
                "mitigation": t.mitigation,
            })

        return RiskReport(
            target=self.target,
            score=score,
            risk_level=risk_level,
            recommendation=_RECOMMENDATIONS[risk_level],
            total_threats=len(self._threats),
            critical_count=sev_counts["critical"],
            high_count=sev_counts["high"],
            medium_count=sev_counts["medium"],
            low_count=sev_counts["low"],
            has_executable_scripts=self._has_executables,
            executable_multiplier=1.3 if self._has_executables else 1.0,
            category_breakdown=cat_breakdown,
            source_breakdown=src_breakdown,
            threats=threat_dicts,
        )
