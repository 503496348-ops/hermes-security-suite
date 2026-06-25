# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · SARIF Report Generator
AtomCollide-智械工坊 · 2026

Generates SARIF (Static Analysis Results Interchange Format) v2.1.0 reports
for CI/CD integration (GitHub Code Scanning, Azure DevOps, VS Code SARIF viewer).

SARIF is the OASIS standard for static analysis tool output. GitHub can ingest
SARIF files to display security findings directly in the Security tab.

Usage:
    from modules.sarif_reporter import generate_sarif
    sarif_json = generate_sarif(report_dict, tool_name="genesisix", tool_version="2.0")
    
    # Write to file
    with open("results.sarif", "w") as f:
        f.write(sarif_json)

References:
    - SARIF v2.1.0 spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
    - GitHub SARIF upload: https://docs.github.com/en/code-security/code-scanning
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# SARIF severity mapping
_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _make_rule_id(threat: Dict[str, Any]) -> str:
    """Generate a stable SARIF rule ID from a threat."""
    rid = threat.get("rule_id", "UNK")
    category = threat.get("category", "unknown").replace(" ", "_").lower()[:30]
    return f"GENESISIX_{rid}_{category}"


def _make_location(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Build a SARIF location object from a threat."""
    filename = threat.get("filename", "")
    line_num = threat.get("line", 1)

    location = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": filename if filename else "<unknown>",
                "uriBaseId": "%SRCROOT%",
            },
            "region": {
                "startLine": max(1, line_num),
            },
        },
    }

    # Add snippet if we have matched text
    matched = threat.get("matched_text", "")
    if matched:
        location["physicalLocation"]["region"]["snippet"] = {"text": matched[:500]}

    return location


def _make_result(threat: Dict[str, Any]) -> Dict[str, Any]:
    """Build a SARIF result from a threat."""
    severity = threat.get("severity", "medium").lower()
    rule_id = _make_rule_id(threat)

    result = {
        "ruleId": rule_id,
        "level": _LEVEL_MAP.get(severity, "warning"),
        "message": {
            "text": threat.get("description", "Security issue detected"),
        },
        "locations": [_make_location(threat)],
        "properties": {
            "confidence": threat.get("confidence", 0.5),
            "source_module": threat.get("source", "unknown"),
        },
    }

    # Add remediation if available
    mitigation = threat.get("mitigation", "")
    if mitigation:
        result["fixes"] = [{
            "description": {"text": mitigation},
        }]

    return result


def _make_rules(threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build SARIF rule definitions from threats."""
    rules = {}
    for t in threats:
        rule_id = _make_rule_id(t)
        if rule_id not in rules:
            severity = t.get("severity", "medium").lower()
            rules[rule_id] = {
                "id": rule_id,
                "name": t.get("category", "SecurityIssue"),
                "shortDescription": {
                    "text": t.get("description", "Security issue")[:200],
                },
                "fullDescription": {
                    "text": "[" + str(t.get("rule_id", "")) + "] " + str(t.get("description", "")),
                },
                "defaultConfiguration": {
                    "level": _LEVEL_MAP.get(severity, "warning"),
                },
                "properties": {
                    "tags": ["security", "genesisix"],
                },
            }
    return rules


def generate_sarif(
    report: Dict[str, Any],
    tool_name: str = "genesisix",
    tool_version: str = "2.0",
    tool_vendor: str = "AtomCollide",
) -> str:
    """
    Generate a SARIF v2.1.0 JSON report from a Genesisix scan report.

    Args:
        report: A dict with at least a "threats" key containing a list of threat dicts.
                Can also be a RiskReport.to_dict() output.
        tool_name: Name of the scanning tool.
        tool_version: Version of the scanning tool.
        tool_vendor: Vendor/organization name.

    Returns:
        SARIF JSON string (suitable for writing to .sarif file).
    """
    threats = report.get("threats", [])
    target = report.get("target", "<unknown>")

    # Build results
    results = [_make_result(t) for t in threats]

    # Build rule definitions
    rules = _make_rules(threats)

    # Build SARIF structure
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "semanticVersion": tool_version,
                        "informationUri": "https://github.com/503496348-ops/hermes-security-suite",
                        "organization": tool_vendor,
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "properties": {
                    "target": target,
                    "score": report.get("score", 0),
                    "risk_level": report.get("risk_level", "UNKNOWN"),
                    "total_threats": report.get("total_threats", len(threats)),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            }
        ],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)


def generate_markdown_report(
    report: Dict[str, Any],
    tool_name: str = "Genesisix",
) -> str:
    """
    Generate a human-readable Markdown report from scan results.

    Args:
        report: Scan report dict (from RiskReport.to_dict() or unified_scan).
        tool_name: Tool name for the report header.

    Returns:
        Markdown-formatted report string.
    """
    score = report.get("score", 0)
    risk_level = report.get("risk_level", "UNKNOWN")
    recommendation = report.get("recommendation", "")
    total = report.get("total_threats", 0)
    target = report.get("target", "<unknown>")

    emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪")

    sev = report.get("severity_counts", {})
    c_count = sev.get("critical", 0)
    h_count = sev.get("high", 0)
    m_count = sev.get("medium", 0)
    l_count = sev.get("low", 0)

    lines = [
        f"# {tool_name} Security Scan Report",
        "",
        f"**Target:** `{target}`",
        f"**Risk Score:** {score}/100 {emoji} ({risk_level})",
        f"**Total Threats:** {total} ({c_count} Critical, {h_count} High, {m_count} Medium, {l_count} Low)",
        "",
        f"**Recommendation:** {recommendation}",
        "",
    ]

    # Category breakdown
    cat = report.get("category_breakdown", {})
    if cat:
        lines.append("## Findings by Category")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat_name, count in sorted(cat.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat_name} | {count} |")
        lines.append("")

    # Detailed threats
    threats = report.get("threats", [])
    if threats:
        lines.append("## Detailed Findings")
        lines.append("")
        for i, t in enumerate(threats[:50], 1):  # Cap at 50 for readability
            sev = t.get("severity", "medium").upper()
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            rid = t.get("rule_id", "")
            cat = t.get("category", "")
            conf = t.get("confidence", 0)
            src = t.get("source", "unknown")
            fname = t.get("filename", "")
            line_no = t.get("line", 0)
            matched = t.get("matched_text", "")[:100]
            mitig = t.get("mitigation", "")
            lines.append(f"### {i}. {sev_emoji} [{rid}] {cat}")
            lines.append(f"- **Severity:** {sev} (confidence: {conf:.0%})")
            lines.append(f"- **Source:** {src}")
            if fname:
                lines.append(f"- **Location:** `{fname}:{line_no}`")
            if matched:
                lines.append(f"- **Matched:** `{matched}`")
            if mitig:
                lines.append(f"- **Fix:** {mitig}")
            lines.append("")

    if len(threats) > 50:
        lines.append(f"*... and {len(threats) - 50} more findings (see JSON/SARIF for full report)*")

    return "\n".join(lines)
