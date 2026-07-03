"""Runtime policy guard for tool manifests and package vulnerability evidence.

This module is intentionally dependency-free so the detector can run inside
restricted incident-response environments.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

DANGEROUS_SCOPES = {"*", "admin", "root", "system", "filesystem:write", "network:raw"}
SENSITIVE_TOOL_HINTS = ("shell", "exec", "eval", "delete", "write_file", "http_post", "credential")


@dataclass(frozen=True)
class RuntimeFinding:
    rule_id: str
    severity: str
    subject: str
    evidence: str
    recommendation: str


def normalize_scopes(scopes: object) -> list[str]:
    if scopes is None:
        return []
    if isinstance(scopes, str):
        return [part.strip().lower() for part in scopes.replace(",", " ").split() if part.strip()]
    if isinstance(scopes, Iterable):
        return [str(part).strip().lower() for part in scopes if str(part).strip()]
    return [str(scopes).strip().lower()]


def inspect_tool_manifest(manifest: Mapping[str, object]) -> list[RuntimeFinding]:
    """Find over-broad tool permissions and tool-poisoning hints.

    Expected input is a JSON-like manifest with a ``tools`` array. Each tool may
    contain ``name``, ``description`` and ``scopes`` fields.
    """
    findings: list[RuntimeFinding] = []
    for raw_tool in manifest.get("tools", []) or []:
        if not isinstance(raw_tool, Mapping):
            continue
        name = str(raw_tool.get("name", "<unnamed>"))
        desc = str(raw_tool.get("description", "")).lower()
        scopes = normalize_scopes(raw_tool.get("scopes"))
        broad = sorted(set(scopes) & DANGEROUS_SCOPES)
        if broad:
            findings.append(RuntimeFinding(
                rule_id="MCP_RUNTIME_001",
                severity="high",
                subject=name,
                evidence="over-broad scopes: " + ", ".join(broad),
                recommendation="split this tool into least-privilege read/write capabilities",
            ))
        if any(hint in name.lower() or hint in desc for hint in SENSITIVE_TOOL_HINTS) and not scopes:
            findings.append(RuntimeFinding(
                rule_id="MCP_RUNTIME_002",
                severity="medium",
                subject=name,
                evidence="sensitive tool has no explicit scope declaration",
                recommendation="require explicit scopes before registering the tool",
            ))
    return findings


def summarize_vulnerability_batch(packages: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Create deterministic vulnerability rollup from package advisory records."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    affected: list[str] = []
    for pkg in packages:
        severity = str(pkg.get("severity", "unknown")).lower()
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
        if severity in {"critical", "high"}:
            affected.append(f"{pkg.get('name', '<unknown>')}@{pkg.get('version', '<unknown>')}")
    return {
        "total": sum(counts.values()),
        "counts": counts,
        "blocking": counts["critical"] > 0 or counts["high"] >= 2,
        "affected_high_risk": sorted(affected),
    }
