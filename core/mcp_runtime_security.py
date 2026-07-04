"""Runtime security primitives for tool manifests and dependency batches.

The module is intentionally self-contained: it does not call external services.
Callers can inject vulnerability records gathered by their own network layer and
use these deterministic checks in hooks, CI, or preflight diagnostics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any, Mapping, Sequence

HIGH_RISK_CAPABILITIES = {"shell", "network", "file_write", "secret_read", "process_control"}
SUSPICIOUS_PROMPT_TERMS = (
    "ignore previous",
    "disable safety",
    "exfiltrate",
    "send token",
    "system prompt",
    "developer message",
)


@dataclass(frozen=True)
class ToolPermission:
    capability: str
    resource: str = "*"

    @classmethod
    def parse(cls, raw: str) -> "ToolPermission":
        if ":" not in raw:
            return cls(raw.strip(), "*")
        capability, resource = raw.split(":", 1)
        return cls(capability.strip(), resource.strip() or "*")


@dataclass
class RuntimeFinding:
    code: str
    severity: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


def build_minimum_permission_profile(manifest: Mapping[str, Any]) -> list[ToolPermission]:
    """Derive a conservative permission profile from declared operations."""
    operations = manifest.get("operations") or []
    profile: list[ToolPermission] = []
    for op in operations:
        if not isinstance(op, Mapping):
            continue
        capability = str(op.get("capability") or op.get("type") or "").strip()
        if not capability:
            continue
        resource = str(op.get("resource") or op.get("path") or "*").strip() or "*"
        profile.append(ToolPermission(capability, resource))
    if not profile:
        for capability in manifest.get("capabilities") or []:
            profile.append(ToolPermission(str(capability), "*"))
    return sorted(profile, key=lambda item: (item.capability, item.resource))


def audit_least_privilege(manifest: Mapping[str, Any]) -> list[RuntimeFinding]:
    """Compare granted permissions with the minimum profile implied by operations."""
    granted = [ToolPermission.parse(str(item)) for item in manifest.get("permissions") or []]
    minimum = build_minimum_permission_profile(manifest)
    findings: list[RuntimeFinding] = []
    for permission in granted:
        if permission.capability in HIGH_RISK_CAPABILITIES and permission.resource == "*":
            findings.append(RuntimeFinding(
                "overbroad_permission",
                "high",
                "High-risk capability is granted without a resource boundary.",
                {"capability": permission.capability},
            ))
        if minimum and not _covered_by_minimum(permission, minimum):
            findings.append(RuntimeFinding(
                "permission_not_required",
                "medium",
                "Granted permission is not required by declared operations.",
                {"permission": f"{permission.capability}:{permission.resource}"},
            ))
    return findings


def _covered_by_minimum(permission: ToolPermission, minimum: Sequence[ToolPermission]) -> bool:
    for required in minimum:
        if required.capability != permission.capability:
            continue
        if permission.resource == required.resource:
            return True
        if permission.resource != "*" and fnmatch(required.resource, permission.resource):
            return True
    return False


def detect_tool_poisoning(manifest: Mapping[str, Any]) -> list[RuntimeFinding]:
    """Detect prompt-like or authority-escalating content inside tool metadata."""
    findings: list[RuntimeFinding] = []
    fields = {
        "name": manifest.get("name", ""),
        "description": manifest.get("description", ""),
        "schema": manifest.get("schema", ""),
    }
    for field_name, value in fields.items():
        text = str(value).lower()
        matched = [term for term in SUSPICIOUS_PROMPT_TERMS if term in text]
        if matched:
            findings.append(RuntimeFinding(
                "tool_metadata_instruction_injection",
                "high",
                "Tool metadata contains instruction-like text that can poison an agent planner.",
                {"field": field_name, "matched_terms": matched},
            ))
    if manifest.get("auth") == "none" and any(cap in HIGH_RISK_CAPABILITIES for cap in manifest.get("capabilities") or []):
        findings.append(RuntimeFinding(
            "unauthenticated_high_risk_tool",
            "critical",
            "High-risk tool is exposed without an authentication boundary.",
            {"capabilities": list(manifest.get("capabilities") or [])},
        ))
    return findings


def summarize_vulnerability_batch(records: Sequence[Mapping[str, Any]], severity_floor: str = "HIGH") -> dict[str, Any]:
    """Summarize vulnerability lookup records without depending on a network call."""
    rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    floor = rank.get(severity_floor.upper(), 3)
    affected: list[dict[str, Any]] = []
    for record in records:
        severity = str(record.get("severity", "UNKNOWN")).upper()
        if rank.get(severity, 0) >= floor:
            affected.append({
                "package": record.get("package"),
                "version": record.get("version"),
                "severity": severity,
                "id": record.get("id"),
            })
    return {
        "checked": len(records),
        "blocked": bool(affected),
        "affected": affected,
        "highest_severity": max((item["severity"] for item in affected), key=lambda s: rank.get(s, 0), default="NONE"),
    }


def audit_runtime_manifest(manifest: Mapping[str, Any], vulnerability_records: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    findings = audit_least_privilege(manifest) + detect_tool_poisoning(manifest)
    vuln_summary = summarize_vulnerability_batch(vulnerability_records)
    return {
        "allowed": not any(f.severity in {"critical", "high"} for f in findings) and not vuln_summary["blocked"],
        "findings": [f.__dict__ for f in findings],
        "vulnerabilities": vuln_summary,
    }
