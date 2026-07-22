#!/usr/bin/env python3
"""Bridge utility to adapt SkillSpector-like manifest outputs into Hermes Security Suite checks.

The bridge focuses on three fusion-relevant capabilities:
- MCP manifest hardening checks (least-privilege + poisoning).
- Runtime permission profile compatibility checks.
- Supply-chain + OSV-style vulnerability hints.

It can be used for smoke validation with deterministic sample data:
`python3 scripts/skillspector_bridge.py --sample --json`
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detector.modules.mcp_analyzer import MCPThreat, scan_mcp_manifest
from core.mcp_runtime_security import audit_runtime_manifest
from detector.modules.supply_chain import scan_with_osv_lookup

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


@dataclass
class ToolBridgeResult:
    """Per-tool normalized bridge report."""

    tool_name: str
    mcp_count: int
    findings: list[dict[str, Any]]
    runtime_allowed: bool
    runtime_findings: list[dict[str, Any]]
    vulnerability_count: int
    vulnerability_blocking: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "mcp_findings": self.mcp_count,
            "runtime_allowed": self.runtime_allowed,
            "runtime_findings": self.runtime_findings,
            "runtime_blocking_findings": [f for f in self.runtime_findings if f.get("severity") in {"high", "critical"}],
            "vulnerability_count": self.vulnerability_count,
            "vulnerability_blocking": self.vulnerability_blocking,
            "findings": self.findings,
        }


def _collect_mcp_tools(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        if isinstance(raw.get("tools"), list):
            return [x for x in raw.get("tools", []) if isinstance(x, dict)]
        if "name" in raw and isinstance(raw.get("name"), str):
            return [raw]
    return []


def _sample_payload() -> dict[str, Any]:
    return {
        "project": "",
        "tools": [
            {
                "name": "sec-file-reader",
                "description": "Read workspace reports from whitelisted paths.",
                "capabilities": ["file_read", "file_write"],
                "operations": [
                    {
                        "capability": "file_read",
                        "resource": "workspace/reports/*.md",
                    },
                    {
                        "capability": "file_write",
                        "resource": "workspace/reports/*.md",
                    },
                ],
                "permissions": [
                    "file_read:workspace/reports/*.md",
                    "file_write:workspace/reports/*.md",
                ],
            },
            {
                "name": "report-agent",
                "description": "Compose safety report with bounded output path.",
                "capabilities": ["file_write"],
                "operations": [
                    {
                        "capability": "file_write",
                        "resource": "workspace/reports/*.md",
                    }
                ],
                "permissions": ["file_write:workspace/reports/*.md"],
            },
        ],
    }


def _serialize_mcp_threats(threats: list[MCPThreat]) -> list[dict[str, Any]]:
    data: list[dict[str, Any]] = []
    for threat in threats:
        data.append(
            {
                "rule_id": threat.rule_id,
                "category": threat.category,
                "severity": threat.severity.lower(),
                "description": threat.description,
                "confidence": threat.confidence,
                "source_field": threat.source_field,
                "mitigation": threat.mitigation,
                "matched_text": threat.matched_text,
            }
        )
    return data


def _serialize_runtime_summary(summary: dict[str, Any]) -> dict[str, Any]:
    findings = summary.get("findings", [])
    return {
        "allowed": bool(summary.get("allowed", False)),
        "finding_count": len(findings),
        "blocking_finding_count": len([f for f in findings if f.get("code") in {"overbroad_permission", "permission_not_required", "tool_metadata_instruction_injection", "unauthenticated_high_risk_tool"}]),
        "findings": findings,
        "vulnerability_summary": summary.get("vulnerabilities", {}),
    }


def _serialize_vulns(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(item.get("severity", "unknown").lower() for item in vulns)
    return {
        "total": len(vulns),
        "high_or_critical": counts.get("high", 0) + counts.get("critical", 0),
        "by_severity": dict(sorted(counts.items())),
        "blocked_by_policy": any(item.get("severity") in {"HIGH", "CRITICAL", "high", "critical"} for item in vulns),
        "vulns": vulns,
    }


def _run_bridge(manifest_payload: dict[str, Any], sample: bool = False, project_path: str | None = None, osv_api_url: str | None = None) -> dict[str, Any]:


    tools = _collect_mcp_tools(manifest_payload)
    tool_reports: list[ToolBridgeResult] = []

    osv_findings: list[dict[str, Any]] = []
    if project_path:
        try:
            for threat in scan_with_osv_lookup(project_path, osv_api_url=osv_api_url):
                osv_findings.append(
                    {
                        "package": threat.package_name,
                        "severity": threat.severity,
                        "rule_id": threat.rule_id,
                        "summary": threat.description,
                        "details": threat.details,
                        "mitigation": threat.mitigation,
                    }
                )
        except Exception as exc:
            osv_findings.append(
                {
                    "package": "_bridge_runtime",
                    "severity": "unknown",
                    "rule_id": "SC4",
                    "summary": "OSV lookup failed in bridge mode",
                    "details": str(exc),
                    "mitigation": "Retry after network restoration or provide offline dependency allowlist",
                }
            )

    for raw_tool in tools:
        tool_name = str(raw_tool.get("name", "<anonymous>")).strip() or "<anonymous>"
        mcp_threats = scan_mcp_manifest(raw_tool)
        runtime_audit = audit_runtime_manifest(raw_tool, vulnerability_records=osv_findings)
        tool_reports.append(
            ToolBridgeResult(
                tool_name=tool_name,
                mcp_count=len(mcp_threats),
                findings=_serialize_mcp_threats(mcp_threats),
                runtime_allowed=bool(runtime_audit.get("allowed", False)),
                runtime_findings=[{**vars(f)} for f in runtime_audit.get("findings", [])],
                vulnerability_count=len(osv_findings),
                vulnerability_blocking=bool(runtime_audit.get("vulnerabilities", {}).get("blocked", False)),
            )
        )

    # Summaries
    all_mcp_findings = [item for report in tool_reports for item in report.findings]
    critical = [f for f in all_mcp_findings if f["severity"] == "critical"]
    high = [f for f in all_mcp_findings if f["severity"] == "high"]
    summary = {
        "total_tools": len(tool_reports),
        "total_findings": len(all_mcp_findings),
        "severity_counts": dict(Counter(item.get("severity", "unknown") for item in all_mcp_findings)),
        "critical_findings": len(critical),
        "high_findings": len(high),
        "tools_with_blocking_findings": [
            report.tool_name
            for report in tool_reports
            if any(item.get("severity") in {"high", "critical"} for item in report.findings)
        ],
        "runtime_allowed_tools": [report.tool_name for report in tool_reports if report.runtime_allowed],
        "tool_results": [report.to_dict() for report in tool_reports],
    }

    return {
        "version": "skillspector-bridge-1",
        "checked_at": datetime.utcnow().isoformat() + "Z",
        "ok": not critical and all(r.runtime_allowed for r in tool_reports),
        "tool_count": len(tools),
        "mcp_summary": summary,
        "vulnerability_summary": _serialize_vulns(osv_findings),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SkillSpector bridge diagnostics")
    parser.add_argument("--manifest", type=str, default="", help="Path to SkillSpector-like JSON manifest")
    parser.add_argument("--project", type=str, default="", help="Project path for OSV lookup")
    parser.add_argument("--osv-api-url", type=str, default=None, help="Custom OSV API base URL (overrides OSV_API_URL env)")
    parser.add_argument("--sample", action="store_true", help="Use deterministic demo manifest")
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    parser.add_argument("--compact", action="store_true", help="Compact output for scripts")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.sample:
        payload = _sample_payload()
    else:
        if args.manifest:
            payload_path = Path(args.manifest).expanduser().resolve()
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
        else:
            raise SystemExit("请提供 --manifest 或 --sample")

    project = args.project.strip() or None
    report = _run_bridge(payload, sample=args.sample, project_path=project, osv_api_url=args.osv_api_url)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2 if not args.compact else None))
        return 0 if report["ok"] else 1

    if args.compact:
        print(f"SkillSpector Bridge: tools={report['tool_count']}, findings={report['mcp_summary']['total_findings']}, ok={report['ok']}")
        print(f"blocking_tools={','.join(report['mcp_summary']['tools_with_blocking_findings']) or 'none'}")
        print(f"vulns={report['vulnerability_summary']['total']}, blocked={report['vulnerability_summary']['blocked_by_policy']}")
        return 0

    print("SkillSpector Bridge Report")
    print(f"Tools: {report['tool_count']}")
    print(f"MCP findings: {report['mcp_summary']['total_findings']}")
    print(f"High risk: {report['mcp_summary']['high_findings']} / Critical: {report['mcp_summary']['critical_findings']}")
    print(f"Blocking tools: {', '.join(report['mcp_summary']['tools_with_blocking_findings']) or 'none'}")
    print(f"OSV risks: {report['vulnerability_summary']['total']} (block={report['vulnerability_summary']['blocked_by_policy']})")
    return 0 if report['ok'] else 1


if __name__ == "__main__":
    raise SystemExit(main())