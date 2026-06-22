# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Unified Scanner
AtomCollide-智械工坊 · 2026

一键扫描入口，整合所有安全检测模块。

Usage:
    from modules.unified_scan import full_scan
    report = full_scan("/path/to/skill_or_project")
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

from .taint_tracker import scan_taint_flows
from .ast_analyzer import scan_ast
from .yara_scanner import scan_yara, scan_yara_dir
from .mcp_analyzer import scan_mcp_manifest, scan_skill_directory, MCPThreat
from .supply_chain import scan_dependencies, SupplyChainThreat
from .osv_client import OSVClient


@dataclass
class ScanReport:
    """统一扫描报告"""
    target: str
    total_threats: int
    critical: int
    high: int
    medium: int
    low: int
    modules_executed: List[str]
    taint_threats: List[Dict]
    ast_threats: List[Dict]
    yara_threats: List[Dict]
    mcp_threats: List[Dict]
    supply_chain_threats: List[Dict]
    osv_vulnerabilities: List[Dict]
    safe: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def summary(self) -> str:
        status = "✅ SAFE" if self.safe else "❌ UNSAFE"
        lines = [
            f"{status} | {self.target}",
            f"Total: {self.total_threats} threats ({self.critical}C {self.high}H {self.medium}M {self.low}L)",
            f"Modules: {', '.join(self.modules_executed)}",
        ]
        if self.taint_threats:
            lines.append(f"  Taint flows: {len(self.taint_threats)}")
        if self.ast_threats:
            lines.append(f"  AST behavioral: {len(self.ast_threats)}")
        if self.yara_threats:
            lines.append(f"  YARA matches: {len(self.yara_threats)}")
        if self.mcp_threats:
            lines.append(f"  MCP poisoning: {len(self.mcp_threats)}")
        if self.supply_chain_threats:
            lines.append(f"  Supply chain: {len(self.supply_chain_threats)}")
        if self.osv_vulnerabilities:
            lines.append(f"  OSV CVEs: {len(self.osv_vulnerabilities)}")
        return "\n".join(lines)


def full_scan(target_path: str, include_osv: bool = False) -> ScanReport:
    """
    对目标路径执行全面安全扫描。

    Args:
        target_path: 技能目录或项目目录
        include_osv: 是否查询OSV.dev (需要网络)

    Returns:
        统一扫描报告
    """
    path = Path(target_path)
    modules = []
    all_taint = []
    all_ast = []
    all_yara = []
    all_mcp = []
    all_sc = []
    all_osv = []

    # 1. Taint tracking on Python files
    try:
        for py_file in path.rglob("*.py"):
            code = py_file.read_text(encoding="utf-8", errors="ignore")
            threats = scan_taint_flows(code, str(py_file.name))
            all_taint.extend(threats)
        modules.append("taint_tracker")
    except Exception:
        pass

    # 2. AST behavioral analysis
    try:
        for py_file in path.rglob("*.py"):
            code = py_file.read_text(encoding="utf-8", errors="ignore")
            threats = scan_ast(code, str(py_file.name))
            all_ast.extend(threats)
        modules.append("ast_analyzer")
    except Exception:
        pass

    # 3. YARA scanning
    try:
        yara_threats = scan_yara_dir(str(path))
        all_yara.extend(yara_threats)
        modules.append("yara_scanner")
    except Exception:
        pass

    # 4. MCP analyzer
    try:
        mcp_threats = scan_skill_directory(str(path))
        all_mcp.extend(mcp_threats)
        modules.append("mcp_analyzer")
    except Exception:
        pass

    # 5. Supply chain
    try:
        sc_threats = scan_dependencies(str(path))
        all_sc.extend(sc_threats)
        modules.append("supply_chain")
    except Exception:
        pass

    # 6. OSV lookup (optional)
    if include_osv:
        try:
            client = OSVClient()
            for req_file in path.rglob("requirements.txt"):
                deps_text = req_file.read_text(encoding="utf-8", errors="ignore")
                for line in deps_text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
                        if pkg:
                            vulns = client.query(pkg)
                            for v in vulns:
                                all_osv.append({
                                    "package": pkg,
                                    "vuln_id": v.vuln_id,
                                    "severity": v.severity,
                                    "summary": v.summary,
                                    "fixed": v.fixed_version,
                                })
            modules.append("osv_client")
        except Exception:
            pass

    # Count severities
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for t in all_taint:
        sev = getattr(t, "severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for t in all_ast:
        sev = getattr(t, "severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for t in all_yara:
        sev = getattr(t, "severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for t in all_mcp:
        sev = getattr(t, "severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for t in all_sc:
        sev = getattr(t, "severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for t in all_osv:
        sev = t.get("severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = sum(severity_counts.values())
    safe = severity_counts["CRITICAL"] == 0 and severity_counts["HIGH"] == 0

    return ScanReport(
        target=str(path),
        total_threats=total,
        critical=severity_counts["CRITICAL"],
        high=severity_counts["HIGH"],
        medium=severity_counts["MEDIUM"],
        low=severity_counts["LOW"],
        modules_executed=modules,
        taint_threats=[_serialize(t) for t in all_taint],
        ast_threats=[_serialize(t) for t in all_ast],
        yara_threats=[_serialize(t) for t in all_yara],
        mcp_threats=[_serialize(t) for t in all_mcp],
        supply_chain_threats=[_serialize(t) for t in all_sc],
        osv_vulnerabilities=all_osv,
        safe=safe,
    )


def _serialize(obj) -> Dict:
    """Serialize dataclass or dict"""
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    return {"value": str(obj)}


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    report = full_scan(target)
    print(report.summary())
    if report.total_threats > 0:
        print("\n" + report.to_json())
