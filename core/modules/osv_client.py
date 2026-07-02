# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · OSV Client
AtomCollide-智械工坊 · 2026

面向 Agent 供应链审计的 OSV.dev 集成能力。

提供实时CVE漏洞查询、批量查询、版本感知检查和离线降级。

Usage:
    from modules.osv_client import OSVClient
    client = OSVClient()
    vulns = client.query("requests", ecosystem="PyPI")
    vulns = client.query_batch(["requests", "flask", "django"])
"""

import json
import subprocess
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass


@dataclass
class Vulnerability:
    """CVE漏洞信息"""
    vuln_id: str  # e.g. "GHSA-xxx" or "CVE-xxx"
    summary: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    aliases: List[str]
    affected_versions: List[str]
    fixed_version: Optional[str]
    references: List[str]


class OSVClient:
    """
    OSV.dev API 客户端。
    在线时查询实时数据，离线时优雅降级。
    """

    API_URL = "https://api.osv.dev/v1"
    TIMEOUT = 8  # seconds

    def __init__(self, offline: bool = False):
        self.offline = offline
        self._cache: Dict[str, List[Vulnerability]] = {}

    def _curl(self, endpoint: str, data: Optional[str] = None) -> Optional[Dict]:
        """发送HTTP请求到OSV API"""
        if self.offline:
            return None

        url = f"{self.API_URL}/{endpoint}"
        cmd = ["curl", "-s", "--max-time", str(self.TIMEOUT)]

        if data:
            cmd.extend(["-X", "POST", "-H", "Content-Type: application/json", "-d", data])

        cmd.append(url)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.TIMEOUT + 2)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass
        return None

    def _parse_vuln(self, raw: Dict) -> Vulnerability:
        """解析OSV API返回的漏洞数据"""
        vuln_id = raw.get("id", "UNKNOWN")
        summary = raw.get("summary", raw.get("details", "")[:200])

        # Determine severity from database_specific or severity field.
        severity = "MEDIUM"
        severity_list = raw.get("severity", [])
        cvss_score = 0.0
        for item in severity_list:
            score_str = str(item.get("score", ""))
            # OSV may return either a CVSS vector or a numeric score.
            try:
                cvss_score = max(cvss_score, float(score_str))
            except ValueError:
                pass
            upper = score_str.upper()
            if "/C:H" in upper or "/I:H" in upper or "/A:H" in upper:
                cvss_score = max(cvss_score, 9.0)
            if "CRITICAL" in upper:
                cvss_score = max(cvss_score, 9.0)
            elif "HIGH" in upper:
                cvss_score = max(cvss_score, 7.0)

        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score > 0:
            severity = "LOW" if cvss_score < 4.0 else "MEDIUM"

        db_severity = raw.get("database_specific", {}).get("severity", "")
        if db_severity:
            severity = str(db_severity).upper()

        # Extract aliases
        aliases = raw.get("aliases", [])

        # Extract affected versions
        affected = []
        fixed_ver = None
        for affected_item in raw.get("affected", []):
            for rng in affected_item.get("ranges", []):
                for evt in rng.get("events", []):
                    if "introduced" in evt:
                        affected.append(f">={evt['introduced']}")
                    if "fixed" in evt:
                        fixed_ver = evt["fixed"]
                        affected.append(f"<{evt['fixed']}")

        # Extract references
        refs = [r.get("url", "") for r in raw.get("references", []) if r.get("url")]

        return Vulnerability(
            vuln_id=vuln_id, summary=summary, severity=severity,
            aliases=aliases, affected_versions=affected,
            fixed_version=fixed_ver, references=refs[:5],
        )

    def query(self, package_name: str, ecosystem: str = "PyPI",
              version: Optional[str] = None) -> List[Vulnerability]:
        """
        查询单个包的已知漏洞。

        Args:
            package_name: 包名
            ecosystem: 生态系统 (PyPI, npm, Go, etc.)
            version: 特定版本 (可选)

        Returns:
            漏洞列表
        """
        cache_key = f"{ecosystem}:{package_name}:{version or '*'}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version

        data = self._curl("query", json.dumps(payload))
        vulns = []

        if data:
            for raw_vuln in data.get("vulns", []):
                try:
                    vulns.append(self._parse_vuln(raw_vuln))
                except Exception:
                    continue

        self._cache[cache_key] = vulns
        return vulns

    def query_batch(
        self,
        packages: List[Union[str, Tuple[str, Optional[str]]]],
        ecosystem: str = "PyPI",
    ) -> Dict[str, List[Vulnerability]]:
        """
        批量查询多个包的漏洞，优先使用 OSV querybatch 端点。

        Args:
            packages: 包名列表，或 (包名, 版本) 元组列表
            ecosystem: 生态系统

        Returns:
            {package_name: [vulnerabilities]}
        """
        normalized: List[Tuple[str, Optional[str]]] = []
        for item in packages:
            if isinstance(item, tuple):
                normalized.append((item[0], item[1]))
            else:
                normalized.append((item, None))

        results: Dict[str, List[Vulnerability]] = {pkg: [] for pkg, _ in normalized}
        if not normalized:
            return results

        payload = {
            "queries": [
                {
                    "package": {"name": pkg, "ecosystem": ecosystem},
                    **({"version": version} if version else {}),
                }
                for pkg, version in normalized
            ]
        }
        data = self._curl("querybatch", json.dumps(payload))
        if data and isinstance(data.get("results"), list):
            for (pkg, _), item in zip(normalized, data.get("results", [])):
                vulns = []
                for raw_vuln in item.get("vulns", []) if isinstance(item, dict) else []:
                    try:
                        vulns.append(self._parse_vuln(raw_vuln))
                    except Exception:
                        continue
                results[pkg] = vulns
            self._cache.update({f"{ecosystem}:{pkg}:{version or '*'}": vulns for (pkg, version), vulns in zip(normalized, results.values())})
            return results

        # Offline/API fallback: keep old per-package behavior.
        for pkg, version in normalized:
            results[pkg] = self.query(pkg, ecosystem, version)
        return results

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """通过ID获取漏洞详情 (e.g. "GHSA-xxx")"""
        data = self._curl(f"vulns/{vuln_id}")
        if data:
            try:
                return self._parse_vuln(data)
            except Exception:
                pass
        return None

    def format_report(self, vulns: List[Vulnerability], package_name: str = "") -> str:
        """格式化漏洞报告"""
        if not vulns:
            return f"✅ {package_name}: No known vulnerabilities" if package_name else "✅ No vulnerabilities found"

        lines = [f"⚠️ {package_name}: {len(vulns)} vulnerabilities found" if package_name
                 else f"⚠️ {len(vulns)} vulnerabilities found"]

        for v in vulns:
            severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(v.severity, "⚪")
            lines.append(f"  {severity_icon} [{v.severity}] {v.vuln_id}: {v.summary[:100]}")
            if v.fixed_version:
                lines.append(f"    Fix: upgrade to {v.fixed_version}")
            if v.references:
                lines.append(f"    Ref: {v.references[0]}")

        return "\n".join(lines)


# ── Convenience function ──

def quick_check(package_name: str, ecosystem: str = "PyPI") -> str:
    """快速检查单个包，返回格式化报告字符串"""
    client = OSVClient()
    vulns = client.query(package_name, ecosystem)
    return client.format_report(vulns, package_name)


# ── Self-test ──

if __name__ == "__main__":
    client = OSVClient()

    # Test single query
    print("=== Testing OSV Client ===")
    print(quick_check("requests"))
    print(quick_check("flask"))
    print(quick_check("nonexistent-package-xyz123"))

    # Test batch
    print("\n=== Batch Check ===")
    results = client.query_batch(["requests", "django", "pillow"])
    for pkg, vulns in results.items():
        print(client.format_report(vulns, pkg))
