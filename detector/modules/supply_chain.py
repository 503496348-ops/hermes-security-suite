# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Supply Chain Scanner
AtomCollide-智械工坊 · 2026

面向 Agent 项目的供应链安全检测能力。

检测能力:
  - SC1: 依赖声明解析 (requirements.txt, setup.py, pyproject.toml, package.json)
  - SC2: 可疑包名检测 (typosquatting, 仿冒知名包)
  - SC3: 版本锁定检查 (未锁定版本 = 供应链风险)
  - SC4: OSV.dev 实时CVE查询
  - SC5: 已知恶意包列表比对
  - SC6: 依赖来源检查 (非PyPI/npm官方源)

Usage:
    from modules.supply_chain import scan_dependencies
    threats = scan_dependencies("/path/to/project")
"""

import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass


@dataclass
class SupplyChainThreat:
    """供应链安全威胁"""
    rule_id: str
    category: str
    description: str
    severity: str
    confidence: float
    package_name: str
    details: str
    mitigation: str


# ── SC2: 可疑包名模式 ──

# Typosquatting patterns: common misspellings of popular packages
_TYPOSQUAT_PATTERNS = {
    "requests": ["request", "requets", "reqeusts", "requsests"],
    "numpy": ["numpay", "numpi", "numppy"],
    "pandas": ["pandass", "pandsa", "pandaz"],
    "flask": ["flaskk", "flsak", "flaask"],
    "django": ["djangoo", "djanog", "djang0"],
    "tensorflow": ["tensorfow", "tensorlfow", "tenserflow"],
    "pytorch": ["pytorchh", "pytorh", "pytroch"],
    "pillow": ["pilow", "pilow", "pilllow"],
    "beautifulsoup4": ["beautifulsoup", "beatifulsoup", "beutifulsoup"],
    "scikit-learn": ["sklearn", "scikit_learn", "sci-kit-learn"],
}

# Known malicious packages (updated periodically)
_KNOWN_MALICIOUS = {
    "python3-dateutil",  # typosquat of python-dateutil
    "jeIlyfish",  # homoglyph of jellyfish
    "colourama",  # typosquat of colorama
    "requesocks",  # typosquat of requests
    "djanga",  # typosquat of django
    "nmap-python",  # impersonation
    "crypt",  # shadowing stdlib
}

# ── SC3: 版本约束模式 ──

_UNSAFE_VERSION_PATTERNS = [
    re.compile(r"^[>=<~!]", re.ASCII),  # Has version constraint
    re.compile(r"\*\s*$"),  # Wildcard
    re.compile(r"latest", re.IGNORECASE),  # "latest" keyword
]

# ── SC6: 可疑安装源 ──

_SUSPICIOUS_INDEX_PATTERNS = [
    re.compile(r"--index-url\s+(?!https?://(pypi\.org|files\.pythonhosted\.org|registry\.npmjs\.org))", re.I),
    re.compile(r"--extra-index-url\s+", re.I),
    re.compile(r"--trusted-host\s+", re.I),
]


def _parse_requirements_txt(filepath: Path) -> List[Tuple[str, str]]:
    """解析 requirements.txt，返回 [(package, version_spec), ...]"""
    deps = []
    try:
        for line in filepath.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle package==version, package>=version, package
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", line)
            if match:
                pkg = match.group(1)
                ver = match.group(2).strip()
                deps.append((pkg, ver))
    except Exception:
        pass
    return deps


def _parse_package_json(filepath: Path) -> List[Tuple[str, str]]:
    """解析 package.json，返回 [(package, version_spec), ...]"""
    deps = []
    try:
        data = json.loads(filepath.read_text(encoding="utf-8"))
        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            for pkg, ver in data.get(section, {}).items():
                deps.append((pkg, str(ver)))
    except Exception:
        pass
    return deps


def _parse_pyproject_toml(filepath: Path) -> List[Tuple[str, str]]:
    """解析 pyproject.toml 依赖"""
    deps = []
    try:
        content = filepath.read_text(encoding="utf-8")
        # Simple regex extraction (doesn't need full TOML parser)
        in_deps = False
        for line in content.splitlines():
            if re.match(r"\[.*dependencies.*\]", line, re.I):
                in_deps = True
                continue
            if in_deps and line.startswith("["):
                in_deps = False
                continue
            if in_deps:
                match = re.match(r'"([a-zA-Z0-9_.-]+)\s*(.*)"', line)
                if match:
                    deps.append((match.group(1), match.group(2).strip('" ')))
    except Exception:
        pass
    return deps




def _extract_pinned_version(version_spec: str) -> Optional[str]:
    """Return exact pinned version if the dependency uses ==/exact npm pin; otherwise None."""
    spec = (version_spec or "").strip()
    if not spec:
        return None
    match = re.match(r"^==\s*([A-Za-z0-9_.!+\-]+)$", spec)
    if match:
        return match.group(1)
    if re.match(r"^[0-9][A-Za-z0-9_.!+\-]*$", spec):
        return spec
    return None

def _check_typosquat(pkg_name: str) -> Optional[SupplyChainThreat]:
    """检查包名是否为typosquat"""
    pkg_lower = pkg_name.lower().replace("-", "_").replace(".", "_")

    for legit, squats in _TYPOSQUAT_PATTERNS.items():
        legit_norm = legit.lower().replace("-", "_").replace(".", "_")
        if pkg_lower in squats or pkg_lower == legit_norm:
            if pkg_lower != legit_norm:
                return SupplyChainThreat(
                    rule_id="SC2", category="Supply Chain",
                    description=f"Possible typosquat: '{pkg_name}' mimics '{legit}'",
                    severity="CRITICAL", confidence=0.85,
                    package_name=pkg_name,
                    details=f"Normalized '{pkg_lower}' matches known squat pattern of '{legit}'",
                    mitigation=f"Replace with official package '{legit}'",
                )

    # Check for homoglyph attacks (Unicode lookalikes)
    ascii_name = pkg_name.encode("ascii", errors="ignore").decode("ascii")
    if ascii_name != pkg_name and len(ascii_name) > 2:
        return SupplyChainThreat(
            rule_id="SC2", category="Supply Chain",
            description=f"Package name '{pkg_name}' contains non-ASCII characters (homoglyph attack)",
            severity="CRITICAL", confidence=0.90,
            package_name=pkg_name,
            details=f"ASCII equivalent: '{ascii_name}'",
            mitigation="Use only ASCII package names from verified sources",
        )

    return None


def _check_known_malicious(pkg_name: str) -> Optional[SupplyChainThreat]:
    """检查已知恶意包列表"""
    if pkg_name in _KNOWN_MALICIOUS:
        return SupplyChainThreat(
            rule_id="SC5", category="Supply Chain",
            description=f"Package '{pkg_name}' is a known malicious package",
            severity="CRITICAL", confidence=0.99,
            package_name=pkg_name,
            details="Found in known-malicious database",
            mitigation=f"Remove '{pkg_name}' immediately and audit system",
        )
    return None


def _check_unpinned(pkg_name: str, version_spec: str) -> Optional[SupplyChainThreat]:
    """检查未锁定版本"""
    if not version_spec or version_spec.strip() in ("", "*"):
        return SupplyChainThreat(
            rule_id="SC3", category="Supply Chain",
            description=f"Package '{pkg_name}' has no version pin",
            severity="MEDIUM", confidence=0.70,
            package_name=pkg_name,
            details="Unpinned dependency can be silently updated to malicious version",
            mitigation=f"Pin to specific version: {pkg_name}==X.Y.Z",
        )
    return None


def _check_suspicious_source(filepath: Path) -> List[SupplyChainThreat]:
    """检查可疑安装源"""
    threats = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        for pattern in _SUSPICIOUS_INDEX_PATTERNS:
            for m in pattern.finditer(content):
                threats.append(SupplyChainThreat(
                    rule_id="SC6", category="Supply Chain",
                    description=f"Suspicious package index in {filepath.name}",
                    severity="HIGH", confidence=0.80,
                    package_name="N/A",
                    details=f"Found: {m.group().strip()[:100]}",
                    mitigation="Use only official package indexes (pypi.org, npmjs.org)",
                ))
    except Exception:
        pass
    return threats


def query_osv(package_name: str, ecosystem: str = "PyPI", version: Optional[str] = None) -> Optional[Dict]:
    """
    查询OSV.dev获取已知漏洞信息。
    离线时返回None。
    """
    try:
        from .osv_client import OSVClient

        client = OSVClient()
        vulns = client.query(package_name, ecosystem, version)
        if vulns:
            return {
                "count": len(vulns),
                "vulns": [
                    {
                        "id": vuln.vuln_id,
                        "summary": vuln.summary,
                        "severity": vuln.severity,
                        "fixed_version": vuln.fixed_version,
                    }
                    for vuln in vulns[:5]
                ],
            }
    except Exception:
        pass
    return None


def scan_dependencies(project_path: str) -> List[SupplyChainThreat]:
    """
    扫描项目依赖文件，检测供应链安全威胁。

    Args:
        project_path: 项目根目录路径

    Returns:
        检测到的威胁列表
    """
    path = Path(project_path)
    all_threats: List[SupplyChainThreat] = []

    # Collect dependency files
    dep_files = {
        "requirements.txt": _parse_requirements_txt,
        "setup.py": None,  # TODO: regex parse
        "pyproject.toml": _parse_pyproject_toml,
        "package.json": _parse_package_json,
    }

    for filename, parser in dep_files.items():
        filepath = path / filename
        if not filepath.exists() or parser is None:
            continue

        deps = parser(filepath)

        # Check suspicious sources in the file
        all_threats.extend(_check_suspicious_source(filepath))

        for pkg, ver in deps:
            # SC2: Typosquat
            threat = _check_typosquat(pkg)
            if threat:
                all_threats.append(threat)

            # SC5: Known malicious
            threat = _check_known_malicious(pkg)
            if threat:
                all_threats.append(threat)

            # SC3: Unpinned version
            threat = _check_unpinned(pkg, ver)
            if threat:
                all_threats.append(threat)

    # Also check Pipfile, poetry.lock, etc.
    for lockfile in ["Pipfile.lock", "poetry.lock", "package-lock.json", "yarn.lock"]:
        lockpath = path / lockfile
        if lockpath.exists():
            # Lock files exist = good practice (SC3 mitigated)
            pass

    return all_threats


def scan_with_osv_lookup(
    project_path: str,
    ecosystem: str = "PyPI",
    osv_client: Optional[Any] = None,
) -> List[SupplyChainThreat]:
    """
    扫描依赖并查询OSV.dev获取实时CVE信息。
    注意: 需要网络访问，离线时跳过OSV查询。
    """
    threats = scan_dependencies(project_path)

    if osv_client is None:
        try:
            from .osv_client import OSVClient
            osv_client = OSVClient()
        except Exception:
            osv_client = None

    path = Path(project_path)
    for filename, parser in [("requirements.txt", _parse_requirements_txt),
                              ("package.json", _parse_package_json)]:
        filepath = path / filename
        if not filepath.exists() or parser is None:
            continue

        eco = ecosystem if filename.endswith(".txt") else "npm"
        deps = parser(filepath)[:20]
        package_queries = [(pkg, _extract_pinned_version(ver)) for pkg, ver in deps]

        batch_results = {}
        if osv_client is not None:
            try:
                batch_results = osv_client.query_batch(package_queries, eco)
            except Exception:
                batch_results = {}

        for pkg, pinned_version in package_queries:
            vulns = batch_results.get(pkg, [])
            if not vulns:
                continue
            top = vulns[0]
            fixed = getattr(top, "fixed_version", None)
            vuln_id = getattr(top, "vuln_id", "N/A")
            severity = getattr(top, "severity", "HIGH") or "HIGH"
            summary = getattr(top, "summary", "")
            threats.append(SupplyChainThreat(
                rule_id="SC4", category="Supply Chain",
                description=f"Package '{pkg}' has {len(vulns)} known vulnerabilities (OSV.dev)",
                severity=severity if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "HIGH",
                confidence=0.96,
                package_name=pkg,
                details=f"Top vuln: {vuln_id}; installed={pinned_version or 'unresolved'}; summary={summary[:120]}",
                mitigation=f"Update '{pkg}' to {fixed} or latest secure version" if fixed else f"Update '{pkg}' to latest secure version",
            ))

    return threats


# ── Self-test ──

if __name__ == "__main__":
    import tempfile, os

    # Create test requirements.txt
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir="/tmp") as f:
        f.write("requests==2.31.0\n")
        f.write("colourama\n")  # Known malicious typosquat
        f.write("numpy\n")  # Unpinned
        f.write("python-dateutil>=2.8.0\n")
        tmpfile = f.name

    # Create test project dir
    test_dir = "/tmp/test_supply_chain"
    os.makedirs(test_dir, exist_ok=True)
    os.rename(tmpfile, os.path.join(test_dir, "requirements.txt"))

    threats = scan_dependencies(test_dir)
    print(f"Found {len(threats)} threats:")
    for t in threats:
        print(f"  [{t.severity}] {t.rule_id}: {t.description}")

    # Cleanup
    os.remove(os.path.join(test_dir, "requirements.txt"))
    os.rmdir(test_dir)
