# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · YARA Signature Scanner
AtomCollide-智械工坊 · 2026

YARA-based signature scanning for AI agent skill artifacts.
Detects malware, webshells, cryptominers, hack tools, and exploit patterns
using curated YARA rules based on Neo23x0/signature-base and community research.

Built-in rules ship in detector/yara_rules/. Users can supply additional rules.

Requires: yara-python (pip install yara-python)
Gracefully degrades to no-op if yara-python is not installed.

Usage:
    from modules.yara_scanner import scan_yara
    threats = scan_yara(source_code, filename="plugin.py")
    # or scan a directory:
    threats = scan_yara_dir("/path/to/skill/")
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ============================================================
# Data Structures
# ============================================================

@dataclass
class YARAThreat:
    """A single YARA match finding."""
    rule_id: str
    rule_name: str
    message: str
    severity: str
    confidence: float
    filename: str
    line: int
    matched_text: str
    category: str
    mitigation: str = ""


# ============================================================
# Constants
# ============================================================

_YARA_RULES_DIR = Path(__file__).parent.parent / "yara_rules"

_CATEGORY_MAP: dict[str, Tuple[str, str, float]] = {
    # category → (rule_id, severity, confidence)
    "malware":     ("YR1", "critical", 0.85),
    "webshell":    ("YR2", "critical", 0.85),
    "cryptominer": ("YR3", "high", 0.80),
    "hack_tool":   ("YR4", "high", 0.70),
    "exploit":     ("YR4", "high", 0.80),
}

_DEFAULT_RULE_ID = "YR4"
_DEFAULT_SEVERITY = "medium"
_DEFAULT_CONFIDENCE = 0.70

_MITIGATIONS: dict[str, str] = {
    "malware":     "Remove or quarantine — reverse shells, keyloggers, ransomware indicators",
    "webshell":    "Remove immediately — webshell code should never appear in agent skills",
    "cryptominer": "Remove — crypto mining code is unauthorized resource consumption",
    "hack_tool":   "Review and remove — offensive tools should not be bundled in skills",
    "exploit":     "Remove — exploit code is a critical security risk",
}


# ============================================================
# YARA Compilation (lazy, cached)
# ============================================================

_yara_available: Optional[bool] = None
_compiled_rules = None
_rules_hash: Optional[str] = None


def _check_yara_available() -> bool:
    global _yara_available
    if _yara_available is None:
        try:
            import yara
            _yara_available = True
        except ImportError:
            _yara_available = False
    return _yara_available


def _collect_rule_files() -> List[Path]:
    """Collect all .yar and .yara files from the built-in rules directory."""
    if not _YARA_RULES_DIR.is_dir():
        return []
    files: set[Path] = set()
    for ext in ("*.yar", "*.yara"):
        files.update(_YARA_RULES_DIR.rglob(ext))
    return sorted(files)


def _content_hash(rule_files: List[Path]) -> str:
    h = hashlib.sha256()
    for p in rule_files:
        h.update(str(p).encode())
        h.update(str(p.stat().st_size).encode())
    return h.hexdigest()


def _build_namespace_map(rule_files: List[Path]) -> Dict[str, str]:
    filepaths: Dict[str, str] = {}
    for rf in rule_files:
        ns = rf.stem
        if ns in filepaths:
            ns = f"{rf.parent.name}/{rf.stem}"
        filepaths[ns] = str(rf)
    return filepaths


def _load_rules():
    """Compile and cache YARA rules."""
    global _compiled_rules, _rules_hash

    if not _check_yara_available():
        return None

    import yara

    rule_files = _collect_rule_files()
    if not rule_files:
        return None

    current_hash = _content_hash(rule_files)
    if _compiled_rules is not None and _rules_hash == current_hash:
        return _compiled_rules

    filepaths = _build_namespace_map(rule_files)

    try:
        _compiled_rules = yara.compile(filepaths=filepaths)
    except yara.SyntaxError:
        # Fallback: compile per-file, skip broken rules
        good: Dict[str, str] = {}
        for ns, fp in filepaths.items():
            try:
                yara.compile(filepath=fp)
                good[ns] = fp
            except (yara.SyntaxError, yara.Error):
                pass
        _compiled_rules = yara.compile(filepaths=good) if good else None

    _rules_hash = current_hash
    return _compiled_rules


def _get_line_number(content: str, offset: int) -> int:
    """Get line number from byte offset."""
    return content[:offset].count("\n") + 1


def _get_context(content: str, offset: int, context_lines: int = 2) -> str:
    """Get surrounding context lines for a match."""
    lines = content.splitlines()
    match_line = content[:offset].count("\n")
    start = max(0, match_line - context_lines)
    end = min(len(lines), match_line + context_lines + 1)
    return "\n".join(lines[start:end])[:500]


# ============================================================
# Core Scanner
# ============================================================

def _match_content(rules, content: str, filename: str) -> List[YARAThreat]:
    """Run compiled YARA rules against content."""
    data = content.encode("utf-8", errors="replace")
    try:
        matches = rules.match(data=data)
    except Exception:
        return []

    threats: List[YARAThreat] = []
    for match in matches:
        # Extract metadata
        meta = match.meta or {}
        category = str(meta.get("category", "")).lower()
        description = str(meta.get("description", "")) or match.rule

        rule_id, severity, confidence = _CATEGORY_MAP.get(
            category, (_DEFAULT_RULE_ID, _DEFAULT_SEVERITY, _DEFAULT_CONFIDENCE)
        )

        # Allow per-rule severity/confidence overrides from meta
        sev_override = str(meta.get("severity", "")).lower()
        if sev_override in ("critical", "high", "medium", "low"):
            severity = sev_override
        try:
            confidence = float(str(meta.get("confidence", confidence)))
        except (ValueError, TypeError):
            pass

        # Extract matched text
        first_offset = 0
        matched_parts: list[str] = []
        for sd in (match.strings or []):
            for inst in (sd.instances or []):
                if first_offset == 0:
                    first_offset = inst.offset
                matched_bytes = inst.matched_data
                if isinstance(matched_bytes, bytes):
                    matched_parts.append(matched_bytes.decode("utf-8", errors="replace"))
        matched_text = "; ".join(matched_parts)[:200] if matched_parts else ""

        line = _get_line_number(content, first_offset)
        mitigation = _MITIGATIONS.get(category, "Review and remove suspicious code")

        threats.append(YARAThreat(
            rule_id=rule_id,
            rule_name=match.rule,
            message=f"YARA '{match.rule}': {description}",
            severity=severity,
            confidence=confidence,
            filename=filename,
            line=line,
            matched_text=matched_text,
            category=category or "unknown",
            mitigation=mitigation,
        ))

    return threats


# ============================================================
# Public API
# ============================================================

def scan_yara(content: str, filename: str = "<unknown>") -> List[YARAThreat]:
    """Scan a single file's content against YARA rules.

    Args:
        content:  File content as string
        filename: Logical filename for reporting

    Returns:
        List of YARAThreat objects (empty if no matches or yara-python unavailable)
    """
    if not content or not content.strip():
        return []

    if len(content) > 1_048_576:  # 1MB limit
        return []

    rules = _load_rules()
    if rules is None:
        return []

    return _match_content(rules, content, filename)


def scan_yara_dir(directory: str) -> List[YARAThreat]:
    """Scan all files in a directory against YARA rules.

    Args:
        directory: Path to scan

    Returns:
        List of YARAThreat objects
    """
    rules = _load_rules()
    if rules is None:
        return []

    threats: List[YARAThreat] = []
    dirpath = Path(directory)
    if not dirpath.is_dir():
        return []

    # Binary/text extensions to scan
    TEXT_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".php",
                 ".java", ".jsp", ".aspx", ".rb", ".pl", ".lua", ".go", ".rs",
                 ".c", ".cpp", ".h", ".cs", ".yaml", ".yml", ".json", ".toml",
                 ".xml", ".html", ".htm", ".svg", ".md", ".txt", ".cfg", ".conf",
                 ".ini", ".env", ".dockerfile"}

    for fpath in dirpath.rglob("*"):
        if not fpath.is_file():
            continue
        if fpath.stat().st_size > 1_048_576:
            continue
        # Scan text files by extension, or scan all small files
        ext = fpath.suffix.lower()
        if ext not in TEXT_EXTS and fpath.stat().st_size > 256_000:
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            threats.extend(_match_content(rules, content, str(fpath)))
        except Exception:
            continue

    return threats


def is_yara_available() -> bool:
    """Check if yara-python is installed and usable."""
    return _check_yara_available()
