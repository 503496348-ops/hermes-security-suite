# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Behavioral AST Analyzer
AtomCollide-智械工坊 · 2026

Python AST-based static analysis to detect dangerous execution patterns in code.
Parses Python source files into Abstract Syntax Trees and walks them to identify:

  - exec() / eval() / compile() calls (AST1-AST3)
  - subprocess module calls (AST4)
  - os.system / os.exec* calls (AST5)
  - Dynamic __import__() usage (AST6)
  - Dangerous execution chains — exec(base64.b64decode(...)) etc. (AST7)
  - Suspicious getattr() with non-literal attribute (AST8)

Usage:
    from modules.ast_analyzer import scan_ast
    threats = scan_ast(source_code, filename="plugin.py")
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ============================================================
# Data Structures
# ============================================================

@dataclass
class ASTThreat:
    """A single AST-detected threat."""
    rule_id: str
    message: str
    severity: str          # critical / high / medium / low
    confidence: float
    filename: str
    line: int
    end_line: Optional[int]
    matched_text: str
    mitigation: str = ""


# ============================================================
# Constants
# ============================================================

_DANGEROUS_BUILTINS = frozenset({"exec", "eval", "compile", "__import__"})

_SUBPROCESS_CALLS = frozenset({
    "call", "run", "Popen", "check_output", "check_call",
    "getoutput", "getstatusoutput",
})

_OS_EXEC_CALLS = frozenset({
    "system", "popen", "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
})

_RULE_META: dict[str, dict] = {
    "AST1": {
        "message": "exec() call detected",
        "severity": "high",
        "confidence": 0.85,
        "mitigation": "Avoid exec() — use safe alternatives or restrict to trusted input",
    },
    "AST2": {
        "message": "eval() call detected",
        "severity": "high",
        "confidence": 0.85,
        "mitigation": "Replace eval() with ast.literal_eval() or structured parsing",
    },
    "AST3": {
        "message": "Dynamic import via __import__()",
        "severity": "medium",
        "confidence": 0.75,
        "mitigation": "Use importlib.import_module() with validated module names",
    },
    "AST4": {
        "message": "subprocess module call",
        "severity": "medium",
        "confidence": 0.70,
        "mitigation": "Validate and sanitize all arguments to subprocess calls",
    },
    "AST5": {
        "message": "os.system() or os exec-family call",
        "severity": "high",
        "confidence": 0.85,
        "mitigation": "Replace os.system() with subprocess.run(shell=False) and validate input",
    },
    "AST6": {
        "message": "compile() call detected — may be used to construct malicious code objects",
        "severity": "medium",
        "confidence": 0.65,
        "mitigation": "Restrict compile() to trusted, validated source strings",
    },
    "AST7": {
        "message": "Dangerous execution chain detected",
        "severity": "critical",
        "confidence": 0.95,
        "mitigation": "Block execution of dynamically decoded/decompressed payloads",
    },
    "AST8": {
        "message": "Dynamic attribute access via getattr() with non-literal attribute",
        "severity": "low",
        "confidence": 0.50,
        "mitigation": "Use getattr() with a whitelist of allowed attribute names",
    },
}


# ============================================================
# AST Helpers
# ============================================================

def _resolve_call_name(call_node: ast.Call) -> Optional[str]:
    """Resolve a Call node to its dotted name (e.g. 'os.system', 'subprocess.run').

    Returns None if the call target is too complex to resolve statically.
    """
    func = call_node.func

    # Simple name: exec, eval, etc.
    if isinstance(func, ast.Name):
        return func.id

    # Attribute chain: os.system, subprocess.run, etc.
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        node: ast.expr = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            return ".".join(reversed(parts))

    return None


def _is_chain_sink(call_node: ast.Call) -> bool:
    """True if this call is exec(), eval(), or compile()."""
    name = _resolve_call_name(call_node)
    return name in ("exec", "eval", "compile")


def _contains_dangerous_source(node: ast.AST) -> Optional[str]:
    """Walk children to find a nested dangerous call that forms a chain."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _resolve_call_name(child)
        if name is None:
            continue
        if name in ("compile", "__import__"):
            return name
        if name.startswith("subprocess.") or name.startswith("os."):
            return name
        if any(part in name for part in ("base64", "codecs", "marshal", "urllib", "requests", "httpx")):
            return name
    return None


def _get_source_segment(lines: list[str], lineno: int, end_lineno: Optional[int]) -> str:
    """Extract source text for the given line range."""
    start = max(0, lineno - 1)
    end = end_lineno if end_lineno else lineno
    return "\n".join(lines[start:end])[:300]


# ============================================================
# Core Analyzer
# ============================================================

def _analyze_python(content: str, filename: str) -> List[ASTThreat]:
    """Parse Python content via AST and detect dangerous execution patterns."""
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError:
        return []

    lines = content.splitlines()
    threats: List[ASTThreat] = []
    seen: set[Tuple[str, int]] = set()

    def _emit(rule_id: str, lineno: int, end_lineno: Optional[int] = None, msg_override: Optional[str] = None):
        key = (rule_id, lineno)
        if key in seen:
            return
        seen.add(key)
        meta = _RULE_META[rule_id]
        threats.append(ASTThreat(
            rule_id=rule_id,
            message=msg_override or meta["message"],
            severity=meta["severity"],
            confidence=meta["confidence"],
            filename=filename,
            line=lineno,
            end_line=end_lineno,
            matched_text=_get_source_segment(lines, lineno, end_lineno),
            mitigation=meta["mitigation"],
        ))

    for ast_node in ast.walk(tree):
        if not isinstance(ast_node, ast.Call):
            continue

        call_name = _resolve_call_name(ast_node)
        if call_name is None:
            continue

        lineno = getattr(ast_node, "lineno", 1)
        end_lineno = getattr(ast_node, "end_lineno", None)

        # exec()
        if call_name == "exec":
            if _is_chain_sink(ast_node) and ast_node.args:
                source = _contains_dangerous_source(ast_node.args[0])
                if source:
                    _emit("AST7", lineno, end_lineno, f"Dangerous chain: exec() wrapping {source}")
            _emit("AST1", lineno, end_lineno)

        # eval()
        elif call_name == "eval":
            if _is_chain_sink(ast_node) and ast_node.args:
                source = _contains_dangerous_source(ast_node.args[0])
                if source:
                    _emit("AST7", lineno, end_lineno, f"Dangerous chain: eval() wrapping {source}")
            _emit("AST2", lineno, end_lineno)

        # __import__()
        elif call_name == "__import__":
            _emit("AST3", lineno, end_lineno)

        # compile()
        elif call_name == "compile":
            _emit("AST6", lineno, end_lineno)

        # subprocess.*
        elif call_name.startswith("subprocess."):
            attr = call_name.split(".", 1)[1]
            if attr in _SUBPROCESS_CALLS:
                _emit("AST4", lineno, end_lineno)

        # os.system / os.exec*
        elif call_name.startswith("os."):
            attr = call_name.split(".", 1)[1]
            if attr in _OS_EXEC_CALLS:
                _emit("AST5", lineno, end_lineno)

        # getattr() with dynamic attribute
        elif call_name == "getattr" and len(ast_node.args) >= 2:
            if not isinstance(ast_node.args[1], ast.Constant):
                _emit("AST8", lineno, end_lineno)

    return threats


# ============================================================
# Public API
# ============================================================

def scan_ast(source: str, filename: str = "<unknown>") -> List[ASTThreat]:
    """Scan Python source code for dangerous execution patterns via AST analysis.

    Args:
        source:   Python source code string
        filename: Logical filename for reporting

    Returns:
        List of ASTThreat objects (empty if no issues or unparseable)
    """
    if not source or not source.strip():
        return []

    # Skip files larger than 500KB
    if len(source) > 512_000:
        return []

    return _analyze_python(source, filename)
