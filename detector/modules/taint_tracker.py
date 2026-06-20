# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Taint Tracker / Data-Flow Analyzer
AtomCollide-智械工坊 · 2026

Python AST-based data-flow analysis that tracks tainted data from sources to sinks.

Source categories:
  - Credential / environment: os.environ, os.getenv, os.environ.get
  - File read: open(), pathlib.Path.read_text/bytes
  - Network input: requests.get/post, httpx.*, urllib.request.urlopen, socket.recv
  - User input: input(), sys.stdin.read/readline

Sink categories:
  - Network output: requests.post/put/patch/get, httpx.*, urllib.request.urlopen, socket.send*
  - Code execution: exec, eval, compile, os.system, subprocess.*
  - File write: open(mode='w'/'a'), pathlib.Path.write_text/bytes, shutil.copy*

Rules:
  - TT1: Direct source→sink flow in single expression
  - TT2: Indirect/tainted variable flow (source assigned to var, var later used in sink)
  - TT3: CRITICAL — credential/env source → network output (secret exfiltration)
  - TT4: HIGH — file read → network output (data exfiltration)
  - TT5: CRITICAL — external input → code execution (RCE via user input)

Usage:
    from modules.taint_tracker import scan_taint_flows
    threats = scan_taint_flows(source_code, filename="plugin.py")
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ============================================================
# Data Structures
# ============================================================

@dataclass
class TaintThreat:
    """A single taint-flow finding."""
    rule_id: str
    message: str
    severity: str
    confidence: float
    filename: str
    line: int
    end_line: Optional[int]
    matched_text: str
    mitigation: str = ""


# ============================================================
# Source / Sink Definitions
# ============================================================

_CREDENTIAL_SOURCES = frozenset({
    "os.environ.get", "os.environ", "os.getenv",
})

_FILE_READ_SOURCES = frozenset({
    "open", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
})

_NETWORK_INPUT_SOURCES = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "socket.socket.recv", "socket.socket.recvfrom",
})

_USER_INPUT_SOURCES = frozenset({
    "input", "sys.stdin.read", "sys.stdin.readline",
})

_ALL_SOURCES = _CREDENTIAL_SOURCES | _FILE_READ_SOURCES | _NETWORK_INPUT_SOURCES | _USER_INPUT_SOURCES

_NETWORK_OUTPUT_SINKS = frozenset({
    "requests.post", "requests.put", "requests.patch", "requests.get",
    "httpx.post", "httpx.put", "httpx.patch", "httpx.get",
    "urllib.request.urlopen",
    "socket.socket.send", "socket.socket.sendall", "socket.socket.sendto",
})

_EXEC_SINKS = frozenset({
    "exec", "eval", "compile",
    "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.check_output",
    "subprocess.check_call", "subprocess.Popen",
})

_FILE_WRITE_SINKS = frozenset({
    "open", "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    "shutil.copy", "shutil.copy2", "shutil.copyfile",
})

_ALL_SINKS = _NETWORK_OUTPUT_SINKS | _EXEC_SINKS | _FILE_WRITE_SINKS

_EXTERNAL_INPUT_SOURCES = _NETWORK_INPUT_SOURCES | _USER_INPUT_SOURCES

_SOURCE_CATEGORIES = [
    (_CREDENTIAL_SOURCES, "credential/environment"),
    (_FILE_READ_SOURCES, "file read"),
    (_NETWORK_INPUT_SOURCES, "network input"),
    (_USER_INPUT_SOURCES, "user input"),
]

_SINK_CATEGORIES = [
    (_NETWORK_OUTPUT_SINKS, "network output"),
    (_EXEC_SINKS, "code execution"),
    (_FILE_WRITE_SINKS, "file write"),
]

_RULE_META: dict[str, dict] = {
    "TT1": {
        "message": "Direct data flow from source to sink",
        "severity": "high",
        "confidence": 0.80,
        "mitigation": "Validate and sanitize data before passing to sensitive sinks",
    },
    "TT2": {
        "message": "Indirect tainted data flow via variable assignment",
        "severity": "medium",
        "confidence": 0.65,
        "mitigation": "Ensure tainted variables are sanitized before reaching sinks",
    },
    "TT3": {
        "message": "CRITICAL: Credential/secret exfiltration chain detected",
        "severity": "critical",
        "confidence": 0.90,
        "mitigation": "NEVER send environment variables/secrets over the network — block this pattern",
    },
    "TT4": {
        "message": "File content exfiltration to network detected",
        "severity": "high",
        "confidence": 0.80,
        "mitigation": "Validate which files are read and where data is sent",
    },
    "TT5": {
        "message": "CRITICAL: External input flows to code execution (RCE risk)",
        "severity": "critical",
        "confidence": 0.90,
        "mitigation": "NEVER pass user/network input to exec/eval/subprocess — use safe parsers",
    },
}


# ============================================================
# AST Helpers
# ============================================================

def _resolve_call_name(call_node: ast.Call) -> Optional[str]:
    """Resolve a Call node to its dotted name."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
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


def _resolve_dotted_name(node: ast.expr) -> Optional[str]:
    """Resolve an expression to a dotted name (e.g. os.environ)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        n: ast.expr = node
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
            return ".".join(reversed(parts))
    return None


def _build_type_map(tree: ast.Module) -> Dict[str, str]:
    """Build a simple {variable_name: type_name} map from assignments.

    Handles: import os, import requests, from pathlib import Path, etc.
    """
    type_map: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                type_map[name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local_name = alias.asname or alias.name
                type_map[local_name] = f"{node.module}.{alias.name}"
    return type_map


def _resolve_with_types(name: str, type_map: Dict[str, str]) -> str:
    """Resolve a dotted name using the type map.

    e.g. if 'requests' is in type_map as 'requests',
    then 'requests.get' stays 'requests.get'.
    """
    parts = name.split(".", 1)
    if parts[0] in type_map:
        base = type_map[parts[0]]
        if len(parts) > 1:
            return f"{base}.{parts[1]}"
        return base
    return name


def _classify(name: str, categories: list, default: str) -> str:
    for names, label in categories:
        if name in names:
            return label
    return default


def _pick_rule(source_name: str, sink_name: str, is_direct: bool) -> str:
    """Choose the most specific rule ID for a source→sink pair."""
    if source_name in _CREDENTIAL_SOURCES and sink_name in _NETWORK_OUTPUT_SINKS:
        return "TT3"
    if source_name in _FILE_READ_SOURCES and sink_name in _NETWORK_OUTPUT_SINKS:
        return "TT4"
    if source_name in _EXTERNAL_INPUT_SOURCES and sink_name in _EXEC_SINKS:
        return "TT5"
    return "TT1" if is_direct else "TT2"


def _is_open_for_write(call_node: ast.Call) -> bool:
    """Heuristic: open() is a write sink if mode arg contains 'w' or 'a'."""
    if len(call_node.args) >= 2 and isinstance(call_node.args[1], ast.Constant):
        mode = str(call_node.args[1].value)
        return any(c in mode for c in "wa")
    for kw in call_node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = str(kw.value.value)
            return any(c in mode for c in "wa")
    return False


def _get_source_segment(lines: list[str], lineno: int, end_lineno: Optional[int]) -> str:
    start = max(0, lineno - 1)
    end = end_lineno if end_lineno else lineno
    return "\n".join(lines[start:end])[:300]


# ============================================================
# Taint Tracking Engine
# ============================================================

class _TaintedVar:
    """Represents a variable that holds tainted data."""
    __slots__ = ("name", "source_call", "lineno")

    def __init__(self, name: str, source_call: str, lineno: int):
        self.name = name
        self.source_call = source_call
        self.lineno = lineno


def _find_source_in_expr(node: ast.expr, type_map: Dict[str, str]) -> Optional[str]:
    """Find a source call anywhere in an expression tree."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        raw_name = _resolve_call_name(child)
        if raw_name is None:
            continue
        name = _resolve_with_types(raw_name, type_map)
        if name not in _ALL_SOURCES:
            continue
        if name == "open" and _is_open_for_write(child):
            continue
        return name
    return None


def _find_nested_sources(call_node: ast.Call, type_map: Dict[str, str]) -> List[Tuple[str, ast.Call]]:
    """Walk children to find source calls nested inside a sink call."""
    results: List[Tuple[str, ast.Call]] = []
    for child in ast.walk(call_node):
        if child is call_node:
            continue
        if not isinstance(child, ast.Call):
            continue
        raw_name = _resolve_call_name(child)
        if raw_name is None:
            continue
        name = _resolve_with_types(raw_name, type_map)
        if name in _ALL_SOURCES:
            results.append((name, child))
    return results


def _find_tainted_names_in_args(call_node: ast.Call, tainted: Dict[str, _TaintedVar]) -> List[_TaintedVar]:
    """Find references to tainted variables in a call's arguments."""
    seen: set[str] = set()
    hits: List[_TaintedVar] = []
    for child in ast.walk(call_node):
        if child is call_node:
            continue
        var_name: Optional[str] = None
        if isinstance(child, ast.Name):
            var_name = child.id
        elif isinstance(child, ast.Subscript):
            var_name = _resolve_dotted_name(child.value)
        if var_name and var_name not in seen:
            tv = tainted.get(var_name)
            if tv:
                seen.add(var_name)
                hits.append(tv)
    return hits


def _find_tainted_in_expr(node: ast.expr, tainted: Dict[str, _TaintedVar]) -> Optional[_TaintedVar]:
    """Return the first tainted variable referenced in node."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            tv = tainted.get(child.id)
            if tv:
                return tv
    return None


def _mark_targets(targets: list, tainted: Dict[str, _TaintedVar], src_name: str, lineno: int):
    """Mark assignment targets as tainted."""
    for target in targets:
        if isinstance(target, ast.Name):
            tainted[target.id] = _TaintedVar(target.id, src_name, lineno)
        elif isinstance(target, ast.Tuple):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    tainted[elt.id] = _TaintedVar(elt.id, src_name, lineno)


# ============================================================
# Core Analyzer
# ============================================================

def _analyze_python(content: str, filename: str) -> List[TaintThreat]:
    """Parse Python content and detect source→sink data flows."""
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError:
        return []

    type_map = _build_type_map(tree)
    lines = content.splitlines()
    threats: List[TaintThreat] = []
    tainted: Dict[str, _TaintedVar] = {}
    seen: set[Tuple[str, int]] = set()

    def _emit(rule_id: str, lineno: int, end_lineno: Optional[int], msg: str):
        key = (rule_id, lineno)
        if key in seen:
            return
        seen.add(key)
        meta = _RULE_META[rule_id]
        threats.append(TaintThreat(
            rule_id=rule_id,
            message=msg,
            severity=meta["severity"],
            confidence=meta["confidence"],
            filename=filename,
            line=lineno,
            end_line=end_lineno,
            matched_text=_get_source_segment(lines, lineno, end_lineno),
            mitigation=meta["mitigation"],
        ))

    for ast_node in ast.walk(tree):
        # Record tainted assignments.
        if isinstance(ast_node, ast.Assign):
            src_name = _find_source_in_expr(ast_node.value, type_map)

            # Subscript sources like os.environ["KEY"]
            if src_name is None and isinstance(ast_node.value, ast.Subscript):
                base = _resolve_dotted_name(ast_node.value.value)
                if base:
                    resolved = _resolve_with_types(base, type_map)
                    if resolved in _CREDENTIAL_SOURCES:
                        src_name = resolved

            # Propagate taint through re-assignment
            if src_name is None:
                tv = _find_tainted_in_expr(ast_node.value, tainted)
                if tv:
                    src_name = tv.source_call

            if src_name:
                _mark_targets(ast_node.targets, tainted, src_name, ast_node.lineno)
            continue

        # Detect flows at sink call sites.
        if not isinstance(ast_node, ast.Call):
            continue

        raw_sink = _resolve_call_name(ast_node)
        if raw_sink is None:
            continue
        sink_name = _resolve_with_types(raw_sink, type_map)
        if sink_name not in _ALL_SINKS:
            continue

        if sink_name == "open" and not _is_open_for_write(ast_node):
            continue

        lineno = getattr(ast_node, "lineno", 1)
        end_lineno = getattr(ast_node, "end_lineno", None)

        # Direct flows: source nested inside sink call
        for src_name, src_node in _find_nested_sources(ast_node, type_map):
            if src_name == "open" and _is_open_for_write(src_node):
                continue
            rule = _pick_rule(src_name, sink_name, is_direct=True)
            src_cat = _classify(src_name, _SOURCE_CATEGORIES, "data source")
            sink_cat = _classify(sink_name, _SINK_CATEGORIES, "data sink")
            _emit(rule, lineno, end_lineno,
                  f"Direct flow: {src_name} ({src_cat}) → {sink_name} ({sink_cat})")

        # Indirect flows: tainted variable used in sink
        for tv in _find_tainted_names_in_args(ast_node, tainted):
            rule = _pick_rule(tv.source_call, sink_name, is_direct=False)
            src_cat = _classify(tv.source_call, _SOURCE_CATEGORIES, "data source")
            sink_cat = _classify(sink_name, _SINK_CATEGORIES, "data sink")
            _emit(rule, lineno, end_lineno,
                  f"Tainted flow: '{tv.name}' from {tv.source_call} (line {tv.lineno}, "
                  f"{src_cat}) → {sink_name} ({sink_cat})")

    return threats


# ============================================================
# Public API
# ============================================================

def scan_taint_flows(source: str, filename: str = "<unknown>") -> List[TaintThreat]:
    """Scan Python source for data-flow taint issues (source→sink chains).

    Args:
        source:   Python source code string
        filename: Logical filename for reporting

    Returns:
        List of TaintThreat objects
    """
    if not source or not source.strip():
        return []
    if len(source) > 512_000:
        return []
    return _analyze_python(source, filename)
