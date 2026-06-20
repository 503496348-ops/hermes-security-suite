# -*- coding: utf-8 -*-
"""
奇点造物-Genesisix · Advanced Analysis Modules
AtomCollide-智械工坊 · 2026

Modules:
  - ast_analyzer:   Python AST behavioral analysis (dangerous execution patterns)
  - taint_tracker:  Source→sink data-flow taint tracking
  - yara_scanner:   YARA signature scanning for malware/webshell/cryptominer/hacktool
"""

from .ast_analyzer import scan_ast
from .taint_tracker import scan_taint_flows
from .yara_scanner import scan_yara

__all__ = ["scan_ast", "scan_taint_flows", "scan_yara"]
