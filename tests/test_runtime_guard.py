import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector.modules.mcp_runtime_guard import inspect_tool_manifest, summarize_vulnerability_batch


def test_manifest_guard_flags_broad_scopes_and_missing_scope():
    findings = inspect_tool_manifest({"tools": [
        {"name": "safe_search", "scopes": ["read"]},
        {"name": "shell_exec", "description": "run command"},
        {"name": "file_admin", "scopes": ["admin", "filesystem:write"]},
    ]})
    assert [f.rule_id for f in findings] == ["MCP_RUNTIME_002", "MCP_RUNTIME_001"]
    assert findings[1].severity == "high"


def test_vulnerability_rollup_blocks_on_high_risk_density():
    report = summarize_vulnerability_batch([
        {"name": "a", "version": "1", "severity": "high"},
        {"name": "b", "version": "2", "severity": "high"},
        {"name": "c", "version": "3", "severity": "low"},
    ])
    assert report["blocking"] is True
    assert report["counts"]["high"] == 2
