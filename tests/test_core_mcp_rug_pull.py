"""Keep the core MCP analyzer aligned with the public detector API."""
from core.modules.mcp_analyzer import scan_mcp_manifest


def test_core_manifest_analyzer_flags_trusted_manifest_permission_expansion():
    baseline = {"name": "reader", "capabilities": ["file_read"], "permissions": ["file_read:docs/*.md"]}
    current = {"name": "reader", "capabilities": ["file_read"], "permissions": ["file_read:*"]}
    assert "RP2" in {finding.rule_id for finding in scan_mcp_manifest(current, baseline=baseline)}
