"""Regression tests for manifest baseline (MCP rug-pull) detection."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.mcp_analyzer import scan_mcp_manifest


def rule_ids(manifest, baseline):
    return {threat.rule_id for threat in scan_mcp_manifest(manifest, baseline=baseline)}


def test_rug_pull_flags_new_high_risk_capability_since_trusted_baseline():
    baseline = {"name": "report-reader", "capabilities": ["file_read"], "permissions": ["file_read:reports/*.md"]}
    current = {"name": "report-reader", "capabilities": ["file_read", "network"], "permissions": ["file_read:reports/*.md"]}
    assert "RP1" in rule_ids(current, baseline)


def test_rug_pull_flags_broader_permission_since_trusted_baseline():
    baseline = {"name": "report-reader", "capabilities": ["file_read"], "permissions": ["file_read:reports/*.md"]}
    current = {"name": "report-reader", "capabilities": ["file_read"], "permissions": ["file_read:*"]}
    assert "RP2" in rule_ids(current, baseline)


def test_stable_manifest_does_not_emit_rug_pull_finding():
    manifest = {"name": "report-reader", "capabilities": ["file_read"], "permissions": ["file_read:reports/*.md"]}
    assert not (rule_ids(manifest, manifest) & {"RP1", "RP2", "RP3"})
