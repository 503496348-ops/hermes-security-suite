# -*- coding: utf-8 -*-
"""Regression coverage for MCP least-privilege and OSV fusion hardening."""

from __future__ import annotations

import json

from detector.modules.mcp_analyzer import (
    build_least_privilege_profile,
    scan_mcp_manifest,
)
from detector.modules.osv_client import OSVClient
from detector.modules.supply_chain import scan_with_osv_lookup


def test_mcp_least_privilege_flags_wildcards_and_scope_mismatch() -> None:
    manifest = {
        "name": "wide-access-tool",
        "description": "Reads one project report.",
        "capabilities": ["filesystem:*", "network:http", "shell"],
        "permissions": ["files:read:/tmp/reports/*.md", "network:egress:*"],
        "parameters": [
            {"name": "path", "description": "Read any file on the system"},
        ],
    }

    threats = scan_mcp_manifest(manifest)
    rule_ids = {threat.rule_id for threat in threats}
    descriptions = "\n".join(threat.description for threat in threats)

    assert "LP1" in rule_ids
    assert "LP2" in rule_ids
    assert "wildcard" in descriptions.lower() or "broad" in descriptions.lower()
    assert any(threat.severity in {"HIGH", "CRITICAL"} for threat in threats)


def test_build_least_privilege_profile_returns_actionable_reductions() -> None:
    manifest = {
        "name": "report-writer",
        "capabilities": ["file_write", "network", "admin"],
        "permissions": ["files:write:/workspace/reports/*.md", "network:egress:api.internal"],
    }

    profile = build_least_privilege_profile(manifest)

    assert profile["tool_name"] == "report-writer"
    assert "file_write" in profile["dangerous_capabilities"]
    assert "admin" in profile["dangerous_capabilities"]
    assert profile["recommended_capabilities"] == ["files:write:/workspace/reports/*.md", "network:egress:api.internal"]
    assert profile["risk_score"] >= 50
    assert profile["recommendations"]


def test_osv_client_supports_batch_endpoint_and_cvss_severity(monkeypatch) -> None:
    captured = {}

    def fake_curl(self, endpoint, data=None):
        captured["endpoint"] = endpoint
        captured["payload"] = json.loads(data)
        return {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-test",
                            "summary": "critical package issue",
                            "aliases": ["CVE-2099-0001"],
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}],
                            "references": [{"url": "https://advisories.example/GHSA-test"}],
                        }
                    ]
                },
                {},
            ]
        }

    monkeypatch.setattr(OSVClient, "_curl", fake_curl)
    client = OSVClient()
    results = client.query_batch([("vulnlib", "1.0.0"), ("safelib", "2.0.0")], ecosystem="PyPI")

    assert captured["endpoint"] == "querybatch"
    assert captured["payload"]["queries"][0]["version"] == "1.0.0"
    assert results["vulnlib"][0].severity == "CRITICAL"
    assert results["vulnlib"][0].fixed_version == "9.9.9"
    assert results["safelib"] == []


def test_supply_chain_osv_lookup_uses_versions_and_injected_client(tmp_path) -> None:
    (tmp_path / "requirements.txt").write_text("vulnlib==1.2.3\nsafelib>=2.0\n", encoding="utf-8")

    class FakeClient:
        def query_batch(self, packages, ecosystem="PyPI"):
            assert packages == [("vulnlib", "1.2.3"), ("safelib", None)]
            assert ecosystem == "PyPI"
            vuln = type(
                "Vuln",
                (),
                {
                    "vuln_id": "GHSA-unit",
                    "summary": "unit vulnerability",
                    "severity": "HIGH",
                    "fixed_version": "1.2.4",
                    "references": ["https://advisories.example/GHSA-unit"],
                },
            )()
            return {"vulnlib": [vuln], "safelib": []}

    threats = scan_with_osv_lookup(str(tmp_path), osv_client=FakeClient())

    osv_threats = [threat for threat in threats if threat.rule_id == "SC4"]
    assert len(osv_threats) == 1
    assert osv_threats[0].package_name == "vulnlib"
    assert "GHSA-unit" in osv_threats[0].details
    assert "1.2.4" in osv_threats[0].mitigation
