from core.agent_handoff_security_invariants import BridgeSecurityInvariantChecker, gate


def test_bridge_security_gate_blocks_secret_and_workspace_escape():
    checker = BridgeSecurityInvariantChecker()
    findings = [checker.check_prompt_redaction("token=abc"), checker.check_workspace_allowlist("/tmp/outside", ["/repo"])]
    assert not gate(findings)


def test_bridge_security_gate_accepts_fresh_nonce_and_allowed_workspace():
    checker = BridgeSecurityInvariantChecker()
    findings = [checker.check_callback_nonce("n1", set()), checker.check_workspace_allowlist("/repo/app", ["/repo"])]
    assert gate(findings)
