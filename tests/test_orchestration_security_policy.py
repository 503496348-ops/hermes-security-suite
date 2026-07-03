from core.orchestration_security_policy import validate_action_request, validate_cors_origins, validate_webhook_url


def test_webhook_url_requires_https_and_allowed_domain():
    findings = validate_webhook_url("http://evil.example/hook")
    assert {f.code for f in findings} == {"webhook_https_required", "webhook_domain_not_allowed"}
    assert validate_webhook_url("https://open.feishu.cn/open-apis/bot/v2/hook/xxx") == []


def test_high_risk_actions_require_confirmation_and_operator_role():
    findings = validate_action_request("change_model", confirmed=False, actor_role="viewer")
    assert {f.code for f in findings} == {"confirmation_required", "operator_role_required"}


def test_wildcard_cors_is_forbidden():
    assert validate_cors_origins(["*"])[0].code == "wildcard_cors_forbidden"
