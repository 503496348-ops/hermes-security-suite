"""Security invariants for agent action control surfaces."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_WEBHOOK_DOMAINS = ("open.feishu.cn", "open.larksuite.com", "hooks.slack.com")
HIGH_RISK_ACTIONS = {"complete", "cancel_running", "delete", "rollback", "change_model"}


@dataclass(frozen=True)
class PolicyFinding:
    severity: str
    code: str
    message: str


def validate_webhook_url(url: str) -> list[PolicyFinding]:
    parsed = urlparse(url)
    findings: list[PolicyFinding] = []
    if parsed.scheme != "https":
        findings.append(PolicyFinding("critical", "webhook_https_required", "webhook must use https"))
    host = parsed.hostname or ""
    if not any(host == d or host.endswith("." + d) for d in ALLOWED_WEBHOOK_DOMAINS):
        findings.append(PolicyFinding("critical", "webhook_domain_not_allowed", f"domain not allowed: {host}"))
    return findings


def validate_action_request(action: str, *, confirmed: bool, actor_role: str) -> list[PolicyFinding]:
    findings: list[PolicyFinding] = []
    if action in HIGH_RISK_ACTIONS and not confirmed:
        findings.append(PolicyFinding("critical", "confirmation_required", f"{action} requires explicit confirmation"))
    if action == "change_model" and actor_role != "operator":
        findings.append(PolicyFinding("critical", "operator_role_required", "model changes require operator role"))
    return findings


def validate_cors_origins(origins: list[str]) -> list[PolicyFinding]:
    if "*" in origins:
        return [PolicyFinding("critical", "wildcard_cors_forbidden", "control plane cannot allow wildcard CORS")]
    return []
