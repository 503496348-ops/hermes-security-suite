"""Security invariants for agent handoff callbacks and workspaces."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable

SECRET_MARKERS = ("api_key", "token=", "password=", "secret=", "sk-")

@dataclass(frozen=True)
class BridgeSecurityFinding:
    invariant: str
    ok: bool
    detail: str

class BridgeSecurityInvariantChecker:
    def check_prompt_redaction(self, text: str) -> BridgeSecurityFinding:
        lowered = text.lower()
        hits = [m for m in SECRET_MARKERS if m in lowered]
        return BridgeSecurityFinding("prompt-redaction", not hits, "hits=" + ",".join(hits) if hits else "clean")

    def check_workspace_allowlist(self, cwd: str, allowlist: Iterable[str]) -> BridgeSecurityFinding:
        allowed = tuple(allowlist)
        ok = any(cwd == root or cwd.startswith(root.rstrip("/") + "/") for root in allowed)
        return BridgeSecurityFinding("workspace-allowlist", ok, cwd if ok else f"outside allowlist: {cwd}")

    def check_callback_nonce(self, nonce: str | None, seen: set[str]) -> BridgeSecurityFinding:
        if not nonce:
            return BridgeSecurityFinding("callback-nonce", False, "missing nonce")
        if nonce in seen:
            return BridgeSecurityFinding("callback-nonce", False, "replayed nonce")
        return BridgeSecurityFinding("callback-nonce", True, "fresh")

def gate(findings: Iterable[BridgeSecurityFinding]) -> bool:
    return all(f.ok for f in findings)
