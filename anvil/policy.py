"""
ANVIL policy layer: the gate every tool call passes through BEFORE it runs.

This is where "don't trust the model" becomes mechanical. Four enforced rules:

  1. Tool allowlist  - a task may only use tools its contract granted.
  2. Scope guard      - a task may only touch paths inside its declared scope.
                        Runs on EVERY call, not just at plan review, so scope
                        creep is caught in-flight, not after the damage.
  3. Risk gate        - irreversible actions never auto-run; they require a
                        recorded, hash-chained human approval (commit-point).
  4. Credential wall  - the agent never receives raw secrets. Tools that need
                        prod credentials are unavailable unless the environment
                        is explicitly elevated AND approval exists. Secrets live
                        with the harness; the agent gets brokered calls only.

Extension point: to make this *non-bypassable* (Gemini's point), wire `decide`
into your selfconnect-terminal PTY interception so the shell physically cannot
exec a denied call. At the controller layer it governs a cooperating adapter;
at the PTY layer it governs an adversarial one.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

from .schemas import PolicyDecision, Risk, Task, ToolCall


@dataclass
class ToolPolicy:
    # tools that touch irreversible/external state -> always commit-point gated
    irreversible_tools: set[str] = field(default_factory=lambda: {
        "deploy", "db_migrate", "db_write_prod", "delete", "rm", "publish",
        "pay", "transfer", "dns_write", "terraform_apply", "force_push",
    })
    # tools that require an elevated environment (prod creds) to even be offered
    privileged_tools: set[str] = field(default_factory=lambda: {
        "db_write_prod", "deploy", "terraform_apply", "dns_write", "pay", "transfer",
    })


class PolicyEngine:
    def __init__(self, policy: Optional[ToolPolicy] = None, elevated: bool = False):
        self.policy = policy or ToolPolicy()
        # elevated == this session is permitted to hold prod credentials.
        # Default False: development credentials only, prod is unreachable.
        self.elevated = elevated

    def classify_risk(self, call: ToolCall) -> Risk:
        if call.risk == Risk.IRREVERSIBLE or call.tool in self.policy.irreversible_tools:
            return Risk.IRREVERSIBLE
        return Risk.REVERSIBLE

    def _in_scope(self, target: str, allowed: list[str]) -> bool:
        if not allowed:
            # No declared paths => the task is not permitted to touch the filesystem.
            return False
        return any(fnmatch.fnmatch(target, pat) for pat in allowed)

    def decide(self, call: ToolCall, task: Task) -> PolicyDecision:
        # 1. allowlist
        if task.tools and call.tool not in task.tools:
            return PolicyDecision(False, f"tool '{call.tool}' not in task '{task.id}' allowlist")

        # 4a. credential wall: privileged tools need an elevated session
        if call.tool in self.policy.privileged_tools and not self.elevated:
            return PolicyDecision(
                False,
                f"tool '{call.tool}' needs prod credentials; session is dev-isolated "
                f"(no prod secrets reachable in agent session)",
            )

        # 2. scope guard on every path touched
        for p in call.paths:
            if not self._in_scope(p, task.paths):
                return PolicyDecision(False, f"path '{p}' outside task scope {task.paths}")

        # 3. risk gate
        if self.classify_risk(call) == Risk.IRREVERSIBLE:
            return PolicyDecision(
                False,
                f"irreversible action '{call.tool}' requires commit-point approval",
                requires_approval=True,
            )

        return PolicyDecision(True, "allowed")
