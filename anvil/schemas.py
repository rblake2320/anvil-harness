"""
ANVIL core schemas: the vocabulary the whole harness shares.

Everything that crosses a boundary (ledger, policy, gates) is one of these.
Stdlib-only by design so the controller can run anywhere — including air-gapped
IL5-style environments — with no supply chain to vet.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Phase(str, enum.Enum):
    """The cradle-to-grave lifecycle. Order is enforced by the lifecycle engine."""
    INTAKE = "intake"        # freeze the request, immutable + hashed
    BASELINE = "baseline"    # discover repo/world state before planning
    COMPILE = "compile"      # emit the execution contract (DAG, acceptance, budgets)
    REVIEW = "review"        # verifier gate on the PLAN itself (scope/tests/risk)
    EXECUTE = "execute"      # one leaf task at a time, scoped tools + context
    VERIFY = "verify"        # independent proof check; executor != verifier
    RELEASE = "release"      # commit-point gate for irreversible actions
    MONITOR = "monitor"      # post-release watch
    LEARN = "learn"          # write durable cross-session memory
    DONE = "done"
    HALTED = "halted"        # circuit breaker / operator pause


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    READY = "ready"          # all deps satisfied
    RUNNING = "running"
    AWAITING_PROOF = "awaiting_proof"
    AWAITING_APPROVAL = "awaiting_approval"   # irreversible commit-point
    DONE = "done"
    FAILED = "failed"
    BLOCKED = "blocked"      # blocking ambiguity / dependency failure


class Risk(str, enum.Enum):
    """Reversibility is the axis that decides autonomy vs commit-point HITL."""
    REVERSIBLE = "reversible"        # read, search, plan, branch edit, run tests -> autonomous
    IRREVERSIBLE = "irreversible"    # deploy, migrate, delete, publish, pay -> commit-point gate


class AmbiguityClass(str, enum.Enum):
    """GPT's ambiguity policy: never freeze on missing detail, but never silently guess."""
    BLOCKING = "blocking"            # cannot proceed safely -> escalate
    SAFE_DEFAULT = "safe_default"    # proceed with recorded assumption (reversible)
    SANDBOX_ONLY = "sandbox_only"    # proceed only in an isolated sandbox


class EventType(str, enum.Enum):
    INTAKE_FROZEN = "intake_frozen"
    BASELINE_CAPTURED = "baseline_captured"
    CONTRACT_COMPILED = "contract_compiled"
    REVIEW_PASSED = "review_passed"
    REVIEW_REJECTED = "review_rejected"
    TASK_STARTED = "task_started"
    TOOL_CALL_ALLOWED = "tool_call_allowed"
    TOOL_CALL_DENIED = "tool_call_denied"
    SCOPE_VIOLATION = "scope_violation"
    EVIDENCE_RECORDED = "evidence_recorded"
    PROOF_ACCEPTED = "proof_accepted"
    PROOF_REJECTED = "proof_rejected"
    ACCEPTANCE_TAMPERED = "acceptance_tampered"
    TASK_DONE = "task_done"
    TASK_FAILED = "task_failed"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    CHECKPOINT_MADE = "checkpoint_made"
    ROLLED_BACK = "rolled_back"
    COMPENSATED = "compensated"
    BUDGET_TRIPPED = "budget_tripped"
    CIRCUIT_OPEN = "circuit_open"
    ASSUMPTION_RECORDED = "assumption_recorded"
    MEMORY_WRITTEN = "memory_written"
    PHASE_CHANGED = "phase_changed"
    TOKEN_CHARGED = "token_charged"
    CONTEXT_COMMITTED = "context_committed"  # bundle hash anchored before agent call
    CONTEXT_TAMPERED  = "context_tampered"   # spec hash mismatch — security event
    CONTEXT_OVERSIZE  = "context_oversize"   # bundle exceeds per-task token ceiling


@dataclass
class AcceptanceCheck:
    """One verifiable success criterion. `kind` tells the verifier how to prove it."""
    id: str
    description: str
    kind: str                      # "command" | "behavior" | "artifact" | "manual"
    spec: dict[str, Any] = field(default_factory=dict)   # e.g. {"cmd": "...", "expect_exit": 0}
    authored_by: str = "qa"        # anti-gaming: test author != code author on high risk

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Task:
    id: str
    title: str
    risk: Risk = Risk.REVERSIBLE
    deps: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)      # tools this task is permitted to use
    paths: list[str] = field(default_factory=list)      # filesystem scope this task may touch
    acceptance: list[AcceptanceCheck] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    strikes: int = 0
    evidence: list[str] = field(default_factory=list)   # ledger entry hashes proving work

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["risk"] = self.risk.value
        d["status"] = self.status.value
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Task":
        return Task(
            id=d["id"],
            title=d["title"],
            risk=Risk(d.get("risk", "reversible")),
            deps=list(d.get("deps", [])),
            tools=list(d.get("tools", [])),
            paths=list(d.get("paths", [])),
            acceptance=[AcceptanceCheck(**a) for a in d.get("acceptance", [])],
            status=TaskStatus(d.get("status", "pending")),
            strikes=int(d.get("strikes", 0)),
            evidence=list(d.get("evidence", [])),
        )


@dataclass
class ToolCall:
    """A requested action. The policy layer decides allow/deny BEFORE it runs."""
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    task_id: Optional[str] = None
    paths: list[str] = field(default_factory=list)      # filesystem targets, if any
    risk: Risk = Risk.REVERSIBLE


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    requires_approval: bool = False


@dataclass
class Evidence:
    """Proof that work happened. Stored in the ledger; referenced by tasks."""
    task_id: str
    check_id: str
    ok: bool
    detail: str
    artifact: dict[str, Any] = field(default_factory=dict)  # cmd output, diff, exit code...
