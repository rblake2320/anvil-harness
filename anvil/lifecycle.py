"""
ANVIL lifecycle engine: the controller that owns truth.

Runs the cradle-to-grave state machine and enforces, at each step, the invariants
the council converged on. The agent proposes; the harness disposes.

PHASES
  intake   -> freeze + hash the request (immutable source of truth)
  baseline -> capture world/repo state before planning (recorded in ledger)
  compile  -> turn request into a Contract; LOCK acceptance hashes (seals)
  review   -> gate the PLAN: every task has acceptance; high-risk tasks have
              independent (non-executor) test authorship; scope is explicit
  execute  -> DAG-ordered, one ready leaf at a time:
                * agent proposes tool calls
                * policy gates each call (allowlist / scope / risk / creds)
                * irreversible calls -> AWAITING_APPROVAL (commit-point HITL)
                * budget/circuit checked on every charge
  verify   -> independent ProofGate: no proof = not done; tamper => reject
  release  -> irreversible actions execute only after recorded approval, with a
              compensation registered the instant a side effect succeeds
  monitor  -> post-release hook (recorded)
  learn    -> write durable MEMORY.md and final audit vs ORIGINAL_REQUEST

Every transition and decision is appended to the hash-chained ledger AND fanned
out to specialist log channels via the LogRouter.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from .adapters import AgentAdapter, VerifierAdapter
from .budget import Budget, CircuitBreaker
from .ledger import Ledger, LedgerEntry
from .log import EVENT_LEVELS, LogChannel, LogLevel, LogRouter, TraceContext
from .policy import PolicyEngine, ToolPolicy
from .proofgate import ProofGate
from .recovery import Compensation, RecoveryManager, RepairAction
from .schemas import (
    AmbiguityClass, EventType, Phase, PolicyDecision, Risk, Task, TaskStatus, ToolCall,
)
from .store import Contract, MissionStore

# An approval callback returns True to grant a commit-point, False to deny.
ApprovalFn = Callable[[Task, ToolCall], bool]


@dataclass
class StepResult:
    phase: Phase
    note: str
    halted: bool = False


class Lifecycle:
    def __init__(
        self,
        store: MissionStore,
        agent: AgentAdapter,
        verifier: VerifierAdapter,
        *,
        policy: Optional[PolicyEngine] = None,
        budget: Optional[Budget] = None,
        approval_fn: Optional[ApprovalFn] = None,
        signing_key: Optional[bytes] = None,
        code_author: str = "executor",
        trace_id: Optional[str] = None,
    ):
        self.store = store
        self.agent = agent
        self.verifier = verifier
        self.policy = policy or PolicyEngine(ToolPolicy(), elevated=False)
        self.ledger = Ledger(store.ledger_path, signing_key=signing_key)
        self.breaker = CircuitBreaker(budget or Budget())
        self.gate = ProofGate(code_author=code_author)
        self.recovery = RecoveryManager()
        self.log_router = LogRouter(store.log_dir)
        # Pass prior run's trace_id to link resumed segments; None generates a fresh one.
        self.trace = TraceContext(trace_id=trace_id)
        # default approval: deny everything (fail safe). Wire a real HITL fn in.
        self.approval_fn = approval_fn or (lambda t, c: False)
        self.phase = Phase.INTAKE
        self.contract: Optional[Contract] = None
        self._anchored = False

    # ---- ledger + log router ----

    def _maybe_anchor(self) -> None:
        """Commit channel hashes to the ledger exactly once per run."""
        if not self._anchored:
            self.log_router.anchor(self.ledger)
            self._anchored = True

    def _log(self, etype: EventType, **payload) -> LedgerEntry:
        entry = self.ledger.append(etype.value, payload)
        level = EVENT_LEVELS.get(etype.value, LogLevel.INFO.value)
        self.log_router.route(
            etype.value, payload,
            level=level,
            trace_id=self.trace.trace_id,
            span_id=self.trace.current_span_id,
        )
        return entry

    def _set_phase(self, phase: Phase, note: str = "") -> None:
        self.phase = phase
        self._log(EventType.PHASE_CHANGED, phase=phase.value, note=note)
        if self.contract:
            self.store.save_state(phase, self.contract.tasks)
        if phase == Phase.HALTED:
            self._maybe_anchor()

    def _guard_budget(self, steps: int = 1, cost: float = 0.0) -> Optional[StepResult]:
        self.breaker.charge(steps=steps, cost=cost)
        ok, reason = self.breaker.check()
        if not ok:
            self._log(EventType.CIRCUIT_OPEN, reason=reason)
            self._set_phase(Phase.HALTED, note=reason or "circuit open")
            return StepResult(Phase.HALTED, reason or "circuit open", halted=True)
        return None

    # ================= phases =================

    def intake(self, request_text: str) -> StepResult:
        h = self.store.freeze_request(request_text)
        # Log trace_id in the ledger so resumed runs can recover it for continuity.
        self._log(EventType.INTAKE_FROZEN, request_hash=h, trace_id=self.trace.trace_id)
        # surface durable memory at session start (cross-session amnesia fix)
        mem = self.store.read_memory()
        if mem:
            self._log(EventType.MEMORY_WRITTEN, action="loaded", chars=len(mem))
        self._set_phase(Phase.BASELINE, note="request frozen")
        return StepResult(self.phase, f"request frozen sha256={h[:12]}")

    def baseline(self, snapshot: dict) -> StepResult:
        self._log(EventType.BASELINE_CAPTURED, snapshot=snapshot)
        ref = snapshot.get("ref", "baseline")
        self.recovery.checkpoint("baseline", ref)
        self._log(EventType.CHECKPOINT_MADE, label="baseline", ref=ref)
        self._set_phase(Phase.COMPILE, note="baseline captured")
        return StepResult(self.phase, "baseline captured")

    def compile(self, contract: Contract) -> StepResult:
        # LOCK acceptance hashes (the seal that defeats test-gaming)
        for t in contract.tasks:
            contract.acceptance_locks[t.id] = self.gate.lock(t)
        self.contract = contract
        self.store.save_contract(contract)
        self._log(EventType.CONTRACT_COMPILED,
                  tasks=[t.id for t in contract.tasks],
                  locks=contract.acceptance_locks)
        self._set_phase(Phase.REVIEW, note="contract compiled + sealed")
        return StepResult(self.phase, f"compiled {len(contract.tasks)} tasks")

    def review(self) -> StepResult:
        """Gate the plan itself before any work begins."""
        assert self.contract
        problems: list[str] = []
        for t in self.contract.tasks:
            if not t.acceptance:
                problems.append(f"{t.id}: no acceptance criteria")
            if t.risk == Risk.IRREVERSIBLE:
                self_authored = [c.id for c in t.acceptance if c.authored_by == self.gate.code_author]
                if self_authored:
                    problems.append(
                        f"{t.id}: high-risk task has executor-authored checks {self_authored}; "
                        f"require independent (QA) authorship"
                    )
            for dep in t.deps:
                if dep not in {x.id for x in self.contract.tasks}:
                    problems.append(f"{t.id}: unknown dependency '{dep}'")
        if problems:
            self._log(EventType.REVIEW_REJECTED, problems=problems)
            self._set_phase(Phase.HALTED, note="review rejected")
            return StepResult(Phase.HALTED, "; ".join(problems), halted=True)
        self._log(EventType.REVIEW_PASSED, tasks=len(self.contract.tasks))
        self._set_phase(Phase.EXECUTE, note="plan approved")
        return StepResult(self.phase, "plan approved")

    # ---- DAG readiness ----

    def _ready_tasks(self) -> list[Task]:
        assert self.contract
        done = {t.id for t in self.contract.tasks if t.status == TaskStatus.DONE}
        ready = []
        for t in self.contract.tasks:
            if t.status in (TaskStatus.DONE, TaskStatus.FAILED):
                continue
            if all(d in done for d in t.deps):
                ready.append(t)
        return ready

    def record_assumption(self, question: str, klass: AmbiguityClass, decision: str) -> None:
        """Ambiguity policy: never freeze, never silently guess."""
        reversible = klass == AmbiguityClass.SAFE_DEFAULT
        self.store.record_assumption(question, decision, reversible)
        self._log(EventType.ASSUMPTION_RECORDED, question=question,
                  klass=klass.value, decision=decision)

    # ---- one task, end to end ----

    def run_task(self, task: Task) -> bool:
        """Span-tracking wrapper: opens a trace span, delegates to _do_task,
        then records timing to PERF and TRACE channels."""
        if self._guard_budget():
            return False

        span_id = self.trace.start_span(f"task:{task.id}")
        self.log_router.write(
            LogChannel.TRACE, "span_started",
            {"span_id": span_id, "name": f"task:{task.id}", "task": task.id,
             "parent_id": self.trace.current_span_id},
            trace_id=self.trace.trace_id, span_id=span_id,
        )

        task.status = TaskStatus.RUNNING
        self._log(EventType.TASK_STARTED, task=task.id, risk=task.risk.value, strikes=task.strikes)

        success = False
        try:
            success = self._do_task(task, span_id)
        finally:
            status = "ok" if task.status == TaskStatus.DONE else "error"
            span = self.trace.end_span(span_id, status=status)
            self.log_router.write(
                LogChannel.TRACE, "span_ended",
                {"span_id": span_id, "duration_ms": span.duration_ms(), "status": status},
                trace_id=self.trace.trace_id,
            )
            self.log_router.write(
                LogChannel.PERF, "task_timing",
                {"task": task.id, "duration_ms": span.duration_ms(),
                 "status": status, "strikes": task.strikes},
                trace_id=self.trace.trace_id,
            )
        return success

    def _do_task(self, task: Task, span_id: str) -> bool:
        """Execute -> verify -> (approve+release if irreversible). Returns success."""

        # 1) AGENT DECISION: log what the executor proposes before gating
        calls = self.agent.plan_calls(task)
        if calls:
            self.log_router.write(
                LogChannel.AGENT, "agent_decision",
                {"task": task.id,
                 "proposed_calls": [{"tool": c.tool, "paths": c.paths, "risk": c.risk.value}
                                    for c in calls]},
                trace_id=self.trace.trace_id, span_id=span_id,
            )

        # 2) EXECUTE: harness gates each proposed call
        for call in calls:
            if self._guard_budget():
                return False

            decision: PolicyDecision = self.policy.decide(call, task)
            if not decision.allowed and not decision.requires_approval:
                etype = (EventType.SCOPE_VIOLATION if "scope" in decision.reason
                         else EventType.TOOL_CALL_DENIED)
                self._log(etype, task=task.id, tool=call.tool, reason=decision.reason)
                return self._strike(task, f"denied: {decision.reason}")

            if decision.requires_approval:
                # commit-point: irreversible work pauses for recorded human approval
                task.status = TaskStatus.AWAITING_APPROVAL
                self._log(EventType.APPROVAL_REQUESTED, task=task.id, tool=call.tool,
                          args=call.args)
                granted = self.approval_fn(task, call)
                if not granted:
                    self._log(EventType.APPROVAL_DENIED, task=task.id, tool=call.tool)
                    return self._strike(task, "approval denied")
                self._log(EventType.APPROVAL_GRANTED, task=task.id, tool=call.tool)

            self._log(EventType.TOOL_CALL_ALLOWED, task=task.id, tool=call.tool)

            # DEPENDENCY: time the actual execution and log latency
            dep_start = time.monotonic()
            result = self.agent.perform(task, call)
            dep_ms = (time.monotonic() - dep_start) * 1000.0
            self.log_router.write(
                LogChannel.DEPENDENCY, "dependency_result",
                {"task": task.id, "tool": call.tool,
                 "ok": result.get("ok"), "duration_ms": dep_ms},
                trace_id=self.trace.trace_id, span_id=span_id,
            )

            # TOKEN: if the adapter returns usage, charge + log it
            inp = result.get("input_tokens", 0)
            out = result.get("output_tokens", 0)
            call_cost = result.get("cost", 0.0)
            if inp or out or call_cost:
                self.breaker.charge(input_tokens=inp, output_tokens=out, cost=call_cost)
                self._log(EventType.TOKEN_CHARGED, task=task.id, tool=call.tool,
                          input_tokens=inp, output_tokens=out, cost=call_cost,
                          cumulative_cost=self.breaker.cost,
                          cumulative_input_tokens=self.breaker.input_tokens,
                          cumulative_output_tokens=self.breaker.output_tokens)

            # SAGA: if an irreversible side effect succeeded, register compensation NOW
            if self.policy.classify_risk(call) == Risk.IRREVERSIBLE and result.get("ok"):
                idem = result.get("idempotency_key", f"{task.id}:{call.tool}")
                undo = result.get("undo")
                if callable(undo):
                    comp = Compensation(side_effect=f"{call.tool}", idempotency_key=idem,
                                        undo=undo, note=task.id)
                    if self.recovery.register_compensation(comp):
                        self._log(EventType.CHECKPOINT_MADE, kind="compensation",
                                  side_effect=call.tool, idem=idem)

        # 3) VERIFY: independent proof gate against the LOCKED acceptance
        task.status = TaskStatus.AWAITING_PROOF
        locked = self.contract.acceptance_locks.get(task.id, "")
        gate = self.gate.evaluate(task, locked, self.verifier)
        for ev in gate.evidence:
            entry = self._log(EventType.EVIDENCE_RECORDED, task=task.id, check=ev.check_id,
                              ok=ev.ok, detail=ev.detail)
            task.evidence.append(entry.hash)
        if not gate.ok:
            etype = (EventType.ACCEPTANCE_TAMPERED if "tamper" in gate.reason
                     else EventType.PROOF_REJECTED)
            self._log(etype, task=task.id, reason=gate.reason)
            return self._strike(task, gate.reason)

        self._log(EventType.PROOF_ACCEPTED, task=task.id)
        task.status = TaskStatus.DONE
        self._log(EventType.TASK_DONE, task=task.id, evidence=task.evidence)
        self.store.save_state(self.phase, self.contract.tasks)
        return True

    def _strike(self, task: Task, reason: str) -> bool:
        """Apply the repair ladder. Returns False (task did not complete this pass)."""
        task.strikes += 1
        action = self.recovery.next_action(task.strikes)
        self._log(EventType.TASK_FAILED, task=task.id, strikes=task.strikes,
                  reason=reason, next_action=action.value)
        if self.recovery.exhausted(task.strikes) or action == RepairAction.ESCALATE:
            task.status = TaskStatus.BLOCKED
            # roll back code state + compensate any external effects from this task
            cp = self.recovery.last_checkpoint()
            if cp:
                self._log(EventType.ROLLED_BACK, to=cp.ref, task=task.id)
            compensated = self.recovery.compensate_all()
            if compensated:
                self._log(EventType.COMPENSATED, effects=compensated)
            self._set_phase(Phase.HALTED, note=f"{task.id} escalated to operator")
        else:
            task.status = TaskStatus.READY  # eligible for retry (same or swapped model)
        return False

    def execute_all(self) -> StepResult:
        """Drive the DAG until done, blocked, or halted."""
        assert self.contract
        guard = 0
        while True:
            if self.phase == Phase.HALTED:
                return StepResult(Phase.HALTED, "halted", halted=True)
            ready = self._ready_tasks()
            if not ready:
                break
            task = ready[0]
            self.run_task(task)
            guard += 1
            if guard > 10_000:  # structural backstop
                self._set_phase(Phase.HALTED, note="scheduler backstop")
                return StepResult(Phase.HALTED, "scheduler backstop", halted=True)

        remaining = [t.id for t in self.contract.tasks
                     if t.status not in (TaskStatus.DONE,)]
        if remaining:
            blocked = [t.id for t in self.contract.tasks if t.status == TaskStatus.BLOCKED]
            note = f"incomplete: {remaining} (blocked: {blocked})"
            if self.phase != Phase.HALTED:
                self._set_phase(Phase.HALTED, note=note)
            return StepResult(Phase.HALTED, note, halted=True)

        self._set_phase(Phase.LEARN, note="all tasks done")
        return StepResult(self.phase, "all tasks done")

    def learn(self, lessons: list[str]) -> StepResult:
        """Final audit vs ORIGINAL_REQUEST + durable memory write."""
        ok, reason = self.ledger.verify()
        self._log(EventType.MEMORY_WRITTEN, action="audit", ledger_ok=ok, reason=reason)
        self._maybe_anchor()  # anchor channel digests before closing the ledger
        for line in lessons:
            self.store.append_memory(f"- {line}")
        self.store.append_memory(f"- run complete; request={self.store.request_hash()}")
        self._set_phase(Phase.DONE, note="learned + audited")
        return StepResult(self.phase, f"done; ledger_ok={ok}")

    # ---- audit ----

    def audit(self) -> tuple[bool, Optional[str]]:
        return self.ledger.verify()
