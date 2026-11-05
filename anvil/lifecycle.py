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

ENFORCEMENT NOTES
  * Phase order is mechanical: each phase method raises RuntimeError if called
    out of order, so no caller can execute a plan that never passed review.
  * Adapters (agent, verifier, approval_fn) only ever receive deep copies of a
    Task. Policy decisions use the harness's sealed copy, so an agent mutating
    its view (adding tools/paths, dropping checks) gains nothing; the harness
    also diffs the view afterwards and treats any mutation as tampering.
  * Every adapter call sits behind a fault barrier: an exception or malformed
    return is a strike, never a crashed controller with a task stuck RUNNING.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .adapters import AgentAdapter, VerifierAdapter
from .budget import Budget, CircuitBreaker
from .context import ContextCompiler, summarize_evidence, DEFAULT_MAX_TOKENS
from .ledger import Ledger, LedgerEntry
from .log import EVENT_LEVELS, LogChannel, LogLevel, LogRouter, TraceContext
from .policy import PolicyEngine, ToolPolicy
from .proofgate import ProofGate, acceptance_hash
from .recovery import Checkpoint, Compensation, RecoveryManager, RepairAction
from .schemas import (
    AmbiguityClass, EventType, Phase, PolicyDecision, Risk, Task, TaskStatus, ToolCall,
)
from .store import Contract, MissionStore

# An approval callback returns True to grant a commit-point, False to deny.
# Only the literal `True` grants; any other value (truthy or not) or an
# exception is a denial. Fail safe.
ApprovalFn = Callable[[Task, ToolCall], bool]
# Restores code state to a checkpoint (e.g. `git reset --hard <ref>`).
RollbackFn = Callable[[Checkpoint], None]


def _usage(result: dict) -> tuple[int, int, float]:
    """Validate adapter-reported usage. Raises ValueError on anything that could
    refund or disable the budget (negative, NaN, inf, bool, non-numeric)."""
    vals = []
    for key, kind in (("input_tokens", int), ("output_tokens", int), ("cost", float)):
        v = result.get(key, 0)
        if v is None:
            v = 0
        ok_type = isinstance(v, int) if kind is int else isinstance(v, (int, float))
        if isinstance(v, bool) or not ok_type:
            raise ValueError(f"{key}={v!r} is not a valid {kind.__name__}")
        if not math.isfinite(v) or v < 0:
            raise ValueError(f"{key}={v!r} must be finite and >= 0")
        vals.append(v)
    return int(vals[0]), int(vals[1]), float(vals[2])


def _call_digest(call: ToolCall) -> str:
    """Stable identity of a side effect: same tool + args + paths = same effect."""
    body = json.dumps({"tool": call.tool, "args": call.args, "paths": call.paths},
                      sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


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
        rollback_fn: Optional[RollbackFn] = None,
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
        # Without a rollback_fn, ROLLED_BACK is recorded with executed=False: the
        # ledger says what SHOULD be restored; nothing claims it was.
        self.rollback_fn = rollback_fn
        self.phase = Phase.INTAKE
        self.contract: Optional[Contract] = None
        self._anchored = False
        self._context_compiler = ContextCompiler()
        # Per-task evidence summaries (proof travels; narrative does not).
        # Populated in-memory as tasks complete; rebuilt from the ledger on resume.
        self._evidence_summaries: dict[str, str] = {}
        self._load_evidence_from_ledger()

    # ---- evidence rebuild (resume durability) ----

    def _load_evidence_from_ledger(self) -> None:
        """Rebuild evidence summaries from the hash-chained ledger.

        Called at __init__ so a resumed Lifecycle recovers upstream evidence for
        all PROOF_ACCEPTED tasks without re-running them.

        Invariant: TASK_STARTED resets the in-progress accumulator so a failed
        attempt's evidence is discarded before the retry begins. Only evidence
        from a PROOF_ACCEPTED path is committed to _evidence_summaries.
        """
        if not self.store.ledger_path.exists():
            return
        ok, _ = self.ledger.verify()
        if not ok:
            return  # tampered ledger — trust nothing
        in_progress: dict[str, list] = {}
        for entry in self.ledger:
            if entry.type == "task_started":
                task_id = entry.payload.get("task")
                if task_id:
                    in_progress[task_id] = []  # reset: discard any prior attempt's evidence
            elif entry.type == "evidence_recorded":
                task_id = entry.payload.get("task")
                if task_id is not None:
                    in_progress.setdefault(task_id, []).append(entry)
            elif entry.type == "proof_accepted":
                task_id = entry.payload.get("task")
                if task_id and task_id in in_progress:
                    self._evidence_summaries[task_id] = summarize_evidence(in_progress[task_id])

    # ---- ledger + log router ----

    def _maybe_anchor(self) -> None:
        """Commit channel hashes to the ledger exactly once per run."""
        if not self._anchored:
            self.log_router.anchor(self.ledger)
            self._anchored = True

    def _log(self, etype: EventType, **payload) -> LedgerEntry:
        entry = self.ledger.append(etype.value, payload)
        level = EVENT_LEVELS.get(etype.value, LogLevel.INFO.value)
        # Fan out the ledger's normalized payload (JSON-safe), not the raw kwargs.
        self.log_router.route(
            etype.value, entry.payload,
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

    def _require_phase(self, method: str, *allowed: Phase) -> None:
        """Mechanical phase ordering. Out-of-order calls are programming errors
        that would skip a gate (e.g. execute without review), so they raise."""
        if self.phase not in allowed:
            raise RuntimeError(
                f"{method}() not permitted in phase '{self.phase.value}' "
                f"(requires {', '.join(p.value for p in allowed)})")

    # ---- adapter isolation ----

    @staticmethod
    def _view(task: Task) -> Task:
        """What adapters get: a deep copy. Mutating it cannot touch the grant."""
        return copy.deepcopy(task)

    def _view_tampered(self, task: Task, view: Task, where: str) -> bool:
        """Diff an adapter's view against the sealed task. Logs + strikes on drift.

        Mutation is an attempted gate bypass (widen tools/paths, drop a hard
        check). It is a security event, and deterministic: the same agent will
        do it again, so escalate on strike 1 instead of burning retries.
        """
        if acceptance_hash(view.acceptance) != acceptance_hash(task.acceptance):
            self._log(EventType.ACCEPTANCE_TAMPERED, task=task.id,
                      reason=f"agent mutated acceptance criteria during {where} (tamper)")
            self._strike(task, f"acceptance tamper during {where}", deterministic=True)
            return True
        grant = lambda t: (t.id, t.risk, sorted(t.tools), sorted(t.paths), sorted(t.deps))
        if grant(view) != grant(task):
            self._log(EventType.CONTEXT_TAMPERED, task=task.id,
                      reason=f"agent mutated its grant (id/risk/tools/paths/deps) during {where}")
            self._strike(task, f"grant tamper during {where}", deterministic=True)
            return True
        return False

    # ================= phases =================

    def intake(self, request_text: str) -> StepResult:
        self._require_phase("intake", Phase.INTAKE)
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
        self._require_phase("baseline", Phase.BASELINE)
        self._log(EventType.BASELINE_CAPTURED, snapshot=snapshot)
        ref = snapshot.get("ref", "baseline")
        self.recovery.checkpoint("baseline", ref)
        self._log(EventType.CHECKPOINT_MADE, label="baseline", ref=ref)
        self._set_phase(Phase.COMPILE, note="baseline captured")
        return StepResult(self.phase, "baseline captured")

    def compile(self, contract: Contract) -> StepResult:
        self._require_phase("compile", Phase.COMPILE)
        # LOCK acceptance hashes (defeats test-gaming) and context spec hashes
        # (defeats task-mutation between compile and execute).
        max_tokens = contract.context_budget.get("max_tokens_per_task", DEFAULT_MAX_TOKENS)
        for t in contract.tasks:
            contract.acceptance_locks[t.id] = self.gate.lock(t)
            contract.context_spec_locks[t.id] = (
                self._context_compiler.build_spec(t, max_tokens).spec_hash
            )
        self.contract = contract
        self.store.save_contract(contract)
        self._log(EventType.CONTRACT_COMPILED,
                  tasks=[t.id for t in contract.tasks],
                  locks=contract.acceptance_locks,
                  context_spec_locks=contract.context_spec_locks)
        self._set_phase(Phase.REVIEW, note="contract compiled + sealed")
        return StepResult(self.phase, f"compiled {len(contract.tasks)} tasks")

    @staticmethod
    def _task_path_in_scope(task_path: str, scope_in: list[str]) -> bool:
        """True if task_path is contained within the contract's scope_in.

        The literal (non-glob) prefix is normalized and must not contain any
        '..' component: `src/../etc/*` textually starts with `src/` but names
        a directory outside it.
        """
        raw = task_path.replace("\\", "/")
        if any(seg == ".." for seg in raw.split("/")):
            return False
        cut = min((i for i, ch in enumerate(raw) if ch in "*?["), default=len(raw))
        prefix = raw[:cut].rstrip("/")
        if not prefix:
            return False  # bare wildcard (*) can escape any bounded scope
        prefix = PolicyEngine.normalize_path(prefix)
        if prefix is None:
            return False
        for s in scope_in:
            scope_root = s.replace("\\", "/").rstrip("/*")
            if not scope_root:
                continue
            if prefix == scope_root or prefix.startswith(scope_root + "/"):
                return True
        return False

    @staticmethod
    def _find_dag_cycles(tasks: list) -> list[str]:
        """Kahn's algorithm: return task IDs that are part of a cycle."""
        id_set = {t.id for t in tasks}
        successors: dict[str, list[str]] = {t.id: [] for t in tasks}
        in_degree: dict[str, int] = {t.id: 0 for t in tasks}
        for t in tasks:
            for dep in t.deps:
                if dep in id_set:
                    successors[dep].append(t.id)
                    in_degree[t.id] += 1
        queue = [tid for tid, deg in in_degree.items() if deg == 0]
        processed = 0
        while queue:
            node = queue.pop()
            processed += 1
            for succ in successors[node]:
                in_degree[succ] -= 1
                if in_degree[succ] == 0:
                    queue.append(succ)
        return [tid for tid, deg in in_degree.items() if deg > 0]

    def review(self) -> StepResult:
        """Gate the plan itself before any work begins."""
        self._require_phase("review", Phase.REVIEW)
        assert self.contract
        problems: list[str] = []

        # Duplicate task IDs collapse acceptance locks and make state incoherent.
        seen_ids: set[str] = set()
        for t in self.contract.tasks:
            if t.id in seen_ids:
                problems.append(f"duplicate task id '{t.id}'")
            seen_ids.add(t.id)

        # DAG cycles would make execute_all spin forever with no ready tasks.
        cycle_nodes = self._find_dag_cycles(self.contract.tasks)
        if cycle_nodes:
            problems.append(f"dependency cycle among tasks: {cycle_nodes}")

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
            # A reversible task granted an irreversible tool would dodge the
            # QA-authorship rule above. The contract must declare the real risk.
            irrev = sorted(set(t.tools) & self.policy.policy.irreversible_tools)
            if irrev and t.risk != Risk.IRREVERSIBLE:
                problems.append(
                    f"{t.id}: grants irreversible tool(s) {irrev} but is declared "
                    f"reversible; declare risk=IRREVERSIBLE"
                )
            for dep in t.deps:
                if dep not in seen_ids:
                    problems.append(f"{t.id}: unknown dependency '{dep}'")
            # Task paths must be contained within the contract's declared scope.
            for p in t.paths:
                if not self._task_path_in_scope(p, self.contract.scope_in):
                    problems.append(
                        f"{t.id}: path '{p}' is outside contract scope {self.contract.scope_in}"
                    )
        if problems:
            self._log(EventType.REVIEW_REJECTED, problems=problems)
            self._set_phase(Phase.HALTED, note="review rejected")
            return StepResult(Phase.HALTED, "; ".join(problems), halted=True)
        self._log(EventType.REVIEW_PASSED, tasks=len(self.contract.tasks))
        self._set_phase(Phase.EXECUTE, note="plan approved")
        return StepResult(self.phase, "plan approved")

    # ---- resume (process death / operator restart) ----

    def resume(self) -> StepResult:
        """Continue a mission from disk. The LEDGER is the trust anchor, not the
        unsigned PLAN.graph.json / STATE.json files:

          * ledger must verify (pass the same signing_key to Lifecycle);
          * the on-disk contract must reproduce the acceptance + context-spec
            seals committed in the ledger's CONTRACT_COMPILED event (an edited
            plan that widens a grant is refused);
          * the plan must have passed review (REVIEW_PASSED after compile);
          * task completion is taken from TASK_DONE ledger events; everything
            else restarts PENDING with zero strikes (operator reset);
          * checkpoints are restored from the ledger. Saga compensations hold
            live callables and cannot be restored; the ledger records them.
        Pass `trace_id=store.recover_trace_id(signing_key)` to Lifecycle to keep
        one correlated trace.
        """
        self._require_phase("resume", Phase.INTAKE)
        ok, reason = self.ledger.verify()
        if not ok:
            raise RuntimeError(f"cannot resume: ledger failed verification: {reason}")
        entries = self.ledger.entries()
        compiled = [e for e in entries if e.type == EventType.CONTRACT_COMPILED.value]
        if not compiled:
            raise RuntimeError("cannot resume: no compiled contract in the ledger")
        seal = compiled[-1]
        if not any(e.type == EventType.REVIEW_PASSED.value and e.seq > seal.seq
                   for e in entries):
            raise RuntimeError("cannot resume: sealed contract never passed review")
        phases = [e.payload.get("phase") for e in entries
                  if e.type == EventType.PHASE_CHANGED.value]
        if phases and phases[-1] == Phase.DONE.value:
            raise RuntimeError("cannot resume: mission already DONE")

        contract = self.store.load_contract()
        max_tokens = contract.context_budget.get("max_tokens_per_task", DEFAULT_MAX_TOKENS)
        if [t.id for t in contract.tasks] != seal.payload.get("tasks"):
            raise RuntimeError("cannot resume: on-disk task list differs from sealed contract")
        for t in contract.tasks:
            if (self.gate.lock(t) != seal.payload["locks"].get(t.id)
                    or self._context_compiler.build_spec(t, max_tokens).spec_hash
                    != seal.payload["context_spec_locks"].get(t.id)):
                raise RuntimeError(
                    f"cannot resume: task '{t.id}' on disk differs from the sealed contract")
        contract.acceptance_locks = dict(seal.payload["locks"])
        contract.context_spec_locks = dict(seal.payload["context_spec_locks"])

        done = {e.payload.get("task") for e in entries if e.type == EventType.TASK_DONE.value}
        for t in contract.tasks:
            t.status = TaskStatus.DONE if t.id in done else TaskStatus.PENDING
            t.strikes = 0
        for e in entries:
            if e.type == EventType.CHECKPOINT_MADE.value and "label" in e.payload:
                self.recovery.checkpoint(e.payload["label"], e.payload.get("ref", ""))

        self.contract = contract
        remaining = [t.id for t in contract.tasks if t.status != TaskStatus.DONE]
        target = Phase.EXECUTE if remaining else Phase.LEARN
        self._set_phase(target, note=f"resumed; remaining={remaining}")
        return StepResult(self.phase, f"resumed {len(done)} done, {len(remaining)} remaining")

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
        if self.phase == Phase.HALTED:
            return False
        self._require_phase("run_task", Phase.EXECUTE)
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

        # 0) CONTEXT GATE: verify spec hash, build minimal bundle, pre-flight size check.
        #    Bundle hash committed to the ledger BEFORE the agent sees any content —
        #    attested provenance linking every subsequent action to its exact context.
        max_tokens = self.contract.context_budget.get("max_tokens_per_task", DEFAULT_MAX_TOKENS)
        locked_hash = self.contract.context_spec_locks.get(task.id, "")
        bundle = None
        if locked_hash:
            live_spec = self._context_compiler.build_spec(task, max_tokens)
            if live_spec.spec_hash != locked_hash:
                self._log(EventType.CONTEXT_TAMPERED, task=task.id,
                          locked=locked_hash, live=live_spec.spec_hash)
                return self._strike(task, "context spec tampered", deterministic=True)
            bundle = self._context_compiler.build_bundle(
                live_spec, self.contract, self._evidence_summaries,
                tokenizer=getattr(self.agent, "count_tokens", None),
            )
            if bundle.estimated_tokens > max_tokens:
                self._log(EventType.CONTEXT_OVERSIZE, task=task.id,
                          estimated=bundle.estimated_tokens, limit=max_tokens)
                return self._strike(
                    task,
                    f"context oversize ({bundle.estimated_tokens}>{max_tokens})",
                    deterministic=True,
                )
            self._log(EventType.CONTEXT_COMMITTED, task=task.id,
                      bundle_hash=bundle.bundle_hash,
                      estimated_tokens=bundle.estimated_tokens,
                      estimator=bundle.estimator)

        # 1) AGENT DECISION: the agent plans against a COPY of the task (fault
        #    barrier + tamper diff), then we log what it proposes before gating.
        view = self._view(task)
        try:
            if bundle is not None and hasattr(self.agent, "plan_calls_with_context"):
                calls = self.agent.plan_calls_with_context(view, bundle)
            else:
                calls = self.agent.plan_calls(view)
        except Exception as e:  # noqa: BLE001 - adapter fault barrier
            return self._strike(task, f"plan_calls raised {type(e).__name__}: {e}")
        if self._view_tampered(task, view, "plan_calls"):
            return False
        if (not isinstance(calls, (list, tuple))
                or not all(isinstance(c, ToolCall) for c in calls)):
            return self._strike(task, "agent returned a malformed plan (expected list[ToolCall])")
        if calls:
            self.log_router.write(
                LogChannel.AGENT, "agent_decision",
                {"task": task.id,
                 "proposed_calls": [{"tool": c.tool, "paths": c.paths, "risk": c.risk.value}
                                    for c in calls]},
                trace_id=self.trace.trace_id, span_id=span_id,
            )

        # 2) EXECUTE: harness gates each proposed call against ITS sealed task
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
                # commit-point: irreversible work pauses for recorded human approval.
                # Only a literal True grants; exceptions and other values deny.
                task.status = TaskStatus.AWAITING_APPROVAL
                self._log(EventType.APPROVAL_REQUESTED, task=task.id, tool=call.tool,
                          args=call.args)
                try:
                    granted = self.approval_fn(self._view(task), copy.deepcopy(call)) is True
                    why = "denied by approver"
                except Exception as e:  # noqa: BLE001 - fail-safe deny
                    granted, why = False, f"approval_fn raised {type(e).__name__}: {e}"
                if not granted:
                    self._log(EventType.APPROVAL_DENIED, task=task.id, tool=call.tool,
                              reason=why)
                    return self._strike(task, "approval denied")
                self._log(EventType.APPROVAL_GRANTED, task=task.id, tool=call.tool)

            self._log(EventType.TOOL_CALL_ALLOWED, task=task.id, tool=call.tool)

            # DEPENDENCY: time the actual execution and log latency
            view = self._view(task)
            dep_start = time.monotonic()
            try:
                result = self.agent.perform(view, call)
                perform_error = None
            except Exception as e:  # noqa: BLE001 - adapter fault barrier
                result, perform_error = {"ok": False}, f"{type(e).__name__}: {e}"
            dep_ms = (time.monotonic() - dep_start) * 1000.0
            if not isinstance(result, dict):
                perform_error = f"perform returned {type(result).__name__}, not dict"
                result = {"ok": False}
            ok = bool(result.get("ok", True)) and perform_error is None
            self.log_router.write(
                LogChannel.DEPENDENCY, "dependency_result",
                {"task": task.id, "tool": call.tool, "ok": ok, "duration_ms": dep_ms,
                 **({"error": perform_error} if perform_error else {})},
                trace_id=self.trace.trace_id, span_id=span_id,
            )
            # TOKEN: charge usage BEFORE judging ok -- a failed call still burned
            # real tokens/money, and retries must not run uncharged. Usage is
            # validated: negative/NaN/inf would refund or disable the breaker.
            try:
                inp, out, call_cost = _usage(result)
            except ValueError as e:
                return self._strike(task, f"invalid usage report: {e}")
            if inp or out or call_cost:
                self.breaker.charge(steps=0, input_tokens=inp, output_tokens=out,
                                    cost=call_cost)
                self._log(EventType.TOKEN_CHARGED, task=task.id, tool=call.tool,
                          input_tokens=inp, output_tokens=out, cost=call_cost,
                          cumulative_cost=self.breaker.cost,
                          cumulative_input_tokens=self.breaker.input_tokens,
                          cumulative_output_tokens=self.breaker.output_tokens)
                ok_b, reason_b = self.breaker.check()
                if not ok_b:
                    self._log(EventType.CIRCUIT_OPEN, reason=reason_b)
                    task.status = TaskStatus.BLOCKED
                    self._set_phase(Phase.HALTED, note=reason_b or "token budget exceeded")
                    return False

            # If the adapter signals failure (or raised), strike.
            # _strike() logs TASK_FAILED -- don't log it here too.
            if not ok:
                return self._strike(
                    task, f"perform failed: {perform_error}" if perform_error
                    else "adapter returned ok=False")

            # SAGA: an irreversible side effect succeeded -> register compensation NOW.
            # Default idempotency key covers tool+args+paths so two distinct side
            # effects in one task never collide (and an exact replay still dedupes).
            if self.policy.classify_risk(call, task) == Risk.IRREVERSIBLE:
                idem = result.get("idempotency_key") or f"{task.id}:{call.tool}:{_call_digest(call)}"
                undo = result.get("undo")
                if callable(undo):
                    comp = Compensation(side_effect=f"{call.tool}", idempotency_key=str(idem),
                                        undo=undo, note=task.id, task_id=task.id)
                    if self.recovery.register_compensation(comp):
                        self._log(EventType.CHECKPOINT_MADE, kind="compensation",
                                  side_effect=call.tool, idem=str(idem))

            # Tamper check AFTER saga registration: if the agent mutated its view
            # while also completing a side effect, escalation must still unwind it.
            if self._view_tampered(task, view, "perform"):
                return False

        # 3) VERIFY: independent proof gate against the LOCKED acceptance
        task.status = TaskStatus.AWAITING_PROOF
        locked = self.contract.acceptance_locks.get(task.id, "")
        gate = self.gate.evaluate(task, locked, self.verifier)
        evidence_entries = []
        for ev in gate.evidence:
            entry = self._log(EventType.EVIDENCE_RECORDED, task=task.id, check=ev.check_id,
                              ok=ev.ok, detail=ev.detail)
            task.evidence.append(entry.hash)
            evidence_entries.append(entry)
        if not gate.ok:
            etype = (EventType.ACCEPTANCE_TAMPERED if "tamper" in gate.reason
                     else EventType.PROOF_REJECTED)
            self._log(etype, task=task.id, reason=gate.reason)
            return self._strike(task, gate.reason)

        self._log(EventType.PROOF_ACCEPTED, task=task.id)
        task.status = TaskStatus.DONE
        self._log(EventType.TASK_DONE, task=task.id, evidence=task.evidence)
        # Compact evidence for downstream tasks (proof travels; raw transcripts do not)
        self._evidence_summaries[task.id] = summarize_evidence(evidence_entries)
        self.store.save_state(self.phase, self.contract.tasks)
        return True

    def _strike(self, task: Task, reason: str, *, deterministic: bool = False) -> bool:
        """Apply the repair ladder. Returns False (task did not complete this pass).

        deterministic=True: the same spec and store will produce the identical failure
        (context tamper, oversize). Retrying is pure waste — skip the ladder and
        escalate to operator immediately on strike 1.
        """
        task.strikes += 1
        action = (RepairAction.ESCALATE if deterministic
                  else self.recovery.next_action(task.strikes))
        self._log(EventType.TASK_FAILED, task=task.id, strikes=task.strikes,
                  reason=reason, next_action=action.value, deterministic=deterministic)
        if self.recovery.exhausted(task.strikes) or action == RepairAction.ESCALATE:
            task.status = TaskStatus.BLOCKED
            # roll back code state + compensate THIS task's external effects. Other
            # tasks' effects were verified DONE; unwinding them would leave STATE
            # claiming DONE for work that no longer exists. Operators can unwind
            # the whole mission explicitly via recovery.compensate().
            cp = self.recovery.last_checkpoint()
            if cp:
                executed, err = False, None
                if self.rollback_fn is not None:
                    try:
                        self.rollback_fn(cp)
                        executed = True
                    except Exception as e:  # noqa: BLE001 - fault barrier
                        err = f"{type(e).__name__}: {e}"
                self._log(EventType.ROLLED_BACK, to=cp.ref, task=task.id,
                          executed=executed, **({"error": err} if err else {}))
            report = self.recovery.compensate(task_id=task.id)
            if report.done or report.failed:
                self._log(EventType.COMPENSATED, effects=report.done, failed=report.failed)
            self._set_phase(Phase.HALTED, note=f"{task.id} escalated to operator")
        else:
            task.status = TaskStatus.READY  # eligible for retry (same or swapped model)
        return False

    def execute_all(self) -> StepResult:
        """Drive the DAG until done, blocked, or halted."""
        if self.phase != Phase.HALTED:
            self._require_phase("execute_all", Phase.EXECUTE)
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
        """Final audit vs ORIGINAL_REQUEST + durable memory write.

        Only reachable from LEARN (all tasks verified DONE). A HALTED run must
        not be relabeled DONE; record lessons from a failed run with
        store.append_memory() instead.
        """
        self._require_phase("learn", Phase.LEARN)
        ok, reason = self.ledger.verify()
        self._log(EventType.MEMORY_WRITTEN, action="audit", ledger_ok=ok, reason=reason)
        for line in lessons:
            self.store.append_memory(f"- {line}")
        self.store.append_memory(f"- run complete; request={self.store.request_hash()}")
        self._set_phase(Phase.DONE, note="learned + audited")
        self._maybe_anchor()  # anchor AFTER all channel writes including DONE phase change
        return StepResult(self.phase, f"done; ledger_ok={ok}")

    # ---- audit ----

    def audit(self) -> tuple[bool, Optional[str]]:
        return self.ledger.verify()
