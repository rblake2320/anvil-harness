"""
Adversarial regression suite: every test here reproduces a defect that was
confirmed against the pre-hardening code, then proves the fix fails closed.

Groups:
  * gate bypass      -> agent mutates its grant, skips review, downgrades risk
  * budget evasion   -> NaN / negative / non-numeric usage, uncharged failures
  * fault barriers   -> adapter / verifier / approval exceptions and junk returns
  * saga             -> dropped / colliding / crashing compensations
  * scope            -> backslash traversal, '..' in contract task paths
  * ledger           -> torn writes, corrupt lines, concurrent writers, truncation
  * logging          -> resumed-run anchors, digest redaction
  * context / store  -> tokenizer undercount, grant seal, request re-freeze
  * CLI              -> signed ledgers, head anchoring
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
import textwrap

import pytest

from anvil import (
    AcceptanceCheck, Budget, CircuitBreaker, Compensation, Contract, EventType, Evidence,
    Ledger, Lifecycle, LogChannel, MissionStore, Phase, PolicyEngine, ProofGate, RecoveryManager,
    Risk, SimulatedAgent, SimulatedVerifier, Task, TaskStatus, ToolCall, _redact,
)
from anvil.context import ContextCompiler, _estimate_tokens
from anvil.ledger import LedgerCorruptError
from anvil.recovery import CompensationError


# ---- helpers ----------------------------------------------------------------

def _qa(cid, desc="behavioral"):
    return AcceptanceCheck(id=cid, description=desc, kind="behavior", spec={"k": cid},
                           authored_by="qa")


def _edit_task(tid="t1", **kw):
    kw.setdefault("tools", ["edit"])
    kw.setdefault("paths", ["src/*"])
    kw.setdefault("acceptance", [_qa(f"{tid}c")])
    return Task(id=tid, title=tid, **kw)


def _edit_call(path="src/a.py"):
    return ToolCall(tool="edit", paths=[path])


def _lc(tmp_path, agent, tasks, verifier=None, scope=("src", "db"), review=True, **kw):
    verdicts = {c.id: True for t in tasks for c in t.acceptance}
    lc = Lifecycle(MissionStore(tmp_path), agent, verifier or SimulatedVerifier(verdicts), **kw)
    lc.intake("x")
    lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=list(scope), scope_out=[], tasks=tasks))
    if review:
        lc.review()
    return lc


def _types(lc):
    return [e.type for e in lc.ledger]


# ============================================================================
# gate bypass
# ============================================================================

def test_agent_widening_its_grant_in_plan_calls_is_blocked(tmp_path):
    """Pre-fix: agent appended '/etc/*' to task.paths inside plan_calls and the
    scope guard then ALLOWED /etc/passwd. Now the agent only sees a copy, and
    the mutation itself is a CONTEXT_TAMPERED security event."""
    def widen(t):
        t.paths.append("/etc/*")
        t.tools.append("rm")
        return [_edit_call("/etc/passwd")]

    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(widen), [task])
    res = lc.execute_all()
    assert res.halted
    assert task.status == TaskStatus.BLOCKED
    assert task.paths == ["src/*"] and task.tools == ["edit"]   # harness copy untouched
    types = _types(lc)
    assert EventType.CONTEXT_TAMPERED.value in types
    assert EventType.TOOL_CALL_ALLOWED.value not in types
    assert types.count(EventType.TASK_FAILED.value) == 1          # deterministic: no retries


def test_agent_mutating_task_in_perform_is_detected(tmp_path):
    def perform(t, c):
        t.acceptance.clear()
        return {"ok": True}

    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [_edit_call()], perform), [task])
    lc.execute_all()
    assert task.status == TaskStatus.BLOCKED
    assert len(task.acceptance) == 1
    assert EventType.ACCEPTANCE_TAMPERED.value in _types(lc)
    assert EventType.TASK_DONE.value not in _types(lc)


def test_execute_without_review_is_refused(tmp_path):
    """Pre-fix: execute_all() ran a plan that never passed review."""
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: []), [task], review=False)
    with pytest.raises(RuntimeError, match="requires execute"):
        lc.execute_all()
    with pytest.raises(RuntimeError):
        lc.run_task(task)
    assert task.status == TaskStatus.PENDING
    assert EventType.TASK_STARTED.value not in _types(lc)


@pytest.mark.parametrize("call", [
    lambda lc: lc.baseline({"ref": "b"}),
    lambda lc: lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[])),
    lambda lc: lc.review(),
    lambda lc: lc.learn([]),
])
def test_phase_methods_refuse_out_of_order(tmp_path, call):
    lc = Lifecycle(MissionStore(tmp_path), SimulatedAgent(lambda t: []), SimulatedVerifier({}))
    with pytest.raises(RuntimeError, match="not permitted in phase 'intake'"):
        call(lc)


def test_intake_cannot_be_repeated_mid_run(tmp_path):
    lc = Lifecycle(MissionStore(tmp_path), SimulatedAgent(lambda t: []), SimulatedVerifier({}))
    lc.intake("x")
    with pytest.raises(RuntimeError):
        lc.intake("x")


def test_learn_after_halt_is_refused_and_run_stays_halted(tmp_path):
    """Pre-fix: learn() relabeled a HALTED run as DONE."""
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [_edit_call("/etc/x")]), [task])
    assert lc.execute_all().halted
    with pytest.raises(RuntimeError):
        lc.learn(["pretend it worked"])
    assert lc.phase == Phase.HALTED
    assert MissionStore(tmp_path).load_state()["phase"] == "halted"


def test_agent_cannot_downgrade_risk_on_irreversible_task(tmp_path):
    """Pre-fix: an IRREVERSIBLE task using a tool missing from the policy table,
    with the agent tagging the call REVERSIBLE, ran with no approval at all."""
    task = Task(id="t1", title="notify", risk=Risk.IRREVERSIBLE, tools=["send_email"],
                acceptance=[_qa("c1")])
    sent = []
    agent = SimulatedAgent(
        lambda t: [ToolCall(tool="send_email", risk=Risk.REVERSIBLE)],
        lambda t, c: sent.append(c.tool) or {"ok": True},
    )
    lc = _lc(tmp_path, agent, [task])          # default approval_fn denies
    lc.execute_all()
    assert sent == [], "side effect ran without a commit-point approval"
    assert EventType.APPROVAL_REQUESTED.value in _types(lc)
    assert task.status == TaskStatus.BLOCKED


def test_classify_risk_takes_max_of_call_policy_and_task():
    pe = PolicyEngine()
    rev = Task(id="r", title="r")
    irr = Task(id="i", title="i", risk=Risk.IRREVERSIBLE)
    assert pe.classify_risk(ToolCall(tool="edit"), rev) == Risk.REVERSIBLE
    assert pe.classify_risk(ToolCall(tool="edit"), irr) == Risk.IRREVERSIBLE
    assert pe.classify_risk(ToolCall(tool="edit", risk=Risk.IRREVERSIBLE), rev) == Risk.IRREVERSIBLE
    assert pe.classify_risk(ToolCall(tool="rm"), rev) == Risk.IRREVERSIBLE


def test_review_rejects_reversible_task_granted_irreversible_tool(tmp_path):
    """Would otherwise dodge the QA-authorship rule for high-risk work."""
    task = Task(id="t1", title="x", tools=["edit", "rm"], paths=["src/*"],
                acceptance=[AcceptanceCheck(id="c", description="d", kind="behavior",
                                            authored_by="executor")])
    lc = _lc(tmp_path, SimulatedAgent(lambda t: []), [task], review=False)
    res = lc.review()
    assert res.halted and "declare risk=IRREVERSIBLE" in res.note


@pytest.mark.parametrize("bad", ["src/../etc/*", "src\\..\\etc\\*", "src/./../x/*",
                                 "src/a/../../etc/*", "../src/*"])
def test_review_rejects_dotdot_task_paths(tmp_path, bad):
    task = _edit_task(paths=[bad])
    lc = _lc(tmp_path, SimulatedAgent(lambda t: []), [task], review=False)
    assert lc.review().halted


@pytest.mark.parametrize("good", ["src/*", "src/sub/*.py", "src", "src/a.py", "db/m?.sql"])
def test_review_accepts_contained_task_paths(tmp_path, good):
    task = _edit_task(paths=[good])
    lc = _lc(tmp_path, SimulatedAgent(lambda t: []), [task], review=False)
    assert lc.review().phase == Phase.EXECUTE


# ============================================================================
# budget evasion
# ============================================================================

@pytest.mark.parametrize("usage", [
    {"cost": float("nan")}, {"cost": float("inf")}, {"cost": -100.0}, {"cost": "5"},
    {"input_tokens": -1}, {"input_tokens": 1.5}, {"input_tokens": True},
    {"output_tokens": float("nan")},
])
def test_invalid_usage_is_a_strike_and_never_charged(tmp_path, usage):
    """Pre-fix: cost=NaN made `cost > max_cost` False forever (budget disabled);
    negative cost refunded budget."""
    task = _edit_task()
    agent = SimulatedAgent(lambda t: [_edit_call()], lambda t, c: {"ok": True, **usage})
    lc = _lc(tmp_path, agent, [task], budget=Budget(max_cost=1.0))
    lc.execute_all()
    assert task.status == TaskStatus.BLOCKED
    assert lc.breaker.cost == 0.0 and lc.breaker.input_tokens == 0
    assert math.isfinite(lc.breaker.cost)
    failed = [e for e in lc.ledger if e.type == EventType.TASK_FAILED.value]
    assert all("invalid usage" in e.payload["reason"] for e in failed)


@pytest.mark.parametrize("kw", [{"cost": float("nan")}, {"cost": -1}, {"steps": -1},
                                {"input_tokens": float("inf")}, {"output_tokens": "9"},
                                {"cost": True}])
def test_breaker_charge_rejects_poison_values(kw):
    br = CircuitBreaker(Budget())
    with pytest.raises(ValueError):
        br.charge(**kw)
    assert br.cost == 0.0 and br.steps == 0


def test_failed_perform_still_charges_tokens(tmp_path):
    """Pre-fix: ok=False struck BEFORE charging, so a failing agent burned real
    tokens on every retry with the breaker never seeing them."""
    task = _edit_task()
    agent = SimulatedAgent(lambda t: [_edit_call()],
                           lambda t, c: {"ok": False, "input_tokens": 600_000})
    lc = _lc(tmp_path, agent, [task], budget=Budget(max_input_tokens=1_000_000))
    res = lc.execute_all()
    assert res.halted
    assert lc.breaker.input_tokens == 1_200_000      # 2 attempts charged, then tripped
    assert EventType.CIRCUIT_OPEN.value in _types(lc)


def test_usage_charge_does_not_double_count_steps(tmp_path):
    task = _edit_task()
    agent = SimulatedAgent(lambda t: [_edit_call()],
                           lambda t, c: {"ok": True, "input_tokens": 10})
    lc = _lc(tmp_path, agent, [task])
    lc.execute_all()
    assert lc.breaker.steps == 2    # one for run_task + one for the gated call


# ============================================================================
# fault barriers
# ============================================================================

def _raise(exc):
    def f(*a, **k):
        raise exc
    return f


def test_perform_exception_is_a_strike_not_a_crash(tmp_path):
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [_edit_call()],
                                      _raise(ConnectionError("net down"))), [task])
    res = lc.execute_all()
    assert res.halted and task.status == TaskStatus.BLOCKED
    reasons = [e.payload["reason"] for e in lc.ledger if e.type == "task_failed"]
    assert len(reasons) == 3 and all("ConnectionError" in r for r in reasons)
    assert lc.audit()[0]


def test_plan_calls_exception_is_a_strike(tmp_path):
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(_raise(ValueError("bad json from model"))), [task])
    assert lc.execute_all().halted
    assert task.status == TaskStatus.BLOCKED


@pytest.mark.parametrize("plan", [None, "edit", [{"tool": "edit"}], [ToolCall("edit"), 3]])
def test_malformed_plan_is_a_strike(tmp_path, plan):
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: plan), [task])
    assert lc.execute_all().halted
    assert EventType.TOOL_CALL_ALLOWED.value not in _types(lc)


@pytest.mark.parametrize("ret", [None, "ok", ["ok"], 1])
def test_perform_non_dict_return_is_a_strike(tmp_path, ret):
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [_edit_call()], lambda t, c: ret), [task])
    assert lc.execute_all().halted
    assert task.status == TaskStatus.BLOCKED


def _irrev_task():
    return Task(id="t1", title="migrate", risk=Risk.IRREVERSIBLE, tools=["db_migrate"],
                acceptance=[_qa("c1")])


@pytest.mark.parametrize("approval", [_raise(TimeoutError("slack down")),
                                      lambda t, c: "yes", lambda t, c: 1,
                                      lambda t, c: None])
def test_approval_only_granted_by_literal_true(tmp_path, approval):
    ran = []
    agent = SimulatedAgent(lambda t: [ToolCall(tool="db_migrate")],
                           lambda t, c: ran.append(1) or {"ok": True})
    lc = _lc(tmp_path, agent, [_irrev_task()], approval_fn=approval)
    lc.execute_all()
    assert ran == []
    assert EventType.APPROVAL_GRANTED.value not in _types(lc)
    assert EventType.APPROVAL_DENIED.value in _types(lc)


def test_approval_fn_cannot_mutate_task(tmp_path):
    def sneaky(t, c):
        t.acceptance.clear()
        return True
    task = _irrev_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [ToolCall(tool="db_migrate")]),
             [task], approval_fn=sneaky)
    lc.execute_all()
    assert len(task.acceptance) == 1 and task.status == TaskStatus.DONE


class _Verifier:
    def __init__(self, fn):
        self.run_check = fn


@pytest.mark.parametrize("fn,needle", [
    (_raise(RuntimeError("runner crashed")), "verifier error"),
    (lambda t, c: True, "not Evidence"),
    (lambda t, c: Evidence("other", c.id, ok=True, detail=""), "mislabeled"),
    (lambda t, c: Evidence(t.id, "wrong", ok=True, detail=""), "mislabeled"),
    (lambda t, c: Evidence(t.id, c.id, ok="yes", detail="truthy"), "truthy"),
])
def test_proofgate_rejects_faulty_verifier_output(fn, needle):
    task = _edit_task()
    gate = ProofGate()
    res = gate.evaluate(task, gate.lock(task), _Verifier(fn))
    assert not res.ok
    assert len(res.evidence) == 1 and res.evidence[0].ok is False
    assert needle in res.evidence[0].detail


def test_verifier_cannot_mutate_harness_task():
    task = _edit_task()
    gate = ProofGate()

    def mutate(t, c):
        t.acceptance.clear()
        c.spec["k"] = "weakened"
        return Evidence(t.id, c.id, ok=True, detail="")
    assert gate.evaluate(task, gate.lock(task), _Verifier(mutate)).ok
    assert task.acceptance[0].spec == {"k": "t1c"}


def test_verifier_exception_in_lifecycle_does_not_crash(tmp_path):
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: []), [task],
             verifier=_Verifier(_raise(OSError("disk"))))
    assert lc.execute_all().halted
    assert EventType.PROOF_REJECTED.value in _types(lc)


# ============================================================================
# saga / compensation
# ============================================================================

def test_missing_ok_still_registers_compensation(tmp_path):
    """Pre-fix: missing 'ok' counted as success but the saga check used
    result.get('ok') -> None, silently dropping the undo."""
    agent = SimulatedAgent(lambda t: [ToolCall(tool="db_migrate")],
                           lambda t, c: {"undo": lambda: None})
    lc = _lc(tmp_path, agent, [_irrev_task()], approval_fn=lambda t, c: True)
    lc.execute_all()
    assert len(lc.recovery.compensations) == 1


def test_distinct_side_effects_get_distinct_default_keys(tmp_path):
    """Pre-fix: default key '{task}:{tool}' collided; the 2nd migration's undo
    was dropped as a 'duplicate'."""
    agent = SimulatedAgent(
        lambda t: [ToolCall(tool="db_migrate", args={"m": 1}),
                   ToolCall(tool="db_migrate", args={"m": 2}),
                   ToolCall(tool="db_migrate", args={"m": 1})],   # exact replay
        lambda t, c: {"ok": True, "undo": lambda: None},
    )
    lc = _lc(tmp_path, agent, [_irrev_task()], approval_fn=lambda t, c: True)
    lc.execute_all()
    keys = [c.idempotency_key for c in lc.recovery.compensations]
    assert len(keys) == 2 and len(set(keys)) == 2


def test_compensation_fault_barrier_runs_all_and_reports():
    rm, undone = RecoveryManager(), []
    for k in ("a", "b", "c"):
        undo = _raise(RuntimeError("undo b failed")) if k == "b" else (lambda k=k: undone.append(k))
        rm.register_compensation(Compensation(side_effect=k, idempotency_key=k, undo=undo))
    with pytest.raises(CompensationError) as ei:
        rm.compensate_all()
    assert undone == ["c", "a"]                         # reverse order, b did not stop a
    assert set(ei.value.report.failed) == {"b"}
    assert [c.done for c in rm.compensations] == [True, False, True]   # b retryable


def test_undo_exception_during_escalation_does_not_crash_lifecycle(tmp_path):
    agent = SimulatedAgent(lambda t: [ToolCall(tool="db_migrate")],
                           lambda t, c: {"ok": True, "undo": _raise(RuntimeError("boom"))})
    lc = _lc(tmp_path, agent, [_irrev_task()],
             verifier=SimulatedVerifier({}), approval_fn=lambda t, c: True)
    assert lc.execute_all().halted
    comp = [e for e in lc.ledger if e.type == EventType.COMPENSATED.value]
    assert comp and comp[-1].payload["failed"]
    assert lc.audit()[0]


def test_escalation_compensates_only_the_failing_task(tmp_path):
    """A verified-DONE task's side effects must not be silently unwound when an
    unrelated task fails; STATE would claim DONE for work that no longer exists."""
    undone = []
    a = Task(id="a", title="a", risk=Risk.IRREVERSIBLE, tools=["db_migrate"],
             acceptance=[_qa("ca")])
    b = Task(id="b", title="b", deps=["a"], risk=Risk.IRREVERSIBLE, tools=["db_migrate"],
             acceptance=[_qa("cb")])
    agent = SimulatedAgent(lambda t: [ToolCall(tool="db_migrate", args={"t": t.id})],
                           lambda t, c: {"ok": True, "undo": lambda tid=t.id: undone.append(tid)})
    lc = _lc(tmp_path, agent, [a, b], verifier=SimulatedVerifier({"ca": True, "cb": False}),
             approval_fn=lambda t, c: True)
    assert lc.execute_all().halted
    assert a.status == TaskStatus.DONE and b.status == TaskStatus.BLOCKED
    assert undone == ["b"]


def test_rollback_fn_runs_on_escalation_and_failure_is_recorded(tmp_path):
    seen = []
    task = _edit_task()
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [_edit_call("/etc/x")]), [task],
             rollback_fn=lambda cp: seen.append(cp.ref))
    lc.execute_all()
    rb = [e for e in lc.ledger if e.type == EventType.ROLLED_BACK.value][-1]
    assert seen == ["b"] and rb.payload["executed"] is True

    task2 = _edit_task()
    lc2 = _lc(tmp_path / "2", SimulatedAgent(lambda t: [_edit_call("/etc/x")]), [task2],
              rollback_fn=_raise(OSError("git locked")))
    lc2.execute_all()
    rb2 = [e for e in lc2.ledger if e.type == EventType.ROLLED_BACK.value][-1]
    assert rb2.payload["executed"] is False and "git locked" in rb2.payload["error"]


def test_rolled_back_is_honest_without_rollback_fn(tmp_path):
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [_edit_call("/etc/x")]), [_edit_task()])
    lc.execute_all()
    rb = [e for e in lc.ledger if e.type == EventType.ROLLED_BACK.value][-1]
    assert rb.payload["executed"] is False


# ============================================================================
# scope guard
# ============================================================================

@pytest.mark.parametrize("target", [
    "src\\..\\..\\Windows\\System32\\cmd.exe",   # pre-fix: ALLOWED on POSIX hosts
    "src/..\\..\\etc\\passwd",
    "src/../../etc/passwd",
    "src/\x00/../../x",
    "..",
    "",
])
def test_scope_guard_blocks_traversal_variants(target):
    pe = PolicyEngine()
    t = _edit_task()
    assert not pe.decide(ToolCall(tool="edit", paths=[target]), t).allowed


@pytest.mark.parametrize("target", ["src\\app.py", "src/./app.py", "src/sub/../app.py"])
def test_scope_guard_allows_equivalent_in_scope_forms(target):
    assert PolicyEngine().decide(ToolCall(tool="edit", paths=[target]), _edit_task()).allowed


def test_scope_guard_is_case_sensitive_on_every_os():
    """fnmatch() case-folds on Windows only; policy must not depend on host OS."""
    assert not PolicyEngine().decide(ToolCall(tool="edit", paths=["SRC/app.py"]),
                                     _edit_task()).allowed


# ============================================================================
# ledger crash safety / concurrency / truncation
# ============================================================================

def test_torn_tail_fails_closed(tmp_path):
    """Pre-fix: verify() and append() both crashed with JSONDecodeError."""
    led = Ledger(tmp_path / "L.jsonl")
    led.append("a", {})
    with (tmp_path / "L.jsonl").open("ab") as f:
        f.write(b'{"seq": 1, "ts"')                 # crash mid-write
    ok, reason = led.verify()
    assert not ok and "torn" in reason
    with pytest.raises(LedgerCorruptError):
        led.append("b", {})


def test_corrupt_middle_line_is_reported_not_raised(tmp_path):
    p = tmp_path / "L.jsonl"
    led = Ledger(p)
    for i in range(3):
        led.append("e", {"i": i})
    lines = p.read_bytes().split(b"\n")
    lines[1] = b"{garbage"
    p.write_bytes(b"\n".join(lines))
    ok, reason = led.verify()
    assert not ok and "line 2" in reason


def test_unknown_fields_in_entry_reported_as_corrupt(tmp_path):
    p = tmp_path / "L.jsonl"
    led = Ledger(p)
    led.append("e", {})
    d = json.loads(p.read_text())
    d["evil"] = 1
    p.write_text(json.dumps(d) + "\n")
    assert not led.verify()[0]


def test_expected_head_detects_tail_truncation(tmp_path):
    p = tmp_path / "L.jsonl"
    led = Ledger(p)
    for i in range(5):
        led.append("e", {"i": i})
    head = led.last().hash
    assert led.verify(expected_head=head) == (True, None)
    p.write_bytes(b"".join(p.read_bytes().splitlines(keepends=True)[:3]))   # drop tail
    assert led.verify()[0], "chain alone cannot see tail truncation"
    ok, reason = led.verify(expected_head=head)
    assert not ok and "truncated" in reason


def test_tail_read_handles_entries_larger_than_chunk(tmp_path):
    led = Ledger(tmp_path / "L.jsonl")
    led.append("big", {"blob": "x" * 200_000})
    e = led.append("next", {})
    assert e.seq == 1 and led.verify()[0]


def test_unserializable_payload_is_normalized_not_crash(tmp_path):
    led = Ledger(tmp_path / "L.jsonl")
    e = led.append("e", {"obj": object(), "tup": (1, 2), "b": b"x"})
    assert isinstance(e.payload["obj"], str) and e.payload["tup"] == [1, 2]
    assert led.entries()[0].payload == e.payload
    assert led.verify()[0]


_WORKER = textwrap.dedent("""
    import sys
    from anvil.ledger import Ledger
    led = Ledger(sys.argv[1])
    for i in range(int(sys.argv[3])):
        led.append("w", {"worker": sys.argv[2], "i": i})
""")


def test_concurrent_processes_never_fork_the_chain(tmp_path):
    """Pre-fix: two writers both read the same tail and appended duplicate seqs."""
    path = tmp_path / "L.jsonl"
    Ledger(path)
    n_proc, n_each = 4, 25
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(path), str(w), str(n_each)])
             for w in range(n_proc)]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    led = Ledger(path)
    ok, reason = led.verify()
    assert ok, reason
    assert [e.seq for e in led] == list(range(n_proc * n_each))


# ============================================================================
# logging
# ============================================================================

def _full_run(root, request="x"):
    t = [_edit_task()]
    lc = Lifecycle(MissionStore(root), SimulatedAgent(lambda t: [_edit_call()]),
                   SimulatedVerifier({"t1c": True}))
    lc.intake(request); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=t))
    lc.review(); lc.execute_all(); lc.learn([])
    return lc


def test_resumed_run_on_same_store_verifies_clean(tmp_path):
    """Pre-fix: a second run restarted every channel chain at genesis, so
    verify-logs reported TAMPERED + APPENDED on an honest store."""
    from anvil.cli import main as cli_main
    _full_run(tmp_path)
    _full_run(tmp_path)
    assert cli_main(["verify-logs", str(tmp_path)]) == 0


def test_append_after_latest_anchor_still_detected_across_runs(tmp_path):
    from anvil.cli import main as cli_main
    _full_run(tmp_path)
    _full_run(tmp_path)
    with (tmp_path / ".mission" / "logs" / "txn.jsonl").open("a") as f:
        f.write(json.dumps({"forged": True}) + "\n")
    assert cli_main(["verify-logs", str(tmp_path)]) == 1


def test_harness_digests_survive_redaction(tmp_path):
    """Pre-fix: every SHA-256 the harness emitted (bundle_hash, locks, evidence)
    matched the base64 rule and was replaced with [REDACTED] in the channels."""
    lc = _full_run(tmp_path)
    ctx = [e for e in lc.log_router.read(LogChannel.CHANGE) if e.event == "context_committed"]
    assert len(ctx[0].payload["bundle_hash"]) == 64
    comp = [e for e in lc.log_router.read(LogChannel.CHANGE) if e.event == "contract_compiled"]
    assert all(len(h) == 64 for h in comp[0].payload["locks"].values())
    done = [e for e in lc.log_router.read(LogChannel.TXN) if e.event == "task_done"]
    assert all(len(h) == 64 for h in done[0].payload["evidence"])


def test_hex_secret_outside_digest_keys_still_redacted():
    hexkey = hashlib.sha256(b"k").hexdigest()
    out = _redact({"detail": hexkey, "bundle_hash": hexkey, "locks": {"t": hexkey},
                   "bundle_hash_note": hexkey, "evidence": ["sk-" + "A" * 30]})
    assert out["detail"] == "[REDACTED]"
    assert out["bundle_hash_note"] == "[REDACTED]"
    assert out["bundle_hash"] == hexkey and out["locks"]["t"] == hexkey
    assert out["evidence"] == ["[REDACTED]"]          # non-hex under digest key: scrubbed


def test_unserializable_args_reach_channels_without_crash(tmp_path):
    agent = SimulatedAgent(lambda t: [ToolCall(tool="db_migrate", args={"conn": object()})])
    lc = _lc(tmp_path, agent, [_irrev_task()])
    assert lc.execute_all().halted
    acc = [e for e in lc.log_router.read(LogChannel.ACCESS) if e.event == "approval_requested"]
    assert acc and isinstance(acc[0].payload["args"]["conn"], str)


# ============================================================================
# context / store
# ============================================================================

def test_tokenizer_undercount_cannot_loosen_size_gate():
    text = "word " * 4000                               # heuristic ~5000
    count, label = _estimate_tokens(text, tokenizer=lambda s: 1)
    assert count >= 4000 and label == "heuristic"
    count, label = _estimate_tokens(text, tokenizer=lambda s: 9000)
    assert (count, label) == (9000, "adapter")         # adapter may tighten


def test_lying_tokenizer_cannot_bypass_oversize_in_lifecycle(tmp_path):
    class Liar(SimulatedAgent):
        def count_tokens(self, s):
            return 1
    lc = Lifecycle(MissionStore(tmp_path), Liar(lambda t: []), SimulatedVerifier({"t1c": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="M" * 50_000, scope_in=["src"], scope_out=[],
                        tasks=[_edit_task()], context_budget={"max_tokens_per_task": 100}))
    lc.review()
    assert lc.execute_all().halted
    assert EventType.CONTEXT_OVERSIZE.value in _types(lc)


@pytest.mark.parametrize("mutate", [
    lambda t: t.tools.append("rm"),
    lambda t: setattr(t, "risk", Risk.IRREVERSIBLE),
])
def test_context_spec_seal_covers_tools_and_risk(mutate):
    cc = ContextCompiler()
    t = _edit_task()
    before = cc.build_spec(t).spec_hash
    mutate(t)
    assert cc.build_spec(t).spec_hash != before


def test_refreeze_with_different_request_raises(tmp_path):
    s = MissionStore(tmp_path)
    h = s.freeze_request("build X")
    assert s.freeze_request("build X") == h            # idempotent resume
    with pytest.raises(ValueError, match="already frozen"):
        s.freeze_request("build Y")


def test_request_hash_is_over_exact_bytes(tmp_path):
    s = MissionStore(tmp_path)
    text = "line1\r\nline2\n"
    h = s.freeze_request(text)
    assert h == hashlib.sha256(text.encode("utf-8")).hexdigest() == s.request_hash()
    assert s.request_path.read_bytes() == text.encode("utf-8")


def test_state_and_plan_writes_are_atomic(tmp_path):
    lc = _full_run(tmp_path)
    d = lc.store.dir
    assert not [p for p in d.iterdir() if p.name.endswith(".tmp")]
    assert json.loads(lc.store.state_path.read_text())["phase"] == "done"
    assert json.loads(lc.store.plan_path.read_text())["tasks"][0]["id"] == "t1"


def test_recover_trace_id_from_signed_ledger(tmp_path):
    key = os.urandom(32)
    lc = Lifecycle(MissionStore(tmp_path), SimulatedAgent(lambda t: []), SimulatedVerifier({}),
                   signing_key=key)
    lc.intake("x")
    s = MissionStore(tmp_path)
    assert s.recover_trace_id() is None                # keyless verify fails closed
    assert s.recover_trace_id(signing_key=key) == lc.trace.trace_id


# ============================================================================
# CLI
# ============================================================================

def test_cli_audits_signed_ledger_with_key_env(tmp_path, monkeypatch, capsys):
    from anvil.cli import main as cli_main
    key = os.urandom(32)
    lc = Lifecycle(MissionStore(tmp_path), SimulatedAgent(lambda t: [_edit_call()]),
                   SimulatedVerifier({"t1c": True}), signing_key=key)
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[_edit_task()]))
    lc.review(); lc.execute_all(); lc.learn([])

    assert cli_main(["audit", str(tmp_path)]) == 1                 # no key: TAMPERED
    monkeypatch.setenv("ANVIL_KEY", key.hex())
    assert cli_main(["audit", str(tmp_path), "--key-env", "ANVIL_KEY"]) == 0
    assert cli_main(["verify-logs", str(tmp_path), "--key-env", "ANVIL_KEY"]) == 0
    monkeypatch.setenv("ANVIL_KEY", os.urandom(32).hex())
    assert cli_main(["audit", str(tmp_path), "--key-env", "ANVIL_KEY"]) == 1
    monkeypatch.setenv("ANVIL_KEY", "not-hex")
    with pytest.raises(SystemExit):
        cli_main(["audit", str(tmp_path), "--key-env", "ANVIL_KEY"])


def test_cli_expect_head_and_corrupt_ledger(tmp_path, capsys):
    from anvil.cli import main as cli_main
    lc = _full_run(tmp_path)
    head = lc.ledger.last().hash
    assert cli_main(["audit", str(tmp_path), "--expect-head", head]) == 0
    assert cli_main(["audit", str(tmp_path), "--expect-head", "0" * 64]) == 1
    with lc.store.ledger_path.open("ab") as f:
        f.write(b"{torn")
    assert cli_main(["audit", str(tmp_path)]) == 1
    assert cli_main(["ledger", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "torn" in out
    out.encode("ascii")                                   # CLI output stays ASCII


# ============================================================================
# resume (replaces the broken agents.md recipe that poked lc.phase directly)
# ============================================================================

def _two_task_run(root, fail_t2=True, **kw):
    t1 = _edit_task("t1")
    t2 = _edit_task("t2", deps=["t1"])
    lc = Lifecycle(MissionStore(root), SimulatedAgent(lambda t: [_edit_call()]),
                   SimulatedVerifier({"t1c": True, "t2c": not fail_t2}), **kw)
    lc.intake("x"); lc.baseline({"ref": "base-sha"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[t1, t2]))
    lc.review(); lc.execute_all()
    return lc


def test_resume_runs_only_unfinished_tasks(tmp_path):
    first = _two_task_run(tmp_path)
    assert first.phase == Phase.HALTED                 # t2 escalated after 3 strikes
    started = []
    agent = SimulatedAgent(lambda t: started.append(t.id) or [_edit_call()])
    lc = Lifecycle(MissionStore(tmp_path), agent,
                   SimulatedVerifier({"t1c": True, "t2c": True}),
                   trace_id=MissionStore(tmp_path).recover_trace_id())
    res = lc.resume()
    assert res.phase == Phase.EXECUTE and "1 remaining" in res.note
    assert lc.recovery.last_checkpoint().ref == "base-sha"
    assert lc.execute_all().phase == Phase.LEARN
    assert started == ["t2"], "DONE task t1 must not re-run"
    lc.learn([])
    assert lc.audit()[0]
    assert lc.trace.trace_id == first.trace.trace_id


def test_resume_refuses_plan_edited_on_disk(tmp_path):
    _two_task_run(tmp_path)
    store = MissionStore(tmp_path)
    plan = json.loads(store.plan_path.read_text())
    plan["tasks"][1]["paths"] = ["src/*", "/etc/*"]     # widen the grant on disk
    store.plan_path.write_text(json.dumps(plan))
    lc = Lifecycle(store, SimulatedAgent(lambda t: []), SimulatedVerifier({}))
    with pytest.raises(RuntimeError, match="differs from the sealed contract"):
        lc.resume()


def test_resume_refuses_forged_locks_on_disk(tmp_path):
    """Recomputing the plan's own locks after editing it must not help: the
    seals that count are the ones in the hash-chained ledger."""
    _two_task_run(tmp_path)
    store = MissionStore(tmp_path)
    c = store.load_contract()
    c.tasks[1].tools.append("rm")
    c.context_spec_locks["t2"] = ContextCompiler().build_spec(c.tasks[1]).spec_hash
    store.save_contract(c)
    with pytest.raises(RuntimeError, match="sealed contract"):
        Lifecycle(store, SimulatedAgent(lambda t: []), SimulatedVerifier({})).resume()


def test_resume_refuses_unreviewed_done_or_tampered(tmp_path):
    # never reviewed
    lc = Lifecycle(MissionStore(tmp_path / "a"), SimulatedAgent(lambda t: []),
                   SimulatedVerifier({}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[_edit_task()]))
    with pytest.raises(RuntimeError, match="never passed review"):
        Lifecycle(MissionStore(tmp_path / "a"), SimulatedAgent(lambda t: []),
                  SimulatedVerifier({})).resume()
    # already done
    _full_run(tmp_path / "b")
    with pytest.raises(RuntimeError, match="already DONE"):
        Lifecycle(MissionStore(tmp_path / "b"), SimulatedAgent(lambda t: []),
                  SimulatedVerifier({})).resume()
    # tampered ledger
    _two_task_run(tmp_path / "c")
    p = MissionStore(tmp_path / "c").ledger_path
    p.write_text(p.read_text().replace('"t1"', '"tX"', 1))
    with pytest.raises(RuntimeError, match="failed verification"):
        Lifecycle(MissionStore(tmp_path / "c"), SimulatedAgent(lambda t: []),
                  SimulatedVerifier({})).resume()


def test_resume_signed_ledger_needs_key(tmp_path):
    key = os.urandom(32)
    _two_task_run(tmp_path, signing_key=key)
    with pytest.raises(RuntimeError, match="failed verification"):
        Lifecycle(MissionStore(tmp_path), SimulatedAgent(lambda t: []),
                  SimulatedVerifier({})).resume()
    lc = Lifecycle(MissionStore(tmp_path), SimulatedAgent(lambda t: [_edit_call()]),
                   SimulatedVerifier({"t1c": True, "t2c": True}), signing_key=key)
    assert lc.resume().phase == Phase.EXECUTE


def test_tamper_during_irreversible_perform_still_unwinds_side_effect(tmp_path):
    undone = []

    def perform(t, c):
        t.tools.append("deploy")
        return {"ok": True, "undo": lambda: undone.append("migration")}
    lc = _lc(tmp_path, SimulatedAgent(lambda t: [ToolCall(tool="db_migrate")], perform),
             [_irrev_task()], approval_fn=lambda t, c: True)
    assert lc.execute_all().halted
    assert EventType.CONTEXT_TAMPERED.value in _types(lc)
    assert undone == ["migration"]
