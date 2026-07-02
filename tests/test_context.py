"""
Proof-gated context: tests for durability, tamper detection, and real failure paths.

Every test here exercises a scenario that breaks under the old approach (no context
gating) or that validates a property the harness claims to provide.  No mocks.
"""
import json

import pytest

from anvil import (
    AcceptanceCheck, Contract, EventType, Evidence, Lifecycle, MissionStore,
    Phase, SimulatedAgent, SimulatedVerifier, Task, TaskStatus, ToolCall,
    ContextBundle, ContextCompiler, ContextSpec, DEFAULT_MAX_TOKENS, summarize_evidence,
)
from anvil.context import _estimate_tokens
from anvil.ledger import LedgerEntry


# ---- helpers ----------------------------------------------------------------

def _qa(cid: str, desc: str = "check desc") -> AcceptanceCheck:
    return AcceptanceCheck(id=cid, description=desc, kind="behavior",
                           spec={}, authored_by="qa")


def _types(lc: Lifecycle) -> list[str]:
    return [e.type for e in lc.ledger]


def _fake_entry(task_id: str, check_id: str, ok: bool, detail: str) -> LedgerEntry:
    """Build a minimal LedgerEntry that looks like an evidence_recorded event."""
    return LedgerEntry(
        seq=0, ts=0.0,
        type="evidence_recorded",
        payload={"task": task_id, "check": check_id, "ok": ok, "detail": detail},
        prev="0" * 64,
        hash="0" * 64,
    )


# ---- ContextSpec -----------------------------------------------------------

def test_spec_hash_is_stable():
    """Same task inputs always produce the same spec hash (deterministic)."""
    task = Task(id="t1", title="x", deps=[], paths=["src/*"],
                acceptance=[_qa("c1", "do the thing")])
    c1 = ContextCompiler()
    s1 = c1.build_spec(task)
    s2 = c1.build_spec(task)
    assert s1.spec_hash == s2.spec_hash
    assert s1.spec_hash != ""


def test_spec_hash_changes_on_dep_mutation():
    """Adding a dep after locking produces a different hash."""
    task = Task(id="t1", title="x", deps=[], paths=["src/*"],
                acceptance=[_qa("c1")])
    compiler = ContextCompiler()
    spec_before = compiler.build_spec(task)
    task.deps = ["extra"]
    spec_after = compiler.build_spec(task)
    assert spec_before.spec_hash != spec_after.spec_hash


def test_spec_lock_and_verify():
    """lock() sets spec_hash; verify() confirms it matches current fields."""
    spec = ContextSpec(task_id="t1", dep_task_ids=[], file_globs=["src/*"],
                       acceptance_descriptions=["pass"], max_input_tokens=1000)
    assert spec.spec_hash == ""
    spec.lock()
    assert spec.spec_hash != ""
    assert spec.verify()


def test_spec_verify_fails_after_mutation():
    """Mutating a field after locking makes verify() return False."""
    spec = ContextSpec(task_id="t1", dep_task_ids=[], file_globs=["src/*"],
                       acceptance_descriptions=["pass"], max_input_tokens=1000)
    spec.lock()
    spec.dep_task_ids.append("injected")  # mutate AFTER lock
    assert not spec.verify()


# ---- _estimate_tokens -------------------------------------------------------

def test_estimate_tokens_ascii_baseline():
    text = "a" * 400  # 400 ASCII chars = ~100 tokens
    count, label = _estimate_tokens(text)
    assert label == "heuristic"
    assert count == 100


def test_estimate_tokens_multibyte_counted_as_one_each():
    """Non-ASCII chars (e.g. CJK) must each count as ~1 token (overestimate)."""
    cjk = "中文" * 50  # 100 CJK chars; real tokenizer gives ~100 tokens
    count, label = _estimate_tokens(cjk)
    assert label == "heuristic"
    assert count == 100  # 0 ASCII + 100 non-ASCII = 100


def test_estimate_tokens_adapter_success():
    """A valid adapter result overrides the heuristic."""
    count, label = _estimate_tokens("hello world", tokenizer=lambda t: 42)
    assert count == 42
    assert label == "adapter"


def test_estimate_tokens_adapter_exception_falls_back():
    """An exception from the adapter must fall back to heuristic, not propagate."""
    def bad_tokenizer(text):
        raise RuntimeError("segfault simulation")

    count, label = _estimate_tokens("abcd", tokenizer=bad_tokenizer)
    assert label == "heuristic"
    assert count == 1  # 4 chars / 4


def test_estimate_tokens_adapter_invalid_type_falls_back():
    """Non-int return from adapter must fall back to heuristic."""
    count, label = _estimate_tokens("abcd", tokenizer=lambda t: "not-a-number")
    assert label == "heuristic"


def test_estimate_tokens_adapter_zero_falls_back():
    """count=0 is not a valid positive count; must fall back to heuristic."""
    count, label = _estimate_tokens("abcd", tokenizer=lambda t: 0)
    assert label == "heuristic"


def test_estimate_tokens_adapter_negative_falls_back():
    """count=-7 must fall back to heuristic (adapter contract: positive int only)."""
    count, label = _estimate_tokens("abcd", tokenizer=lambda t: -7)
    assert label == "heuristic"


# ---- summarize_evidence -----------------------------------------------------

def test_summarize_evidence_compact():
    entries = [
        _fake_entry("t1", "c1", True, "exit=0"),
        _fake_entry("t1", "c2", False, "assertion failed on line 42"),
    ]
    summary = summarize_evidence(entries)
    assert "[PASS] c1: exit=0" in summary
    assert "[FAIL] c2: assertion failed on line 42" in summary


def test_summarize_evidence_only_evidence_recorded():
    """Events that are not evidence_recorded must be ignored."""
    class OtherEvent:
        type = "proof_accepted"
        payload = {"task": "t1"}

    entries = [
        _fake_entry("t1", "c1", True, "ok"),
        OtherEvent(),
    ]
    summary = summarize_evidence(entries)
    lines = summary.strip().splitlines()
    assert len(lines) == 1, "only the evidence_recorded line should appear"


def test_summarize_evidence_empty_on_no_entries():
    assert summarize_evidence([]) == ""


# ---- ContextBundle ---------------------------------------------------------

def test_bundle_stable_prefix_constant_across_tasks():
    """The stable_prefix is identical for all tasks in the same contract."""
    contract = Contract(mission="Build the API", scope_in=["src"], scope_out=["prod"],
                        tasks=[])
    compiler = ContextCompiler()
    t1 = Task(id="t1", title="a", deps=[], paths=["src/*"], acceptance=[_qa("c1")])
    t2 = Task(id="t2", title="b", deps=["t1"], paths=["src/*"], acceptance=[_qa("c2")])

    spec1 = compiler.build_spec(t1)
    spec2 = compiler.build_spec(t2)
    b1 = compiler.build_bundle(spec1, contract, {})
    b2 = compiler.build_bundle(spec2, contract, {})

    assert b1.stable_prefix == b2.stable_prefix
    assert "Build the API" in b1.stable_prefix


def test_bundle_task_block_varies_by_task():
    """Each task produces a different task_block."""
    contract = Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[])
    compiler = ContextCompiler()
    t1 = Task(id="t1", title="first", deps=[], paths=["src/*"],
              acceptance=[_qa("c1", "first check")])
    t2 = Task(id="t2", title="second", deps=["t1"], paths=["src/*"],
              acceptance=[_qa("c2", "second check")])
    b1 = compiler.build_bundle(compiler.build_spec(t1), contract, {})
    b2 = compiler.build_bundle(compiler.build_spec(t2), contract, {})

    assert b1.task_block != b2.task_block
    assert "t1" in b1.task_block
    assert "t2" in b2.task_block


def test_bundle_includes_dep_evidence():
    """A task with deps must include the upstream evidence summary in its bundle."""
    contract = Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[])
    compiler = ContextCompiler()
    t2 = Task(id="t2", title="second", deps=["t1"], paths=["src/*"],
              acceptance=[_qa("c2")])
    dep_evidence = {"t1": "[PASS] c1: exit=0"}
    bundle = compiler.build_bundle(compiler.build_spec(t2), contract, dep_evidence)
    assert "[PASS] c1: exit=0" in bundle.task_block


# ---- Lifecycle integration --------------------------------------------------

def test_context_committed_on_clean_run(tmp_path):
    """CONTEXT_COMMITTED must appear in the ledger once per task on a clean run."""
    tasks = [
        Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
             acceptance=[_qa("t1c1")]),
        Task(id="t2", title="t2", deps=["t1"], tools=["edit"], paths=["src/*"],
             acceptance=[_qa("t2c1")]),
    ]
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]
    )
    lc = Lifecycle(MissionStore(tmp_path), agent,
                   SimulatedVerifier({"t1c1": True, "t2c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=tasks))
    lc.review(); lc.execute_all()

    committed = [e for e in lc.ledger.entries()
                 if e.type == EventType.CONTEXT_COMMITTED.value]
    assert len(committed) == 2
    task_ids = {e.payload["task"] for e in committed}
    assert task_ids == {"t1", "t2"}
    for e in committed:
        assert e.payload.get("bundle_hash"), "bundle_hash must be set"
        assert isinstance(e.payload.get("estimated_tokens"), int)
        assert e.payload.get("estimator") in ("heuristic", "adapter")


def test_context_tampered_fires_on_spec_mismatch(tmp_path):
    """Mutating a task between compile and execute must trigger CONTEXT_TAMPERED."""
    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    lc = Lifecycle(
        MissionStore(tmp_path),
        SimulatedAgent(calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]),
        SimulatedVerifier({"t1c1": True}),
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review()

    # Mutate paths after compile — breaks the spec hash without affecting scheduling
    task.paths = ["injected/*"]

    lc.execute_all()

    assert EventType.CONTEXT_TAMPERED.value in _types(lc)
    assert task.status == TaskStatus.BLOCKED
    assert lc.phase == Phase.HALTED


def test_context_tampered_escalates_immediately(tmp_path):
    """Context tamper is deterministic — exactly one strike, immediately BLOCKED."""
    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    lc = Lifecycle(
        MissionStore(tmp_path),
        SimulatedAgent(calls_for=lambda t: []),
        SimulatedVerifier({"t1c1": True}),
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review()
    task.paths = ["tampered/*"]  # breaks spec hash without affecting scheduling
    lc.execute_all()

    failed = [e for e in lc.ledger.entries() if e.type == EventType.TASK_FAILED.value]
    assert len(failed) == 1, "tamper must produce exactly one TASK_FAILED — no retry"
    assert failed[0].payload["strikes"] == 1
    assert failed[0].payload.get("deterministic") is True


def test_context_oversize_fires_and_escalates_immediately(tmp_path):
    """Bundle exceeding max_tokens_per_task must fire CONTEXT_OVERSIZE and halt."""
    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    lc = Lifecycle(
        MissionStore(tmp_path),
        SimulatedAgent(calls_for=lambda t: []),
        SimulatedVerifier({"t1c1": True}),
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    # max_tokens=1 guarantees oversize: any real bundle has at least a few tokens
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task],
                        context_budget={"max_tokens_per_task": 1}))
    lc.review()
    result = lc.execute_all()

    assert result.halted
    assert EventType.CONTEXT_OVERSIZE.value in _types(lc)
    assert task.status == TaskStatus.BLOCKED

    failed = [e for e in lc.ledger.entries() if e.type == EventType.TASK_FAILED.value]
    assert len(failed) == 1, "oversize must produce exactly one TASK_FAILED — no retry"
    assert failed[0].payload.get("deterministic") is True


def test_context_gate_does_not_charge_tokens(tmp_path):
    """The context gate must not add to breaker.input_tokens or output_tokens."""
    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)],
        perform_fn=lambda t, c: {"ok": True},  # no usage returned
    )
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"t1c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    assert lc.breaker.input_tokens == 0
    assert lc.breaker.output_tokens == 0


def test_plan_calls_with_context_called_when_available(tmp_path):
    """An adapter that exposes plan_calls_with_context receives the ContextBundle."""
    received: list[ContextBundle] = []

    class ContextAwareAgent:
        def plan_calls(self, task):
            return [ToolCall(tool="edit", paths=["src/a.py"], task_id=task.id)]

        def plan_calls_with_context(self, task, bundle):
            received.append(bundle)
            return [ToolCall(tool="edit", paths=["src/a.py"], task_id=task.id)]

        def perform(self, task, call):
            return {"ok": True}

    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    lc = Lifecycle(MissionStore(tmp_path), ContextAwareAgent(),
                   SimulatedVerifier({"t1c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="mission text", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    assert len(received) == 1, "plan_calls_with_context must be called exactly once"
    assert received[0].task_id == "t1"
    assert "mission text" in received[0].stable_prefix


def test_fallback_to_plan_calls_without_context(tmp_path):
    """Adapters without plan_calls_with_context still execute normally."""
    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]
    )
    assert not hasattr(agent, "plan_calls_with_context")

    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"t1c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review()
    result = lc.execute_all()

    assert result.phase == Phase.LEARN
    assert task.status == TaskStatus.DONE


def test_resume_rebuilds_evidence_from_ledger(tmp_path):
    """A fresh Lifecycle over an existing store must rebuild evidence from the ledger."""
    t1 = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
              acceptance=[_qa("t1c1")])
    t2 = Task(id="t2", title="t2", deps=["t1"], tools=["edit"], paths=["src/*"],
              acceptance=[_qa("t2c1")])

    store = MissionStore(tmp_path)
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]
    )
    verifier = SimulatedVerifier({"t1c1": True, "t2c1": True})

    # Run 1: drive t1 to completion, then "die"
    lc1 = Lifecycle(store, agent, verifier)
    lc1.intake("x"); lc1.baseline({"ref": "b"})
    lc1.compile(Contract(mission="Build", scope_in=["src"], scope_out=[], tasks=[t1, t2]))
    lc1.review()
    lc1.run_task(t1)
    assert t1.status == TaskStatus.DONE
    assert "t1" in lc1._evidence_summaries
    del lc1  # simulate process death

    # Run 2: fresh Lifecycle from the same on-disk store
    lc2 = Lifecycle(MissionStore(tmp_path), agent, verifier)

    # _load_evidence_from_ledger() fires in __init__; t1 must already be here
    assert "t1" in lc2._evidence_summaries, "evidence must survive process death"
    assert lc2._evidence_summaries["t1"] != "", "evidence summary must not be empty"


def test_downstream_bundle_includes_upstream_evidence(tmp_path):
    """After t1 completes, t2's bundle must include t1's evidence summary."""
    t1 = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
              acceptance=[_qa("t1c1", "t1 acceptance")])
    t2 = Task(id="t2", title="t2", deps=["t1"], tools=["edit"], paths=["src/*"],
              acceptance=[_qa("t2c1")])

    lc = Lifecycle(
        MissionStore(tmp_path),
        SimulatedAgent(calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]),
        SimulatedVerifier({"t1c1": True, "t2c1": True}),
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="Build", scope_in=["src"], scope_out=[], tasks=[t1, t2]))
    lc.review()
    lc.run_task(t1)

    assert "t1" in lc._evidence_summaries
    compiler = ContextCompiler()
    spec2 = compiler.build_spec(t2, DEFAULT_MAX_TOKENS)
    bundle2 = compiler.build_bundle(spec2, lc.contract, lc._evidence_summaries)

    assert "t1" in bundle2.task_block, "t2 bundle must reference t1 evidence"
    # evidence summary content should appear
    assert lc._evidence_summaries["t1"] in bundle2.task_block


def test_failed_attempt_evidence_not_leaked(tmp_path):
    """Evidence from a failed attempt must not appear after a successful retry."""
    t1 = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
              acceptance=[_qa("t1c1")])

    call_count = [0]

    class RetryingVerifier:
        def run_check(self, task, check):
            call_count[0] += 1
            ok = call_count[0] >= 2  # fail first, pass second
            return Evidence(
                task.id, check.id, ok=ok,
                detail=f"attempt_{call_count[0]}_{'pass' if ok else 'fail'}",
            )

    lc = Lifecycle(
        MissionStore(tmp_path),
        SimulatedAgent(calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]),
        RetryingVerifier(),
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[t1]))
    lc.review(); lc.execute_all()

    assert t1.status == TaskStatus.DONE
    summary = lc._evidence_summaries.get("t1", "")
    assert "fail" not in summary, "failed-attempt evidence must not appear in final summary"
    assert "pass" in summary, "successful-attempt evidence must appear in summary"


def test_failed_attempt_evidence_not_leaked_on_resume(tmp_path):
    """After process death, only PROOF_ACCEPTED evidence appears — not failed attempts."""
    t1 = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
              acceptance=[_qa("t1c1")])

    call_count = [0]

    class RetryingVerifier:
        def run_check(self, task, check):
            call_count[0] += 1
            ok = call_count[0] >= 2
            return Evidence(
                task.id, check.id, ok=ok,
                detail=f"attempt_{call_count[0]}_{'pass' if ok else 'fail'}",
            )

    store = MissionStore(tmp_path)
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]
    )

    # Run to completion in lc1
    lc1 = Lifecycle(store, agent, RetryingVerifier())
    lc1.intake("x"); lc1.baseline({"ref": "b"})
    lc1.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[t1]))
    lc1.review(); lc1.execute_all()
    assert t1.status == TaskStatus.DONE
    del lc1

    # Resume — rebuild from ledger
    lc2 = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({}))
    summary = lc2._evidence_summaries.get("t1", "")
    assert "fail" not in summary, "failed-attempt evidence must not survive process death"
    assert "pass" in summary, "passing evidence must survive process death"


def test_context_tampered_appears_in_security_channel(tmp_path):
    """CONTEXT_TAMPERED events must be routed to the SECURITY log channel."""
    from anvil import LogChannel

    task = Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("t1c1")])
    lc = Lifecycle(
        MissionStore(tmp_path),
        SimulatedAgent(calls_for=lambda t: []),
        SimulatedVerifier({"t1c1": True}),
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review()
    task.paths = ["injected/*"]  # mutate to break spec hash
    lc.execute_all()

    sec = lc.log_router.read(LogChannel.SECURITY)
    assert any(e.event == "context_tampered" for e in sec), \
        "context_tampered must appear in SECURITY channel"


def test_clean_audit_after_context_gating(tmp_path):
    """Full run with context gating must produce a tamper-evident, verifiable ledger."""
    tasks = [
        Task(id="t1", title="t1", tools=["edit"], paths=["src/*"],
             acceptance=[_qa("t1c1")]),
        Task(id="t2", title="t2", deps=["t1"], tools=["edit"], paths=["src/*"],
             acceptance=[_qa("t2c1")]),
    ]
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]
    )
    lc = Lifecycle(MissionStore(tmp_path), agent,
                   SimulatedVerifier({"t1c1": True, "t2c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=tasks))
    lc.review(); lc.execute_all(); lc.learn([])

    ok, reason = lc.audit()
    assert ok, f"ledger must verify cleanly after context-gated run: {reason}"
