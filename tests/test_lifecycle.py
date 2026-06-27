"""
Integration: prove the whole machine upholds its invariants, not just the parts.

Each test maps to a real-world pain point the council raised:
  * happy path           -> long multi-step work completes with proof + clean audit
  * scope violation       -> in-flight scope creep is blocked and halts safely
  * irreversible no-approval -> destructive action cannot run without commit-point
  * irreversible + approval  -> runs, and registers a compensation (saga) the moment
                                the side effect succeeds
  * audit                 -> the ledger verifies end-to-end (tamper-evident)
"""
from anvil import (
    AcceptanceCheck, Contract, EventType, Lifecycle, MissionStore, Phase,
    PolicyEngine, Risk, SimulatedAgent, SimulatedVerifier, Task, TaskStatus, ToolCall,
    ToolPolicy,
)


def _qa(cid):
    return AcceptanceCheck(id=cid, description="behavioral check", kind="behavior",
                           spec={"k": cid}, authored_by="qa")


def _types(lc):
    return [e.type for e in lc.ledger]


def test_happy_path_completes_with_clean_audit(tmp_path):
    tasks = [
        Task(id="t1", title="scaffold", tools=["edit"], paths=["src/*"],
             acceptance=[_qa("t1c1")]),
        Task(id="t2", title="feature", deps=["t1"], tools=["edit", "run_tests"],
             paths=["src/*"], acceptance=[_qa("t2c1")]),
    ]
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/app.py"], task_id=t.id)],
    )
    verifier = SimulatedVerifier({"t1c1": True, "t2c1": True})
    lc = Lifecycle(MissionStore(tmp_path), agent, verifier)

    lc.intake("Build the thing with several steps")
    lc.baseline({"ref": "sha-base"})
    lc.compile(Contract(mission="thing", scope_in=["src"], scope_out=["prod"], tasks=tasks))
    assert lc.review().phase == Phase.EXECUTE
    res = lc.execute_all()
    assert res.phase == Phase.LEARN, res.note
    assert all(t.status == TaskStatus.DONE for t in tasks)
    lc.learn(["KCL pattern worked; reuse for next recompete task"])
    assert lc.phase == Phase.DONE
    ok, reason = lc.audit()
    assert ok, reason
    # tasks recorded evidence hashes
    assert all(t.evidence for t in tasks)


def test_scope_creep_is_blocked_and_halts(tmp_path):
    task = Task(id="t1", title="edit", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    rogue = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["/etc/passwd"], task_id=t.id)],
    )
    lc = Lifecycle(MissionStore(tmp_path), rogue, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review()
    res = lc.execute_all()
    assert res.halted
    assert EventType.SCOPE_VIOLATION.value in _types(lc)
    assert task.status == TaskStatus.BLOCKED


def test_irreversible_action_blocked_without_approval(tmp_path):
    task = Task(id="t1", title="migrate", risk=Risk.IRREVERSIBLE, tools=["db_migrate"],
                acceptance=[_qa("c1")])
    agent = SimulatedAgent(calls_for=lambda t: [ToolCall(tool="db_migrate", task_id=t.id)])
    # default approval_fn denies everything (fail safe)
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["db"], scope_out=[], tasks=[task]))
    lc.review()
    res = lc.execute_all()
    assert res.halted
    types = _types(lc)
    assert EventType.APPROVAL_REQUESTED.value in types
    assert EventType.APPROVAL_DENIED.value in types
    assert task.status == TaskStatus.BLOCKED


def test_irreversible_with_approval_runs_and_registers_compensation(tmp_path):
    undo_calls = []
    task = Task(id="t1", title="migrate", risk=Risk.IRREVERSIBLE, tools=["db_migrate"],
                acceptance=[_qa("c1")])
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="db_migrate", task_id=t.id)],
        perform_fn=lambda t, c: {"ok": True, "idempotency_key": "mig-0042",
                                 "undo": lambda: undo_calls.append("rolled back migration")},
    )
    lc = Lifecycle(
        MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}),
        approval_fn=lambda t, c: True,   # operator grants the commit-point
    )
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["db"], scope_out=[], tasks=[task]))
    lc.review()
    res = lc.execute_all()
    assert res.phase == Phase.LEARN, res.note
    assert task.status == TaskStatus.DONE
    types = _types(lc)
    assert EventType.APPROVAL_GRANTED.value in types
    # a compensation was registered for the successful irreversible side effect
    assert any(e.type == EventType.CHECKPOINT_MADE.value
               and e.payload.get("kind") == "compensation" for e in lc.ledger)
    # and it actually unwinds when invoked
    assert lc.recovery.compensate_all() == ["db_migrate"]
    assert undo_calls == ["rolled back migration"]


def test_review_blocks_partial_executor_authored_acceptance(tmp_path):
    """review() must reject any executor-authored check on IRREVERSIBLE tasks, not only all-executor."""
    from anvil import AcceptanceCheck
    def _exec(cid):
        return AcceptanceCheck(id=cid, description="d", kind="behavior", spec={}, authored_by="executor")

    task = Task(id="t1", title="risky", risk=Risk.IRREVERSIBLE, tools=["db_migrate"],
                paths=["db/*"],
                acceptance=[_qa("c1"), _exec("c2")])   # 1 QA + 1 executor = mixed
    lc = Lifecycle(MissionStore(tmp_path), SimulatedAgent(calls_for=lambda t: []),
                   SimulatedVerifier({"c1": True, "c2": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["db"], scope_out=[], tasks=[task]))
    res = lc.review()
    assert res.halted, "mixed-author IRREVERSIBLE task should be rejected at review"
    assert EventType.REVIEW_REJECTED.value in _types(lc)


def test_repair_ladder_gives_retry_same_then_swap_then_escalate(tmp_path):
    """First strike retries same, second swaps model, third escalates (true 3-strike rule)."""
    attempts = []
    task = Task(id="t1", title="flaky", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])

    def fail_twice_then_pass(t):
        # track calls; fail first two verifications, pass third
        return [ToolCall(tool="edit", paths=["src/app.py"], task_id=t.id)]

    call_count = [0]

    class CountingVerifier:
        def run_check(self, task, check):
            from anvil import Evidence
            call_count[0] += 1
            ok = call_count[0] >= 3   # fail first 2, pass on 3rd
            return Evidence(task.id, check.id, ok=ok, detail=f"attempt {call_count[0]}")

    lc = Lifecycle(MissionStore(tmp_path),
                   SimulatedAgent(calls_for=fail_twice_then_pass),
                   CountingVerifier())
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review()
    res = lc.execute_all()
    assert res.phase.value == "learn", res.note
    assert task.strikes == 2             # two failures before success
    types = _types(lc)
    assert types.count(EventType.TASK_FAILED.value) == 2
    assert EventType.TASK_DONE.value in types


def test_credential_wall_blocks_prod_tool(tmp_path):
    task = Task(id="t1", title="deploy", risk=Risk.IRREVERSIBLE, tools=["deploy"],
                acceptance=[_qa("c1")])
    agent = SimulatedAgent(calls_for=lambda t: [ToolCall(tool="deploy", task_id=t.id)])
    # elevated=False: prod credentials are not reachable in the agent session
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}),
                   policy=PolicyEngine(ToolPolicy(), elevated=False),
                   approval_fn=lambda t, c: True)
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["infra"], scope_out=[], tasks=[task]))
    lc.review()
    res = lc.execute_all()
    assert res.halted
    assert EventType.TOOL_CALL_DENIED.value in _types(lc)
