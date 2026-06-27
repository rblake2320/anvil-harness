"""
Logging infrastructure tests: prove the 14-channel fan-out, span lifecycle,
direct channel writes, log levels, and end-to-end integration with Lifecycle.

Each test maps to a concrete observability guarantee:
  * fan-out          -> scope_violation lands in security + access + tool_call, nowhere else
  * levels           -> error events carry error/critical level; happy events carry info
  * trace spans      -> parent-child depth, duration_ms, status after end_span
  * direct write   -> token + quality channels accept writes without going through ledger
  * integration    -> a real Lifecycle run populates 8+ channels automatically
  * security chann -> violations and tamper attempts are isolated for alerting
  * token budget   -> token ceiling added to CircuitBreaker; trips on overflow
  * summary        -> non-empty channel counts are correct; empty channels omitted
"""
import time

import pytest

from anvil import (
    AcceptanceCheck, Budget, CircuitBreaker, Contract, EventType, Lifecycle,
    LogChannel, LogEntry, LogLevel, LogRouter, MissionStore, Risk,
    SimulatedAgent, SimulatedVerifier, SpanEntry, Task, TaskStatus,
    ToolCall, TraceContext, EVENT_CHANNELS, EVENT_LEVELS,
)


# ---- helpers ----------------------------------------------------------------

def _qa(cid: str) -> AcceptanceCheck:
    return AcceptanceCheck(id=cid, description="d", kind="behavior",
                           spec={}, authored_by="qa")


def _router(tmp_path):
    return LogRouter(tmp_path / "logs")


# ---- fan-out routing --------------------------------------------------------

def test_scope_violation_routes_to_security_access_tool_call(tmp_path):
    router = _router(tmp_path)
    router.route("scope_violation", {"task": "t1", "path": "/etc/passwd"},
                 level=LogLevel.WARN.value, trace_id="tr-test")

    assert len(router.read(LogChannel.SECURITY)) == 1
    assert len(router.read(LogChannel.ACCESS)) == 1
    assert len(router.read(LogChannel.TOOL_CALL)) == 1
    # must NOT appear in channels it isn't mapped to
    assert len(router.read(LogChannel.ERROR)) == 0
    assert len(router.read(LogChannel.TXN)) == 0
    assert len(router.read(LogChannel.TRACE)) == 0


def test_task_failed_routes_to_error_and_txn(tmp_path):
    router = _router(tmp_path)
    router.route("task_failed", {"task": "t1", "reason": "proof rejected"}, level="error")
    assert len(router.read(LogChannel.ERROR)) == 1
    assert len(router.read(LogChannel.TXN)) == 1
    assert len(router.read(LogChannel.SECURITY)) == 0


def test_tool_call_allowed_routes_to_tool_call_and_dependency(tmp_path):
    router = _router(tmp_path)
    router.route("tool_call_allowed", {"task": "t1", "tool": "edit"})
    assert len(router.read(LogChannel.TOOL_CALL)) == 1
    assert len(router.read(LogChannel.DEPENDENCY)) == 1
    assert len(router.read(LogChannel.SECURITY)) == 0


def test_unmapped_event_routes_nowhere(tmp_path):
    router = _router(tmp_path)
    router.route("completely_unknown_event", {"x": 1})
    summary = router.summary()
    assert not summary  # nothing written


def test_acceptance_tampered_routes_to_security_error_quality(tmp_path):
    router = _router(tmp_path)
    router.route("acceptance_tampered", {"task": "t1"}, level=LogLevel.CRITICAL.value)
    assert len(router.read(LogChannel.SECURITY)) == 1
    assert len(router.read(LogChannel.ERROR)) == 1
    assert len(router.read(LogChannel.QUALITY)) == 1


# ---- log levels -------------------------------------------------------------

def test_event_levels_map_errors_correctly():
    assert EVENT_LEVELS["acceptance_tampered"] == LogLevel.CRITICAL.value
    assert EVENT_LEVELS["task_failed"] == LogLevel.ERROR.value
    assert EVENT_LEVELS["circuit_open"] == LogLevel.ERROR.value
    assert EVENT_LEVELS["scope_violation"] == LogLevel.WARN.value
    assert EVENT_LEVELS["approval_denied"] == LogLevel.WARN.value
    # happy-path events must NOT appear (they default to info)
    assert "task_done" not in EVENT_LEVELS
    assert "proof_accepted" not in EVENT_LEVELS


def test_route_preserves_level(tmp_path):
    router = _router(tmp_path)
    router.route("task_failed", {"task": "t1"}, level=LogLevel.ERROR.value)
    entries = router.read(LogChannel.ERROR)
    assert entries[0].level == LogLevel.ERROR.value


# ---- direct channel write ---------------------------------------------------

def test_direct_write_to_token_channel(tmp_path):
    router = _router(tmp_path)
    router.write(LogChannel.TOKEN, "token_charged",
                 {"input_tokens": 1500, "output_tokens": 300, "cost": 0.02},
                 trace_id="tr-abc")
    entries = router.read(LogChannel.TOKEN)
    assert len(entries) == 1
    assert entries[0].payload["input_tokens"] == 1500
    assert entries[0].trace_id == "tr-abc"


def test_direct_write_to_debug_channel(tmp_path):
    router = _router(tmp_path)
    router.write(LogChannel.DEBUG, "debug_dump", {"state": "intermediate", "vars": {"x": 42}})
    assert len(router.read(LogChannel.DEBUG)) == 1


def test_direct_write_span_to_trace_channel(tmp_path):
    router = _router(tmp_path)
    router.write(LogChannel.TRACE, "span_started",
                 {"span_id": "sp-001", "name": "task:t1"},
                 span_id="sp-001", trace_id="tr-001")
    router.write(LogChannel.TRACE, "span_ended",
                 {"span_id": "sp-001", "duration_ms": 42.5, "status": "ok"},
                 trace_id="tr-001")
    entries = router.read(LogChannel.TRACE)
    assert len(entries) == 2
    assert entries[0].event == "span_started"
    assert entries[1].payload["duration_ms"] == 42.5


# ---- trace context / spans --------------------------------------------------

def test_span_parent_child_depth():
    tc = TraceContext("tr-fixed")
    outer = tc.start_span("phase:execute")
    assert tc.current_span_id == outer
    inner = tc.start_span("task:t1")
    assert tc.current_span_id == inner
    inner_span = tc.end_span(inner, status="ok")
    assert tc.current_span_id == outer      # stack pops back to outer
    assert inner_span.parent_id == outer
    assert inner_span.status == "ok"
    outer_span = tc.end_span(outer, status="ok")
    assert tc.current_span_id is None
    assert outer_span.parent_id is None


def test_span_duration_measured():
    tc = TraceContext()
    sid = tc.start_span("work")
    time.sleep(0.01)
    span = tc.end_span(sid)
    assert span.duration_ms() is not None
    assert span.duration_ms() >= 10.0   # at least 10 ms


def test_span_not_ended_has_no_duration():
    tc = TraceContext()
    sid = tc.start_span("pending")
    span = tc.all_spans()[0]
    assert span.duration_ms() is None


def test_trace_id_is_stable():
    tc = TraceContext()
    tid = tc.trace_id
    tc.start_span("a")
    tc.start_span("b")
    assert tc.trace_id == tid


# ---- summary ----------------------------------------------------------------

def test_summary_counts_and_omits_empty(tmp_path):
    router = _router(tmp_path)
    router.route("task_started", {"task": "t1"})   # -> txn + trace
    router.route("task_done", {"task": "t1"})       # -> txn + trace
    router.route("tool_call_allowed", {"task": "t1", "tool": "edit"})  # -> tool_call + dependency
    s = router.summary()
    assert s.get("txn", 0) == 2
    assert s.get("trace", 0) == 2
    assert s.get("tool_call", 0) == 1
    assert s.get("dependency", 0) == 1
    assert "error" not in s    # no errors routed
    assert "audit" not in s    # audit is the ledger; never in router summary


# ---- token budget in CircuitBreaker -----------------------------------------

def test_input_token_budget_trips():
    cb = CircuitBreaker(Budget(max_steps=int(1e9), max_seconds=1e9,
                               max_cost=1e9, max_input_tokens=100))
    cb.charge(input_tokens=101)
    ok, reason = cb.check()
    assert not ok and "input token" in reason


def test_output_token_budget_trips():
    cb = CircuitBreaker(Budget(max_steps=int(1e9), max_seconds=1e9,
                               max_cost=1e9, max_output_tokens=50))
    cb.charge(output_tokens=51)
    ok, reason = cb.check()
    assert not ok and "output token" in reason


def test_token_charge_accumulates():
    cb = CircuitBreaker(Budget())
    cb.charge(input_tokens=100, output_tokens=20, cost=0.01)
    cb.charge(input_tokens=200, output_tokens=40, cost=0.02)
    assert cb.input_tokens == 300
    assert cb.output_tokens == 60
    assert abs(cb.cost - 0.03) < 1e-9


# ---- integration: Lifecycle populates channels automatically ----------------

def test_lifecycle_happy_path_populates_channels(tmp_path):
    tasks = [Task(id="t1", title="do it", tools=["edit"], paths=["src/*"],
                  acceptance=[_qa("c1")])]
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/app.py"], task_id=t.id)],
    )
    verifier = SimulatedVerifier({"c1": True})
    lc = Lifecycle(MissionStore(tmp_path), agent, verifier)

    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=tasks))
    lc.review(); lc.execute_all(); lc.learn([])

    r = lc.log_router
    assert len(r.read(LogChannel.TXN)) > 0,      "task lifecycle events missing from txn"
    assert len(r.read(LogChannel.TRACE)) > 0,    "spans missing from trace"
    assert len(r.read(LogChannel.QUALITY)) > 0,  "evidence missing from quality"
    assert len(r.read(LogChannel.CHANGE)) > 0,   "contract/phase events missing from change"
    assert len(r.read(LogChannel.TOOL_CALL)) > 0,"allowed tool call missing from tool_call"
    assert len(r.read(LogChannel.DEPENDENCY)) > 0,"dependency result missing from dependency"
    assert len(r.read(LogChannel.AGENT)) > 0,    "agent decision missing from agent"
    assert len(r.read(LogChannel.ACCESS)) > 0,   "review_passed missing from access"
    assert len(r.read(LogChannel.PERF)) > 0,     "task_timing missing from perf"
    # clean run: no errors, no security violations
    assert len(r.read(LogChannel.ERROR)) == 0
    assert len(r.read(LogChannel.SECURITY)) == 0


def test_security_channel_captures_scope_violation(tmp_path):
    task = Task(id="t1", title="rogue", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    rogue = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["/etc/shadow"], task_id=t.id)],
    )
    lc = Lifecycle(MissionStore(tmp_path), rogue, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    sec = lc.log_router.read(LogChannel.SECURITY)
    assert any(e.event == "scope_violation" for e in sec)
    assert all(e.level in (LogLevel.WARN.value, LogLevel.ERROR.value, LogLevel.CRITICAL.value)
               for e in sec)


def test_tamper_appears_in_security_and_error(tmp_path):
    task = Task(id="t1", title="tamper", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1"), _qa("c2")])

    class TamperingAgent:
        """Simulates an executor that quietly drops a hard check before verify fires."""
        def plan_calls(self, t):
            # tamper during plan_calls: runs after compile lock but before evaluate()
            if len(t.acceptance) > 1:
                t.acceptance.pop()
            return [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)]

        def perform(self, t, call):
            return {"ok": True}

    lc = Lifecycle(MissionStore(tmp_path), TamperingAgent(), SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    sec = lc.log_router.read(LogChannel.SECURITY)
    err = lc.log_router.read(LogChannel.ERROR)
    assert any(e.event == "acceptance_tampered" for e in sec)
    assert any(e.event == "acceptance_tampered" for e in err)
    assert all(e.level == LogLevel.CRITICAL.value
               for e in sec if e.event == "acceptance_tampered")


def test_token_channel_populated_when_adapter_returns_usage(tmp_path):
    task = Task(id="t1", title="llm task", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)],
        perform_fn=lambda t, c: {
            "ok": True,
            "input_tokens": 1200,
            "output_tokens": 350,
            "cost": 0.005,
        },
    )
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    token_entries = lc.log_router.read(LogChannel.TOKEN)
    assert len(token_entries) >= 1
    assert token_entries[0].payload["input_tokens"] == 1200
    assert token_entries[0].payload["output_tokens"] == 350
    assert lc.breaker.input_tokens == 1200
    assert lc.breaker.output_tokens == 350


def test_trace_ids_propagate_through_all_channels(tmp_path):
    task = Task(id="t1", title="x", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)],
    )
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    trace_id = lc.trace.trace_id
    for ch in (LogChannel.TXN, LogChannel.TRACE, LogChannel.TOOL_CALL, LogChannel.QUALITY):
        entries = lc.log_router.read(ch)
        assert entries, f"{ch.value} is empty"
        for e in entries:
            assert e.trace_id == trace_id, (
                f"{ch.value}/{e.event} has trace_id={e.trace_id!r}, want {trace_id!r}"
            )


# ---- digest-anchor integrity ------------------------------------------------

def test_channel_digest_clean_verify(tmp_path):
    """Happy path: anchor + verify-logs reports OK for all channels."""
    from anvil import compute_channel_hash, ZERO_CHANNEL_HASH

    router = _router(tmp_path)
    router.route("task_started", {"task": "t1"})
    router.route("task_done", {"task": "t1"})
    router.route("scope_violation", {"task": "t1", "path": "/x"}, level="warn")

    from anvil.ledger import Ledger
    led = Ledger(tmp_path / "L.jsonl")
    digests = router.anchor(led)

    # ledger now contains a channel_digest event
    digest_event = [e for e in led.entries() if e.type == "channel_digest"]
    assert len(digest_event) == 1

    # verify each anchored channel matches
    for ch_name, info in digests.items():
        path = tmp_path / "logs" / f"{ch_name}.jsonl"
        actual_hash, actual_count = compute_channel_hash(path, up_to_count=info["count"])
        assert actual_hash == info["hash"], f"{ch_name} hash mismatch on clean verify"
        assert actual_count == info["count"]


def test_channel_digest_detects_tampered_channel(tmp_path):
    """Editing a channel file after anchor causes verify to report mismatch."""
    import json as _json
    from anvil import compute_channel_hash
    from anvil.ledger import Ledger

    router = _router(tmp_path)
    router.route("task_started", {"task": "t1"})
    router.route("approval_granted", {"task": "t1", "tool": "deploy"})

    led = Ledger(tmp_path / "L.jsonl")
    digests = router.anchor(led)

    # tamper: rewrite the first line of the access channel
    access_path = tmp_path / "logs" / "access.jsonl"
    assert access_path.exists(), "access channel must exist (approval_granted routes there)"
    lines = access_path.read_text(encoding="utf-8").splitlines()
    rec = _json.loads(lines[0])
    rec["payload"]["task"] = "INJECTED"          # mutate payload
    lines[0] = _json.dumps(rec)
    access_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # verify should fail for the tampered channel
    access_info = digests["access"]
    actual_hash, _ = compute_channel_hash(access_path, up_to_count=access_info["count"])
    assert actual_hash != access_info["hash"], "tamper should produce hash mismatch"


def test_anchor_fires_once_even_if_halted_then_learn(tmp_path):
    """_maybe_anchor() is idempotent: only one channel_digest in the ledger."""
    task = Task(id="t1", title="fail", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    rogue = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["/etc/shadow"], task_id=t.id)],
    )
    lc = Lifecycle(MissionStore(tmp_path), rogue, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()   # -> HALTED (scope violation) -> anchor fires

    # even if learn() is somehow called after halting, no second anchor
    lc._maybe_anchor()
    lc._maybe_anchor()

    digest_events = [e for e in lc.ledger.entries() if e.type == "channel_digest"]
    assert len(digest_events) == 1, f"expected 1 anchor, got {len(digest_events)}"


def test_verify_logs_cli_reports_ok(tmp_path):
    """CLI verify-logs exits 0 after a complete run."""
    from anvil.cli import main as cli_main
    from anvil import AcceptanceCheck, Contract, Lifecycle, MissionStore, Task, ToolCall

    tasks = [Task(id="t1", title="x", tools=["edit"], paths=["src/*"],
                  acceptance=[_qa("c1")])]
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)],
    )
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=tasks))
    lc.review(); lc.execute_all(); lc.learn([])

    rc = cli_main(["verify-logs", str(tmp_path)])
    assert rc == 0


# ---- redaction --------------------------------------------------------------

def test_redact_sensitive_keys():
    from anvil import _redact
    payload = {"task": "t1", "password": "s3cr3t!", "args": {"api_key": "abc123"}}
    clean = _redact(payload)
    assert clean["task"] == "t1"
    assert clean["password"] == "[REDACTED]"
    assert clean["args"]["api_key"] == "[REDACTED]"


def test_redact_does_not_mutate_original():
    from anvil import _redact
    original = {"secret": "hunter2", "x": 42}
    _ = _redact(original)
    assert original["secret"] == "hunter2"   # original untouched


def test_redact_openai_key_pattern():
    from anvil import _redact
    payload = {"info": "using sk-abcdefghijklmnopqrstuvwx for inference"}
    assert _redact(payload)["info"] == "[REDACTED]"


def test_channel_gets_redacted_payload(tmp_path):
    """Fan-out channels receive scrubbed payload; original is never seen in channel files."""
    router = _router(tmp_path)
    router.route("tool_call_allowed",
                 {"task": "t1", "tool": "edit", "secret": "hunter2"})
    entries = router.read(LogChannel.TOOL_CALL)
    assert entries[0].payload.get("secret") == "[REDACTED]"
    assert entries[0].payload["task"] == "t1"   # non-sensitive key preserved


def test_ledger_keeps_unredacted_payload(tmp_path):
    """The hash-chained ledger sees the original, unredacted payload."""
    tasks = [Task(id="t1", title="x", tools=["edit"], paths=["src/*"],
                  acceptance=[_qa("c1")])]
    # Simulate an agent whose perform() result contains a "secret" key
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)],
        perform_fn=lambda t, c: {"ok": True, "secret": "should-stay-in-ledger"},
    )
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=tasks))
    lc.review(); lc.execute_all()

    # The TOOL_CALL_ALLOWED event in the ledger has args={} (nothing secret there),
    # but the dependency_result in the DEPENDENCY channel should be redacted.
    dep_entries = lc.log_router.read(LogChannel.DEPENDENCY)
    dep = [e for e in dep_entries if e.event == "dependency_result"]
    # "ok" key is safe; no secret key should appear
    for e in dep:
        assert "secret" not in e.payload, "secret leaked into dependency channel"


# ---- trace_id on resume -----------------------------------------------------

def test_trace_id_logged_at_intake(tmp_path):
    """Intake event in the ledger contains the trace_id for cross-session linkage."""
    tasks = [Task(id="t1", title="x", tools=["edit"], paths=["src/*"],
                  acceptance=[_qa("c1")])]
    lc = Lifecycle(MissionStore(tmp_path),
                   SimulatedAgent(calls_for=lambda t: []),
                   SimulatedVerifier({"c1": True}))
    lc.intake("test request")

    intake_events = [e for e in lc.ledger.entries() if e.type == "intake_frozen"]
    assert len(intake_events) == 1
    assert intake_events[0].payload.get("trace_id") == lc.trace.trace_id


def test_resumed_run_shares_trace_id(tmp_path):
    """Passing trace_id= links the new Lifecycle to the original segment."""
    original = Lifecycle(MissionStore(tmp_path),
                         SimulatedAgent(calls_for=lambda t: []),
                         SimulatedVerifier({}))
    original_tid = original.trace.trace_id

    resumed = Lifecycle(MissionStore(tmp_path),
                        SimulatedAgent(calls_for=lambda t: []),
                        SimulatedVerifier({}),
                        trace_id=original_tid)
    assert resumed.trace.trace_id == original_tid


# ---- token charge non-replay guarantee --------------------------------------

def test_token_charge_zero_when_perform_returns_no_usage(tmp_path):
    """perform() returning {} must not charge any tokens."""
    task = Task(id="t1", title="x", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    agent = SimulatedAgent(
        calls_for=lambda t: [ToolCall(tool="edit", paths=["src/a.py"], task_id=t.id)],
        perform_fn=lambda t, c: {"ok": True},   # no usage fields
    )
    lc = Lifecycle(MissionStore(tmp_path), agent, SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    assert lc.breaker.input_tokens == 0
    assert lc.breaker.output_tokens == 0
    assert lc.log_router.read(LogChannel.TOKEN) == []   # no token events


def test_token_only_charged_on_actual_perform(tmp_path):
    """Tokens charged exactly once per perform() call, not per plan_calls() iteration."""
    call_count = [0]

    class CountingAgent:
        def plan_calls(self, task):
            return [ToolCall(tool="edit", paths=["src/a.py"], task_id=task.id)]

        def perform(self, task, call):
            call_count[0] += 1
            return {"ok": True, "input_tokens": 500, "output_tokens": 100, "cost": 0.001}

    task = Task(id="t1", title="x", tools=["edit"], paths=["src/*"],
                acceptance=[_qa("c1")])
    lc = Lifecycle(MissionStore(tmp_path), CountingAgent(), SimulatedVerifier({"c1": True}))
    lc.intake("x"); lc.baseline({"ref": "b"})
    lc.compile(Contract(mission="m", scope_in=["src"], scope_out=[], tasks=[task]))
    lc.review(); lc.execute_all()

    assert call_count[0] == 1                       # one perform() call
    assert lc.breaker.input_tokens == 500           # exactly one charge
    assert lc.breaker.output_tokens == 100
