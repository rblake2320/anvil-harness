"""
ANVIL CLI.

  anvil demo        <dir>  run a full offline cradle-to-grave demo
  anvil status      <dir>  show phase + per-task status from STATE.json
  anvil audit       <dir>  verify the hash-chained ledger end-to-end
  anvil ledger      <dir>  print the ledger event stream
  anvil verify-logs <dir>  check channel digests against their ledger anchors

The demo proves the machine end to end with simulated seats.  For real runs,
implement AgentAdapter/VerifierAdapter against Claude Code + a test runner and
call the Lifecycle phases the same way demo() does.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import SimulatedAgent, SimulatedVerifier
from .lifecycle import Lifecycle
from .schemas import AcceptanceCheck, Risk, Task, ToolCall
from .store import Contract, MissionStore


def _demo(root: str) -> int:
    store = MissionStore(root)
    qa = lambda cid: AcceptanceCheck(id=cid, description="behavioral", kind="behavior",
                                     spec={"k": cid}, authored_by="qa")
    tasks = [
        Task(id="scaffold", title="scaffold project", tools=["edit"], paths=["src/*"],
             acceptance=[qa("a1")]),
        Task(id="feature", title="implement feature", deps=["scaffold"],
             tools=["edit", "run_tests"], paths=["src/*"], acceptance=[qa("a2")]),
        Task(id="migrate", title="run db migration", deps=["feature"], risk=Risk.IRREVERSIBLE,
             tools=["db_migrate"], acceptance=[qa("a3")]),
    ]
    agent = SimulatedAgent(
        calls_for=lambda t: ([ToolCall(tool="db_migrate", task_id=t.id)]
                             if t.id == "migrate"
                             else [ToolCall(tool="edit", paths=["src/app.py"], task_id=t.id)]),
        perform_fn=lambda t, c: ({"ok": True, "idempotency_key": f"{t.id}-0001",
                                  "undo": lambda: None}
                                 if c.tool == "db_migrate" else {"ok": True}),
    )
    verifier = SimulatedVerifier({"a1": True, "a2": True, "a3": True})

    # NB: pass signing_key=b"..." to turn the ledger into an HMAC/PKA chain.
    # Left unsigned here so `anvil audit` verifies without needing the key.
    lc = Lifecycle(store, agent, verifier,
                   approval_fn=lambda t, c: True)  # operator grants the migration

    print("-> intake");   print("  ", lc.intake("Build feature X and migrate the DB").note)
    print("-> baseline"); print("  ", lc.baseline({"ref": "git:HEAD"}).note)
    print("-> compile");  print("  ", lc.compile(
        Contract(mission="Feature X + migration", scope_in=["src", "db"],
                 scope_out=["prod infra"], tasks=tasks)).note)
    print("-> review");   print("  ", lc.review().note)
    print("-> execute");  print("  ", lc.execute_all().note)
    print("-> learn");    print("  ", lc.learn(["demo run complete"]).note)
    ok, reason = lc.audit()
    print(f"\nledger verified: {ok}" + (f" ({reason})" if reason else ""))
    print(f"events: {len(store and lc.ledger.entries())}   artifacts: {store.dir}")
    return 0 if ok else 1


def _status(root: str) -> int:
    store = MissionStore(root)
    state = store.load_state()
    print(f"phase: {state['phase']}")
    for tid, st in state.get("tasks", {}).items():
        strikes = state.get("strikes", {}).get(tid, 0)
        mark = {"done": "ok", "blocked": "!!", "failed": "!!"}.get(st, " .")
        print(f"  {mark} {tid:20s} {st}" + (f"  (strikes={strikes})" if strikes else ""))
    return 0


def _audit(root: str) -> int:
    from .ledger import Ledger
    led = Ledger(MissionStore(root).ledger_path)
    ok, reason = led.verify()
    print(f"ledger: {'OK' if ok else 'TAMPERED'}  entries={len(led.entries())}"
          + (f"  reason={reason}" if reason else ""))
    return 0 if ok else 1


def _ledger(root: str) -> int:
    from .ledger import Ledger
    for e in Ledger(MissionStore(root).ledger_path):
        print(f"{e.seq:4d} {e.type:24s} {json.dumps(e.payload)[:120]}")
    return 0


def _verify_logs(root: str) -> int:
    """Re-derive each channel's rolling hash and compare against ledger anchors.

    The ledger is verified first (tampered ledger = can't trust anchors).
    Then for each channel_digest event, every channel's file is replayed entry
    by entry to recompute the hash up to the anchored count and compared.
    Any insertion, deletion, reorder, or payload mutation will produce a mismatch.
    """
    from .ledger import Ledger
    from .log import compute_channel_hash

    store = MissionStore(root)
    led = Ledger(store.ledger_path)

    ok, reason = led.verify()
    if not ok:
        print(f"LEDGER TAMPERED - anchors are untrusted: {reason}")
        return 1

    digest_events = [e for e in led.entries() if e.type == "channel_digest"]
    if not digest_events:
        print("No channel_digest anchors in ledger (run completes via learn() to anchor).")
        return 0

    any_fail = False
    for event in digest_events:
        print(f"anchor @ ledger seq {event.seq}:")
        for ch_name, info in sorted(event.payload.get("channels", {}).items()):
            path = store.log_dir / f"{ch_name}.jsonl"
            expected_hash = info["hash"]
            expected_count = info["count"]
            actual_hash, actual_count = compute_channel_hash(path, up_to_count=expected_count)
            if actual_count < expected_count:
                print(f"  TRUNCATED  {ch_name}: {actual_count}/{expected_count} entries")
                any_fail = True
            elif actual_hash != expected_hash:
                print(f"  TAMPERED   {ch_name}: hash mismatch ({expected_count} entries)")
                any_fail = True
            else:
                print(f"  ok         {ch_name}: {actual_count} entries")
    return 1 if any_fail else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="anvil", description="Governed agent execution harness")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("demo", "status", "audit", "ledger", "verify-logs"):
        sp = sub.add_parser(name)
        sp.add_argument("dir", nargs="?", default=".")
    args = p.parse_args(argv)
    fn = {"demo": _demo, "status": _status, "audit": _audit,
          "ledger": _ledger, "verify-logs": _verify_logs}
    return fn[args.cmd](args.dir)


if __name__ == "__main__":
    sys.exit(main())
