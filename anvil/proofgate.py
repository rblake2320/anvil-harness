"""
ANVIL proof gate: a task is DONE only when an independent verifier accepts
evidence against acceptance criteria that were LOCKED before execution.

Two distinct failure modes are closed here:

  A. Fake completion - executor narrates success without doing the work.
     Fix: status can only advance on Evidence committed to the ledger; the
     verifier (not the executor) decides ok/not-ok.

  B. Test gaming     - executor quietly weakens or rewrites acceptance tests so
     they pass. Fix: at COMPILE time we hash each task's acceptance set and lock
     it. At VERIFY time we recompute the hash; if it changed, the gate rejects
     with ACCEPTANCE_TAMPERED regardless of whether "tests pass."

  Anti-circularity: on IRREVERSIBLE / high-risk tasks, acceptance checks must be
  authored_by != the code author (QA-writes-tests-first). The gate enforces it.

The Verifier is an adapter (see adapters.py). It runs the checks and returns
Evidence. The harness owns the verdict; the verifier only supplies proof.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Protocol

from .schemas import AcceptanceCheck, Evidence, Risk, Task


def acceptance_hash(checks: list[AcceptanceCheck]) -> str:
    """Stable hash over the acceptance set. Order-independent, content-sensitive."""
    norm = sorted(
        ({"id": c.id, "description": c.description, "kind": c.kind, "spec": c.spec,
          "authored_by": c.authored_by} for c in checks),
        key=lambda d: d["id"],
    )
    blob = json.dumps(norm, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Verifier(Protocol):
    def run_check(self, task: Task, check: AcceptanceCheck) -> Evidence: ...


@dataclass
class GateResult:
    ok: bool
    reason: str
    evidence: list[Evidence]


class ProofGate:
    def __init__(self, code_author: str = "executor"):
        self.code_author = code_author

    def lock(self, task: Task) -> str:
        """Call at COMPILE/REVIEW: returns the hash to store as the task's seal."""
        return acceptance_hash(task.acceptance)

    def evaluate(self, task: Task, locked_hash: str, verifier: Verifier) -> GateResult:
        # B. tamper check first - cheap and decisive
        if acceptance_hash(task.acceptance) != locked_hash:
            return GateResult(False, "acceptance criteria changed since lock (tamper)", [])

        # anti-circularity on high-risk work
        if task.risk == Risk.IRREVERSIBLE:
            self_authored = [c for c in task.acceptance if c.authored_by == self.code_author]
            if self_authored:
                return GateResult(
                    False,
                    f"high-risk task has self-authored checks {[c.id for c in self_authored]}; "
                    f"require independent (QA) authorship",
                    [],
                )

        if not task.acceptance:
            return GateResult(False, "no acceptance criteria; cannot prove completion", [])

        # A. run every check via the independent verifier
        results = [verifier.run_check(task, c) for c in task.acceptance]
        failed = [e for e in results if not e.ok]
        if failed:
            return GateResult(False, f"{len(failed)} check(s) failed: "
                              f"{[e.check_id for e in failed]}", results)
        return GateResult(True, "all acceptance checks passed", results)
