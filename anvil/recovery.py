"""
ANVIL recovery: the way forward when a task fails. Failure is designed-for,
not hoped-against.

Two layers, because Claude's council point is the one most demos miss:

  CODE STATE (cheap, safe to roll back):
    Checkpoints are content snapshots (here: a recorded ref; in your repo, a git
    commit/stash SHA). Rolling back restores files. This is always safe because
    nothing external happened.

  EXTERNAL STATE (cannot be "restored", must be COMPENSATED):
    A migration ran, a webhook fired, a cloud resource was created, an email was
    sent. You cannot un-send these by restoring a snapshot. Every irreversible
    side effect must register a COMPENSATING action (saga pattern) at the moment
    it succeeds, keyed by an idempotency key so retries never double-fire.
    Recovery runs compensations in reverse order.

Repair ladder (the "3-strike rule" that keeps throughput up):
    strike 1 -> retry with same model + the failure evidence injected
    strike 2 -> retry with a different/stronger model (swap)
    strike 3 -> stop autonomy, escalate to operator (no infinite loop)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class RepairAction(str, Enum):
    RETRY_SAME = "retry_same"
    RETRY_SWAP_MODEL = "retry_swap_model"
    ESCALATE = "escalate"


@dataclass
class Checkpoint:
    label: str
    ref: str                  # git SHA / stash id / snapshot id
    ts: float = field(default_factory=time.time)


@dataclass
class Compensation:
    """Registered when an irreversible side effect SUCCEEDS. Reverse it on failure."""
    side_effect: str          # e.g. "db_migrate:0042"
    idempotency_key: str      # dedupe so we never compensate/redo twice
    undo: Callable[[], None]  # the compensating action
    note: str = ""
    done: bool = False
    task_id: str = ""         # owning task; lets recovery unwind one task's effects


@dataclass
class CompensationReport:
    done: list[str] = field(default_factory=list)            # side effects undone
    failed: dict[str, str] = field(default_factory=dict)     # idem key -> error


class CompensationError(RuntimeError):
    """One or more compensations raised. All were still attempted."""

    def __init__(self, report: CompensationReport):
        super().__init__(f"compensation failed: {report.failed}")
        self.report = report


class RecoveryManager:
    def __init__(self, max_strikes: int = 3):
        self.max_strikes = max_strikes
        self.checkpoints: list[Checkpoint] = []
        self.compensations: list[Compensation] = []
        self._idem_seen: set[str] = set()

    # ---- code-state checkpoints ---------------------------------------
    def checkpoint(self, label: str, ref: str) -> Checkpoint:
        cp = Checkpoint(label=label, ref=ref)
        self.checkpoints.append(cp)
        return cp

    def last_checkpoint(self) -> Optional[Checkpoint]:
        return self.checkpoints[-1] if self.checkpoints else None

    # ---- external-state compensations (saga) --------------------------
    def register_compensation(self, comp: Compensation) -> bool:
        """Idempotent registration. Returns False if this side effect was already seen."""
        if comp.idempotency_key in self._idem_seen:
            return False
        self._idem_seen.add(comp.idempotency_key)
        self.compensations.append(comp)
        return True

    def compensate(self, task_id: Optional[str] = None) -> CompensationReport:
        """Run un-done compensations in reverse order, behind a fault barrier.

        task_id: only unwind that task's side effects (None = every task).
        A compensation that raises is recorded in `failed` and left un-done so an
        operator can retry it; the remaining compensations still run. One broken
        undo must never strand every other side effect.
        """
        report = CompensationReport()
        for comp in reversed(self.compensations):
            if comp.done or (task_id is not None and comp.task_id != task_id):
                continue
            try:
                comp.undo()
            except Exception as e:  # noqa: BLE001 - fault barrier
                report.failed[comp.idempotency_key] = f"{type(e).__name__}: {e}"
                continue
            comp.done = True
            report.done.append(comp.side_effect)
        return report

    def compensate_all(self) -> list[str]:
        """Unwind every task's side effects. Returns labels compensated.

        Every compensation is attempted; if any raised, CompensationError is
        raised afterwards carrying the full report.
        """
        report = self.compensate()
        if report.failed:
            raise CompensationError(report)
        return report.done

    # ---- repair ladder ------------------------------------------------
    def next_action(self, strikes: int) -> RepairAction:
        # strikes is always post-increment (1, 2, 3...) when called from _strike()
        if strikes == 1:
            return RepairAction.RETRY_SAME
        if strikes == 2:
            return RepairAction.RETRY_SWAP_MODEL
        return RepairAction.ESCALATE

    def exhausted(self, strikes: int) -> bool:
        return strikes >= self.max_strikes
