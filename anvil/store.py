"""
ANVIL mission store: the execution CONTRACT as on-disk artifacts.

The long vibecoding prompt is treated as source code. COMPILE emits a contract;
the loop executes the contract, never the raw prompt. Layout (`.mission/`):

  ORIGINAL_REQUEST.md   immutable, hashed at intake; never edited
  MISSION.md            distilled goal
  SCOPE.md              in/out of scope + change-control rule
  PLAN.graph.json       task DAG + locked acceptance hashes (the seal)
  CONTEXT_BUDGET.yaml   always-load vs JIT-retrieve rules (curation, anti context-rot)
  TOOL_POLICY.yaml      allowlists + privileged tools + elevation
  STATE.json            phase + per-task status (machine-owned, not in the model)
  ASSUMPTIONS.md        recorded safe-default decisions (ambiguity policy)
  MEMORY.md             durable cross-session memory (read at session start)
  WORKSTATE.md          volatile current-session scratch
  LEDGER.jsonl          hash-chained truth (see ledger.py)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .schemas import Phase, Task, TaskStatus


@dataclass
class Contract:
    mission: str
    scope_in: list[str]
    scope_out: list[str]
    tasks: list[Task]
    acceptance_locks: dict[str, str] = field(default_factory=dict)  # task_id -> locked hash
    context_budget: dict[str, Any] = field(default_factory=dict)


class MissionStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.dir = self.root / ".mission"
        self.dir.mkdir(parents=True, exist_ok=True)

    # ---- paths ----
    @property
    def ledger_path(self) -> Path: return self.dir / "LEDGER.jsonl"
    @property
    def log_dir(self) -> Path: return self.dir / "logs"
    @property
    def state_path(self) -> Path: return self.dir / "STATE.json"
    @property
    def plan_path(self) -> Path: return self.dir / "PLAN.graph.json"
    @property
    def request_path(self) -> Path: return self.dir / "ORIGINAL_REQUEST.md"
    @property
    def memory_path(self) -> Path: return self.dir / "MEMORY.md"
    @property
    def assumptions_path(self) -> Path: return self.dir / "ASSUMPTIONS.md"

    # ---- intake: freeze the request, immutable + hashed ----
    def freeze_request(self, text: str) -> str:
        if self.request_path.exists():
            existing = self.request_path.read_text(encoding="utf-8")
            return hashlib.sha256(existing.encode()).hexdigest()
        self.request_path.write_text(text, encoding="utf-8")
        # make it read-only on disk as a belt-and-suspenders signal
        try:
            self.request_path.chmod(0o444)
        except OSError:
            pass
        return hashlib.sha256(text.encode()).hexdigest()

    def request_hash(self) -> Optional[str]:
        if not self.request_path.exists():
            return None
        return hashlib.sha256(self.request_path.read_text(encoding="utf-8").encode()).hexdigest()

    # ---- contract persistence ----
    def save_contract(self, c: Contract) -> None:
        (self.dir / "MISSION.md").write_text(f"# Mission\n\n{c.mission}\n", encoding="utf-8")
        (self.dir / "SCOPE.md").write_text(
            "# Scope\n\n## In scope\n" + "\n".join(f"- {s}" for s in c.scope_in) +
            "\n\n## Out of scope\n" + "\n".join(f"- {s}" for s in c.scope_out) +
            "\n\n## Change control\n- Anything not listed In scope requires explicit "
            "operator approval and a new contract revision before work proceeds.\n",
            encoding="utf-8",
        )
        plan = {
            "mission": c.mission,
            "scope_in": c.scope_in,
            "scope_out": c.scope_out,
            "context_budget": c.context_budget,
            "acceptance_locks": c.acceptance_locks,
            "tasks": [t.to_dict() for t in c.tasks],
        }
        self.plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")

    def load_contract(self) -> Contract:
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        return Contract(
            mission=plan["mission"],
            scope_in=plan.get("scope_in", []),
            scope_out=plan.get("scope_out", []),
            tasks=[Task.from_dict(t) for t in plan.get("tasks", [])],
            acceptance_locks=plan.get("acceptance_locks", {}),
            context_budget=plan.get("context_budget", {}),
        )

    # ---- state (machine-owned, not the model's memory) ----
    def save_state(self, phase: Phase, tasks: list[Task]) -> None:
        self.state_path.write_text(json.dumps({
            "phase": phase.value,
            "tasks": {t.id: t.status.value for t in tasks},
            "strikes": {t.id: t.strikes for t in tasks},
        }, indent=2), encoding="utf-8")

    def load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"phase": Phase.INTAKE.value, "tasks": {}, "strikes": {}}
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    # ---- durable memory (cross-session) ----
    def append_memory(self, line: str) -> None:
        with self.memory_path.open("a", encoding="utf-8") as f:
            f.write(line.rstrip() + "\n")

    def read_memory(self) -> str:
        return self.memory_path.read_text(encoding="utf-8") if self.memory_path.exists() else ""

    # ---- ambiguity / assumption log ----
    def record_assumption(self, question: str, decision: str, reversible: bool) -> None:
        with self.assumptions_path.open("a", encoding="utf-8") as f:
            f.write(f"- Q: {question}\n  decision: {decision}\n  reversible: {reversible}\n")
