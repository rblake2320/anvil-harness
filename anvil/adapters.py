"""
ANVIL adapters: the seam between the governed harness and the (replaceable) model.

The harness is the controller and owns truth. It NEVER is the model. It talks to:

  * AgentAdapter   - proposes tool calls / does work for a task (the "executor").
  * VerifierAdapter- runs acceptance checks and returns Evidence (the "judge").
                     Must be a different seat than the executor.

Wire your real stack by implementing these two Protocols:
  - Claude Code / Anthropic API executor -> AgentAdapter
  - a behavioral test runner / second model -> VerifierAdapter

The simulated implementations below are deterministic so the test suite can
prove the harness's safety invariants without a network or a live model.
"""
from __future__ import annotations

import subprocess
from typing import Callable, Optional, Protocol

from .schemas import AcceptanceCheck, Evidence, Task, ToolCall


class AgentAdapter(Protocol):
    def plan_calls(self, task: Task) -> list[ToolCall]: ...
    def perform(self, task: Task, call: ToolCall) -> dict: ...


class VerifierAdapter(Protocol):
    def run_check(self, task: Task, check: AcceptanceCheck) -> Evidence: ...


class CommandVerifier:
    """Real verifier for `kind == "command"` checks: runs a shell command in a
    sandbox dir and proves it by exit code / expected substring. Independent of
    whatever the executor claims it did."""

    def __init__(self, cwd: Optional[str] = None, timeout: int = 120):
        self.cwd = cwd
        self.timeout = timeout

    def run_check(self, task: Task, check: AcceptanceCheck) -> Evidence:
        if check.kind != "command":
            return Evidence(task.id, check.id, ok=False,
                            detail=f"CommandVerifier cannot handle kind={check.kind}")
        cmd = check.spec.get("cmd")
        expect_exit = check.spec.get("expect_exit", 0)
        expect_sub = check.spec.get("expect_substring")
        try:
            proc = subprocess.run(cmd, shell=True, cwd=self.cwd, capture_output=True,
                                  text=True, timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            return Evidence(task.id, check.id, ok=False, detail=f"exec error: {e}")
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == expect_exit
        if ok and expect_sub is not None:
            ok = expect_sub in out
        return Evidence(task.id, check.id, ok=ok,
                        detail=f"exit={proc.returncode}",
                        artifact={"cmd": cmd, "exit": proc.returncode, "output": out[-4000:]})


# ---- simulated seats for the test suite / offline demo -----------------

class SimulatedAgent:
    """Deterministic executor. `behavior` lets tests script success/failure and
    even a scope-violating or test-tampering agent."""

    def __init__(self, calls_for: Callable[[Task], list[ToolCall]],
                 perform_fn: Optional[Callable[[Task, ToolCall], dict]] = None):
        self._calls_for = calls_for
        self._perform = perform_fn or (lambda t, c: {"ok": True})

    def plan_calls(self, task: Task) -> list[ToolCall]:
        return self._calls_for(task)

    def perform(self, task: Task, call: ToolCall) -> dict:
        return self._perform(task, call)


class SimulatedVerifier:
    """Deterministic judge. `verdicts[check_id] -> bool` decides each check."""

    def __init__(self, verdicts: dict[str, bool]):
        self.verdicts = verdicts

    def run_check(self, task: Task, check: AcceptanceCheck) -> Evidence:
        ok = self.verdicts.get(check.id, False)
        return Evidence(task.id, check.id, ok=ok,
                        detail="simulated", artifact={"simulated": True})
