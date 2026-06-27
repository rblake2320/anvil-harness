"""
ANVIL budget + circuit breaker.

Long-horizon runs fail open without hard ceilings: the loop spins, tokens burn,
nothing converges. This module makes budgets *enforced facts*, not prompt advice.

Three ceilings, any of which trips the breaker:
  * steps  - total agent actions across the run
  * seconds- wall-clock
  * cost   - estimated $ (you feed per-call cost; harness sums)
Plus a per-task strike ceiling handled in recovery.py.

When tripped, the breaker OPENS: every subsequent gated action is denied and the
lifecycle moves to HALTED for operator attention. Fail closed, not open.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Budget:
    max_steps: int = 200
    max_seconds: float = 3600.0
    max_cost: float = 25.0
    max_input_tokens: int = 1_000_000
    max_output_tokens: int = 100_000


@dataclass
class CircuitBreaker:
    budget: Budget = field(default_factory=Budget)
    steps: int = 0
    cost: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    started_at: float = field(default_factory=time.time)
    open: bool = False
    reason: Optional[str] = None

    def charge(self, steps: int = 1, cost: float = 0.0,
               input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.steps += steps
        self.cost += cost
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens

    def check(self) -> tuple[bool, Optional[str]]:
        """Returns (ok, reason). Once open, stays open (manual reset required)."""
        if self.open:
            return False, self.reason
        if self.steps > self.budget.max_steps:
            return self._trip(f"step budget exceeded ({self.steps}/{self.budget.max_steps})")
        elapsed = time.time() - self.started_at
        if elapsed > self.budget.max_seconds:
            return self._trip(f"time budget exceeded ({elapsed:.0f}s/{self.budget.max_seconds:.0f}s)")
        if self.cost > self.budget.max_cost:
            return self._trip(f"cost budget exceeded (${self.cost:.2f}/${self.budget.max_cost:.2f})")
        if self.input_tokens > self.budget.max_input_tokens:
            return self._trip(f"input token budget exceeded ({self.input_tokens}/{self.budget.max_input_tokens})")
        if self.output_tokens > self.budget.max_output_tokens:
            return self._trip(f"output token budget exceeded ({self.output_tokens}/{self.budget.max_output_tokens})")
        return True, None

    def _trip(self, reason: str) -> tuple[bool, Optional[str]]:
        self.open = True
        self.reason = reason
        return False, reason

    def reset(self) -> None:
        """Operator-only: clears the breaker after intervention."""
        self.open = False
        self.reason = None
        self.started_at = time.time()
