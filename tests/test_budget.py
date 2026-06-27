import time

from anvil import Budget, CircuitBreaker


def test_step_budget_trips():
    cb = CircuitBreaker(Budget(max_steps=3, max_seconds=1e9, max_cost=1e9))
    for _ in range(3):
        cb.charge(steps=1)
        assert cb.check()[0]
    cb.charge(steps=1)
    ok, reason = cb.check()
    assert not ok and "step" in reason


def test_cost_budget_trips():
    cb = CircuitBreaker(Budget(max_steps=1e9, max_seconds=1e9, max_cost=0.50))
    cb.charge(cost=0.60)
    ok, reason = cb.check()
    assert not ok and "cost" in reason


def test_time_budget_trips():
    cb = CircuitBreaker(Budget(max_steps=1e9, max_seconds=0.01, max_cost=1e9))
    time.sleep(0.02)
    ok, reason = cb.check()
    assert not ok and "time" in reason


def test_breaker_stays_open_until_reset():
    cb = CircuitBreaker(Budget(max_steps=0))
    cb.charge(steps=1)
    assert not cb.check()[0]
    # even a fresh-looking check stays open
    assert not cb.check()[0]
    cb.reset()
    cb.steps = 0
    assert cb.check()[0]
