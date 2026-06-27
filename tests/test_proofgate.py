from anvil import AcceptanceCheck, ProofGate, Risk, SimulatedVerifier, Task


def _check(cid, author="qa"):
    return AcceptanceCheck(id=cid, description="d", kind="behavior",
                           spec={"k": cid}, authored_by=author)


def test_no_acceptance_cannot_complete():
    gate = ProofGate()
    t = Task(id="t", title="x", acceptance=[])
    locked = gate.lock(t)
    res = gate.evaluate(t, locked, SimulatedVerifier({}))
    assert not res.ok and "no acceptance" in res.reason


def test_failing_check_blocks_completion():
    gate = ProofGate()
    t = Task(id="t", title="x", acceptance=[_check("c1"), _check("c2")])
    locked = gate.lock(t)
    res = gate.evaluate(t, locked, SimulatedVerifier({"c1": True, "c2": False}))
    assert not res.ok and "c2" in res.reason


def test_all_pass_completes():
    gate = ProofGate()
    t = Task(id="t", title="x", acceptance=[_check("c1"), _check("c2")])
    locked = gate.lock(t)
    res = gate.evaluate(t, locked, SimulatedVerifier({"c1": True, "c2": True}))
    assert res.ok


def test_weakened_acceptance_after_lock_is_tamper():
    gate = ProofGate()
    t = Task(id="t", title="x", acceptance=[_check("c1"), _check("c2")])
    locked = gate.lock(t)
    # executor quietly drops the hard check, leaving an easy one it can pass
    t.acceptance = [_check("c1")]
    res = gate.evaluate(t, locked, SimulatedVerifier({"c1": True}))
    assert not res.ok and "tamper" in res.reason


def test_high_risk_self_authored_tests_rejected():
    gate = ProofGate(code_author="executor")
    t = Task(id="t", title="x", risk=Risk.IRREVERSIBLE,
             acceptance=[_check("c1", author="executor")])
    locked = gate.lock(t)
    res = gate.evaluate(t, locked, SimulatedVerifier({"c1": True}))
    assert not res.ok and "independent" in res.reason
