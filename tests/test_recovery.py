from anvil import RecoveryManager, Compensation, RepairAction


def test_strike_ladder():
    # next_action() receives post-increment strike counts (1, 2, 3...) from _strike()
    rm = RecoveryManager(max_strikes=3)
    assert rm.next_action(1) == RepairAction.RETRY_SAME
    assert rm.next_action(2) == RepairAction.RETRY_SWAP_MODEL
    assert rm.next_action(3) == RepairAction.ESCALATE
    assert not rm.exhausted(2)
    assert rm.exhausted(3)


def test_compensation_is_idempotent():
    rm = RecoveryManager()
    calls = []
    c = Compensation("db_migrate", "idem-1", undo=lambda: calls.append("undo"))
    assert rm.register_compensation(c) is True
    # same idempotency key -> not registered twice
    dup = Compensation("db_migrate", "idem-1", undo=lambda: calls.append("dup"))
    assert rm.register_compensation(dup) is False
    rm.compensate_all()
    assert calls == ["undo"]


def test_compensations_run_in_reverse_order():
    rm = RecoveryManager()
    order = []
    rm.register_compensation(Compensation("a", "k1", undo=lambda: order.append("a")))
    rm.register_compensation(Compensation("b", "k2", undo=lambda: order.append("b")))
    rm.register_compensation(Compensation("c", "k3", undo=lambda: order.append("c")))
    done = rm.compensate_all()
    assert order == ["c", "b", "a"]
    assert done == ["c", "b", "a"]
    # second call is a no-op (all marked done)
    assert rm.compensate_all() == []


def test_checkpoints_track_latest():
    rm = RecoveryManager()
    rm.checkpoint("baseline", "sha0")
    rm.checkpoint("task1", "sha1")
    assert rm.last_checkpoint().ref == "sha1"
