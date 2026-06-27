from anvil import PolicyEngine, Risk, Task, ToolPolicy, ToolCall


def _task(**kw):
    base = dict(id="t1", title="x", tools=["edit", "run_tests"], paths=["src/*"])
    base.update(kw)
    return Task(**base)


def test_tool_allowlist_blocks_unlisted_tool():
    pe = PolicyEngine()
    d = pe.decide(ToolCall(tool="curl"), _task())
    assert not d.allowed and "allowlist" in d.reason


def test_scope_guard_blocks_out_of_scope_path():
    pe = PolicyEngine()
    d = pe.decide(ToolCall(tool="edit", paths=["/etc/passwd"]), _task())
    assert not d.allowed and "scope" in d.reason


def test_scope_guard_allows_in_scope_path():
    pe = PolicyEngine()
    d = pe.decide(ToolCall(tool="edit", paths=["src/app.py"]), _task())
    assert d.allowed


def test_irreversible_requires_approval():
    pe = PolicyEngine()
    # 'delete' is irreversible but NOT privileged -> isolates the risk gate from
    # the credential wall (which fires first for prod tools like 'deploy').
    t = _task(tools=["delete"])
    d = pe.decide(ToolCall(tool="delete"), t)
    assert not d.allowed and d.requires_approval


def test_privileged_irreversible_hits_credential_wall_first():
    pe = PolicyEngine()  # not elevated
    t = _task(tools=["deploy"])
    d = pe.decide(ToolCall(tool="deploy"), t)
    # prod tool from a dev-isolated session is denied outright, not merely deferred
    assert not d.allowed and not d.requires_approval and "prod" in d.reason


def test_credential_wall_blocks_prod_without_elevation():
    pe = PolicyEngine(ToolPolicy(), elevated=False)
    t = _task(tools=["db_write_prod"])
    d = pe.decide(ToolCall(tool="db_write_prod"), t)
    assert not d.allowed and "prod" in d.reason


def test_no_declared_paths_means_no_filesystem():
    pe = PolicyEngine()
    t = _task(paths=[])
    d = pe.decide(ToolCall(tool="edit", paths=["src/app.py"]), t)
    assert not d.allowed


def test_path_traversal_blocked():
    """src/../secret.txt must not bypass the src/* scope guard."""
    pe = PolicyEngine()
    d = pe.decide(ToolCall(tool="edit", paths=["src/../secret.txt"]), _task())
    assert not d.allowed, "traversal path should be denied"


def test_double_dot_escape_blocked():
    """../../etc/passwd must be denied even though task allows src/*."""
    pe = PolicyEngine()
    d = pe.decide(ToolCall(tool="edit", paths=["../../etc/passwd"]), _task())
    assert not d.allowed


def test_normalized_sibling_path_allowed():
    """src/sub/../sibling.py normalizes to src/sibling.py which IS in scope."""
    pe = PolicyEngine()
    d = pe.decide(ToolCall(tool="edit", paths=["src/sub/../sibling.py"]), _task())
    assert d.allowed, "legitimate intra-scope traversal should be allowed"


def test_empty_tools_list_denies_all():
    """task.tools=[] must be fail-closed — no tool call is permitted."""
    pe = PolicyEngine()
    t = _task(tools=[])
    d = pe.decide(ToolCall(tool="edit", paths=["src/a.py"]), t)
    assert not d.allowed, "empty tool list should deny everything"


def test_task_with_no_tools_field_denies_all():
    """tools=None / empty is fail-closed regardless of how it arrives."""
    pe = PolicyEngine()
    t = Task(id="t1", title="x", tools=[], paths=["src/*"], acceptance=[])
    d = pe.decide(ToolCall(tool="curl"), t)
    assert not d.allowed
