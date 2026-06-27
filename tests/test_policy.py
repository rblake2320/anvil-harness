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
