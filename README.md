# ANVIL — governed, proof-gated execution harness for long-horizon agent work

ANVIL is the harness the three-model council converged on, built as runnable code.
It treats a long vibecoding prompt as **source to be compiled**, not a script to be
executed, and it makes every reliability control a **mechanical fact** (a gate, a
policy, an artifact, a verifier, a recovery path) rather than advice inside a prompt.

Core stance: **the harness is the controller and owns truth. It is never the model.**
The model proposes; the harness disposes. The executor's narration is never
authoritative — only what is committed to the hash-chained ledger counts.

```
pip install -e .                         # stdlib-only core; nothing to vet, runs air-gapped
python -m anvil.cli demo /tmp/run        # full offline cradle-to-grave run
python -m anvil.cli status /tmp/run      # phase + per-task state
python -m anvil.cli audit  /tmp/run      # verify the tamper-evident ledger
python -m anvil.cli ledger /tmp/run      # print the event stream
python -m anvil.cli verify-logs /tmp/run # check channel digests against ledger anchors
pytest -q                                # 67 tests prove the safety invariants
```

## The lifecycle (cradle to grave)

| Phase | What it enforces |
|-------|------------------|
| **intake** | Freeze + hash `ORIGINAL_REQUEST.md` (immutable, chmod 0444). Load durable `MEMORY.md`. |
| **baseline** | Capture world/repo state; lay the first rollback checkpoint. |
| **compile** | Turn the request into a `Contract` (DAG + scope + acceptance). **Lock** each task's acceptance hash — the seal that defeats test-gaming. |
| **review** | Gate the *plan*: every task has acceptance; high-risk tasks have independent (non-executor) test authorship; deps resolve; scope is explicit. |
| **execute** | DAG-ordered, one ready leaf at a time. Every tool call passes the policy gate. Budget checked on every charge. |
| **verify** | Independent proof gate against the locked acceptance. **No proof = not done.** Tampered acceptance ⇒ rejected. |
| **release** | Irreversible actions run only after a recorded, hash-chained human approval, registering a compensation the instant a side effect succeeds. |
| **monitor** | Post-release hook (recorded). |
| **learn** | Final audit vs `ORIGINAL_REQUEST`; write durable `MEMORY.md`. |

## The invariants the tests prove (not assert)

1. **Tamper-evidence** — any edit/reorder/truncation of a past ledger entry breaks
   verification of all later entries (`test_ledger.py`). Optional HMAC/PKA signing
   stops an attacker who can write the file but lacks the key.
2. **No fake completion** — a task cannot reach `DONE` without an *independent*
   verifier accepting evidence; the executor never grades itself (`test_proofgate.py`).
3. **No test-gaming** — acceptance criteria are hashed and locked at compile; if the
   executor weakens them before verify, the gate returns `ACCEPTANCE_TAMPERED`.
4. **No scope creep in flight** — the scope guard runs on *every* tool call, not just
   at plan review; an out-of-scope path is blocked and halts safely (`test_lifecycle.py`).
5. **No destructive action without a commit-point** — irreversible tools require a
   recorded human approval; default is fail-safe deny.
6. **Credential isolation** — prod tools are unreachable from a dev-isolated session;
   secrets live with the harness, never the agent.
7. **Bounded failure with a way forward** — 3-strike repair ladder (retry → swap model →
   escalate); code state rolls back via checkpoints; **external** side effects are
   undone via idempotent, reverse-order **compensations** (saga), because you cannot
   "restore a snapshot" to un-send a webhook or un-run a migration (`test_recovery.py`).
8. **Runaway containment** — step/time/cost circuit breaker trips closed and stays open
   until an operator resets (`test_budget.py`).

## Wiring your real stack

The harness drives two adapters (`anvil/adapters.py`):

```python
class AgentAdapter(Protocol):
    def plan_calls(self, task) -> list[ToolCall]: ...   # the executor (Claude Code / API)
    def perform(self, task, call) -> dict: ...

class VerifierAdapter(Protocol):
    def run_check(self, task, check) -> Evidence: ...    # the judge (test runner / 2nd model)
```

- **Executor** → wrap Claude Code or the Anthropic API. Have it emit `ToolCall`s; the
  harness gates them. Never give it raw prod credentials.
- **Verifier** → a *different seat* than the executor. Use `CommandVerifier` for
  command/behavioral checks (real exit codes, real test runs), or a second model for
  judgment checks. On high-risk tasks the QA seat authors the failing tests first.
- **Approval** → pass `approval_fn=lambda task, call: ...` that surfaces a real HITL
  prompt (Slack, terminal, web). The grant is recorded in the ledger, non-repudiable.
- **Non-bypassable enforcement** → call `PolicyEngine.decide` from your
  `selfconnect-terminal` PTY interception so a denied call physically cannot exec. At
  the controller layer ANVIL governs a cooperating adapter; at the PTY layer it governs
  an adversarial one. This is the "enforce at the execution surface" layer.
- **Signed ledger** → pass `signing_key=` to `Lifecycle` to MAC-chain the ledger; drop
  in your PKA signer to match the GUMBO ledger model.

## What I added beyond the council transcript

The council covered compile/DAG/proof-gates/context-budget/tool-policy/verifier-
separation/saga/commit-point/credential-isolation/QA-first/memory/ambiguity. I wired
those, and added the controls that close the *remaining* gaps:

- **Locked acceptance hashes** — concrete defeat for "agent weakens its own tests."
- **In-flight scope guard** — scope creep caught per call, not only at plan review.
- **Idempotency keys on compensations** — retries never double-fire side effects.
- **Hard circuit breaker** — step/time/cost ceilings that fail closed.
- **Non-repudiable approvals** — every commit-point grant is a hash-chained ledger entry.
- **End-to-end audit** — `ledger.verify()` re-walks the chain; surfaced via `anvil audit`.
- **Fail-safe defaults** — deny approvals, deny prod tools, deny filesystem on tasks
  with no declared paths.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `anvil audit` says TAMPERED on a clean run | Ledger was signed; keyless audit can't verify the MAC | Audit with the same `signing_key`, or run unsigned. |
| Irreversible task halts immediately | No `approval_fn` wired ⇒ fail-safe deny | Pass a real `approval_fn`. |
| `deploy` denied even with approval | It's a privileged (prod) tool; session is dev-isolated | Set `PolicyEngine(elevated=True)` only in a session that legitimately holds prod creds. |
| Task loops then blocks | Strikes exhausted (3) | Inspect ledger `task_failed` reasons; fix the check or the agent. |
| Review rejects the plan | Missing acceptance, self-authored high-risk tests, or unknown dep | Add QA-authored checks; fix the DAG. |

## Next steps

1. Implement `ClaudeCodeAgent(AgentAdapter)` against your Claude Code MCP environment.
2. Implement `CommandVerifier` checks for your real acceptance criteria (exit codes,
   behavioral end-to-end flows), and a second-model judge for non-command checks.
3. Wire `approval_fn` to your real HITL channel.
4. Hook `PolicyEngine.decide` into `selfconnect-terminal` PTY interception.
5. Swap the SHA-256 ledger signer for your PKA signer (GUMBO parity).
6. Add a `monitor` adapter (post-release health checks) and feed failures back as new
   tasks.
