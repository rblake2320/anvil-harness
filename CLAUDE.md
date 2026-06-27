# ANVIL — Claude Code working instructions

## Quick start

```
pip install -e .
pytest -q                              # 67 tests; all must pass before any commit
python -m anvil.cli demo /tmp/run      # full offline cradle-to-grave
python -m anvil.cli verify-logs /tmp/run
```

## Before adding anything to ANVIL

Climb this ladder. Stop at the first rung that holds.

1. Does this need to exist? → no: skip it (YAGNI)
2. Does stdlib / a built-in cover it? → use that
3. Does an existing ANVIL module already do it? → extend that
4. Can it be one function / one line? → do that
5. Only then: write the minimum code that actually works, with tests

This applies equally to new modules, new EventTypes, new CLI subcommands, new fields
on existing dataclasses, and new test helpers.

## Architecture law: the harness owns truth

The fundamental invariant is: **the harness is the controller; the model only proposes.**
Every control (gate, policy, budget, verifier, recovery) is mechanical code, never a
prompt instruction. Never refactor in a way that lets the model skip a gate.

## Module map

```
schemas.py    — Task, ToolCall, EventType, Phase, AcceptanceCheck, Risk
ledger.py     — Hash-chained LEDGER.jsonl (single source of truth)
budget.py     — Budget + CircuitBreaker (steps / cost / time / tokens)
policy.py     — PolicyEngine: tool allowlist + scope guard + credential wall
proofgate.py  — ProofGate: locked acceptance hashes, independent verifier, tamper detection
recovery.py   — RecoveryManager: saga compensations, checkpoints, 3-strike repair
store.py      — MissionStore: on-disk artifacts (.mission/), Contract dataclass
adapters.py   — AgentAdapter + VerifierAdapter protocols, SimulatedAgent, SimulatedVerifier
lifecycle.py  — Lifecycle: the main orchestrator, wires all of the above
log.py        — 14-channel structured logging: LogRouter, ChannelWriter, TraceContext
cli.py        — anvil demo/status/audit/ledger/verify-logs
```

## Logging: zero-call-site fan-out

Every `self._log(EventType.X, **kw)` in `lifecycle.py` fans out automatically — it
appends to the ledger AND calls `log_router.route()`. **Never** bypass `_log()` to
write to the ledger directly from lifecycle code.

- The **audit** channel is the Ledger; `LogRouter` never writes to it.
- `channel_digest` events are written by `LogRouter.anchor()` only — not in `EVENT_CHANNELS`.
- Redaction (`_redact()`) runs before fan-out in `route()` and `write()`. The ledger
  keeps the original. Do not add redaction to ledger paths.
- `_maybe_anchor()` is idempotent (one channel_digest per run). It fires at HALTED (inside
  `_set_phase`) and at the very end of `learn()`, after `_set_phase(DONE)`, so that the
  DONE PHASE_CHANGED event is included in the anchor. Do not call `anchor()` directly from
  lifecycle code, and do not move `_maybe_anchor()` before the final phase change in learn().

**Adding a new EventType**: add the string to `EventType` in `schemas.py`, then add the
routing entry in `EVENT_CHANNELS` in `log.py`. If it is an error/warning, add its level
to `EVENT_LEVELS`. Tests in `test_logging.py` will catch missing routing.

## Recovery: post-increment strike counts

`_strike()` increments `task.strikes` *before* calling `next_action(task.strikes)`.
Thresholds in `RecoveryManager.next_action()` are `1→RETRY_SAME`, `2→RETRY_SWAP_MODEL`,
`≥3→ESCALATE`. Do not change without updating `tests/test_recovery.py`.

## Adapter contract

`perform(task, call) -> dict` may return any of:

| key | type | meaning |
|-----|------|---------|
| `ok` | bool | success flag |
| `input_tokens` | int | tokens consumed; charges the circuit breaker |
| `output_tokens` | int | tokens generated; charges the circuit breaker |
| `cost` | float | USD cost; charges the circuit breaker |
| `idempotency_key` | str | deduplicate replays |
| `undo` | callable | registered as a saga compensation if task is `IRREVERSIBLE` |

Missing fields default to zero / no-op. Token charging happens **only inside
`_do_task()`** on the actual `agent.perform()` return value, never on the planning loop.

## CLI: ASCII-only

`cli.py` runs on Windows with cp1252. Use only printable ASCII — no `→ ✓ ✗ •` etc.

## Tests

```
pytest -q                    # full suite
pytest tests/test_logging.py # logging / digest-anchor / redaction
pytest tests/test_lifecycle.py
pytest -k tamper             # tamper-detection tests only
```

All 67 tests must pass. Do not mark tests `xfail` to paper over failures.
