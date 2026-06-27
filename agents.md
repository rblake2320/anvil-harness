# Wiring real agents to ANVIL

ANVIL drives two adapters. Both are structural subtypes (Protocol); no base class needed.

## AgentAdapter

```python
class AgentAdapter(Protocol):
    def plan_calls(self, task: Task) -> list[ToolCall]:
        """Return the calls the executor wants to make for this task.
        The harness gates every call through PolicyEngine before anything runs.
        Must be side-effect free — called once per task execution attempt."""
        ...

    def perform(self, task: Task, call: ToolCall) -> dict:
        """Execute one gated call and return results.

        Return dict may include:
          ok            bool   — success / failure
          input_tokens  int    — charged to the circuit breaker
          output_tokens int    — charged to the circuit breaker
          cost          float  — USD charged to the circuit breaker
          idempotency_key str  — deduplicate safe replays
          undo          callable — registered as saga compensation for IRREVERSIBLE tasks
        """
        ...
```

## VerifierAdapter

```python
class VerifierAdapter(Protocol):
    def run_check(self, task: Task, check: AcceptanceCheck) -> Evidence:
        """Run one acceptance check and return Evidence.
        Must be a DIFFERENT seat than the AgentAdapter — executor must not grade itself.
        For behavioral checks: use CommandVerifier (real exit codes, real test runner).
        For judgment checks: use a second model prompted to evaluate the evidence."""
        ...
```

## Implementing ClaudeCodeAgent

```python
import anthropic

class ClaudeCodeAgent:
    def __init__(self, client: anthropic.Anthropic, model: str = "claude-opus-4-8"):
        self.client = client
        self.model = model

    # Compact system prompt used for every plan_calls() call.
    # Kept short deliberately: this text is paid for on every task invocation,
    # and the savings compound across a long run (Caveman principle: every token
    # in the system prompt is paid N times, where N = number of tasks).
    PLAN_SYSTEM = (
        "You are the executor. Before proposing any tool call, climb this ladder:\n"
        "1. Does this call need to happen? If no — skip it.\n"
        "2. Does an already-running process / cached result cover it? Use that.\n"
        "3. Does the platform / stdlib handle it natively? Use that.\n"
        "4. Can it be one read-only call instead of a write? Do that.\n"
        "5. Only then: propose the minimum ToolCall that actually moves the task forward.\n"
        "Return ONLY a JSON array of ToolCall objects. No prose."
    )

    def plan_calls(self, task: Task) -> list[ToolCall]:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self.PLAN_SYSTEM,
            messages=[{"role": "user", "content": task.title}],
        )
        # Parse resp.content into ToolCall list — adapt to your schema.
        return _parse_tool_calls(resp, task.id)

    def perform(self, task: Task, call: ToolCall) -> dict:
        import dataclasses, json
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=8192,
            system="Execute the following tool call exactly.",
            messages=[{"role": "user", "content": json.dumps(dataclasses.asdict(call))}],
        )
        return {
            "ok": True,
            "input_tokens": resp.usage.input_tokens,
            "output_tokens": resp.usage.output_tokens,
            "cost": _cost(resp.usage, self.model),
        }
```

Token usage from `resp.usage` flows directly into the circuit breaker via the return
dict. **Never charge tokens outside `perform()`** — replayed idempotent calls must
return zero usage.

### Token cost compounds — keep system prompts short

Every token in `PLAN_SYSTEM` is paid once per `plan_calls()` invocation. A 100-task
run with a 500-token system prompt = 50,000 tokens of pure overhead before the executor
writes a single line. Rules of thumb:

- Strip filler, articles, hedging, and examples from system prompts — keep directives only
- Put long context (scope, background, constraints) in the `task.title` / task payload,
  not the static system prompt — the harness already sends the task; don't repeat it
- For multi-model swap (strike 2), the fallback model's system prompt can be even more
  compressed since it's a recovery path, not the happy path

## CommandVerifier

The built-in `CommandVerifier` runs a shell command and returns `Evidence`:

```python
from anvil import CommandVerifier, AcceptanceCheck

# CommandVerifier reads check.spec["cmd"] for the shell command to run.
verifier = CommandVerifier(cwd="/path/to/repo", timeout=60)

# When compiling tasks, put the command in spec["cmd"]:
check = AcceptanceCheck(
    id="c1", description="tests pass", kind="command",
    spec={"cmd": "pytest tests/ -q", "expect_exit": 0},
    authored_by="qa",
)
```

Return code matches `spec["expect_exit"]` (default 0) → passed.
Optional `spec["expect_substring"]` checks stdout+stderr for a string.
A non-zero exit or missing substring → failed with combined output as detail.

## approval_fn

Lifecycle's default `approval_fn` is `lambda task, call: False` (fail-safe deny).
Wire a real HITL channel:

```python
def slack_approval(task: Task, call: ToolCall) -> bool:
    msg = f"ANVIL approval request\ntask={task.id}  tool={call.tool}"
    response = slack_client.chat_postMessage(channel="#ops", text=msg)
    # block until human reacts with :white_check_mark: or :x:
    return wait_for_reaction(response["ts"])

lc = Lifecycle(store, agent, verifier, approval_fn=slack_approval)
```

The grant (or denial) is recorded in the hash-chained ledger as a non-repudiable event.

## Signed ledger (HMAC)

```python
import secrets
key = secrets.token_bytes(32)   # store in your secrets manager, not in code
lc = Lifecycle(store, agent, verifier, signing_key=key)
```

Pass the same key to `Lifecycle` on every resumed run for the same mission. To audit:

```python
from anvil import Ledger, MissionStore
ok, reason = Ledger(MissionStore(root).ledger_path, signing_key=key).verify()
```

Auditing without the key on a signed ledger will report TAMPERED. Use the CLI
`anvil audit` only for unsigned (dev) runs.

## Token cost rollup per task

```python
summary = lc.log_router.token_summary_by_task()
# {"t1": {"input_tokens": 1200, "output_tokens": 400, "cost": 0.018}, ...}
for task_id, usage in summary.items():
    print(f"{task_id}: ${usage['cost']:.4f}  in={usage['input_tokens']} out={usage['output_tokens']}")
```

Reads the TOKEN channel and aggregates `token_charged` events by `task_id`. Useful
for cost attribution after a multi-task run and for feeding back into budget tuning.

## verify-logs

After any completed or halted run, check channel integrity:

```
anvil verify-logs /path/to/mission/root
```

Each channel's rolling SHA-256 hash is replayed from the JSONL file and compared
against the `channel_digest` anchors committed to the ledger at run close. Exit 0 = all
clean; exit 1 = ledger tampered, channel truncated, or channel payload mutated.

Anchor fires automatically at `HALTED` (scope violation, budget trip, blocked) and in
`learn()` (clean close). If a run was interrupted mid-flight (process kill), no anchor
will exist; `verify-logs` reports that and exits 0 (absence of anchor ≠ tamper).

## PTY interception (enforcement layer)

The `PolicyEngine.decide()` call in `lifecycle.py` is a cooperating adapter — the agent
has to call `perform()` for the gate to apply. For adversarial containment, intercept at
the execution surface:

```python
# In your PTY controller / sandboxed subprocess wrapper:
from anvil import PolicyEngine, ToolCall

policy = PolicyEngine(tool_policy, elevated=False)
pty_interceptor = lambda tool, args, paths: policy.decide(
    ToolCall(tool=tool, paths=paths, task_id=current_task_id)
)
# Block the syscall if pty_interceptor returns DENY
```

This means a denied call physically cannot execute — not just "ANVIL won't log it."
Run the cooperating adapter for telemetry; run the PTY interceptor for containment.

## Multi-model swap on strike 2

`RecoveryManager` signals `RETRY_SWAP_MODEL` on the second strike. Wire it:

```python
class SwappingAgent:
    def __init__(self, primary, fallback):
        self.primary = primary
        self.fallback = fallback
        self._use_fallback = False

    def plan_calls(self, task):
        return (self.fallback if self._use_fallback else self.primary).plan_calls(task)

    def perform(self, task, call):
        return (self.fallback if self._use_fallback else self.primary).perform(task, call)

# In a subclass of Lifecycle, override _strike() to flip the flag on RETRY_SWAP_MODEL.
```

## Resuming a run

```python
from anvil import Lifecycle, MissionStore

store = MissionStore(root)
# recover_trace_id() reads the ledger and returns the trace_id from the first
# intake_frozen event — no manual ledger parsing needed.
prior_trace_id = store.recover_trace_id()   # None if run never reached intake

lc = Lifecycle(store, agent, verifier, trace_id=prior_trace_id)
state = store.load_state()
contract = store.load_contract()
lc.contract = contract
lc.phase = Phase[state["phase"]]
# Continue from the last known phase
lc.execute_all()
```

Passing `trace_id=` links the resumed segment's spans to the original trace in any
aggregator that understands OpenTelemetry-style parent-child correlation.
