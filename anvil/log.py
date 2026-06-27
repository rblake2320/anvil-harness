"""
ANVIL structured logging: fan-out from the hash-chained audit ledger to 14
specialist log channels, each an append-only JSONL file under .mission/logs/.

Channel taxonomy (research-backed priority):

  Must-Have  : audit, error, security, access, trace
  Should-Have: perf, txn, change, dependency, agent, tool_call
  Nice-to-Have: token, quality, debug

Architecture: integrity by design
  The AUDIT channel is the existing hash-chained Ledger — tamper-evident and the
  canonical source of truth. The 13 specialist channels are plain JSONL: fast and
  aggregator-friendly, but by themselves repudiable.

  The gap is closed via digest-anchoring: at each terminal lifecycle event (DONE or
  HALTED), LogRouter.anchor(ledger) computes a rolling hash over each channel's
  entries and commits a `channel_digest` event to the ledger. Editing a channel
  file after that point breaks the comparison against its ledger-anchored hash.
  The ledger remains the single root of trust; the channels are cryptographically
  attested projections.

  Redaction: channel payloads are scrubbed for secret-shaped strings and key names
  before fan-out. The ledger (access-controlled, chained) retains the original.

Rolling hash per channel:
  H_0 = SHA256("channel:genesis")
  H_n = SHA256(H_{n-1} || "|" || json_line_n)

  where json_line_n is the exact JSON string written to disk (no trailing newline).
  This makes the channel verifiable entry-by-entry and detects insertion, deletion,
  reorder, and payload mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional


# ---- channel taxonomy -------------------------------------------------------

class LogChannel(str, Enum):
    AUDIT      = "audit"       # Must-Have : tamper-evident ledger (written by Ledger)
    ERROR      = "error"       # Must-Have : failures, exceptions, circuit trips, tamper
    SECURITY   = "security"    # Must-Have : threats, violations, tamper, denied actions
    ACCESS     = "access"      # Must-Have : auth, approval, permission events
    TRACE      = "trace"       # Must-Have : spans, distributed observability
    PERF       = "perf"        # Should   : timing, latency, circuit breaker
    TXN        = "txn"         # Should   : task and business lifecycle events
    CHANGE     = "change"      # Should   : contract changes, deployments, rollbacks
    DEPENDENCY = "dependency"  # Should   : external tool calls, results, latency
    AGENT      = "agent"       # Should   : model decisions, proposed calls
    TOOL_CALL  = "tool_call"   # Should   : every gated tool call (allowed + denied)
    TOKEN      = "token"       # Nice     : token usage and cost accounting
    QUALITY    = "quality"     # Nice     : evidence, evaluations, proof results
    DEBUG      = "debug"       # Nice     : developer traces, verbose state


class LogLevel(str, Enum):
    DEBUG    = "debug"
    INFO     = "info"
    WARN     = "warn"
    ERROR    = "error"
    CRITICAL = "critical"


# ---- fan-out map ------------------------------------------------------------
# Maps each EventType value to the specialist channels that receive it.
# AUDIT is always written by Ledger directly; it is NOT in this map.
# channel_digest is a meta-event committed by anchor(); also not in this map.

_C = LogChannel

EVENT_CHANNELS: dict[str, list[LogChannel]] = {
    "intake_frozen":       [_C.TRACE, _C.TXN],
    "baseline_captured":   [_C.TRACE, _C.CHANGE],
    "contract_compiled":   [_C.CHANGE, _C.TXN],
    "review_passed":       [_C.ACCESS, _C.CHANGE],
    "review_rejected":     [_C.ACCESS, _C.SECURITY, _C.ERROR],
    "phase_changed":       [_C.TRACE, _C.TXN],
    "task_started":        [_C.TXN, _C.TRACE],
    "task_done":           [_C.TXN, _C.TRACE],
    "task_failed":         [_C.ERROR, _C.TXN],
    "tool_call_allowed":   [_C.TOOL_CALL, _C.DEPENDENCY],
    "tool_call_denied":    [_C.SECURITY, _C.ACCESS, _C.TOOL_CALL],
    "scope_violation":     [_C.SECURITY, _C.ACCESS, _C.TOOL_CALL],
    "approval_requested":  [_C.ACCESS],
    "approval_granted":    [_C.ACCESS],
    "approval_denied":     [_C.SECURITY, _C.ACCESS],
    "evidence_recorded":   [_C.QUALITY],
    "proof_accepted":      [_C.QUALITY, _C.TXN],
    "proof_rejected":      [_C.ERROR, _C.QUALITY],
    "acceptance_tampered": [_C.SECURITY, _C.ERROR, _C.QUALITY],
    "checkpoint_made":     [_C.CHANGE],
    "rolled_back":         [_C.CHANGE, _C.TXN],
    "compensated":         [_C.CHANGE, _C.TXN],
    "budget_tripped":      [_C.PERF, _C.ERROR],
    "circuit_open":        [_C.PERF, _C.ERROR],
    "token_charged":       [_C.TOKEN, _C.TXN],
    "assumption_recorded": [_C.AGENT],
    "memory_written":      [_C.AGENT, _C.CHANGE],
}

EVENT_LEVELS: dict[str, str] = {
    "acceptance_tampered": LogLevel.CRITICAL.value,
    "review_rejected":     LogLevel.ERROR.value,
    "task_failed":         LogLevel.ERROR.value,
    "circuit_open":        LogLevel.ERROR.value,
    "proof_rejected":      LogLevel.ERROR.value,
    "budget_tripped":      LogLevel.WARN.value,
    "scope_violation":     LogLevel.WARN.value,
    "tool_call_denied":    LogLevel.WARN.value,
    "approval_denied":     LogLevel.WARN.value,
}


# ---- redaction --------------------------------------------------------------
# Applied to payloads before fan-out. The ledger (chained, access-controlled)
# retains the original. Channels are scrubbed because they ship to aggregators.

_REDACT_KEYS: frozenset[str] = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_key", "private_key", "credential", "credentials",
    "authorization", "auth_token", "bearer", "signing_key",
})

_SECRET_RE = re.compile(
    r"(?:"
    r"sk-[A-Za-z0-9]{20,}"                            # OpenAI-style API keys
    r"|ghp_[A-Za-z0-9]{36}"                           # GitHub personal tokens
    r"|AKIA[0-9A-Z]{16}"                              # AWS access key IDs
    r"|xox[bpas]-[0-9A-Za-z-]{20,}"                  # Slack bot/user/app tokens
    r"|eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+"  # JWTs (3 base64url parts)
    r"|[A-Za-z0-9+/]{48,}={0,2}"                     # long base64 blobs (>=48 chars)
    r")",
    re.ASCII,
)

_REDACTED = "[REDACTED]"


def _redact(obj: Any) -> Any:
    """Recursively scrub sensitive key names and secret-looking string values."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _REDACT_KEYS:
                out[k] = _REDACTED
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    if isinstance(obj, str) and _SECRET_RE.search(obj):
        return _REDACTED
    return obj


# ---- rolling hash constants -------------------------------------------------

ZERO_CHANNEL_HASH = hashlib.sha256(b"channel:genesis").hexdigest()


def _next_hash(prev: str, line: str) -> str:
    return hashlib.sha256(f"{prev}|{line}".encode("utf-8")).hexdigest()


def compute_channel_hash(path: Path, up_to_count: int = -1) -> tuple[str, int]:
    """Replay a channel file to compute its rolling hash.

    Returns (hash, entry_count).  If up_to_count > 0, stops after that many entries.
    The path need not exist (returns genesis hash + 0 count).

    Used by CLI verify-logs to check channel state against ledger-anchored digests.
    """
    h = ZERO_CHANNEL_HASH
    count = 0
    if not path.exists():
        return h, 0
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            h = _next_hash(h, line)
            count += 1
            if 0 < up_to_count <= count:
                break
    return h, count


# ---- log entry --------------------------------------------------------------

@dataclass
class LogEntry:
    ts: float
    channel: str
    level: str
    event: str
    payload: dict[str, Any]
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---- per-channel JSONL writer with rolling hash ----------------------------

class ChannelWriter:
    """Append-only JSONL + rolling hash.

    Every write extends the channel's hash chain (same algorithm as Ledger but
    applied to JSON-line content instead of structured fields). The tail_hash is
    committed to the audit ledger by LogRouter.anchor(), binding the channel's
    state to the tamper-evident chain.

    max_bytes: if > 0, rotates the active file to <name>.1 when it would exceed
    this size. Rotation resets the hash chain (the new file starts from genesis).
    verify-logs correctly reports TRUNCATED for any anchor made before rotation,
    since actual_count < anchored_count — this is expected and not a tamper signal.
    """

    def __init__(self, path: Path, max_bytes: int = 0) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self._hash = ZERO_CHANNEL_HASH
        self._count = 0

    @property
    def tail_hash(self) -> str:
        return self._hash

    @property
    def entry_count(self) -> int:
        return self._count

    def _maybe_rotate(self, line_bytes: int) -> None:
        """Rotate active file to .1 if adding line_bytes would exceed max_bytes."""
        if self.max_bytes <= 0:
            return
        try:
            current = self.path.stat().st_size
        except FileNotFoundError:
            return
        if current + line_bytes > self.max_bytes:
            backup = self.path.with_suffix(self.path.suffix + ".1")
            self.path.replace(backup)
            self.path.touch()
            self._hash = ZERO_CHANNEL_HASH
            self._count = 0

    def write(self, entry: LogEntry) -> None:
        line = json.dumps(entry.to_dict(), ensure_ascii=False)
        self._maybe_rotate(len(line.encode("utf-8")) + 1)
        self._hash = _next_hash(self._hash, line)
        self._count += 1
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def entries(self) -> list[LogEntry]:
        if not self.path.exists():
            return []
        result = []
        with self.path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line:
                    d = json.loads(line)
                    result.append(LogEntry(**d))
        return result


# ---- trace / span context ---------------------------------------------------

def _new_id(prefix: str = "") -> str:
    return prefix + os.urandom(6).hex()


@dataclass
class SpanEntry:
    span_id: str
    name: str
    parent_id: Optional[str]
    started_at: float
    ended_at: Optional[float] = None
    status: str = "ok"

    def duration_ms(self) -> Optional[float]:
        if self.ended_at is None:
            return None
        return (self.ended_at - self.started_at) * 1000.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TraceContext:
    """Lightweight span tracker. One trace per Lifecycle run.

    trace_id is stable for the lifetime of the run and stored in the intake
    ledger event. To link a resumed run, pass the prior trace_id to __init__
    and the segments share a correlation ID; use a parent_run_id payload field
    to make the relationship explicit in cross-session queries.
    """

    def __init__(self, trace_id: Optional[str] = None) -> None:
        self.trace_id: str = trace_id or _new_id("tr-")
        self._spans: dict[str, SpanEntry] = {}
        self._stack: list[str] = []

    @property
    def current_span_id(self) -> Optional[str]:
        return self._stack[-1] if self._stack else None

    def start_span(self, name: str) -> str:
        span_id = _new_id("sp-")
        parent_id = self.current_span_id
        self._spans[span_id] = SpanEntry(
            span_id=span_id, name=name, parent_id=parent_id,
            started_at=time.time(),
        )
        self._stack.append(span_id)
        return span_id

    def end_span(self, span_id: str, status: str = "ok") -> SpanEntry:
        span = self._spans[span_id]
        span.ended_at = time.time()
        span.status = status
        if self._stack and self._stack[-1] == span_id:
            self._stack.pop()
        return span

    def all_spans(self) -> list[SpanEntry]:
        return list(self._spans.values())


# ---- log router -------------------------------------------------------------

class LogRouter:
    """
    Fan-out hub: routes harness events to specialist channels with redaction
    and maintains a rolling hash per channel for digest-anchoring.

    route()  — automatic fan-out after ledger.append(). Redacts payload first.
    write()  — direct channel write for non-ledger events (spans, dep timing, etc.)
    anchor() — hash every active channel and commit a channel_digest to the ledger.
               Call at lifecycle DONE or HALTED; this is what closes the integrity gap.
    read()   — return all entries for a channel.
    summary()— entry count per non-empty channel (excludes audit, which is the ledger).
    """

    def __init__(self, log_dir: str | Path) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._writers: dict[str, ChannelWriter] = {}

    def _writer(self, channel: LogChannel) -> ChannelWriter:
        if channel.value not in self._writers:
            self._writers[channel.value] = ChannelWriter(
                self.log_dir / f"{channel.value}.jsonl"
            )
        return self._writers[channel.value]

    def route(
        self,
        event: str,
        payload: dict[str, Any],
        level: str = LogLevel.INFO.value,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
    ) -> None:
        """Fan out a harness event to all mapped channels, with redaction."""
        channels = EVENT_CHANNELS.get(event)
        if not channels:
            return
        clean = _redact(payload)        # scrub before fan-out; ledger keeps original
        ts = time.time()
        for ch in channels:
            self._writer(ch).write(LogEntry(
                ts=ts, channel=ch.value, level=level,
                event=event, payload=clean,
                trace_id=trace_id, span_id=span_id,
            ))

    def write(
        self,
        channel: LogChannel,
        event: str,
        payload: dict[str, Any],
        level: str = LogLevel.INFO.value,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
    ) -> None:
        """Direct write for channel-specific non-ledger events. Also redacts."""
        clean = _redact(payload)
        self._writer(channel).write(LogEntry(
            ts=time.time(), channel=channel.value, level=level,
            event=event, payload=clean,
            trace_id=trace_id, span_id=span_id,
        ))

    def anchor(self, ledger: Any) -> dict[str, dict[str, Any]]:
        """Commit each active channel's tail hash to the ledger.

        The resulting channel_digest entry in the hash-chained ledger attests
        to the channel's state at this moment. Any subsequent edit to a channel
        file breaks the comparison against the anchored hash.

        Returns the digest map for inspection / testing.
        """
        digests: dict[str, dict[str, Any]] = {}
        for ch_name, writer in self._writers.items():
            digests[ch_name] = {
                "hash": writer.tail_hash,
                "count": writer.entry_count,
            }
        if digests:
            ledger.append("channel_digest", {"channels": digests})
        return digests

    def read(self, channel: LogChannel) -> list[LogEntry]:
        return self._writer(channel).entries()

    def summary(self) -> dict[str, int]:
        """Entry count per channel; omits audit (the ledger) and empty channels."""
        result: dict[str, int] = {}
        for ch in LogChannel:
            if ch == LogChannel.AUDIT:
                continue
            path = self.log_dir / f"{ch.value}.jsonl"
            if path.exists():
                count = sum(
                    1 for raw in path.read_text(encoding="utf-8").splitlines()
                    if raw.strip()
                )
                if count:
                    result[ch.value] = count
        return result

    def token_summary_by_task(self) -> dict[str, dict[str, Any]]:
        """Aggregate token usage and cost per task_id from the TOKEN channel.

        Returns {task_id: {input_tokens, output_tokens, cost}} for every task
        that appears in token_charged events. Useful for cost attribution and
        circuit-breaker post-mortems.
        """
        totals: dict[str, dict[str, Any]] = {}
        for entry in self.read(LogChannel.TOKEN):
            if entry.event != "token_charged":
                continue
            task_id = entry.payload.get("task") or entry.payload.get("task_id")
            if not task_id:
                continue
            if task_id not in totals:
                totals[task_id] = {"input_tokens": 0, "output_tokens": 0, "cost": 0.0}
            totals[task_id]["input_tokens"]  += entry.payload.get("input_tokens", 0)
            totals[task_id]["output_tokens"] += entry.payload.get("output_tokens", 0)
            totals[task_id]["cost"]          += entry.payload.get("cost", 0.0)
        return totals
