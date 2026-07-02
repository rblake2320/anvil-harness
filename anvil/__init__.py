"""ANVIL - a governed, proof-gated execution harness for long-horizon agent work."""
from .schemas import (
    AcceptanceCheck, AmbiguityClass, EventType, Phase, PolicyDecision,
    Risk, Task, TaskStatus, ToolCall, Evidence,
)
from .ledger import Ledger, LedgerEntry
from .budget import Budget, CircuitBreaker
from .context import ContextSpec, ContextBundle, ContextCompiler, summarize_evidence, DEFAULT_MAX_TOKENS
from .policy import PolicyEngine, ToolPolicy
from .proofgate import ProofGate, acceptance_hash
from .recovery import RecoveryManager, Compensation, Checkpoint, RepairAction
from .store import MissionStore, Contract
from .lifecycle import Lifecycle, StepResult
from .adapters import (
    AgentAdapter, VerifierAdapter, CommandVerifier, SimulatedAgent, SimulatedVerifier,
)
from .log import (
    LogChannel, LogLevel, LogRouter, LogEntry, TraceContext, SpanEntry,
    EVENT_CHANNELS, EVENT_LEVELS, ZERO_CHANNEL_HASH, compute_channel_hash,
    _redact,
)

__version__ = "0.2.0"
__all__ = [
    "AcceptanceCheck", "AmbiguityClass", "EventType", "Phase", "PolicyDecision",
    "Risk", "Task", "TaskStatus", "ToolCall", "Evidence",
    "Ledger", "LedgerEntry", "Budget", "CircuitBreaker", "PolicyEngine", "ToolPolicy",
    "ContextSpec", "ContextBundle", "ContextCompiler", "summarize_evidence", "DEFAULT_MAX_TOKENS",
    "ProofGate", "acceptance_hash", "RecoveryManager", "Compensation", "Checkpoint",
    "RepairAction", "MissionStore", "Contract", "Lifecycle", "StepResult",
    "AgentAdapter", "VerifierAdapter", "CommandVerifier", "SimulatedAgent", "SimulatedVerifier",
    "LogChannel", "LogLevel", "LogRouter", "LogEntry", "TraceContext", "SpanEntry",
    "EVENT_CHANNELS", "EVENT_LEVELS", "ZERO_CHANNEL_HASH", "compute_channel_hash",
    "_redact",
]
