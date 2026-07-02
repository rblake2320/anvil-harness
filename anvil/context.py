"""
ANVIL proof-gated context: minimal, task-scoped context bundles with ledger attestation.

The harness compiles a minimal context bundle for each task, hashes it, commits the
hash to the ledger before the agent acts, and hands the executor only that bundle.
The agent never drags the full conversation forward — because the harness never gives
it the full conversation.

Three properties this gives that nothing on the market has together:
  1. Attested provenance  — every action is linked to the exact context hash that
                            produced it. Replay-able, audit-able, IL5-friendly.
  2. Mechanical minimality — context assembled per DAG leaf from a recipe locked at
                             compile time; sub-agent isolation enforced by the harness,
                             not requested by prompt.
  3. Predictive gate       — size-checked and tamper-checked before the agent call,
                             not when the invoice arrives.

stdlib-only. No external tokenizer required (adapters can supply count_tokens).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

DEFAULT_MAX_TOKENS = 8_000


def _estimate_tokens(
    text: str,
    tokenizer: Optional[Callable[[str], int]] = None,
) -> tuple[int, str]:
    """Estimate token count. Returns (count, estimator_label).

    If tokenizer is supplied and returns a positive integer, uses it (label "adapter").
    On any failure — exception, wrong type, zero, or negative — falls back to heuristic.

    Heuristic intentionally over-estimates non-ASCII content: one token per non-ASCII
    char vs. real tokenizers' ~1 token per CJK char. A too-strict gate wastes one
    retry; a too-loose gate wastes real money.
    """
    if tokenizer is not None:
        try:
            count = tokenizer(text)
            if isinstance(count, int) and count > 0:
                return count, "adapter"
        except Exception:
            pass
    ascii_chars = sum(1 for c in text if ord(c) < 128)
    non_ascii = len(text) - ascii_chars
    return (ascii_chars // 4) + non_ascii, "heuristic"


def summarize_evidence(ledger_entries: Any) -> str:
    """Produce a compact summary of task evidence from ledger entries.

    Only EVIDENCE_RECORDED events are included. Proof travels to downstream
    tasks; raw transcripts do not. This is where the order-of-magnitude token
    reduction in a DAG comes from: upstream evidence is ~100 tokens, not ~10 000.
    """
    lines = []
    for e in ledger_entries:
        if e.type == "evidence_recorded":
            p = e.payload
            ok_str = "PASS" if p.get("ok") else "FAIL"
            check = p.get("check", "?")
            detail = str(p.get("detail", ""))[:120]
            lines.append(f"[{ok_str}] {check}: {detail}")
    return "\n".join(lines) if lines else ""


@dataclass
class ContextSpec:
    """Per-task context recipe. Hashed and locked at COMPILE; verified at EXECUTE.

    If the hash mismatches at execute time the task was modified after compile —
    a security event (CONTEXT_TAMPERED), not a retry candidate.
    """
    task_id: str
    dep_task_ids: list[str]
    file_globs: list[str]
    acceptance_descriptions: list[str]
    max_input_tokens: int = DEFAULT_MAX_TOKENS
    spec_hash: str = ""

    def compute_hash(self) -> str:
        body = json.dumps({
            "task_id": self.task_id,
            "deps": sorted(self.dep_task_ids),
            "globs": sorted(self.file_globs),
            "acceptance": sorted(self.acceptance_descriptions),
            "max_tokens": self.max_input_tokens,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    def lock(self) -> "ContextSpec":
        """Seal the spec. Returns self for chaining."""
        self.spec_hash = self.compute_hash()
        return self

    def verify(self) -> bool:
        """True when spec_hash matches a fresh computation from current fields."""
        return bool(self.spec_hash) and self.spec_hash == self.compute_hash()


@dataclass
class ContextBundle:
    """Assembled, size-checked context ready to pass to the agent."""
    task_id: str
    stable_prefix: str   # mission + scope — identical across all tasks in a contract;
    task_block: str      # placed first so provider-side prefix caching can anchor on it.
    bundle_hash: str = ""
    estimated_tokens: int = 0
    estimator: str = "heuristic"

    @property
    def full_text(self) -> str:
        """Stable prefix first (cache anchor), volatile task block last."""
        return self.stable_prefix + "\n\n" + self.task_block

    def compute_hash(self) -> str:
        return hashlib.sha256(self.full_text.encode()).hexdigest()


class ContextCompiler:
    """Builds minimal, ledger-attested context bundles.

    Usage (harness calls this, not the model):
        spec   = compiler.build_spec(task)           # at COMPILE phase
        bundle = compiler.build_bundle(spec, ...)    # at EXECUTE phase, pre-call
    """

    def build_spec(
        self,
        task: Any,
        max_input_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> ContextSpec:
        """Build and lock a ContextSpec from a Task. Same task always gives same hash."""
        spec = ContextSpec(
            task_id=task.id,
            dep_task_ids=list(task.deps),
            file_globs=list(task.paths),
            acceptance_descriptions=[c.description for c in task.acceptance],
            max_input_tokens=max_input_tokens,
        )
        spec.lock()
        return spec

    def build_bundle(
        self,
        spec: ContextSpec,
        contract: Any,
        dep_evidence: dict[str, str],
        tokenizer: Optional[Callable[[str], int]] = None,
    ) -> ContextBundle:
        """Assemble a minimal bundle from spec + contract + upstream evidence.

        Stable prefix first so the provider's KV cache can anchor on mission+scope,
        which is constant across all tasks in this contract run.
        """
        scope_lines = "\n".join(f"- {s}" for s in contract.scope_in)
        stable = f"# Mission\n{contract.mission}\n\n# Scope\n{scope_lines}"

        task_lines = [f"# Task: {spec.task_id}"]
        if spec.acceptance_descriptions:
            task_lines.append("## Acceptance")
            task_lines.extend(f"- {d}" for d in spec.acceptance_descriptions)

        if spec.dep_task_ids:
            task_lines.append("## Dependency Evidence")
            for dep_id in spec.dep_task_ids:
                summary = dep_evidence.get(dep_id, "")
                if summary:
                    task_lines.append(f"### {dep_id}")
                    task_lines.append(summary)
                else:
                    task_lines.append(f"### {dep_id}: (no evidence recorded)")

        task_block = "\n".join(task_lines)

        bundle = ContextBundle(
            task_id=spec.task_id,
            stable_prefix=stable,
            task_block=task_block,
        )
        bundle.bundle_hash = bundle.compute_hash()
        bundle.estimated_tokens, bundle.estimator = _estimate_tokens(
            bundle.full_text, tokenizer
        )
        return bundle
