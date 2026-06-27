"""
ANVIL ledger: hash-chained, append-only, tamper-evident event log.

This is the single source of truth. The executor's narration is NEVER
authoritative; only what is committed here counts. Every state transition,
tool decision, evidence record, and human approval lands here as a link in a
SHA-256 chain. Tampering with any past entry breaks verification of all
subsequent entries.

Design notes:
  * Append-only JSONL on disk (`LEDGER.jsonl`) so it survives crashes and is
    trivially auditable / greppable with no DB.
  * Each entry's `prev` is the hash of the prior entry; genesis prev is the
    zero hash. `hash` covers (seq, ts, type, payload, prev) deterministically.
  * Optional HMAC signing key turns the chain into a MAC chain so an attacker
    who can write the file still cannot forge entries without the key. Drop in
    your PKA signing here to match the GUMBO ledger model.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional

ZERO_HASH = "0" * 64


def _canonical(obj: Any) -> bytes:
    """Deterministic serialization so the same logical entry always hashes equal."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(data: bytes, key: Optional[bytes]) -> str:
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


@dataclass
class LedgerEntry:
    seq: int
    ts: float
    type: str
    payload: dict[str, Any]
    prev: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "type": self.type,
            "payload": self.payload,
            "prev": self.prev,
            "hash": self.hash,
        }


class Ledger:
    def __init__(self, path: str | os.PathLike[str], signing_key: Optional[bytes] = None):
        self.path = Path(path)
        self._key = signing_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    # ---- core ----------------------------------------------------------
    def _compute_hash(self, seq: int, ts: float, etype: str, payload: dict, prev: str) -> str:
        body = _canonical({"seq": seq, "ts": ts, "type": etype, "payload": payload, "prev": prev})
        return _digest(body, self._key)

    def append(self, etype: str, payload: dict[str, Any], ts: Optional[float] = None) -> LedgerEntry:
        last = self.last()
        seq = (last.seq + 1) if last else 0
        prev = last.hash if last else ZERO_HASH
        ts = ts if ts is not None else time.time()
        h = self._compute_hash(seq, ts, etype, payload, prev)
        entry = LedgerEntry(seq=seq, ts=ts, type=etype, payload=payload, prev=prev, hash=h)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return entry

    def __iter__(self) -> Iterator[LedgerEntry]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                yield LedgerEntry(**d)

    def entries(self) -> list[LedgerEntry]:
        return list(self)

    def last(self) -> Optional[LedgerEntry]:
        last = None
        for e in self:
            last = e
        return last

    def find(self, etype: str) -> list[LedgerEntry]:
        return [e for e in self if e.type == etype]

    # ---- integrity -----------------------------------------------------
    def verify(self) -> tuple[bool, Optional[str]]:
        """Re-walk the chain. Returns (ok, reason). Detects tamper, reorder, truncation-of-middle."""
        prev = ZERO_HASH
        expected_seq = 0
        for e in self:
            if e.seq != expected_seq:
                return False, f"seq gap at {e.seq} (expected {expected_seq})"
            if e.prev != prev:
                return False, f"broken link at seq {e.seq}: prev mismatch"
            recomputed = self._compute_hash(e.seq, e.ts, e.type, e.payload, e.prev)
            if recomputed != e.hash:
                return False, f"tampered payload at seq {e.seq}"
            prev = e.hash
            expected_seq += 1
        return True, None
