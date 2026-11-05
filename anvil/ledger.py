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
  * Crash safety: every append runs under a cross-process exclusive lock
    (`LEDGER.jsonl.lock`; fcntl on POSIX, msvcrt on Windows), reads the chain
    tail from disk (O(1) seek, so concurrent writers can never fork the chain),
    writes one complete line, then flush + fsync. A torn final line (crash
    mid-write) is detected and the ledger fails closed: verify() reports it and
    append() refuses to extend a corrupt chain.
  * Truncation: the chain alone cannot detect deletion of the last N entries.
    Record `last().hash` somewhere the agent cannot write, then pass it as
    `verify(expected_head=...)` to prove nothing at or before it was removed.
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
LOCK_TIMEOUT_S = 30.0


class LedgerCorruptError(Exception):
    """The on-disk ledger contains an unparseable or torn entry."""


class _FileLock:
    """Exclusive cross-process lock on a sidecar file. Stdlib only."""

    def __init__(self, path: Path, timeout: float = LOCK_TIMEOUT_S) -> None:
        self.path = path
        self.timeout = timeout
        self._fh: Any = None

    def __enter__(self) -> "_FileLock":
        self._fh = open(self.path, "a+b")
        deadline = time.monotonic() + self.timeout
        if os.name == "nt":  # pragma: no cover - exercised on Windows CI
            import msvcrt
            while True:
                try:
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        self._fh.close()
                        raise TimeoutError(f"ledger lock busy: {self.path}")
                    time.sleep(0.01)
        else:
            import fcntl
            while True:
                try:
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        self._fh.close()
                        raise TimeoutError(f"ledger lock busy: {self.path}")
                    time.sleep(0.01)
        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            if os.name == "nt":  # pragma: no cover
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()


def _canonical(obj: Any) -> bytes:
    """Deterministic serialization so the same logical entry always hashes equal."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
    """Round-trip through JSON so the in-memory entry equals what lands on disk.

    Non-serializable values (agent-supplied args can be anything) are stringified
    instead of crashing the harness mid-task; tuples become lists, etc.
    """
    return json.loads(json.dumps(payload, default=str, ensure_ascii=False))


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
    def __init__(self, path: str | os.PathLike[str], signing_key: Optional[bytes] = None,
                 *, fsync: bool = True):
        self.path = Path(path)
        self._key = signing_key
        self._fsync = fsync
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    # ---- core ----------------------------------------------------------
    def _compute_hash(self, seq: int, ts: float, etype: str, payload: dict, prev: str) -> str:
        body = _canonical({"seq": seq, "ts": ts, "type": etype, "payload": payload, "prev": prev})
        return _digest(body, self._key)

    def append(self, etype: str, payload: dict[str, Any], ts: Optional[float] = None) -> LedgerEntry:
        payload = _normalize(payload)
        with _FileLock(self._lock_path):
            # Tail is re-read under the lock on every append: another process may
            # have extended the chain since we last looked.
            last = self._tail()
            seq = (last.seq + 1) if last else 0
            prev = last.hash if last else ZERO_HASH
            ts = ts if ts is not None else time.time()
            h = self._compute_hash(seq, ts, etype, payload, prev)
            entry = LedgerEntry(seq=seq, ts=ts, type=etype, payload=payload, prev=prev, hash=h)
            line = (json.dumps(entry.to_dict(), ensure_ascii=False) + "\n").encode("utf-8")
            with self.path.open("ab") as f:
                f.write(line)
                f.flush()
                if self._fsync:
                    os.fsync(f.fileno())
        return entry

    @staticmethod
    def _parse(line: bytes | str, where: str) -> LedgerEntry:
        try:
            d = json.loads(line)
            return LedgerEntry(**d)
        except (ValueError, TypeError) as e:
            raise LedgerCorruptError(f"unparseable ledger entry at {where}: {e}") from e

    def _tail(self) -> Optional[LedgerEntry]:
        """Parse only the final line (seek from end). Fails closed on a torn write."""
        with self.path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if end == 0:
                return None
            f.seek(end - 1)
            if f.read(1) != b"\n":
                raise LedgerCorruptError(
                    "torn final ledger entry (no trailing newline): crash mid-write; "
                    "refusing to extend a corrupt chain")
            buf = b""
            pos = end
            while pos > 0:
                step = min(65536, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                body = buf.rstrip()
                if not body:
                    continue
                idx = body.rfind(b"\n")
                if idx != -1 or pos == 0:
                    return self._parse(body[idx + 1:], "tail")
            return None

    def __iter__(self) -> Iterator[LedgerEntry]:
        if not self.path.exists():
            return
        with self.path.open("rb") as f:
            data = f.read()
        if data and not data.endswith(b"\n"):
            raise LedgerCorruptError("torn final ledger entry (no trailing newline)")
        for n, line in enumerate(data.split(b"\n"), start=1):
            line = line.strip()
            if not line:
                continue
            yield self._parse(line, f"line {n}")

    def entries(self) -> list[LedgerEntry]:
        return list(self)

    def last(self) -> Optional[LedgerEntry]:
        return self._tail()

    def find(self, etype: str) -> list[LedgerEntry]:
        return [e for e in self if e.type == etype]

    # ---- integrity -----------------------------------------------------
    def verify(self, expected_head: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """Re-walk the chain. Returns (ok, reason).

        Detects tamper, reorder, insertion, middle deletion, and torn/corrupt lines.
        `expected_head`: a hash previously recorded outside the ledger (e.g. the
        head at the end of a run). It must appear in the chain, which proves no
        entry at or before it was truncated away or the file replaced wholesale.
        """
        prev = ZERO_HASH
        expected_seq = 0
        seen_head = expected_head is None
        try:
            for e in self:
                if e.seq != expected_seq:
                    return False, f"seq gap at {e.seq} (expected {expected_seq})"
                if e.prev != prev:
                    return False, f"broken link at seq {e.seq}: prev mismatch"
                recomputed = self._compute_hash(e.seq, e.ts, e.type, e.payload, e.prev)
                if not hmac.compare_digest(recomputed, str(e.hash)):
                    return False, f"tampered payload at seq {e.seq}"
                if not seen_head and e.hash == expected_head:
                    seen_head = True
                prev = e.hash
                expected_seq += 1
        except LedgerCorruptError as err:
            return False, str(err)
        if not seen_head:
            return False, (f"expected head {expected_head[:16]}... not in chain "
                           f"(truncated or replaced ledger)")
        return True, None
