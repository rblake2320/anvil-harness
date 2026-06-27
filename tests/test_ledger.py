from anvil import Ledger
from anvil.ledger import ZERO_HASH


def test_append_and_chain(tmp_path):
    led = Ledger(tmp_path / "L.jsonl")
    a = led.append("x", {"i": 1})
    b = led.append("y", {"i": 2})
    assert a.seq == 0 and a.prev == ZERO_HASH
    assert b.seq == 1 and b.prev == a.hash
    ok, reason = led.verify()
    assert ok, reason


def test_tamper_is_detected(tmp_path):
    p = tmp_path / "L.jsonl"
    led = Ledger(p)
    led.append("a", {"v": 1})
    led.append("b", {"v": 2})
    led.append("c", {"v": 3})
    # rewrite a middle entry's payload, keep its stored hash -> must be caught
    lines = p.read_text().splitlines()
    import json
    rec = json.loads(lines[1])
    rec["payload"] = {"v": 999}
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    ok, reason = led.verify()
    assert not ok and "tampered" in reason


def test_reorder_is_detected(tmp_path):
    p = tmp_path / "L.jsonl"
    led = Ledger(p)
    led.append("a", {})
    led.append("b", {})
    lines = p.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    p.write_text("\n".join(lines) + "\n")
    ok, _ = led.verify()
    assert not ok


def test_hmac_signing_resists_forgery(tmp_path):
    p = tmp_path / "L.jsonl"
    signed = Ledger(p, signing_key=b"pka-secret")
    signed.append("a", {"v": 1})
    signed.append("b", {"v": 2})
    assert signed.verify()[0]
    # an attacker recomputes a plain SHA-256 chain without the key -> fails MAC verify
    import json, hashlib
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"] = {"v": 2, "injected": True}
    body = json.dumps({"seq": rec["seq"], "ts": rec["ts"], "type": rec["type"],
                       "payload": rec["payload"], "prev": rec["prev"]},
                      sort_keys=True, separators=(",", ":"))
    rec["hash"] = hashlib.sha256(body.encode()).hexdigest()  # no key
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    ok, _ = signed.verify()
    assert not ok
