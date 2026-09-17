"""Gate: the conditions an inbox sets for whoever writes to it, from the writer's side.

From aamio 0.5.0 an inbox can be opened with a gate. This module reads one and
decides what the writer does about it, with no network of its own:

- proof of work advised at up to 18 bits is done without asking;
- proof of work required at up to 20 bits is done, and a 428 is answered by
  doing it and sending again, once;
- a requirement above what this client computes stops the send, and says why;
- a condition this client does not know stops the send under require, since
  it cannot meet what it does not understand, and is passed over and
  mentioned under advise.

The ceilings are the service's own, 20 required and 18 advised. An inbox run by
a stranger can therefore never make this client spend more CPU than aamio lets
any inbox ask for, and aamio can never advise something an up to date client
would skip.
"""

import hashlib

from .client import DEFAULT_HOST

POW_REQUIRE_MAX_BITS = 20
POW_ADVISE_MAX_BITS = 18

# What this client knows how to read, per bucket. per_key and write_until are
# limits the service enforces; a writer cannot do anything to meet them except
# not break them, so knowing them is enough.
KNOWN = {"require": ("per_key", "pow", "write_until"), "advise": ("pow",)}


class GateStop(ValueError):
    """The inbox asks for something this client cannot or will not do, so nothing was sent.

    reason is what the inbox asked and why that stops the send; fix is what the
    caller can do instead. Both are for a reader deciding what to do next.
    """

    def __init__(self, reason, fix):
        super().__init__(reason)
        self.reason = reason
        self.fix = fix


def pow_input(w, key, body_sha256, nonce):
    """What work is computed over. key is the X-Key as sent, or empty for an unsigned message."""
    return "aamio-pow-v1\n%s\n%s\n%s\n%s" % (w, key or "", body_sha256, nonce)


def pow_digest(w, key, body_sha256, nonce):
    """The raw 32 byte digest. Its lowercase hex is the proof_id."""
    return hashlib.sha256(pow_input(w, key, body_sha256, nonce).encode("utf-8")).digest()


def zero_bits(digest):
    """Leading zero bits, counted from the most significant bit of the first byte."""
    bits = 0

    for byte in digest:
        if byte == 0:
            bits += 8
            continue

        return bits + 8 - byte.bit_length()

    return bits


def solve(w, key, body, bits):
    """The first nonce, counting up from 0, whose digest reaches bits.

    body is the exact text or bytes that will be sent, the envelope if sealed,
    since the work covers the hash of those bytes and no others.
    """
    data = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    prefix = hashlib.sha256(("aamio-pow-v1\n%s\n%s\n%s\n" % (w, key or "", hashlib.sha256(data).hexdigest())).encode("utf-8"))
    nonce = 0

    while True:
        attempt = prefix.copy()
        attempt.update(str(nonce).encode("ascii"))

        if zero_bits(attempt.digest()) >= bits:
            return str(nonce)

        nonce += 1


def board_pow_input(key, body_sha256, nonce):
    """What work on a board post is computed over. Computed over, never signed over: the post is signed with aamio-board-v1 as before."""
    return "aamio-board-pow-v1\n%s\n%s\n%s" % (key, body_sha256, nonce)


def board_pow_digest(key, body_sha256, nonce):
    return hashlib.sha256(board_pow_input(key, body_sha256, nonce).encode("utf-8")).digest()


def solve_board(key, body, bits):
    """The first nonce whose board digest reaches bits, over the exact text posted."""
    data = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    prefix = hashlib.sha256(("aamio-board-pow-v1\n%s\n%s\n" % (key, hashlib.sha256(data).hexdigest())).encode("utf-8"))
    nonce = 0

    while True:
        attempt = prefix.copy()
        attempt.update(str(nonce).encode("ascii"))

        if zero_bits(attempt.digest()) >= bits:
            return str(nonce)

        nonce += 1


def board_advised_bits(descriptor):
    """The work a board advises posts to carry, from its descriptor.

    0 when the board advises none, when the descriptor does not say, and when
    it advises more than this client does without asking: an advice above the
    ceiling is passed over, as on an inbox.
    """
    work = descriptor.get("work") if isinstance(descriptor, dict) else None

    if not isinstance(work, dict):
        return 0

    try:
        bits = int(work.get("advise_bits") or 0)
    except (TypeError, ValueError):
        return 0

    return bits if 0 < bits <= POW_ADVISE_MAX_BITS else 0


def plan(gate, w=None, host=None):
    """What to do about a gate before sending to w on host, DEFAULT_HOST when not given.

    Returns {"bits": the work to do or None, "required": bool, "notes": [str]},
    notes being what a caller should be told although the send goes ahead.
    Raises GateStop when the send must not go ahead at all.
    """
    gate = gate if isinstance(gate, dict) else {}
    where = "GET %s/%s/gate" % ((host or DEFAULT_HOST).rstrip("/"), w) if w else "GET /{w}/gate on the inbox"
    notes = []

    for bucket, conditions in gate.items():
        if bucket not in KNOWN:
            raise GateStop(
                "This inbox's gate has a part called %s that this client does not know, so it cannot tell whether a write would be refused, and sent nothing." % bucket,
                "Update the aamio client, which may know it. %s shows the whole gate." % where,
            )

        if not isinstance(conditions, dict):
            continue

        for name in conditions:
            if name in KNOWN[bucket]:
                continue

            if bucket == "require":
                raise GateStop(
                    "This inbox requires %s, a condition this client does not know how to meet, so nothing was sent." % name,
                    "Update the aamio client, which may know it, or reach the owner another way. %s shows the whole gate." % where,
                )

            notes.append("This inbox advises %s, which this client does not know; the message was sent without it." % name)

    required = (gate.get("require") or {}).get("pow") if isinstance(gate.get("require"), dict) else None
    advised = (gate.get("advise") or {}).get("pow") if isinstance(gate.get("advise"), dict) else None

    if isinstance(required, dict):
        bits = int(required.get("bits") or 0)

        if bits > POW_REQUIRE_MAX_BITS:
            raise GateStop(
                "This inbox requires proof of work of %d bits, and this client computes at most %d, the most aamio lets any inbox require. Nothing was sent." % (bits, POW_REQUIRE_MAX_BITS),
                "The inbox asks for more than the service allows, so no client will meet it. Reach the owner another way.",
            )

        return {"bits": bits if bits > 0 else None, "required": True, "notes": notes}

    if isinstance(advised, dict):
        bits = int(advised.get("bits") or 0)

        if bits > POW_ADVISE_MAX_BITS:
            notes.append("This inbox advises proof of work of %d bits, more than the %d this client does without asking, so the message was sent without it and shows met.pow 0." % (bits, POW_ADVISE_MAX_BITS))
            return {"bits": None, "required": False, "notes": notes}

        return {"bits": bits if bits > 0 else None, "required": False, "notes": notes}

    return {"bits": None, "required": False, "notes": notes}
