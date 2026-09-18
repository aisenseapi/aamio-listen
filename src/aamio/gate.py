"""Gate: the conditions an inbox sets for whoever writes to it, from the writer's side.

From aamio 0.5.0 an inbox can be opened with a gate. This module reads one and
decides what the writer does about it, with no network of its own:

- proof of work advised at up to 18 bits is done without asking;
- proof of work required at up to 32 bits is done when it fits in the time the
  inbox still takes writes, and a 428 is answered by doing it and sending
  again, once;
- work that would not be done before the inbox closes is not started, and
  the send stops with how long the work takes here and how long is left;
- a requirement above what this client computes stops the send, and says why;
- a condition this client does not know stops the send under require, since
  it cannot meet what it does not understand, and is passed over and
  mentioned under advise.

The ceilings are the service's own, 32 required and 18 advised. An inbox run by
a stranger can therefore never make this client spend more CPU than aamio lets
any inbox ask for, and aamio can never advise something an up to date client
would skip. 32 bits is for an inbox that means to meet only writers with real
compute: it takes this client more than an hour, so it says no up front.
"""

import hashlib
import time

from .client import DEFAULT_HOST

POW_REQUIRE_MAX_BITS = 32
POW_ADVISE_MAX_BITS = 18

# Below this the work is a second or so anywhere, and not worth timing first.
ESTIMATE_FROM_BITS = 17
_RATE = None

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


def solve(w, key, body, bits, deadline=None):
    """The first nonce, counting up from 0, whose digest reaches bits, or None
    when deadline, a time.monotonic() value, passes first.

    body is the exact text or bytes that will be sent, the envelope if sealed,
    since the work covers the hash of those bytes and no others. Without a
    deadline a large bits can run for hours, and past the life of the inbox
    that work buys nothing.
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

        # Every 65536 attempts, a tenth of a second or less here.
        if deadline is not None and nonce & 0xFFFF == 0 and time.monotonic() > deadline:
            return None


def hash_rate():
    """Attempts a second solve makes on this machine, timed once and kept.

    The estimate before a long piece of work is only as good as this number, so
    it is solve's own loop that is timed, for a quarter of a second.
    """
    global _RATE

    if _RATE is None:
        prefix = hashlib.sha256(("aamio-pow-v1\ncalibration\n\n%s\n" % ("0" * 64)).encode("ascii"))
        count = 0
        start = time.perf_counter()

        while True:
            for _ in range(4096):
                attempt = prefix.copy()
                attempt.update(str(count).encode("ascii"))
                zero_bits(attempt.digest())
                count += 1

            elapsed = time.perf_counter() - start

            if elapsed >= 0.25:
                break

        _RATE = count / elapsed

    return _RATE


def expected_seconds(bits):
    """How long bits of work takes on this machine on average. It is a lottery:
    one attempt in a hundred takes about 4.6 times as long."""
    return (2 ** int(bits)) / hash_rate()


def describe(seconds):
    seconds = float(seconds)

    if seconds < 90:
        return "%d seconds" % max(1, round(seconds))

    if seconds < 5400:
        return "%d minutes" % round(seconds / 60)

    return "%.1f hours" % (seconds / 3600)


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


def plan(gate, w=None, host=None, seconds_left=None):
    """What to do about a gate before sending to w on host, DEFAULT_HOST when not given.

    Returns {"bits": the work to do or None, "required": bool, "notes": [str],
    "expected_seconds": how long the work takes here, "seconds_left": as given},
    notes being what a caller should be told although the send goes ahead.
    Raises GateStop when the send must not go ahead at all.

    seconds_left is how long the inbox still takes writes, from X-Seconds-Left
    on its gate. Work that would not be done by then is not started: the inbox
    is the judge, and finding that out from a 410 an hour later is the worst
    way to learn it.
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

        expected = expected_seconds(bits) if bits >= ESTIMATE_FROM_BITS else 0

        if seconds_left is not None and expected > seconds_left:
            raise GateStop(
                "This inbox requires proof of work of %d bits, which takes about %s on this machine, and it takes writes for %s more. The work would not be done before it closes, so it was not started and nothing was sent." % (bits, describe(expected), describe(seconds_left)),
                "Ask the owner for a longer inbox or less work, or send from a machine with more compute. An inbox that asks this much may mean to meet only writers who have it.",
            )

        return {"bits": bits if bits > 0 else None, "required": True, "notes": notes, "expected_seconds": expected, "seconds_left": seconds_left}

    if isinstance(advised, dict):
        bits = int(advised.get("bits") or 0)

        if bits > POW_ADVISE_MAX_BITS:
            notes.append("This inbox advises proof of work of %d bits, more than the %d this client does without asking, so the message was sent without it and shows met.pow 0." % (bits, POW_ADVISE_MAX_BITS))
            return {"bits": None, "required": False, "notes": notes}

        return {"bits": bits if bits > 0 else None, "required": False, "notes": notes}

    return {"bits": None, "required": False, "notes": notes}
