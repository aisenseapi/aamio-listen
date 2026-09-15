"""A proof must never report itself broken for a reason that is not the proof.

`aamio-listen receipt` said local_root_matches: false on a receipt that was
entirely correct, and said it every single time. The local root is built from
`received`, which lives in the process that polled the messages and is not
saved anywhere; a one-shot command holds none of them, hashes the empty
string, and compares that to a real root. False, always, for the ordinary way
the command is used.

Nothing distinguished that from a genuine mismatch, which is the one thing a
receipt exists to be able to say.

There are two questions in there and they are now asked separately:

  root_adds_up        do the lines this receipt lists hash to the root it
                      claims? Always answerable, needs nothing from us.
  local_root_matches  does it agree with what we ourselves saw? Only
                      answerable when we hold every message it counts, and
                      None rather than False when we do not.
"""

import sys
import threading
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.crypto import Keys, sha256hex
from aamio.runtime import Channel, Runtime

MESSAGES = [
    {"seq": 1, "at": 1700000001, "sha256": "a" * 64, "from": "sender-key"},
    {"seq": 2, "at": 1700000002, "sha256": "b" * 64, "from": None},
]


def root_of(messages):
    return sha256hex(
        "".join(
            "%d\t%d\t%s\t%s\n" % (m["seq"], m["at"], m["sha256"], m.get("from") or "-")
            for m in messages
        )
    )


def build(messages, held, root=None):
    runtime = object.__new__(Runtime)
    channel = Channel("inbox", "read-key", "w" * 20, 2000000000)
    runtime.channels = {"inbox": channel}
    runtime.lock = threading.RLock()
    runtime.keys = Keys.generate()
    runtime.name_for_key = lambda key: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    channel.received = [
        {"seq": m["seq"], "at": m["at"], "sha256": m["sha256"], "from_key": m.get("from")}
        for m in messages[:held]
    ]
    receipt = {
        "schema": "aamio-receipt-v1",
        "w": channel.w,
        "count": len(messages),
        "messages": messages,
        "keys": [m["from"] for m in messages if m.get("from")],
        "root": root or root_of(messages),
        "issued_at": 1700000009,
    }
    runtime.client = SimpleNamespace(receipt=lambda w, key: (200, receipt))

    return runtime


def test_a_process_holding_nothing_says_so_rather_than_no():
    # The one-shot command, which is how the CLI always runs.
    out = build(MESSAGES, held=0).receipt()

    assert out["root_adds_up"] is True
    assert out["held_locally"] == 0
    assert out["local_root_matches"] is None
    assert "holds 0 of the 2" in out["local_check"]


def test_holding_some_but_not_all_is_also_not_an_answer():
    out = build(MESSAGES, held=1).receipt()

    assert out["local_root_matches"] is None
    assert "holds 1 of the 2" in out["local_check"]


def test_holding_all_of_them_gives_the_real_check():
    out = build(MESSAGES, held=2).receipt()

    assert out["local_root_matches"] is True
    assert out["held_locally"] == 2
    assert "local_check" not in out


def test_a_receipt_that_does_not_add_up_is_caught_without_local_knowledge():
    # The check that matters against the network, and it needs nothing from us.
    out = build(MESSAGES, held=0, root="c" * 64).receipt()

    assert out["root_adds_up"] is False
    assert out["local_root_matches"] is None


def test_local_disagreement_is_still_reported():
    runtime = build(MESSAGES, held=2)
    runtime.channels["inbox"].received[1]["sha256"] = "d" * 64
    out = runtime.receipt()

    assert out["root_adds_up"] is True
    # We hold as many as it counts, so this is a real answer, and it is no.
    assert out["local_root_matches"] is False


def test_an_empty_thread_compares_cleanly():
    out = build([], held=0).receipt()

    assert out["count"] == 0
    assert out["root_adds_up"] is True
    assert out["local_root_matches"] is True


def test_the_attestation_is_signed_over_what_was_taken():
    runtime = build(MESSAGES, held=2)
    out = runtime.receipt()

    assert out["signed_by"] == runtime.keys.public
    assert out["root"] in out["signed_text"]

    # Verified with PyNaCl rather than with our own code, so this says the
    # signature is real and not merely self-consistent.
    import base64

    import nacl.signing

    pad = "=" * (-len(out["signed_by"]) % 4)
    verifier = nacl.signing.VerifyKey(base64.urlsafe_b64decode(out["signed_by"] + pad))
    pad = "=" * (-len(out["signature"]) % 4)
    verifier.verify(out["signed_text"].encode("utf-8"), base64.urlsafe_b64decode(out["signature"] + pad))
