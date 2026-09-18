"""A reader checks for itself, keeps its own allowlist, and remembers what it was handed.

Three things came out of a security review on 18 September 2026.

1. `verified` in an answer was the service's word, and every client took it.
   The trust model says an operator cannot forge a signature, which is only
   true for a reader that checks one. The hash and the signature are checked
   here now, and a message the service calls verified that does not check out
   is handed over unverified, and said.

2. The service enforces an allowlist while it holds the thread, and it holds
   it in memory. When the store is emptied, a write to the address opens a new
   thread with no list. The channel keeps the list it was opened with and
   applies it to what it reads, so a stranger's message does not arrive as if
   it had passed.

3. The hashes of what a channel handed over were cleared together with the
   cursor when the thread at the address was new. That lost the replay mark
   exactly when every sender sends the same bytes again.
"""

import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.crypto import check_message, thread_signing_input, verify
from aamio.runtime import Channel, Runtime
from signing import keypair, stored

W = "i" * 20
ALICE = keypair(1)
MALLORY = keypair(9)


def build(answers, allow=None):
    runtime = object.__new__(Runtime)
    runtime.channels = {"inbox": Channel("inbox", "read-key", W, time.time() + 600, allow)}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = [{"name": "alice", "key": ALICE.public}]
    runtime.log = lambda line: None
    runtime.save_state = lambda: None
    runtime.archived = []
    runtime.archive = lambda label, record: runtime.archived.append(record)
    runtime.client = SimpleNamespace(read=lambda w, read_key, after, wait: answers.pop(0))

    return runtime, runtime.channels["inbox"]


def answer(*messages, **facts):
    return 200, dict({"exists": True, "created_at": 1000, "messages": list(messages), "next": max([m["seq"] for m in messages] or [0])}, **facts)


# ------------------------------------------------------------- the check --

def test_the_contract_vector_verifies_and_stops_verifying_when_anything_moves():
    # Section 5 of the client contract: key A, this address, this body.
    key_a = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
    w = "ohcibx4t22xc6hx22fch"
    body = '{"hello":"from python"}'
    signature = "u327kMqo4_mMzm__Wr7BrXcO4cHvx30IWw1K0cTpfTV6ODV4BFC9E0VkN3LlUvx--wFwe2J8kgSWugKXvwL8Dg"

    assert verify(key_a, thread_signing_input(w, body), signature)
    assert not verify(key_a, thread_signing_input("a" * 20, body), signature)
    assert not verify(key_a, thread_signing_input(w, body + " "), signature)
    assert not verify(ALICE.public, thread_signing_input(w, body), signature)
    assert not verify("not a key", "x", "not a signature")


def test_a_signed_message_is_verified_here():
    verified, why_not, digest = check_message(W, stored(W, 1, "hello", ALICE))

    assert verified and why_not is None and len(digest) == 64


def test_an_unsigned_message_is_unverified_without_a_complaint():
    assert check_message(W, stored(W, 1, "hello", None))[:2] == (False, None)


def test_what_the_service_calls_verified_has_to_check_out():
    moved = stored("o" * 20, 1, "hello", ALICE)          # signed for another address
    altered = dict(stored(W, 1, "hello", ALICE), body="hello!", sha256=stored(W, 1, "hello!")["sha256"])
    bare = dict(stored(W, 1, "hello", None), verified=True)
    wrong_hash = dict(stored(W, 1, "hello", ALICE), sha256="0" * 64)

    for message, expected in ((moved, "does not check out"), (altered, "does not check out"), (bare, "gave no key or signature"), (wrong_hash, "does not hash")):
        verified, why_not, _ = check_message(W, message)
        assert not verified and expected in why_not


# ------------------------------------------------------------ in the poll --

def test_poll_goes_by_its_own_result_and_says_when_the_service_was_wrong():
    forged = dict(stored(W, 2, "pay the invoice", MALLORY), **{"from": ALICE.public})     # Mallory's signature under Alice's name
    runtime, channel = build([answer(stored(W, 1, "hello", ALICE), forged)])

    state, entries = runtime.poll(channel)
    attention = runtime.attention_taken()

    assert state == "ok" and [e["verified"] for e in entries] == [True, False]
    assert entries[0]["from_key"] == ALICE.public and entries[0]["known_contact"] is True and entries[0]["sender"] == "alice"
    # Nothing of the claim is left on the forged one: no key, no contact, no name.
    assert entries[1]["from_key"] is None and entries[1]["known_contact"] is False and entries[1]["sender"] == "unsigned"
    assert "does not check out" in entries[1]["unverified_because"] and "unverified_because" not in entries[0]
    assert [(a["channel"], a["state"]) for a in attention] == [("inbox", "unverified")]
    assert "message 2" in attention[0]["what"] and "operator" in attention[0]["what"]


def test_a_forged_sender_teaches_no_reply_address():
    body = '{"reply_to":"%s","text":"write to me here"}' % ("r" * 20)
    forged = dict(stored(W, 1, body, MALLORY), **{"from": ALICE.public})
    runtime, channel = build([answer(forged)])

    runtime.poll(channel)

    assert runtime.peers == {}


# ------------------------------------------------------ the channel's list --

def test_a_channel_opened_for_one_key_keeps_everyone_else_out():
    runtime, channel = build([answer(stored(W, 1, "from alice", ALICE), stored(W, 2, "from a stranger", MALLORY), stored(W, 3, "unsigned", None))], allow=[ALICE.public])

    state, entries = runtime.poll(channel)
    attention = runtime.attention_taken()

    assert state == "ok" and [e["seq"] for e in entries] == [1]
    # Past all three, or the two are read and kept out again on every call.
    assert channel.after == 3
    assert [(a["channel"], a["state"]) for a in attention] == [("inbox", "kept_out")]
    assert "2 message(s)" in attention[0]["what"] and "seq 2, 3" in attention[0]["what"] and "1 named key(s)" in attention[0]["what"]
    assert [record["seq"] for record in runtime.archived] == [1]


def test_a_channel_opened_for_any_signed_key_keeps_the_unsigned_out():
    runtime, channel = build([answer(stored(W, 1, "signed stranger", MALLORY), stored(W, 2, "unsigned", None))], allow=["*"])

    state, entries = runtime.poll(channel)

    assert [e["seq"] for e in entries] == [1] and entries[0]["known_contact"] is False
    assert "any key, signed only" in runtime.attention_taken()[0]["what"]


def test_a_forged_allowed_key_is_kept_out_too():
    forged = dict(stored(W, 1, "let me in", MALLORY), **{"from": ALICE.public})
    runtime, channel = build([answer(forged)], allow=[ALICE.public])

    state, entries = runtime.poll(channel)

    assert entries == [] and channel.after == 1


def test_a_channel_without_a_list_takes_everything_as_before():
    runtime, channel = build([answer(stored(W, 1, "signed", MALLORY), stored(W, 2, "unsigned", None))])

    state, entries = runtime.poll(channel)

    assert [e["seq"] for e in entries] == [1, 2] and runtime.attention_taken() == []


# ------------------------------------------------- what the reader was handed --

def test_a_message_sent_again_after_the_service_lost_its_store_is_a_replay():
    order = stored(W, 1, "release ARC-4471", ALICE)
    runtime, channel = build([
        answer(order),
        (200, {"exists": False, "messages": [], "next": 0}),
        # A new thread at the address, and the sender's outbox sends the same bytes again.
        answer(dict(order, at=5), created_at=2000),
    ])

    first = runtime.poll(channel)[1]
    runtime.poll(channel)
    again = runtime.poll(channel)[1]

    assert [e["replay"] for e in first] == [False]
    assert [e["replay"] for e in again] == [True]


def test_a_reset_keeps_the_hashes_as_well():
    order = stored(W, 1, "release ARC-4471", ALICE)
    runtime, channel = build([answer(order), answer(order, reset={"after": 1, "newest": 1, "what": "the cursor was from an earlier thread"})])

    runtime.poll(channel)
    again = runtime.poll(channel)[1]

    assert [e["replay"] for e in again] == [True]
