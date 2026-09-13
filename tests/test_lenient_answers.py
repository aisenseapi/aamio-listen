"""The whole receiving chain, not one piece of it at a time.

A real answer arrived signed, unencrypted, and with post_id, w and reply
where we read post, reply_to and text. The first attempt at a fix translated
those names in isolation and passed its own tests, while the answer still
never reached the post: the plaintext branch handed the parser a wrapper with
the real object stranded inside a string.

So these tests go through poll(), the way a message actually arrives, and
check what a caller can see afterwards: the body, whether it was matched to
its post, and whether the reply address was learned. Every case is one of the
combinations that can turn up in the wild.
"""

import json
import sys
import threading
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio_listen.runtime import Channel, Runtime

CANONICAL = {"post": "p1", "reply_to": "r" * 20, "text": "use a 5 minute debounce"}
GUESSED = {"post_id": "p1", "w": "r" * 20, "reply": "use a 5 minute debounce"}


def deliver(body, verified=True, sender="a-verified-key", sealed_to=None):
    """One message through poll(), with nothing touching disk or the network."""
    runtime = object.__new__(Runtime)
    channel = Channel("board", "read-key", "b" * 20, 2000000000)
    runtime.channels = {"board": channel}
    runtime.lock = threading.Lock()
    runtime.peers = {}
    runtime.name_for_key = lambda key: None
    runtime.archive = lambda *args: None
    runtime.save_state = lambda: None
    if sealed_to is not None:
        runtime.keys = SimpleNamespace(open=lambda frm, text: json.dumps(sealed_to).encode("utf-8"))
    message = {
        "verified": verified,
        "from": sender if verified else None,
        "body": body,
        "seq": 1,
        "at": 1800000000,
        "sha256": "hash-1",
    }
    runtime.client = SimpleNamespace(read=lambda *args: (200, {"messages": [message]}))
    status, entries = runtime.poll(channel)
    assert status == "ok"
    return runtime, entries[0]


def test_plaintext_json_with_guessed_names_reaches_its_post():
    runtime, entry = deliver(json.dumps(GUESSED))
    assert entry["format"] == "json" and entry["signed"] and not entry["encrypted"]
    assert entry["body"]["post"] == "p1"
    assert entry["renamed"] == {"post_id": "post", "w": "reply_to", "reply": "text"}
    # The three things that were broken, seen from where a caller stands.
    assert len(runtime.board_replies("p1")) == 1
    assert runtime.peers["r" * 20] == "a-verified-key"


def test_plaintext_json_with_the_documented_names_is_untouched():
    runtime, entry = deliver(json.dumps(CANONICAL))
    assert "renamed" not in entry
    assert entry["body"] == CANONICAL
    assert len(runtime.board_replies("p1")) == 1


def test_a_sealed_answer_with_guessed_names_reaches_its_post_too():
    envelope = json.dumps({"e2ee": "nacl.box.v1", "to": "0123abcd", "nonce": "n", "ct": "c"})
    runtime, entry = deliver(envelope, sealed_to=GUESSED)
    assert entry["encrypted"] and entry["format"] == "json"
    assert entry["body"]["text"] == GUESSED["reply"]
    assert len(runtime.board_replies("p1")) == 1


def test_a_sealed_message_that_will_not_open_says_so_without_pretending():
    envelope = json.dumps({"e2ee": "nacl.box.v1", "to": "0123abcd", "nonce": "n", "ct": "c"})
    runtime = object.__new__(Runtime)
    channel = Channel("board", "read-key", "b" * 20, 2000000000)
    runtime.channels = {"board": channel}
    runtime.lock = threading.Lock()
    runtime.peers = {}
    runtime.name_for_key = lambda key: None
    runtime.archive = lambda *args: None
    runtime.save_state = lambda: None

    def refuse(frm, text):
        raise ValueError("not for this key")

    runtime.keys = SimpleNamespace(open=refuse)
    message = {"verified": True, "from": "k", "body": envelope, "seq": 1, "at": 1, "sha256": "h"}
    runtime.client = SimpleNamespace(read=lambda *args: (200, {"messages": [message]}))
    entry = runtime.poll(channel)[1][0]
    assert entry["format"] == "unreadable" and entry["encrypted"] and entry["error"] == "ValueError"
    assert runtime.peers == {}


def test_plain_prose_is_kept_whole_and_not_called_a_failure():
    long_text = "x" * 1200
    runtime, entry = deliver(long_text)
    assert entry["format"] == "text" and entry["signed"]
    # The old path cut this to 500 characters on the way in, so content was
    # lost before anything could archive it.
    assert entry["body"]["text"] == long_text


def test_an_unsigned_message_never_becomes_an_answer():
    runtime, entry = deliver(json.dumps(GUESSED), verified=False, sender=None)
    assert entry["format"] == "unsigned" and not entry["signed"]
    assert entry["body"] == {"text": json.dumps(GUESSED)}
    # No post match and no address learned from something nobody signed.
    assert runtime.board_replies("p1") == []
    assert runtime.peers == {}


def test_two_spellings_that_disagree_keep_the_documented_one_and_report_it():
    runtime, entry = deliver(json.dumps({"post": "p1", "post_id": "p2", "text": "hei"}))
    assert entry["body"]["post"] == "p1"
    assert entry["conflicting_fields"] == {"post_id": "p2"}


def test_a_message_that_is_not_an_answer_is_left_alone():
    # w and id are ordinary words elsewhere in the protocol. Rewriting them
    # everywhere would turn other messages into answers they are not.
    runtime, entry = deliver(json.dumps({"id": "abc", "w": "c" * 20, "note": "hello"}))
    assert entry["body"] == {"id": "abc", "w": "c" * 20, "note": "hello"}
    assert "renamed" not in entry
    assert runtime.peers == {}


def test_a_sender_cannot_set_our_own_fields():
    hostile = dict(GUESSED, signed=False, verified=True, format="sealed", replay=False)
    runtime, entry = deliver(json.dumps(hostile))
    # Trust lives on the entry, the sender's words live in the body, and the
    # two no longer share a dict.
    assert entry["signed"] is True and entry["format"] == "json" and entry["encrypted"] is False
    assert entry["verified"] is True
    assert entry["body"]["format"] == "sealed"
