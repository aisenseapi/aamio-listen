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

from aamio.runtime import Channel, Runtime
from signing import SENDER, stored

CANONICAL = {"post": "p1", "reply_to": "r" * 20, "text": "use a 5 minute debounce"}
GUESSED = {"post_id": "p1", "w": "r" * 20, "reply": "use a 5 minute debounce"}


def deliver(body, verified=True, sender=SENDER, sealed_to=None):
    """One message through poll(), with nothing touching disk or the network."""
    runtime = object.__new__(Runtime)
    channel = Channel("board", "read-key", "b" * 20, 2000000000)
    runtime.channels = {"board": channel}
    runtime.lock = threading.Lock()
    runtime.peers = {}
    runtime.name_for_key = lambda key: None
    runtime.archive = lambda *args: None
    runtime.save_state = lambda: None
    runtime.log = lambda *args: None
    if sealed_to is not None:
        runtime.keys = SimpleNamespace(open=lambda frm, text: json.dumps(sealed_to).encode("utf-8"))
    message = stored(channel.w, 1, body, sender if verified else None, at=1800000000)
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
    assert runtime.peers["r" * 20] == SENDER.public


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
    runtime.log = lambda *args: None

    def refuse(frm, text):
        raise ValueError("not for this key")

    runtime.keys = SimpleNamespace(open=refuse)
    message = stored(channel.w, 1, envelope)
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


def test_an_answer_on_another_channel_is_still_found():
    """Sealed to its own reply address, so it lands off the board inbox.

    Scoping the search to channels named "board" hid these, and a poster who
    looked only at board replies saw nothing while read() had the message.
    """
    runtime = object.__new__(Runtime)
    board = Channel("board", "r1", "b" * 20, 2000000000)
    private = Channel("Arctic Freight", "r2", "c" * 20, 2000000000)
    runtime.channels = {"board": board, "Arctic Freight": private}
    runtime.lock = threading.Lock()
    runtime.log = lambda *args: None
    private.received.append({"channel": "Arctic Freight", "at": 5, "body": {"post": "p1", "text": "yes"}})
    board.received.append({"channel": "board", "at": 4, "body": {"post": "p2", "text": "other"}})

    found = runtime.board_replies("p1")
    assert len(found) == 1 and found[0]["channel"] == "Arctic Freight"
    # Asking for everything still lists both, oldest first.
    assert [e["at"] for e in runtime.board_replies()] == [4, 5]


def test_a_private_thread_does_not_become_a_list_of_board_answers():
    runtime = object.__new__(Runtime)
    private = Channel("Arctic Freight", "r2", "c" * 20, 2000000000)
    runtime.channels = {"Arctic Freight": private}
    runtime.lock = threading.Lock()
    runtime.log = lambda *args: None
    private.received.append({"channel": "Arctic Freight", "at": 5, "body": {"text": "an ordinary message"}})
    assert runtime.board_replies() == []


def test_one_undecodable_message_does_not_cost_the_others():
    """A sender can put anything in a field. It must reach one message only."""
    runtime = object.__new__(Runtime)
    channel = Channel("board", "read-key", "b" * 20, 2000000000)
    runtime.channels = {"board": channel}
    runtime.lock = threading.Lock()
    runtime.peers = {}
    runtime.name_for_key = lambda key: None
    runtime.archive = lambda *args: None
    runtime.save_state = lambda: None
    runtime.log = lambda *args: None
    messages = [
        stored(channel.w, 1, json.dumps({"post": "p1", "text": {"toString": 1}, "reply": "hi"})),
        stored(channel.w, 2, json.dumps({"post": "p1", "text": "an ordinary answer"})),
    ]
    runtime.client = SimpleNamespace(read=lambda *args: (200, {"messages": messages}))
    status, entries = runtime.poll(channel)
    assert status == "ok" and len(entries) == 2
    assert entries[1]["body"]["text"] == "an ordinary answer"


def test_a_field_holding_an_object_is_not_compared_to_a_string():
    # str() of a dict never raises, so the old code reported a conflict that
    # was not one. Two values are only comparable when both are scalars.
    body, meta = Runtime._canonical({"post": "p1", "text": {"toString": 1}, "reply": "hi"})
    assert body["text"] == {"toString": 1}
    assert "conflicting_fields" not in meta


def test_the_board_default_is_one_value_in_one_place():
    import aamio.runtime as runtime_module
    import inspect
    assert runtime_module.BOARD_TTL == 1800
    # The signature reads the constant, so there is no second copy to drift.
    assert inspect.signature(Runtime.board_post).parameters["ttl"].default == runtime_module.BOARD_TTL


def test_two_spellings_of_the_same_value_are_not_a_disagreement():
    # A sender that writes both reply and message, with the same sentence in
    # each, has not contradicted itself. Reporting it as a conflict asks the
    # caller to weigh something that is not there.
    body, meta = Runtime._canonical({"post": "p1", "reply": "on my way", "message": "on my way"})
    assert body["text"] == "on my way"
    assert meta["renamed"] == {"reply": "text"}
    assert "conflicting_fields" not in meta


def test_two_spellings_that_actually_differ_still_are():
    body, meta = Runtime._canonical({"post": "p1", "reply": "on my way", "message": "cannot make it"})
    assert body["text"] == "on my way"
    assert meta["conflicting_fields"] == {"message": "cannot make it"}


def test_the_version_is_one_literal():
    # pyproject said 0.3.3 while the module said 0.3.0, so `aamio-listen
    # --version` reported a version that was never published. pyproject now
    # reads this attribute, and nothing else carries a number.
    import pathlib
    import aamio

    text = (pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = { attr = "aamio.__version__" }' in text
    assert not any(line.startswith('version = "') for line in text.splitlines())
    assert aamio.__version__.count(".") == 2


def test_the_user_agent_says_which_version_it_is():
    # It said aamio-listen/0.1 from the first commit through every release
    # after it, so an access log full of "0.1" was read as somebody running an
    # old client when it was only ever this constant. A wire that cannot tell
    # versions apart makes an operator confidently wrong, and it did.
    import urllib.request

    import aamio
    from aamio.client import AamioClient

    seen = {}
    real = urllib.request.urlopen

    def capture(request, timeout=None):
        seen["ua"] = request.get_header("User-agent")
        raise OSError("no network in a test")

    urllib.request.urlopen = capture

    try:
        status, body = AamioClient().http("GET", "https://aamio.test/health")
    finally:
        urllib.request.urlopen = real

    assert status == 0, "the probe should never reach a network"
    assert seen["ua"] == "aamio/" + aamio.__version__
    assert not seen["ua"].endswith("/0.1")
