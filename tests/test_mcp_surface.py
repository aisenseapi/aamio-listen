"""What the model is told about a message, a failure, and a tool.

Three things were flattened on the way out of the local MCP server, and each
one removed the distinction a reader needs to act on.

A read stripped `from_key`, so two different strangers both arrived as
"unknown key" and could not be told apart. The key is the sender's public
Ed25519 key — the same value that sits on every board post — not a secret.

A failed send was reduced to `str(error)`. The outcome, the status and the
message id are all known at that point; the id was not even in the sentence.
Refused and unknown want opposite reactions, and a model with neither the id
nor the distinction will simply send again.

Every tool said `destructiveHint: false`, closing a thread and withdrawing a
board post included, and the receipt tool called itself read-only although
`anchor` publishes to an external service. Hints are not a permission check,
but a wrong hint shown to a person is worse than no hint.
"""

import sys
import threading
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio_listen.mcp_server import TOOLS, dispatch
from aamio_listen.runtime import Channel, Runtime, SendFailed

BY_NAME = {tool["name"]: tool for tool in TOOLS}


def runtime_holding(messages):
    runtime = object.__new__(Runtime)
    channel = Channel("inbox", "read-key", "w" * 20, 2000000000)
    runtime.channels = {"inbox": channel}
    runtime.lock = threading.RLock()
    runtime.peers = {}
    runtime.partners = [{"name": "builder", "key": "known-key"}]
    runtime.name_for_key = lambda key: "builder" if key == "known-key" else None
    runtime.save_state = lambda: None
    runtime.log = lambda text: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.client = SimpleNamespace(read=lambda *args: (200, {"messages": messages}))

    return runtime, channel


def message(seq, key, body):
    return {
        "seq": seq,
        "at": 1700000000 + seq,
        "verified": True,
        "from": key,
        "sha256": "%064d" % seq,
        "body": body,
    }


def test_two_strangers_are_two_identities():
    runtime, channel = runtime_holding([
        message(1, "stranger-one", "first"),
        message(2, "stranger-two", "second"),
    ])
    entries = runtime.poll(channel)[1]

    assert [e["sender"] for e in entries] == ["unknown key", "unknown key"]
    # The label is the same for both; the key is not, and the key is what a
    # reader has to be able to compare.
    assert entries[0]["from_key"] != entries[1]["from_key"]
    assert [e["known_contact"] for e in entries] == [False, False]


def test_verified_and_unknown_are_separate_facts():
    runtime, channel = runtime_holding([
        message(1, "known-key", "from a contact"),
        message(2, "stranger-one", "from a stranger"),
    ])
    entries = runtime.poll(channel)[1]

    assert entries[0]["known_contact"] is True and entries[0]["sender"] == "builder"
    assert entries[1]["known_contact"] is False
    # Both signatures verified. Verified says nothing about being known.
    assert [e["verified"] for e in entries] == [True, True]


def test_the_public_key_survives_the_read_tool():
    runtime, _ = runtime_holding([message(1, "stranger-one", "hello")])
    runtime.read = lambda wait: runtime.poll(runtime.channels["inbox"])[1]
    out = dispatch(runtime, "aamio_read", {})

    assert out["structuredContent"]["messages"][0]["from_key"] == "stranger-one"


def refused_send(outcome):
    runtime = SimpleNamespace(send=lambda *a, **k: (_ for _ in ()).throw(
        SendFailed(outcome, "m-acac9b3fbdf77d8e", 413 if outcome == "refused" else 0, "detail")
    ))

    return dispatch(runtime, "aamio_send", {"to": "builder", "text": "hello"})["structuredContent"]


def test_a_refused_send_says_so_and_says_not_to_repeat_it():
    out = refused_send("refused")

    assert out["error_code"] == "send_refused"
    assert out["outcome"] == "refused"
    assert out["status"] == 413
    # The same request will be refused again; that is a definite no.
    assert out["retryable"] is False
    assert out["message_id"] == "m-acac9b3fbdf77d8e"


def test_an_unknown_outcome_is_not_reported_as_a_failure():
    out = refused_send("unknown")

    assert out["error_code"] == "send_unknown"
    assert out["outcome"] == "unknown"
    # Not False: whether to send again cannot be decided from this alone.
    assert out["retryable"] is None
    assert out["message_id"] == "m-acac9b3fbdf77d8e"
    assert "aamio_pending" in out["fix"]
    assert "message_id" in out["fix"]


def test_the_message_id_is_reachable_and_not_only_in_prose():
    for outcome in ("refused", "unknown"):
        out = refused_send(outcome)
        assert out["message_id"], outcome


def test_taking_something_away_is_marked_as_taking_something_away():
    for name in ("aamio_close_channel", "aamio_board_withdraw"):
        hints = BY_NAME[name]["annotations"]
        assert hints["destructiveHint"] is True, name
        assert hints["readOnlyHint"] is False, name


def test_a_tool_that_can_publish_externally_is_not_read_only():
    hints = BY_NAME["aamio_receipt"]["annotations"]

    assert hints["readOnlyHint"] is False
    assert hints["idempotentHint"] is False
    assert "anchor" in BY_NAME["aamio_receipt"]["description"]


def test_reading_and_looking_up_stay_read_only():
    for name in ("aamio_read", "aamio_whoami", "aamio_partners", "aamio_channels"):
        assert BY_NAME[name]["annotations"]["readOnlyHint"] is True, name
        assert BY_NAME[name]["annotations"]["destructiveHint"] is False, name


def test_the_receipt_tool_says_the_channel_is_a_local_label():
    description = BY_NAME["aamio_receipt"]["description"]

    # The default is inbox, which is rarely the channel a board answer is on.
    assert "local channel label" in description
    assert "aamio_channels" in description
