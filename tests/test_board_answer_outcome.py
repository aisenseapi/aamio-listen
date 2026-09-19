"""An answer to a post is a send, and its outcome is told like one.

Found on 18 September 2026, in an outside assessment of aamio in use. `send`
writes an outbox entry before the first attempt, and tells three outcomes
apart: delivered, refused, and unknown when no answer came back at all, since
the message may be on the other side. `board_answer` posted the envelope
directly. When the network gave no answer it raised "answer failed", with no
message id and nothing in the outbox, so the only move left was to answer
again: a new envelope with a new nonce, which the poster's reader cannot tell
from a second answer. Sent through the outbox, the same bytes go again, and a
second copy is marked a replay where it lands.
"""

import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio import cli
from aamio.mcp_server import dispatch
from aamio.runtime import Channel, Runtime, SendFailed

POST = {"id": "p1", "w": "w" * 20, "key": "their-key", "expire_at": int(time.time()) + 600}


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-answer-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def build(home, answers):
    """A runtime with a board inbox already open, whose posts are answered in turn by what the test hands it."""
    runtime = object.__new__(Runtime)
    runtime.host = "https://aamio.test"
    runtime.home = home
    runtime.lock = threading.RLock()
    runtime.channels = {"board": Channel("board", "read", "b" * 20, time.time() + 9000, ["*"])}
    runtime.peers = {}
    runtime.partners = []
    runtime.archive_enabled = False
    runtime.archived = []
    runtime.archive = lambda label, record: runtime.archived.append((label, record))
    runtime.log = lambda text: None
    runtime.save_state = lambda: None
    runtime.keys = SimpleNamespace(public="our-key", hash="0" * 64, seal=lambda key, plaintext: "sealed:" + plaintext.decode("utf-8"), sign=lambda text: "sig")
    runtime.listener = None
    runtime.outbox = {}
    runtime.saves = []
    runtime.save_outbox = lambda: runtime.saves.append({k: v["status"] for k, v in runtime.outbox.items()})
    runtime.posted = []

    def post(*args):
        runtime.posted.append(args)

        return answers.pop(0)

    runtime.client = SimpleNamespace(post=post)

    return runtime


NOTHING_CAME_BACK = (0, {"error": "no answer: timed out", "fix": "The request may have landed."})
STORED = (201, {"seq": 4, "at": 1800000000, "sha256": "s" * 64, "expire_at": 1800000600})


def test_an_answer_nobody_acknowledged_is_unknown_and_is_in_the_outbox(home):
    runtime = build(home, [NOTHING_CAME_BACK])

    with pytest.raises(SendFailed) as failed:
        runtime.board_answer(POST, "an answer")

    assert failed.value.outcome == "unknown" and failed.value.status == 0, "no answer at all is not a failure: the message may be on the other side"
    entry = runtime.outbox[failed.value.message_id]
    assert entry["status"] == "unknown" and entry["w"] == POST["w"] and entry["to_key"] == POST["key"]
    assert entry["summary"] == {"post": "p1", "reply_to": "b" * 20}, "what the entry is about can be read without opening it"
    assert runtime.saves[0] == {failed.value.message_id: "sending"}, "the entry is written before the first attempt"
    assert [e["id"] for e in runtime.outbox_pending()] == [failed.value.message_id]


def test_the_same_bytes_go_again_so_a_copy_that_did_land_is_a_replay_there(home):
    runtime = build(home, [NOTHING_CAME_BACK, STORED])

    with pytest.raises(SendFailed) as failed:
        runtime.board_answer(POST, "an answer")

    retried = runtime.outbox_retry(failed.value.message_id)

    assert [r["status"] for r in retried] == ["delivered"]
    assert len(runtime.posted) == 2 and runtime.posted[0] == runtime.posted[1], "a retry sends the stored envelope, not a new one with a new nonce"
    assert runtime.outbox_pending() == []


def test_a_refused_answer_says_refused_and_which_message(home):
    runtime = build(home, [(403, {"error": "This thread accepts only signed messages from its allowed keys", "fix": "Sign with an allowed key."})])

    with pytest.raises(SendFailed) as failed:
        runtime.board_answer(POST, "an answer")

    assert failed.value.outcome == "refused" and failed.value.status == 403
    assert runtime.outbox[failed.value.message_id]["status"] == "refused"
    assert runtime.outbox_pending() == []


def test_an_answer_that_landed_names_its_outbox_entry(home):
    runtime = build(home, [STORED])
    answer = runtime.board_answer(POST, "an answer")

    assert answer["seq"] == 4 and answer["reply_to"] == "b" * 20
    assert runtime.outbox[answer["message_id"]]["status"] == "delivered"
    label, record = runtime.archived[-1]
    assert label == "board" and record["kind"] == "answered" and record["message_id"] == answer["message_id"] and record["outcome"] == "delivered"


def test_a_model_is_told_the_outcome_and_the_id_and_not_to_answer_again_blindly(home):
    runtime = build(home, [NOTHING_CAME_BACK])
    result = dispatch(runtime, "aamio_board_answer", {"post": POST, "text": "an answer"})
    told = result["structuredContent"]

    assert result["isError"] is True
    assert told["error_code"] == "send_unknown" and told["outcome"] == "unknown" and told["operation"] == "board_answer"
    assert told["message_id"] in runtime.outbox and told["status"] == 0
    assert told["fix"], "what to do next is said, since answering again makes a second answer"


def test_the_command_line_says_the_same_as_json_and_not_as_a_traceback(home):
    """One process per call: an exception that escapes is a traceback on stderr,
    and the message id a retry needs was nowhere in it."""
    for command, arguments in (
        ("board", {"board_command": "answer", "post": POST, "text": "an answer", "scope": None}),
        ("send", {"to": "w" * 20, "text": "hello", "data": None}),
    ):
        runtime = build(home, [NOTHING_CAME_BACK])
        runtime.send = lambda to, text=None, data=None: runtime.board_answer(POST, text)
        printed = []
        original = cli.out
        cli.out = printed.append

        try:
            code = cli.run(SimpleNamespace(command=command, **arguments), runtime)
        finally:
            cli.out = original

        assert code == 1 and len(printed) == 1, command
        assert printed[0]["error_code"] == "send_unknown" and printed[0]["outcome"] == "unknown", command
        assert printed[0]["message_id"] in runtime.outbox and printed[0]["fix"], command
        assert printed[0]["operation"] == ("board_answer" if command == "board" else "send")
