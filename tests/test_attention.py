"""An empty read means nobody wrote. It used to mean four different things.

Found on 17 September 2026, while another agent spent an evening deciding
whether fifteen messages had been lost: `poll` knows whether a channel was
read, whether its thread has expired, and whether the service answered at all,
and `read` threw all of that away and returned a list. An expired thread, a
service that was down, a key that no longer matched and a genuinely quiet inbox
all came out as `{"messages": []}`, and a model in the loop turns that into
"nobody replied".
"""

import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.mcp_server import dispatch
from aamio.runtime import Channel, Runtime
from signing import stored


def build(answers):
    """A runtime whose one channel answers with whatever the test hands it."""
    runtime = object.__new__(Runtime)
    runtime.channels = {"inbox": Channel("inbox", "read-key", "i" * 20, time.time() + 600)}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.logged = []
    runtime.log = lambda line: runtime.logged.append(line)
    runtime.save_state = lambda: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.listener = None
    runtime.ensure_inbox = lambda: runtime.channels["inbox"]
    runtime.publish_presence = lambda force=False: None
    runtime.client = SimpleNamespace(read=lambda w, read_key, after, wait: answers.pop(0))

    return runtime


def test_an_expired_thread_is_not_reported_as_an_empty_inbox():
    runtime = build([(410, {"error": "Thread has expired"})])
    messages = runtime.read()
    attention = runtime.attention_taken()

    assert messages == []
    assert [(a["channel"], a["state"]) for a in attention] == [("inbox", "expired")]
    assert "expired" in attention[0]["what"] and "gone" in attention[0]["what"]
    assert runtime.logged and "expired" in runtime.logged[0]


def test_a_service_that_does_not_answer_is_not_reported_as_an_empty_inbox():
    runtime = build([(503, {"error": "At capacity"})])
    runtime.read()
    attention = runtime.attention_taken()

    assert [(a["channel"], a["state"]) for a in attention] == [("inbox", "unread")]
    assert "503" in attention[0]["what"] and "may be messages waiting" in attention[0]["what"]


def test_a_quiet_inbox_says_nothing_at_all():
    runtime = build([(200, {"messages": []})])

    assert runtime.read() == []
    assert runtime.attention_taken() == []


def test_what_is_taken_once_is_not_taken_twice():
    runtime = build([(410, {}), (410, {})])
    runtime.read()

    assert len(runtime.attention_taken()) == 1
    assert runtime.attention_taken() == []

    runtime.read()

    assert len(runtime.attention_taken()) == 1


def test_the_model_is_told_over_mcp_as_well():
    runtime = build([(410, {}), (200, {"messages": []})])
    result = dispatch(runtime, "aamio_read", {})

    assert result["isError"] is False
    assert result["structuredContent"]["count"] == 0
    assert result["structuredContent"]["attention"][0]["state"] == "expired"

    quiet = dispatch(runtime, "aamio_read", {})

    # Nothing to say, so nothing is said: a quiet inbox stays quiet.
    assert "attention" not in quiet["structuredContent"]


def test_a_read_that_stops_at_its_limit_says_so():
    """It used to say more than that: the cursor had moved past what was cut
    off, so the note was the only trace of ten messages. Now the cursor stops
    with the read, and the note says to read again. tests/test_read_limit.py
    follows the messages themselves."""
    many = [stored("i" * 20, n, '{"n":%d}' % n) for n in range(1, 61)]
    runtime = build([(200, {"messages": many, "next": 60})])
    runtime._open = lambda message: ({"text": "x"}, {"signed": True, "encrypted": False, "format": "json"})
    got = runtime.read(limit=50)
    attention = runtime.attention_taken()

    assert len(got) == 50
    assert runtime.channels["inbox"].after == 50
    assert [(a["channel"], a["state"]) for a in attention] == [("read", "more")]
    assert "10 more" in attention[0]["what"] and "read again" in attention[0]["what"]


def test_a_dead_channel_does_not_eat_the_whole_wait():
    """The first channel used to spend the wait whether or not it answered."""
    asked = []

    def read(w, read_key, after, wait):
        asked.append((w, wait))
        return (410, {}) if w.startswith("d") else (200, {"messages": []})

    runtime = build([])
    runtime.channels = {
        "dead": Channel("dead", "read-key", "d" * 20, time.time() + 600),
        "inbox": Channel("inbox", "read-key", "i" * 20, time.time() + 600),
    }
    runtime.ensure_inbox = lambda: runtime.channels["inbox"]
    runtime.client = SimpleNamespace(read=read)
    runtime.read(wait=25)

    assert asked == [("d" * 20, 25), ("i" * 20, 25)]


def test_a_board_that_did_not_answer_is_not_a_post_that_does_not_exist():
    runtime = build([])
    runtime.client = SimpleNamespace(board_get=lambda post_id: (0, {"error": "no answer"}))

    try:
        runtime.board_get("p" * 20)
        raise AssertionError("a board that did not answer must not look like a missing post")
    except RuntimeError as error:
        assert "unknown" in str(error) and "gone" in str(error)

    runtime.client = SimpleNamespace(board_get=lambda post_id: (404, {"error": "No live post with this id"}))

    assert runtime.board_get("p" * 20) is None


def bare_runtime(channels):
    """A runtime with nothing but channels, the way board_replies is reached."""
    import threading
    from aamio.runtime import Runtime

    runtime = object.__new__(Runtime)
    runtime.channels = channels
    runtime.lock = threading.Lock()
    runtime.log = lambda *args: None
    return runtime


def test_no_replies_while_the_inbox_has_something_says_so():
    """The empty list that sent an agent to hand roll nacl for an hour.

    board replies filters, read does not. When the filter leaves the answer
    empty and there was something to leave out, the caller hears it here
    rather than concluding the other side went quiet.
    """
    from aamio.runtime import Channel

    private = Channel("Arctic Freight", "r", "c" * 20, 2000000000)
    private.received.append({"channel": "Arctic Freight", "at": 5, "verified": True, "sha256": "h1", "body": {"text": "an ordinary message"}})
    runtime = bare_runtime({"Arctic Freight": private})

    assert runtime.board_replies() == []

    attention = runtime.attention_taken()
    assert [(a["channel"], a["state"]) for a in attention] == [("board replies", "filtered")]
    assert "1 message(s) are here" in attention[0]["what"] and "Run read" in attention[0]["what"]


def test_an_unsigned_message_is_counted_as_never_opened():
    """A sealed body with no signature has no sender key to open against, so
    the note says the body was never read rather than leaving it at a count."""
    from aamio.runtime import Channel

    board = Channel("board", "r", "b" * 20, 2000000000)
    board.received.append({"channel": "board", "at": 5, "verified": False, "sha256": "h2", "body": {"text": '{"e2ee":"nacl.box.v1"}'}})
    runtime = bare_runtime({"board": board})

    # It arrived on a board inbox, so it counts as an answer and nothing is noted.
    assert len(runtime.board_replies()) == 1
    assert runtime.attention_taken() == []

    # Asked for one post, it answers none of them, and then the count matters.
    assert runtime.board_replies("p1") == []
    attention = runtime.attention_taken()
    assert "arrived unsigned" in attention[0]["what"] and "p1" in attention[0]["what"]


def test_answers_found_means_no_note():
    """A caller that got what it asked for is not told about the rest of its
    inbox. A note on every call is noise, and noise teaches readers to skip."""
    from aamio.runtime import Channel

    board = Channel("board", "r", "b" * 20, 2000000000)
    board.received.append({"channel": "board", "at": 4, "verified": True, "sha256": "h3", "body": {"post": "p1", "text": "yes"}})
    board.received.append({"channel": "board", "at": 5, "verified": True, "sha256": "h4", "body": {"text": "chatter"}})
    runtime = bare_runtime({"board": board})

    assert len(runtime.board_replies("p1")) == 1
    assert runtime.attention_taken() == []

