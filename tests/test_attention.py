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
