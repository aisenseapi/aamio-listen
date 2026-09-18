"""A thread at an address can go, and a new one can open at the same address.

Threads live on tmpfs. A restart takes them, and a write to an address whose
thread is gone opens a new one there that counts from one again, with the
default lifetime and none of the old allowlist. Three things went quiet:

  * a read of the missing thread answered 200 with no messages, and nothing
    here looked at exists, so a thread that was gone read as a quiet inbox;
  * once the new thread was open, the old cursor was past everything in it,
    and the reader was shown nothing until the new thread passed the old
    count, so every message before that was never delivered;
  * the service now resets such a cursor and says so, but this runtime kept
    the higher of its cursor and the last seq, asked past the new thread again
    on every call, and would have handed the same messages over each time.
"""

import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime


def build(answers, label="inbox"):
    """A runtime whose one channel answers with whatever the test hands it, and
    which records every cursor it asked with."""
    runtime = object.__new__(Runtime)
    runtime.channels = {label: Channel(label, "read-key", "i" * 20, time.time() + 600)}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.log = lambda line: None
    runtime.save_state = lambda: None
    runtime.archive = lambda label, record: None
    runtime.name_for_key = lambda key: None
    runtime.asked = []

    def read(w, read_key, after, wait):
        runtime.asked.append(after)
        return answers.pop(0)

    runtime.client = SimpleNamespace(read=read)

    return runtime


def message(seq, body="hello"):
    return {"seq": seq, "at": seq, "verified": False, "from": None, "sha256": "h%d-%s" % (seq, body), "body": body}


def test_a_thread_that_is_gone_is_said_once_and_the_cursor_goes_back_to_zero():
    runtime = build([
        (200, {"exists": False, "messages": [], "next": 0, "note": "no thread"}),
        (200, {"exists": False, "messages": [], "next": 0, "note": "no thread"}),
    ])
    channel = runtime.channels["inbox"]
    channel.after = 40
    channel.created_at = 1000
    channel.seen = {"old"}

    state, entries = runtime.poll(channel)
    first = runtime.attention_taken()
    runtime.poll(channel)
    second = runtime.attention_taken()

    assert state == "gone" and entries == []
    assert [(a["channel"], a["state"]) for a in first] == [("inbox", "gone")]
    assert "new inbox is opened" in first[0]["what"]
    # Said when it happens, not on every read after that.
    assert second == []
    assert channel.after == 0 and channel.seen == set() and channel.created_at is None
    assert channel.gone


def test_a_gone_inbox_is_opened_again():
    runtime = build([])
    runtime.channels["inbox"].gone = True
    opened = []
    runtime.client.open_thread = lambda ttl, allow: opened.append((ttl, allow)) or (201, {"expire_at": int(time.time()) + 3600}, "new-read-key", "n" * 20)
    runtime.publish_presence = lambda force=False: None

    fresh = Runtime.ensure_inbox(runtime)

    assert opened and fresh.w == "n" * 20 and runtime.channels["inbox"] is fresh
    # The old address is still read, for whoever writes there anyway.
    assert any(label.startswith("inbox-") for label in runtime.channels)


def test_after_a_reset_the_cursor_is_the_services_next_and_nothing_comes_twice():
    runtime = build([
        (200, {"exists": True, "created_at": 2000, "messages": [message(1), message(2)], "next": 2, "reset": {"after": 40, "newest": 2, "what": "after 40 is past the last message"}}),
        (200, {"exists": True, "created_at": 2000, "messages": [], "next": 2}),
    ])
    channel = runtime.channels["inbox"]
    channel.after = 40
    channel.created_at = 1000

    state, entries = runtime.poll(channel)
    attention = runtime.attention_taken()
    runtime.poll(channel)

    assert state == "ok" and [e["seq"] for e in entries] == [1, 2]
    assert [(a["channel"], a["state"]) for a in attention] == [("inbox", "restarted")]
    # The next read asks from 2, not from 40 again.
    assert runtime.asked == [40, 2]
    assert channel.after == 2 and channel.created_at == 2000
    assert not any(e["replay"] for e in entries)


def test_a_new_thread_that_passed_the_old_cursor_is_read_from_the_start():
    """The case no answer can flag: the new thread already holds more than the
    old cursor, so the service reads past it as asked. Only created_at shows it."""
    runtime = build([
        (200, {"exists": True, "created_at": 3000, "messages": [message(41)], "next": 41}),
        (200, {"exists": True, "created_at": 3000, "messages": [message(n) for n in range(1, 42)], "next": 41}),
    ])
    channel = runtime.channels["inbox"]
    channel.after = 40
    channel.created_at = 1000

    state, entries = runtime.poll(channel)
    attention = runtime.attention_taken()

    assert runtime.asked == [40, 0]
    assert state == "ok" and len(entries) == 41 and entries[0]["seq"] == 1
    assert [(a["channel"], a["state"]) for a in attention] == [("inbox", "restarted")]
    assert channel.after == 41 and channel.created_at == 3000


def test_the_thread_a_channel_knew_is_kept_across_a_restart_of_the_runtime():
    channel = Channel("inbox", "k", "w" * 20, 2000000000, after=5, created_at=1234)
    again = Channel.from_state(channel.to_state())

    assert again.created_at == 1234 and again.after == 5
