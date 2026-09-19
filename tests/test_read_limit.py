"""A read with a limit stops at the limit, and loses nothing by it.

Found on 18 September 2026, in an outside assessment of aamio in use: with 60
messages waiting, `read(limit=50)` handed over 50, the cursor stood at 60, and
the last ten never came back. `read` polled every channel first, and `poll`
moves the cursor and saves it before the caller sees a message, so what `read`
then cut off the end was already behind the cursor. The note about it said the
rest was in the archive, also when the archive was turned off.

The cursor now stops where the handing over stops, and the rest is still at the
service for the next read.
"""

import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime
from signing import keypair, stored

W = "i" * 20
SIDE = "s" * 20


def build(threads, allow=None):
    """A runtime over a service that holds these threads and answers from the cursor it is asked with."""
    runtime = object.__new__(Runtime)
    runtime.channels = {}

    for label, w in (("inbox", W), ("side", SIDE)):
        if w in threads:
            runtime.channels[label] = Channel(label, "read-key", w, time.time() + 600, allow if label == "inbox" else None)

    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.scopes = []
    runtime.log = lambda line: None
    runtime.saved = []
    runtime.save_state = lambda: runtime.saved.append({label: channel.after for label, channel in runtime.channels.items()})
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.listener = None
    runtime.ensure_inbox = lambda: runtime.channels["inbox"]
    runtime.publish_presence = lambda force=False: None
    runtime._open = lambda message: ({"text": message["body"]}, {"signed": bool(message.get("from")), "encrypted": False, "format": "text"})
    runtime.asked = []

    def read(w, read_key, after, wait):
        runtime.asked.append((w, after))
        held = threads[w]
        answer = {"exists": True, "created_at": 1000, "messages": [m for m in held["messages"] if m["seq"] > after]}

        # What the service does when the cursor is past everything it holds:
        # it reads from the start and says so.
        if held["messages"] and after > held["messages"][-1]["seq"]:
            answer["messages"] = list(held["messages"])
            answer["reset"] = {"after": after, "newest": held["messages"][-1]["seq"], "what": "after %d is past the last message" % after}

        answer["next"] = answer["messages"][-1]["seq"] if answer["messages"] else after

        return 200, answer

    runtime.client = SimpleNamespace(read=read)

    return runtime


def numbered(w, first, last, keys=None):
    return [stored(w, n, "message %d" % n, keys) for n in range(first, last + 1)]


def seqs(entries):
    return [entry["seq"] for entry in entries]


def test_sixty_waiting_and_a_limit_of_fifty_is_two_reads_not_ten_lost():
    runtime = build({W: {"messages": numbered(W, 1, 60)}})

    first = runtime.read(limit=50)
    attention = runtime.attention_taken()

    assert seqs(first) == list(range(1, 51))
    assert runtime.channels["inbox"].after == 50, "the cursor stops where the handing over stopped, not at the service's next"
    assert [(a["channel"], a["state"]) for a in attention] == [("read", "more")]
    assert "limit of 50" in attention[0]["what"] and "10 more" in attention[0]["what"] and "Nothing was passed over" in attention[0]["what"]
    assert "archive" not in attention[0]["what"], "the archive is off here, and nothing should be said to be in it"

    second = runtime.read(limit=50)

    assert seqs(second) == list(range(51, 61)), "the ten the first read left are the second read"
    assert runtime.attention_taken() == [], "and a read that got everything has nothing to add"
    assert runtime.read(limit=50) == []


def test_the_cursor_that_is_saved_is_the_one_the_caller_was_given():
    runtime = build({W: {"messages": numbered(W, 1, 60)}})
    runtime.read(limit=50)

    assert runtime.saved and runtime.saved[-1]["inbox"] == 50, "a one-shot command starts the next read from what was saved"


def test_a_channel_there_was_no_room_for_is_not_asked_and_keeps_its_messages():
    runtime = build({W: {"messages": numbered(W, 1, 30)}, SIDE: {"messages": numbered(SIDE, 1, 30)}})

    first = runtime.read(limit=30)
    attention = runtime.attention_taken()

    assert [(entry["channel"], entry["seq"]) for entry in first] == [("inbox", n) for n in range(1, 31)]
    assert [w for w, after in runtime.asked] == [W], "the second channel was never asked, so its cursor cannot have moved"
    assert runtime.channels["side"].after == 0
    assert [(a["channel"], a["state"]) for a in attention] == [("read", "more")] and "side" in attention[0]["what"]

    second = runtime.read(limit=30)

    assert [(entry["channel"], entry["seq"]) for entry in second] == [("side", n) for n in range(1, 31)]


def test_the_room_left_by_one_channel_is_what_the_next_is_asked_for():
    runtime = build({W: {"messages": numbered(W, 1, 30)}, SIDE: {"messages": numbered(SIDE, 1, 30)}})

    first = runtime.read(limit=50)

    assert len(first) == 50 and seqs(first)[30:] == list(range(1, 21))
    assert runtime.channels["inbox"].after == 30 and runtime.channels["side"].after == 20
    assert seqs(runtime.read(limit=50)) == list(range(21, 31))


def test_a_message_the_list_kept_out_does_not_count_against_the_limit_and_is_not_read_twice():
    alice, stranger = keypair(1), keypair(9)
    held = [stored(W, 1, "one", alice), stored(W, 2, "from a stranger", stranger), stored(W, 3, "three", alice), stored(W, 4, "four", alice)]
    runtime = build({W: {"messages": held}}, allow=[alice.public])

    first = runtime.read(limit=2)
    attention = {a["state"]: a for a in runtime.attention_taken()}

    assert seqs(first) == [1, 3]
    assert runtime.channels["inbox"].after == 3, "past the one that was kept out, and not past the one that was never looked at"
    assert attention["kept_out"]["seqs"] == [2] and "1 more" in attention["more"]["what"]

    second = runtime.read(limit=2)

    assert seqs(second) == [4]
    assert "kept_out" not in {a["state"] for a in runtime.attention_taken()}, "seq 2 was dealt with once"


def test_a_thread_read_from_the_start_again_stops_at_the_limit_too():
    runtime = build({W: {"messages": numbered(W, 1, 60)}})
    runtime.channels["inbox"].after = 90
    runtime.channels["inbox"].created_at = 1000

    first = runtime.read(limit=50)

    assert seqs(first) == list(range(1, 51))
    assert runtime.channels["inbox"].after == 50, "neither the old cursor of 90 nor the service's next of 60"
    assert seqs(runtime.read(limit=50)) == list(range(51, 61))


def test_poll_without_a_limit_reads_everything_as_before():
    runtime = build({W: {"messages": numbered(W, 1, 60)}})
    state, entries = runtime.poll(runtime.channels["inbox"])

    assert state == "ok" and len(entries) == 60 and runtime.channels["inbox"].after == 60
    assert runtime.channels["inbox"].left_waiting == 0
