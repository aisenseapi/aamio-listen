"""A real answer reached a real agent and was never seen, and the silence got blamed on the sender.

What happened, from the logs: an answer went out at 13:11:39 carrying a return
address that closed at 13:27:39. The poster's agent read it at 13:35:35, eight
minutes after the door shut, and could not write back. Everything about the
delivery worked. Two people then spent an afternoon concluding the sender had
withheld their public key, which was never true.

Three separate faults, and each on its own was enough to produce that.

1. The address on an answer lived sixteen minutes while the post it answered
   could live sixty. The service already refuses a *post* whose reply address
   is shorter than the post -- "a post whose address is dead reaches nobody" --
   and our own client broke the same rule in the other direction, unchecked.

2. `board replies` read only what the current process had polled. The command
   line is one process per call, so an answer that arrived earlier was past the
   cursor and invisible, though it was in the archive the whole time.

3. An empty result looked identical whether nobody wrote back or nobody could.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio.runtime import ANSWER_MARGIN, Channel, Runtime


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-window-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def build(home, board_expire=None):
    runtime = object.__new__(Runtime)
    runtime.host = "https://aamio.test"
    runtime.home = home
    runtime.lock = threading.RLock()
    runtime.channels = {}
    runtime.peers = {}
    runtime.archive_enabled = True
    runtime.logged = []
    runtime.log = lambda text: runtime.logged.append(text)
    runtime.save_state = lambda: None
    runtime.keys = SimpleNamespace(public="our-key", hash="0" * 64, seal=lambda key, plaintext: "sealed", sign=lambda text: "sig")
    runtime.listener = None
    runtime.outbox = {}
    runtime.save_outbox = lambda: None
    runtime.archive = lambda label, record: None
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)

    if board_expire is not None:
        runtime.channels["board"] = Channel("board", "read", "b" * 20, board_expire)

    return runtime


def opened(runtime):
    """The ttl the client asked the service for, without a service."""
    asked = {}

    def open_thread(ttl, allow):
        asked["ttl"] = ttl
        return 201, {"expire_at": time.time() + ttl}, "read-key", "n" * 20

    runtime.client = SimpleNamespace(open_thread=open_thread, post=lambda *a: (201, {"seq": 1, "at": 1}))

    return asked


def answer_a_post_lasting(runtime, seconds):
    post = {
        "id": "p1",
        "w": "w" * 20,
        "key": "their-key",
        "expire_at": int(time.time()) + seconds,
    }
    runtime.board_answer(post, "an answer")

    return post


def test_the_reply_address_outlives_the_post_it_answers(home):
    runtime = build(home)
    asked = opened(runtime)
    post = answer_a_post_lasting(runtime, 1800)

    # Sixteen minutes was the old answer for every post, however long it lived.
    assert asked["ttl"] > 1800
    assert runtime.channels["board"].expire_at > post["expire_at"]


def test_a_longer_post_gets_a_longer_address(home):
    short = build(home)
    short_asked = opened(short)
    answer_a_post_lasting(short, 300)

    long = build(home)
    long_asked = opened(long)
    answer_a_post_lasting(long, 3000)

    assert long_asked["ttl"] > short_asked["ttl"]
    assert short_asked["ttl"] >= 300 + ANSWER_MARGIN


def test_an_address_that_already_outlives_the_post_is_reused(home):
    runtime = build(home, board_expire=time.time() + 9000)
    asked = opened(runtime)
    answer_a_post_lasting(runtime, 600)

    # No new thread opened: the one we have is good for far longer.
    assert "ttl" not in asked


def test_an_answer_that_cannot_be_covered_says_so(home):
    runtime = build(home)

    def open_thread(ttl, allow):
        # A service that gives less than asked for, which is its right.
        return 201, {"expire_at": time.time() + 120}, "read-key", "n" * 20

    runtime.client = SimpleNamespace(open_thread=open_thread, post=lambda *a: (201, {"seq": 1, "at": 1}))
    answer_a_post_lasting(runtime, 1800)

    assert any("expires" in line and "before the post" in line for line in runtime.logged)


# --------------------------------------------------------------- replies ---


def archive_an_answer(home, post_id="p1", text="the answer nobody saw"):
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)
    record = {
        "kind": "received",
        "channel": "board",
        "seq": 1,
        "at": 1789470699,
        "verified": True,
        "known_contact": False,
        "from_key": "their-key",
        "sender": "unknown key",
        "sha256": "a" * 64,
        "body": {"post": post_id, "reply_to": "r" * 20, "text": text},
    }

    with open(os.path.join(home, "archive", "board.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def test_an_answer_from_an_earlier_process_is_still_found(home):
    archive_an_answer(home)
    # A fresh process: nothing in memory, cursor already past the message.
    runtime = build(home, board_expire=time.time() + 600)
    replies = runtime.board_replies("p1")

    assert len(replies) == 1
    assert replies[0]["body"]["text"] == "the answer nobody saw"
    assert replies[0]["from_archive"] is True


def test_the_same_answer_is_not_counted_twice(home):
    archive_an_answer(home)
    runtime = build(home, board_expire=time.time() + 600)
    runtime.channels["board"].received = [
        {"channel": "board", "seq": 1, "at": 1789470699, "sha256": "a" * 64,
         "body": {"post": "p1", "text": "the answer nobody saw"}}
    ]
    replies = runtime.board_replies("p1")

    assert len(replies) == 1
    # The live one wins, so nothing says it came from the archive.
    assert "from_archive" not in replies[0]


def test_answers_to_other_posts_are_left_alone(home):
    archive_an_answer(home, post_id="p2")
    runtime = build(home, board_expire=time.time() + 600)

    assert runtime.board_replies("p1") == []
    assert len(runtime.board_replies("p2")) == 1
    assert len(runtime.board_replies()) == 1


def test_archiving_turned_off_is_not_an_error(home):
    archive_an_answer(home)
    runtime = build(home, board_expire=time.time() + 600)
    runtime.archive_enabled = False

    assert runtime.board_replies("p1") == []


# --------------------------------------------------------------- address ---


def test_an_open_address_says_how_long_it_has(home):
    runtime = build(home, board_expire=time.time() + 300)
    where = runtime.board_reply_address()

    assert where["open"] is True
    assert 290 <= where["seconds_left"] <= 300


def test_a_closed_address_says_when_it_closed(home):
    runtime = build(home, board_expire=time.time() - 480)
    where = runtime.board_reply_address()

    assert where["open"] is False
    # The sentence that would have saved an afternoon.
    assert "does not mean nobody wrote back" in where["why"]
    assert "480" in where["why"]


def test_no_address_at_all_is_its_own_answer(home):
    runtime = build(home)
    where = runtime.board_reply_address()

    assert where["open"] is False and where["w"] is None
    assert "No board inbox" in where["why"]
