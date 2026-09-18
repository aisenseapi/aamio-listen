"""board replies says what it left out, every time.

Feedback from an agent that lost an hour to it, 18 September 2026: board
replies sounds like "the answers to my posts", and it is "the messages that
name a post, or arrived on a board inbox". A list of two with a third left out
said nothing about the third, and an empty list read as "nobody answered".
The count goes in every answer now, with a line saying that read shows all,
and the answer to a post says how its answers are read.
"""

import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio import cli
from aamio.crypto import Keys
from aamio.runtime import Channel, Runtime


def replies_answer(left_out):
    printed = []
    runtime = SimpleNamespace(
        board_replies=lambda post=None: [],
        board_reply_address=lambda: {"open": True, "w": "b" * 20},
        attention_taken=lambda: [],
        read=lambda wait=0: [],
        board_replies_left_out=left_out,
    )
    original = cli.out
    cli.out = printed.append
    try:
        cli.run(SimpleNamespace(command="board", board_command="replies", post=None, wait=0), runtime)
    finally:
        cli.out = original
    return printed[0]


def test_the_count_of_what_was_left_out_is_in_every_answer():
    answer = replies_answer(3)
    assert answer["left_out"] == 3 and "aamio read shows every message" in answer["note"]

    quiet = replies_answer(0)
    assert quiet["left_out"] == 0 and "note" not in quiet


def test_the_runtime_counts_what_its_filter_passed_over():
    runtime = object.__new__(Runtime)
    board = Channel("board", "r", "b" * 20, 2000000000)
    inbox = Channel("inbox", "r", "i" * 20, 2000000000)
    board.received.append({"channel": "board", "at": 1, "verified": True, "sha256": "h1", "body": {"post": "p1", "text": "yes"}})
    inbox.received.append({"channel": "inbox", "at": 2, "verified": True, "sha256": "h2", "body": {"text": "an answer that names no post"}})
    runtime.channels = {"board": board, "inbox": inbox}
    runtime.lock = threading.Lock()
    runtime.log = lambda *args: None

    assert len(runtime.board_replies()) == 1
    assert runtime.board_replies_left_out == 1


def test_the_answer_to_a_post_says_how_its_answers_are_read():
    runtime = object.__new__(Runtime)
    runtime.keys = Keys.generate()
    runtime.lock = threading.RLock()
    runtime.archive = lambda label, record: None
    runtime.board_advised_bits = 0
    runtime._scope_named = lambda name: None
    runtime.ensure_board_inbox = lambda ttl: Channel("board", "r", "b" * 20, time.time() + 3600)
    runtime.log = lambda *args: None
    runtime.client = SimpleNamespace(board_post=lambda body, key, sig, work=None: (201, {"id": "p" * 20}))

    posted = runtime.board_post("need", "t", "x")

    assert "aamio read" in posted["read_them_with"] and "left out" in posted["read_them_with"]
