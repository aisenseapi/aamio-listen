"""After close, this runtime writes nothing more.

From an outside assessment of aamio in use, 18 September 2026 (AAM-026). The
pollers are daemon threads in a long poll of up to twenty seconds. close()
saved, released the home and returned, and a poller that came back afterwards
moved its cursor, saved state.json and wrote to the archive, in a home the next
process might already hold. And the messages it had just read went into a
queue nobody would read again, behind a cursor that had moved past them.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime
from signing import stored

W = "i" * 20


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-shutdown-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def test_a_poller_that_comes_back_after_close_writes_nothing(home):
    runtime = Runtime(home=home)
    channel = Channel("inbox", "read-key", W, time.time() + 600)
    runtime.channels["inbox"] = channel
    runtime.save_state()
    asked, answer = threading.Event(), threading.Event()

    def read(w, read_key, after, wait):
        asked.set()
        answer.wait(10)

        return 200, {"exists": True, "created_at": 1, "messages": [stored(W, 1, "arrived late", None)], "next": 1}

    runtime.client.read = read
    runtime._start_poller(channel)
    poller = channel.poller
    assert asked.wait(5), "the poller never asked"

    began = time.time()
    runtime.close()
    assert time.time() - began < 5, "close waits for its threads a moment, not for a long poll to end"

    before = open(os.path.join(home, "state.json"), encoding="utf-8").read()
    answer.set()
    poller.join(5)

    assert not poller.is_alive()
    assert open(os.path.join(home, "state.json"), encoding="utf-8").read() == before, "state.json was written after the home was let go"
    assert json.loads(before)["channels"][0]["after"] == 0, "so the next process reads that message: nothing took it"
    assert not os.path.exists(os.path.join(home, "archive", "inbox.jsonl")), "and nothing was archived after close"


def test_close_waits_for_a_thread_that_is_about_to_finish(home):
    """Not for a long poll to end: for the moment a thread is in the middle of
    writing. Without the wait, close returned while a poller still held the
    home, and what it wrote afterwards was refused rather than finished."""
    runtime = Runtime(home=home)
    channel = Channel("inbox", "read-key", W, time.time() + 600)
    runtime.channels["inbox"] = channel
    asked, done = threading.Event(), []

    def read(w, read_key, after, wait):
        asked.set()
        time.sleep(0.3)
        done.append(True)

        return 200, {"exists": True, "created_at": 1, "messages": [], "next": 0}

    runtime.client.read = read
    runtime._start_poller(channel)
    poller = channel.poller
    assert asked.wait(5)
    runtime.close()

    assert done, "close returned while the poller was still in the middle of a read"
    assert not poller.is_alive()


def test_close_is_said_once_and_a_second_runtime_can_take_the_home_at_once(home):
    first = Runtime(home=home)
    first.close()
    first.close()
    second = Runtime(home=home)

    try:
        assert second.owns_lock
    finally:
        second.close()


def test_what_an_interrupted_write_left_behind_is_cleared_and_the_file_it_was_to_replace_is_whole(home):
    first = Runtime(home=home)
    first.channels["inbox"] = Channel("inbox", "read-key", W, time.time() + 600)
    first.save_state()
    first.close()

    with open(os.path.join(home, "state.json.tmp"), "w", encoding="utf-8") as handle:
        handle.write('{"channels": [{"label": "inb')

    second = Runtime(home=home)

    try:
        assert second.channels["inbox"].read_key == "read-key"
        assert not os.path.exists(os.path.join(home, "state.json.tmp"))
    finally:
        second.close()


def test_a_torn_last_line_in_the_archive_costs_that_line_only(home):
    runtime = Runtime(home=home)

    try:
        runtime.archive("board", {"kind": "received", "at": 1, "body": {"post": "p1", "text": "whole"}})

        with open(os.path.join(home, "archive", "board.jsonl"), "a", encoding="utf-8") as handle:
            handle.write('{"kind": "received", "at": 2, "body": {"post": "p1", "te')

        assert [record["body"]["text"] for record in runtime._archived("board", "received")] == ["whole"]
        runtime.archive("board", {"kind": "received", "at": 3, "body": {"post": "p1", "text": "after"}})
        assert [record["body"]["text"] for record in runtime._archived("board", "received")][-1] == "after"
    finally:
        runtime.close()
