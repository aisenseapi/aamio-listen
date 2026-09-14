"""The archive is a record of delivery, and it must not become the delivery.

One message stopped a whole batch. JSON can carry a lone surrogate, Python
parses it into a str without complaint, and UTF-8 cannot encode it, so the
archive raised on the way to disk. The raise happened after the message was
received and understood and before the next one was looked at: the second
message was never delivered and the cursor was never saved, which means it was
re-read and lost again on every poll after that.

It arrives as plain ASCII on the wire, so nothing upstream flags it and any
sender can send it.

These tests write to a real directory, because the failure was in the writing.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio_listen.runtime import Channel, Runtime


@pytest.fixture
def home():
    """Our own directory rather than pytest's, so this runs anywhere."""
    made = tempfile.mkdtemp(prefix="aamio-archive-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


# A raw string: what travels is the seven ASCII characters backslash u d 8 0 0.
SURROGATE = r'{"post":"p1","text":"\ud800"}'
ORDINARY = '{"post":"p1","text":"ordinary answer"}'
NORWEGIAN = '{"post":"p1","text":"hentes på Grünerløkka"}'
# Enough of an envelope for the receiving side to take the sealed branch; the
# opening itself is stubbed, since what is under test is the writing.
SEALED = json.dumps({"e2ee": "nacl.box.v1", "to": "0011aabb", "nonce": "n", "ct": "c"})


def build(home, sealed=None):
    runtime = object.__new__(Runtime)
    channel = Channel("board", "read-key", "b" * 20, 2000000000)
    runtime.channels = {"board": channel}
    runtime.lock = threading.RLock()
    runtime.peers = {}
    runtime.name_for_key = lambda key: None
    runtime.save_state = lambda: None
    runtime.log = lambda text: runtime.logged.append(text)
    runtime.logged = []
    runtime.home = str(home)
    runtime.archive_enabled = True
    os.makedirs(os.path.join(runtime.home, "archive"), exist_ok=True)

    if sealed is not None:
        runtime.keys = SimpleNamespace(open=lambda frm, body: json.dumps(sealed).encode("utf-8"))

    return runtime, channel


def deliver(runtime, channel, bodies):
    messages = [
        {
            "seq": seq,
            "at": seq,
            "verified": True,
            "from": "a-verified-key",
            "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
            "body": body,
        }
        for seq, body in enumerate(bodies, 1)
    ]
    runtime.client = SimpleNamespace(read=lambda *args: (200, {"messages": messages}))

    return runtime.poll(channel)


def read_archive(home):
    path = os.path.join(str(home), "archive", "board.jsonl")

    with open(path, "rb") as handle:
        return handle.read()


def test_a_body_utf8_cannot_encode_does_not_stop_the_batch(home):
    runtime, channel = build(home)
    state, entries = deliver(runtime, channel, [SURROGATE, ORDINARY])

    assert state == "ok"
    assert [entry["seq"] for entry in entries] == [1, 2]
    assert entries[1]["body"]["text"] == "ordinary answer"
    # The cursor is the thing that made this expensive: without it the same
    # message is read again on every poll, forever.
    assert channel.after == 2


def test_both_messages_are_actually_written(home):
    runtime, channel = build(home)
    deliver(runtime, channel, [SURROGATE, ORDINARY])
    written = read_archive(home)

    assert written.count(b"\n") == 2
    # Escaped rather than dropped or replaced: the value is still recoverable
    # by anything that reads the file as JSON.
    assert b"ud800" in written
    assert b"ordinary answer" in written

    for line in written.splitlines():
        json.loads(line.decode("utf-8"))


def test_ordinary_non_english_text_stays_readable(home):
    runtime, channel = build(home)
    deliver(runtime, channel, [NORWEGIAN])
    written = read_archive(home)

    # The reason ensure_ascii=False is there at all. Escaping everything would
    # have fixed the crash and made the file worse to read.
    assert "Grünerløkka".encode("utf-8") in written


def test_the_same_body_sealed(home):
    runtime, channel = build(home, sealed={"post": "p1", "text": "\ud800"})
    state, entries = deliver(runtime, channel, [SEALED])

    assert state == "ok"
    assert entries[0]["archived"] is True
    assert b"ud800" in read_archive(home)


def test_a_real_storage_failure_is_visible_and_costs_nobody_the_batch(home):
    runtime, channel = build(home)

    def refuse(label, record):
        raise OSError(28, "No space left on device")

    runtime.archive = refuse
    state, entries = deliver(runtime, channel, [ORDINARY, ORDINARY + " "])

    assert state == "ok"
    assert len(entries) == 2
    # Not swallowed. Received and archived are two claims, and only one of them
    # is true here.
    assert [entry["archived"] for entry in entries] == [False, False]
    assert "No space left" in entries[0]["archive_error"]
    assert len(runtime.logged) == 2


def test_archiving_off_is_not_a_failure(home):
    runtime, channel = build(home)
    runtime.archive_enabled = False
    state, entries = deliver(runtime, channel, [ORDINARY])

    assert state == "ok"
    assert entries[0]["archived"] is True
    assert not os.path.exists(os.path.join(str(home), "archive", "board.jsonl"))
