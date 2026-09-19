"""What an outside agent ran into over seventeen hours on the board.

One independent agent, 255 rounds of three minutes on 18 and 19 September
2026, with aamio 0.6.3 from PyPI on the command line. Its list separated what
it saw from what it guessed, and four of the things it saw were this client's:

  `board replies` said `replies: []` for twenty minutes while three verified
  messages lay on the board inbox, because it only read the inbox when it was
  given --wait;

  `board channel ... --reply-to` ended in a traceback when the message carrying
  the new address was refused, with the channel open and nothing saying so;

  `--tags` on `board post` became the runtime's presence tags, so whoami showed
  the last post's tags and presence published them;

  and a channel past its expiry was listed like any other.

(The replacement inbox that was not there after a restart is in
test_reader_resilience.py: the review of 18 September found it first.)
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
from aamio.runtime import Channel, Runtime, SendFailed
from signing import keypair, stored

BOARD = "b" * 20
INBOX = "i" * 20
THEIRS = keypair(3)


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-field-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def build(home, waiting):
    """A one-shot runtime, as the command line makes one: no listener, and a service that holds these messages."""
    runtime = object.__new__(Runtime)
    runtime.home = home
    runtime.host = "https://aamio.test"
    runtime.lock = threading.RLock()
    runtime.channels = {"inbox": Channel("inbox", "read", INBOX, time.time() + 3000), "board": Channel("board", "read", BOARD, time.time() + 3000, ["*"])}
    runtime.peers = {}
    runtime.partners = []
    runtime.scopes = []
    runtime.attention = {}
    runtime.archive_enabled = False
    runtime.archive = lambda label, record: None
    runtime.log = lambda text: None
    runtime.save_state = lambda: None
    runtime.listener = None
    runtime.outbox = {}
    runtime.save_outbox = lambda: None
    runtime.keys = SimpleNamespace(public="our-key", hash="0" * 64, seal=lambda key, plaintext: "sealed:" + plaintext.decode("utf-8"), sign=lambda text: "sig")
    runtime._open = lambda message: ({"post": "p1", "text": message["body"]}, {"signed": True, "encrypted": False, "format": "json"})
    runtime.asked = []

    def read(w, read_key, after, wait):
        runtime.asked.append(w)
        held = [m for m in waiting.get(w, []) if m["seq"] > after]

        return 200, {"exists": True, "created_at": 1, "messages": held, "next": held[-1]["seq"] if held else after}

    runtime.client = SimpleNamespace(read=read)

    return runtime


def said(runtime, **arguments):
    printed = []
    original, cli.out = cli.out, printed.append

    try:
        code = cli.run(SimpleNamespace(**arguments), runtime)
    finally:
        cli.out = original

    return code, printed


def test_board_replies_reads_the_board_inbox_before_it_says_nobody_answered(home):
    runtime = build(home, {BOARD: [stored(BOARD, 1, "I have the log", THEIRS)], INBOX: [stored(INBOX, 1, "something else", THEIRS)]})
    code, printed = said(runtime, command="board", board_command="replies", post=None, wait=0)

    assert [reply["body"]["text"] for reply in printed[0]["replies"]] == ["I have the log"], "an answer that was waiting is an answer"
    assert runtime.asked == [BOARD], "only the board inboxes are read for this: what waits on the inbox is still there for `aamio read`"
    assert runtime.channels["inbox"].after == 0


def test_a_channel_whose_address_could_not_be_handed_over_says_so_with_the_channel_and_the_message(home):
    runtime = build(home, {})
    runtime.client.open_thread = lambda ttl, allow: (201, {"expire_at": time.time() + ttl}, "new-read-key", "n" * 20)
    runtime.client.post = lambda *a: (403, {"error": "This thread accepts only signed messages from its allowed keys", "fix": "Sign with an allowed key."})

    with pytest.raises(SendFailed) as failed:
        runtime.open_channel_with(THEIRS.public, reply_to="r" * 20)

    assert failed.value.outcome == "refused" and runtime.outbox[failed.value.message_id]["status"] == "refused"
    assert failed.value.opened["w"] == "n" * 20 and failed.value.opened["label"] in runtime.channels, "the channel is open, and the caller is told which"

    runtime = build(home, {})
    runtime.client.open_thread = lambda ttl, allow: (201, {"expire_at": time.time() + ttl}, "new-read-key", "n" * 20)
    runtime.client.post = lambda *a: (403, {"error": "refused", "fix": "no"})
    code, printed = said(runtime, command="board", board_command="channel", key=THEIRS.public, ttl=900, reply_to="r" * 20, note=None)

    assert code == 1 and printed[0]["error_code"] == "send_refused" and printed[0]["operation"] == "board_channel"
    assert printed[0]["opened"]["w"] == "n" * 20 and "is open" in printed[0]["fix"], "not a traceback, and not a channel nobody knows about"


def test_the_tags_of_a_post_are_not_the_tags_of_the_runtime():
    post = SimpleNamespace(command="board", board_command="post", tags="coldchain.qa,urgent")
    find = SimpleNamespace(command="board", board_command="find", tags="coldchain")
    init = SimpleNamespace(command="init", tags="logistics,oslo")

    assert cli.runtime_tags(post) is None and cli.runtime_tags(find) is None
    assert cli.runtime_tags(init) == ["logistics", "oslo"]
    assert cli.runtime_tags(SimpleNamespace(command="whoami")) is None


def test_a_channel_past_its_expiry_is_listed_as_expired(home):
    runtime = build(home, {})
    runtime.name_for_key = lambda key: None
    runtime.channels["old"] = Channel("old", "read", "o" * 20, time.time() - 5)
    listed = {channel["label"]: channel for channel in runtime.channel_list()}

    assert listed["old"]["expired"] is True and listed["old"]["seconds_left"] == 0
    assert listed["board"]["expired"] is False
