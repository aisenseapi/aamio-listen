"""Scopes: board posts kept unlisted for a group, with the key kept out of the model's hands.

The board holds nothing about a scope but the address on each post. The key is
the read capability and the address derived from it the write capability. This
runtime gives each scope a name, keeps the key in scopes.json, passes it to a
partner sealed, and takes it out of every message before anyone reads it, so a
model works with names only.

A second health check on 17 September 2026 went at it as an attacker would,
and the tests from "a scope is shared only" down are what it found: the key
could be shared with any address a post named, it was written to the archive
of sent messages, a scopes.json that did not parse lost every key on the next
save, a replayed share brought a removed scope back, a partner could take a
name before it was made here, and a key survived in aamio_scope of any shape
but one.
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

from aamio.crypto import board_signing_input, key_hash
from aamio.client import is_scope_address, is_scope_key, make_scope_key, scope_address, write_address
from aamio.mcp_server import INSTRUCTIONS, TOOLS, dispatch, safely
from aamio.runtime import Channel, Runtime
from signing import keypair, stored

# A partner with a real key, for the reads that go through poll: the reader
# verifies the signature itself, and a share is only taken from a partner.
PARTNER = keypair(4)

VECTOR_KEY = "aamioscopevector0000000000"
VECTOR_ADDRESS = "2o3wek6doqhqatib63vj"
ALICE = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
BOB = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
STRANGER = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-scopes-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def build(home):
    runtime = object.__new__(Runtime)
    runtime.host = "https://aamio.test"
    runtime.home = home
    runtime.lock = threading.RLock()
    runtime.channels = {"board": Channel("board", "read", "b" * 20, time.time() + 3600, ["*"])}
    runtime.peers = {}
    runtime.partners = [{"name": "alice", "key": ALICE}]
    runtime.scopes = []
    runtime.scopes_aside = []
    runtime.archive_enabled = True
    runtime.archived = []
    runtime.archive = lambda label, record: runtime.archived.append((label, json.loads(json.dumps(record))))
    runtime.logged = []
    runtime.log = lambda text: runtime.logged.append(text)
    runtime.save_state = lambda: None
    runtime.signed = []
    runtime.sealed = []
    runtime.keys = SimpleNamespace(public="our-key", hash="0" * 64, seal=lambda key, plaintext: runtime.sealed.append((key, plaintext.decode("utf-8"))) or "sealed", sign=lambda text: runtime.signed.append(text) or "sig")
    runtime.listener = None
    runtime.board_advised_bits = 0
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)

    return runtime


def sending(home):
    """A runtime whose sends run the real path up to the network."""
    runtime = build(home)
    runtime.channels["inbox"] = Channel("inbox", "read", "i" * 20, time.time() + 3600)
    runtime.outbox = {}
    runtime.gates = {}
    runtime.client = SimpleNamespace(gate=lambda w: (404, None))
    runtime.address_for = lambda name: ("a" * 20, runtime.partner_by_name(name)["key"])
    runtime._post = lambda w, envelope, notes, entry=None: (201, {"seq": 1, "at": 1, "sha256": "s" * 64, "expire_at": 2})

    return runtime


def test_the_address_is_the_shared_vector_and_never_a_thread_address():
    assert scope_address(VECTOR_KEY) == VECTOR_ADDRESS
    assert write_address(VECTOR_KEY) == "ysmkpshwyvliz4muxuri"


def test_a_new_key_has_the_form_and_an_address_is_never_a_key():
    key = make_scope_key()

    assert is_scope_key(key) and len(key) == 26
    assert is_scope_address(scope_address(key))
    assert not is_scope_key(scope_address(key))
    assert not is_scope_address(key)
    assert make_scope_key() != key
    assert not is_scope_key(VECTOR_KEY + "\n") and not is_scope_address(VECTOR_ADDRESS + "\n")


def test_a_new_scope_keeps_its_key_on_this_machine_only(home):
    runtime = build(home)
    made = runtime.scope_new("chapter-review")
    stored = json.load(open(os.path.join(home, "scopes.json"), encoding="utf-8"))

    assert made == {"name": "chapter-review", "address": scope_address(stored[0]["key"]), "can_read": True}
    assert is_scope_key(stored[0]["key"])
    assert stored[0]["key"] not in json.dumps(runtime.scope_list())
    assert runtime.scope_key("chapter-review")["key"] == stored[0]["key"]

    with pytest.raises(ValueError):
        runtime.scope_new("chapter-review")

    with pytest.raises(ValueError):
        runtime.scope_new("no spaces")


def test_the_scopes_survive_a_restart(home):
    first = Runtime(home=home)

    try:
        made = first.scope_new("team")
    finally:
        first.close()

    second = Runtime(home=home)

    try:
        assert second.scope_list() == [made]
    finally:
        second.close()


def test_an_address_alone_posts_but_does_not_read_until_the_key_arrives(home):
    runtime = build(home)

    assert runtime.scope_add("inbound", address=VECTOR_ADDRESS) == {"name": "inbound", "address": VECTOR_ADDRESS, "can_read": False}

    with pytest.raises(ValueError, match="post only"):
        runtime.board_find(scope="inbound")

    with pytest.raises(ValueError):
        runtime.scope_key("inbound")

    assert runtime.scope_add("inbound", key=VECTOR_KEY)["can_read"] is True
    assert runtime.scope_add("elsewhere", key=VECTOR_KEY)["name"] == "inbound"

    with pytest.raises(ValueError, match="another address"):
        runtime.scope_add("inbound", key=make_scope_key())

    with pytest.raises(ValueError, match="does not give that address"):
        runtime.scope_add("mixed", key=make_scope_key(), address=VECTOR_ADDRESS)

    with pytest.raises(ValueError):
        runtime.scope_add("wrong", key=VECTOR_ADDRESS)


def test_a_post_carries_the_address_inside_what_is_signed(home):
    runtime = build(home)
    runtime.scope_add("team", key=VECTOR_KEY)
    sent = {}

    def board_post(body, key, signature, work):
        sent["body"] = body
        return 201, {"id": "p" * 20, "scope": VECTOR_ADDRESS}

    runtime.client = SimpleNamespace(board_post=board_post)
    posted = runtime.board_post("need", "Chapter 3 draft ready", "At commit 4f2a9c1.", ["chapter-03"], 900, scope="team")

    assert json.loads(sent["body"])["scope"] == VECTOR_ADDRESS
    assert "scope_key" not in sent["body"] and VECTOR_KEY not in sent["body"]
    assert board_signing_input("our-key", sent["body"]) in runtime.signed
    assert posted["scope"] == "team"

    with pytest.raises(LookupError):
        runtime.board_post("need", "t", "x", scope="nobody")


def test_a_find_sends_the_key_in_the_body_and_believes_only_an_answer_that_names_the_scope(home):
    runtime = build(home)
    runtime.scope_add("team", key=VECTOR_KEY)
    asked = {}

    def answering(answer):
        def board_find(body, wait):
            asked["body"] = body
            return answer
        return board_find

    runtime.client = SimpleNamespace(board_find=answering((200, {"count": 1, "live": 1, "next": 3, "posts": [{"id": "p" * 20, "w": "w" * 20, "key": "k"}], "scope": VECTOR_ADDRESS})))
    found = runtime.board_find(tags=["chapter-03"], scope="team")

    assert asked["body"]["scope_key"] == VECTOR_KEY
    assert found["scope_name"] == "team" and found["count"] == 1

    runtime.client = SimpleNamespace(board_find=answering((200, {"count": 0, "live": 0, "next": 0, "posts": []})))

    with pytest.raises(RuntimeError, match="did not say it read scope team"):
        runtime.board_find(scope="team")

    runtime.client = SimpleNamespace(board_find=answering((400, {"error": "Unknown field scope_key", "fix": "Drop that field"})))

    with pytest.raises(RuntimeError, match="Unknown field scope_key"):
        runtime.board_find(scope="team")


def test_a_post_in_a_scope_is_answered_through_the_scope(home):
    runtime = build(home)
    runtime.scope_add("team", key=VECTOR_KEY)
    post = {"id": "p" * 20, "w": "w" * 20, "key": "their-key", "expire_at": int(time.time()) + 600}
    runtime.client = SimpleNamespace(board_find=lambda body, wait: (200, {"count": 1, "live": 1, "next": 1, "posts": [post], "scope": VECTOR_ADDRESS}), board_get=lambda post_id: (404, {"error": "No live post with this id"}))
    runtime._post = lambda w, envelope, notes, entry=None: (201, {"seq": 1, "at": 1})

    assert runtime.board_answer("p" * 20, "I can read it tonight", scope="team")["post"] == "p" * 20

    with pytest.raises(LookupError, match="found with the scope's name"):
        runtime.board_answer("p" * 20, "without the scope")


def test_an_answer_in_a_scope_finds_its_post_past_the_first_page(home):
    runtime = build(home)
    runtime.scope_add("team", key=VECTOR_KEY)
    wanted = {"id": "q" * 20, "w": "w" * 20, "key": "their-key", "expire_at": int(time.time()) + 600}
    pages = {
        0: {"count": 200, "live": 201, "next": 200, "posts": [{"id": "p%019d" % n} for n in range(200)], "scope": VECTOR_ADDRESS},
        200: {"count": 1, "live": 201, "next": 201, "posts": [wanted], "scope": VECTOR_ADDRESS},
    }
    runtime.client = SimpleNamespace(board_find=lambda body, wait: (200, pages[body["after"]]), board_get=lambda post_id: (404, {}))
    runtime._post = lambda w, envelope, notes, entry=None: (201, {"seq": 1, "at": 1})

    assert runtime.board_answer("q" * 20, "Found it on the second page", scope="team")["post"] == "q" * 20


def test_a_scope_is_shared_only_with_a_partner_and_never_with_an_address(home):
    runtime = sending(home)
    runtime.scope_add("team", key=VECTOR_KEY)
    runtime.scope_add("drop", address=scope_address(make_scope_key()))
    # Learned from a board post: an address and a key, and nobody in the book.
    runtime.peers["s" * 20] = STRANGER

    for to in ("s" * 20, STRANGER, "mallory"):
        with pytest.raises(ValueError, match="only with a partner"):
            runtime.scope_share("team", to, "read")

    assert runtime.sealed == [] and runtime.outbox == {}

    shared = runtime.scope_share("team", "alice", "read")

    assert runtime.sealed[-1][0] == ALICE and json.loads(runtime.sealed[-1][1])["data"] == {"aamio_scope": {"name": "team", "key": VECTOR_KEY}}
    assert VECTOR_KEY not in json.dumps(shared) and shared["access"] == "read" and shared["scope"] == "team"
    assert runtime.scope_share("team", ALICE, "write") and json.loads(runtime.sealed[-1][1])["data"] == {"aamio_scope": {"name": "team", "address": VECTOR_ADDRESS}}

    # A partner named like an address is still that partner, never the address.
    runtime.partners.append({"name": "b" * 20, "key": BOB})
    runtime.peers["b" * 20] = STRANGER
    runtime.scope_share("team", "b" * 20, "read")

    assert runtime.sealed[-1][0] == BOB

    with pytest.raises(ValueError, match="post only"):
        runtime.scope_share("drop", "alice", "read")

    with pytest.raises(ValueError):
        runtime.scope_share("team", "alice", "all")


def test_the_archive_of_sent_messages_says_what_was_shared_and_never_holds_the_key(home):
    runtime = sending(home)
    runtime.scope_add("team", key=VECTOR_KEY)
    runtime.scope_share("team", "alice", "read")
    sent = [record for label, record in runtime.archived if label == "sent"]

    assert len(sent) == 1 and sent[0]["body"]["data"] == {"aamio_scope": {"name": "team", "access": "read"}}
    assert VECTOR_KEY not in json.dumps(runtime.archived)
    assert VECTOR_KEY not in open(os.path.join(home, "outbox.json"), encoding="utf-8").read()


def incoming(key=VECTOR_KEY, name="team", **facts):
    entry = {"verified": True, "encrypted": True, "known_contact": True, "from_key": ALICE, "replay": False, "body": {"from": "abcd1234", "text": "Scope " + name, "data": {"aamio_scope": {"name": name, "key": key}}}}
    entry.update(facts)
    return entry


def test_a_scope_from_a_partner_is_kept_under_the_partners_name_and_the_key_leaves_the_message(home):
    runtime = build(home)
    entry = incoming()
    runtime._take_scope_share(entry)

    assert entry["body"]["data"]["aamio_scope"] == {"shared_as": "team", "name": "alice.team", "address": VECTOR_ADDRESS, "can_read": True, "kept": True}
    assert VECTOR_KEY not in json.dumps(entry)
    assert runtime.scope_key("alice.team")["key"] == VECTOR_KEY


def test_a_partner_cannot_take_a_name_before_it_is_made_here(home):
    runtime = build(home)
    runtime._take_scope_share(incoming(name="review"))
    made = runtime.scope_new("review")

    assert made["name"] == "review" and made["address"] != VECTOR_ADDRESS
    assert [scope["name"] for scope in runtime.scope_list()] == ["alice.review", "review"]


@pytest.mark.parametrize("partner, prefix", [("Bea Ødegård", "Bea-deg-rd"), ("--x..y__", "x..y"), ("0", "0"), ("李明", None), ("a" * 30, "a" * 24)])
def test_the_partner_part_of_a_name_is_made_of_what_a_name_may_hold(home, partner, prefix):
    runtime = build(home)
    runtime.partners = [{"name": partner, "key": ALICE}]

    assert runtime._shared_scope_name(runtime.partners[0], "team") == "%s.team" % (prefix or key_hash(ALICE)[:8])
    assert runtime._shared_scope_name(runtime.partners[0], "t" * 64) == ("%s.%s" % (prefix or key_hash(ALICE)[:8], "t" * 64))[:64]


def test_a_share_seen_before_does_not_bring_a_removed_scope_back(home):
    runtime = build(home)
    runtime._take_scope_share(incoming())
    runtime.scope_remove("alice.team")
    again = incoming(replay=True)
    runtime._take_scope_share(again)

    assert again["body"]["data"]["aamio_scope"]["kept"] is False and "arrived before" in again["body"]["data"]["aamio_scope"]["note"]
    assert runtime.scope_list() == [] and VECTOR_KEY not in json.dumps(again)


@pytest.mark.parametrize("facts", [{"known_contact": False}, {"encrypted": False}, {"verified": False}, {"from_key": STRANGER}, {"from_key": None}])
def test_a_scope_from_a_stranger_or_in_the_clear_is_not_kept_and_the_key_still_leaves(home, facts):
    runtime = build(home)
    entry = incoming(**facts)
    runtime._take_scope_share(entry)

    assert entry["body"]["data"]["aamio_scope"]["kept"] is False
    assert "not kept" in entry["body"]["data"]["aamio_scope"]["note"]
    assert VECTOR_KEY not in json.dumps(entry)
    assert runtime.scope_list() == []


@pytest.mark.parametrize("body", [
    {"text": "t", "aamio_scope": {"name": "team", "key": VECTOR_KEY}},
    {"text": "t", "data": {"aamio_scope": VECTOR_KEY}},
    {"text": "t", "data": {"aamio_scope": [VECTOR_KEY]}},
    {"text": "t", "aamio_scope": VECTOR_KEY, "data": {"aamio_scope": "team " + VECTOR_KEY}},
])
def test_a_key_in_aamio_scope_is_taken_out_whatever_its_shape_and_wherever_it_sits(home, body):
    runtime = build(home)
    entry = incoming()
    entry["body"] = body
    runtime._take_scope_share(entry)

    assert VECTOR_KEY not in json.dumps(entry)
    assert runtime.scope_list() == []


def test_the_key_is_gone_before_the_message_is_archived(home):
    runtime = build(home)
    runtime.partners = [{"name": "alice", "key": PARTNER.public}]
    channel = Channel("inbox", "read", "i" * 20, time.time() + 600)
    runtime.client = SimpleNamespace(read=lambda w, read_key, after, wait: (200, {"messages": [stored("i" * 20, 1, "sealed", PARTNER)]}))
    runtime._open = lambda message: ({"from": "abcd1234", "text": "Scope team", "data": {"aamio_scope": {"name": "team", "key": VECTOR_KEY}}}, {"signed": True, "encrypted": True, "format": "json"})

    state, entries = runtime.poll(channel)

    assert state == "ok" and entries[0]["body"]["data"]["aamio_scope"]["kept"] is True
    assert VECTOR_KEY not in json.dumps(entries) and VECTOR_KEY not in json.dumps(runtime.archived)
    assert VECTOR_KEY not in json.dumps(channel.received)


def test_a_share_that_cannot_be_saved_is_not_kept_and_the_rest_of_the_batch_arrives(home):
    runtime = build(home)
    runtime.partners = [{"name": "alice", "key": PARTNER.public}]
    channel = Channel("inbox", "read", "i" * 20, time.time() + 600)
    runtime.client = SimpleNamespace(read=lambda w, read_key, after, wait: (200, {"messages": [stored("i" * 20, n, "sealed %d" % n, PARTNER) for n in (1, 2)]}))
    bodies = {1: {"text": "Scope team", "data": {"aamio_scope": {"name": "team", "key": VECTOR_KEY}}}, 2: {"text": "and the next message"}}
    runtime._open = lambda message: (bodies[message["seq"]], {"signed": True, "encrypted": True, "format": "json"})

    def full_disk(name, value, private=False):
        raise OSError(28, "No space left on device")

    runtime._save_json = full_disk
    state, entries = runtime.poll(channel)

    assert state == "ok" and [entry["seq"] for entry in entries] == [1, 2] and channel.after == 2
    assert entries[0]["body"]["data"]["aamio_scope"]["kept"] is False and "No space left" in entries[0]["body"]["data"]["aamio_scope"]["note"]
    assert runtime.scope_list() == [] and VECTOR_KEY not in json.dumps(entries)


def test_a_scopes_file_that_cannot_be_read_stops_the_runtime_and_is_left_as_it_was(home):
    path = os.path.join(home, "scopes.json")

    for broken in ('[{"name": "team", "key": "%s", "address": "%s"}' % (VECTOR_KEY, VECTOR_ADDRESS), '{"team": {"key": "%s"}}' % VECTOR_KEY):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(broken)

        with pytest.raises(RuntimeError, match="could not be read"):
            Runtime(home=home)

        assert open(path, encoding="utf-8").read() == broken
        assert not os.path.exists(os.path.join(home, "lock"))

    os.unlink(path)
    Runtime(home=home).close()


def test_an_entry_this_runtime_cannot_use_stays_in_the_file_as_it_was(home):
    path = os.path.join(home, "scopes.json")
    entries = [
        {"name": "typo", "key": VECTOR_KEY.upper(), "address": VECTOR_ADDRESS},
        {"name": "newline", "address": VECTOR_ADDRESS + "\n"},
        {"name": "team", "key": VECTOR_KEY, "address": VECTOR_ADDRESS, "note": "a field from a newer version"},
        {"name": "TEAM", "address": VECTOR_ADDRESS},
        {"name": "wrong-pair", "key": make_scope_key(), "address": VECTOR_ADDRESS},
        "not an entry",
    ]

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(entries, handle)

    runtime = Runtime(home=home)

    try:
        assert [scope["name"] for scope in runtime.scope_list()] == ["team"]
        runtime.scope_new("more")
    finally:
        runtime.close()

    stored = json.load(open(path, encoding="utf-8"))

    assert [scope["name"] for scope in stored[:2]] == ["team", "more"] and stored[0]["note"] == "a field from a newer version"
    assert stored[2:] == [entries[0], entries[1], entries[3], entries[4], entries[5]]


def test_a_key_file_that_is_not_a_key_is_never_replaced_by_a_new_identity(home):
    path = os.path.join(home, "key")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("not a seed\n")

    with pytest.raises(RuntimeError, match="not a 64 character hex seed"):
        Runtime(home=home)

    assert open(path, encoding="utf-8").read() == "not a seed\n"


def test_the_tools_speak_in_names_and_never_hand_out_a_key(home):
    runtime = build(home)
    by_name = {tool["name"]: tool for tool in TOOLS}

    for name in ("aamio_scopes", "aamio_scope_new", "aamio_scope_add", "aamio_scope_share", "aamio_scope_remove"):
        assert name in by_name

    for name in ("aamio_board_post", "aamio_board_find", "aamio_board_answer"):
        assert "scope" in by_name[name]["inputSchema"]["properties"]

    assert by_name["aamio_scope_remove"]["annotations"]["destructiveHint"] is True
    assert by_name["aamio_scopes"]["annotations"]["readOnlyHint"] is True
    assert "aamio_scope_share" in INSTRUCTIONS and "Unlisted is not private" in INSTRUCTIONS
    assert "never to an address" in by_name["aamio_scope_share"]["description"]

    made = dispatch(runtime, "aamio_scope_new", {"name": "team"})
    key = runtime.scope_key("team")["key"]
    listed = dispatch(runtime, "aamio_scopes", {})

    assert made["isError"] is False and listed["isError"] is False
    assert key not in json.dumps(made) and key not in json.dumps(listed)
    assert listed["structuredContent"]["scopes"][0]["can_read"] is True
    assert dispatch(runtime, "aamio_board_find", {"scope": "nobody"})["isError"] is True
    assert dispatch(runtime, "aamio_scope_share", {"name": "team", "to": "s" * 20, "access": "read"})["isError"] is True
    assert dispatch(runtime, "aamio_scope_remove", {"name": "team"})["structuredContent"] == {"removed": "team"}


def test_a_wrong_argument_or_a_failure_nobody_expected_leaves_the_server_running(home):
    runtime = build(home)

    assert dispatch(runtime, "aamio_open_channel", {"label": ["x"], "ttl": 60})["isError"] is True
    assert dispatch(runtime, "aamio_scope_new", {"name": {"a": 1}})["isError"] is True

    runtime.scope_list = lambda: 1 / 0
    reply = safely(runtime, {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "aamio_scopes", "arguments": {}}})

    assert reply["id"] == 7 and reply["error"]["code"] == -32603
    assert safely(runtime, {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "aamio_scopes"}}) is None
