"""Reader boundaries, durable rotation and receipt provenance; no network."""
import json
import time
from types import SimpleNamespace

import pytest

from aamio.client import AamioClient, normalize_allow, scope_address, write_address
from aamio.crypto import Keys
from aamio.runtime import Channel, Runtime
from signing import stored
from test_reader_checks import ALICE, MALLORY, W, answer, build
from test_receipt import root_of


def test_malformed_records_cannot_poison_replay_or_abort_a_batch():
    good = stored(W, 5, "perform once", ALICE)
    bad = [dict(good, seq=1, body=123), dict(good, seq=2, body=123, sha256=[]),
           dict(good, seq=3, body="\ud800"), {"seq": 4, "body": "missing metadata"}, None]
    runtime, channel = build([(200, {"messages": bad + [good], "next": 5})])
    entries = runtime.poll(channel)[1]
    assert len(entries) == 6 and entries[-1]["verified"] and not entries[-1]["replay"]
    assert all(not e["verified"] and e["from_key"] is None and e["sha256"] is None for e in entries[:-1])
    assert channel.seen == {good["sha256"]} and channel.after == 5


def test_attention_accumulates_and_explains_kept_out_disposition():
    forged = dict(stored(W, 1, "forged", MALLORY), **{"from": ALICE.public})
    runtime, channel = build([answer(forged), answer(dict(forged, seq=2))], allow=[ALICE.public])
    runtime.poll(channel)
    runtime.poll(channel)
    notes = {n["state"]: n for n in runtime.attention_taken()}
    for state in ("kept_out", "unverified"):
        assert notes[state]["count"] == 2 and notes[state]["seqs"] == [1, 2]
    assert "kept out" in notes["unverified"]["what"]
    assert "handed over as unverified" not in notes["unverified"]["what"]
    assert runtime.attention_taken() == []


@pytest.mark.parametrize("label", ["inbox", "board"])
def test_rotation_retains_both_channels_across_restart(tmp_path, label):
    runtime = Runtime(home=str(tmp_path), archive=False)
    old = Channel(label, "old-key", "o" * 20, time.time() + 60, [ALICE.public])
    old.seen = {"a" * 64}
    runtime.channels[label] = old
    runtime.client = SimpleNamespace(open_thread=lambda *args: (201, {"expire_at": int(time.time()) + 3600}, "new-key", "n" * 20))
    runtime.publish_presence = lambda **kw: None
    new = runtime.ensure_inbox() if label == "inbox" else runtime.ensure_board_inbox(1800)
    new.seen = {"b" * 64}
    expected_allow = new.allow
    runtime.close()
    again = Runtime(home=str(tmp_path), archive=False)
    try:
        assert again.channels[label].read_key == "new-key"
        assert again.channels[label].seen == {"b" * 64} and again.channels[label].allow == expected_allow
        retired = [c for name, c in again.channels.items() if name != label]
        assert len(retired) == 1 and retired[0].read_key == "old-key"
        assert retired[0].label != label and retired[0].allow == [ALICE.public] and retired[0].seen == {"a" * 64}
    finally:
        again.close()


@pytest.mark.parametrize("reverse", [False, True])
def test_legacy_duplicate_labels_keep_the_newest_and_all_keys(tmp_path, reverse):
    runtime = Runtime(home=str(tmp_path), archive=False)
    runtime.close()
    channels = [Channel("inbox", "old", "o" * 20, time.time() + 600), Channel("inbox", "new", "n" * 20, time.time() + 1200)]
    if reverse:
        channels.reverse()
    # Test fixtures use a temporary runtime home, never native agent history.
    (tmp_path / "state.json").write_text(json.dumps({"channels": [c.to_state() for c in channels]}), encoding="utf-8")
    again = Runtime(home=str(tmp_path), archive=False)
    try:
        assert again.channels["inbox"].read_key == "new"
        assert {c.read_key for c in again.channels.values()} == {"old", "new"}
    finally:
        again.close()


def test_gone_and_only_valid_seen_values_survive_state():
    channel = Channel("inbox", "key", W, time.time() + 600)
    channel.gone = True
    state = channel.to_state()
    state["seen"] = [None, [], 42, "invented", "a" * 64]
    restored = Channel.from_state(state)
    assert restored.gone and restored.seen == {"a" * 64}


def test_one_channel_failure_does_not_hide_another_channels_messages():
    runtime, first = build([])
    runtime.listener = None
    runtime.ensure_inbox = lambda: first
    runtime.publish_presence = lambda: None
    runtime.channels["other"] = Channel("other", "key", "x" * 20, time.time() + 600)
    def poll(channel, wait, limit=None):
        if channel is first:
            return "ok", [{"seq": 1}]
        raise ValueError("malformed answer")
    runtime.poll = poll
    assert runtime.read() == [{"seq": 1}]
    assert runtime.attention_taken()[0]["state"] == "unread"


def test_http_reader_checks_even_without_runtime():
    good = stored(W, 1, "real", ALICE)
    forged = dict(good, seq=2, body="changed", service_verified=False, unverified_because="trusted")
    client = AamioClient()
    client.call = lambda *args, **kw: (200, {"messages": [good, forged, None]})
    messages = client.read(W, "key")[1]["messages"]
    assert messages[0]["verified"] and messages[0]["from"] == ALICE.public
    assert not messages[1]["verified"] and messages[1]["from"] is None
    assert messages[1]["service_verified"] and messages[1]["unverified_because"] != "trusted"
    assert not messages[2]["verified"]


@pytest.mark.parametrize("data", ["proxy page", {}, {"messages": {"seq": 1}}])
def test_malformed_answer_is_not_a_quiet_inbox(data):
    runtime, channel = build([(200, data)])
    channel.created_at = 123
    assert runtime.poll(channel) == ("error", [])
    assert channel.created_at == 123 and runtime.attention_taken()[0]["state"] == "unread"


def test_allow_normalization_and_validation_before_request():
    assert normalize_allow([" a, b ", "", "a"]) == ["a", "b"]
    assert normalize_allow(["a", " * "]) == ["*"]
    client = AamioClient()
    sent = []
    client.call = lambda *args: sent.append(args) or (201, {})
    client.open_thread(600, [" a, b ", "a"])
    assert sent[0][3]["X-Allow"] == "a,b"
    with pytest.raises(ValueError):
        client.open_thread(600, ["*", None])
    assert len(sent) == 1


def test_receipt_tracks_kept_out_without_naming_unverified_claims():
    good = stored(W, 1, "stranger", MALLORY)
    forged = dict(stored(W, 2, "forged", MALLORY), **{"from": ALICE.public})
    runtime, channel = build([answer(good, forged)], allow=[ALICE.public])
    assert runtime.poll(channel)[1] == []
    runtime.keys = Keys.generate()
    messages = [{k: m[k] for k in ("seq", "at", "sha256", "from")} for m in [good, forged]]
    receipt = {"count": 2, "messages": messages, "keys": [ALICE.public, MALLORY.public], "root": root_of(messages)}
    runtime.client.receipt = lambda *args: (200, receipt)
    out = runtime.receipt()
    assert out["held_locally"] == 2 and out["local_root_matches"] is True
    assert out["keys"][0] == ALICE.public and out["keys_unverified_count"] == 1
    assert out["signers_not_verified_locally"] == [2]
    changed = [dict(messages[0], at=999), messages[1]]
    receipt.update(messages=changed, root=root_of(changed))
    out = runtime.receipt()
    assert out["local_root_matches"] is False and out["local_differences"] == [{"seq": 1, "fields": ["at"]}]
    receipt.update(count=1, messages=messages[:1], root=root_of(messages[:1]))
    assert runtime.receipt()["local_root_matches"] is False
    channel.forget_thread()
    assert runtime.receipt()["local_root_matches"] is None


@pytest.mark.parametrize("derive", [write_address, scope_address])
def test_read_capabilities_reject_trailing_newlines(derive):
    with pytest.raises(ValueError):
        derive("a" * 26 + "\n")
