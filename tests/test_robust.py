"""What the runtime must still get right when things stop halfway.

Four properties, each with a test that fails if the property is missing:

    a redelivered message is known as a replay, even after a restart
    a message exists in the outbox before the first network attempt
    no answer means unknown, never failure
    one live runtime per home

Runs against AAMIO_HOST (default https://aamio.at) and leaves nothing behind.

    python aamio-listen/tests/test_robust.py
"""

import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from aamio.crypto import thread_signing_input  # noqa: E402
from aamio.runtime import Runtime, SendFailed  # noqa: E402


def shut(*runtimes):
    for runtime in runtimes:
        for label in list(runtime.channels):
            try:
                runtime.close_channel(label)
            except Exception:
                pass
        runtime.close()


def test_replay_survives_a_restart():
    """The same bytes twice is a replay, and a restarted runtime still knows it."""
    base = tempfile.mkdtemp(prefix="aamio-replay-")
    home = os.path.join(base, "receiver")
    receiver = Runtime(home=home, archive=False)
    sender = Runtime(home=os.path.join(base, "sender"), archive=False)
    try:
        inbox = receiver.ensure_inbox()
        envelope = sender.keys.seal(receiver.keys.public, b'{"text":"do the thing once"}')
        signature = sender.keys.sign(thread_signing_input(inbox.w, envelope))

        status, first = sender.client.post(inbox.w, envelope, sender.keys.public, signature)
        assert status == 201, first
        status, second = sender.client.post(inbox.w, envelope, sender.keys.public, signature)
        assert status == 201, second
        assert first["sha256"] == second["sha256"], "the same bytes must hash the same"

        got = receiver.read(wait=10)
        mine = [m for m in got if m["sha256"] == first["sha256"]]
        assert len(mine) == 2, mine
        assert mine[0]["replay"] is False and mine[1]["replay"] is True, [m["replay"] for m in mine]

        # The receive boundary closed before we were handed anything: the
        # cursor and the hash are already on disk.
        state = json.load(open(os.path.join(home, "state.json"), encoding="utf-8"))
        stored = [c for c in state["channels"] if c["label"] == "inbox"][0]
        assert stored["after"] >= 2 and first["sha256"] in stored["seen"], stored

        # A third copy after a restart is still a replay, which is the whole
        # point: without this a crash would let the model act twice.
        receiver.close()
        again = Runtime(home=home, archive=False)
        try:
            status, third = again.client.post(inbox.w, envelope, sender.keys.public, signature)
            assert status == 201, third
            got = again.read(wait=10)
            mine = [m for m in got if m["sha256"] == first["sha256"]]
            assert mine and all(m["replay"] for m in mine), mine
            print("ok: a replay is still a replay after a restart")
        finally:
            shut(again)
    finally:
        shut(sender)
        shutil.rmtree(base, ignore_errors=True)


def test_outbox_and_unknown_outcome():
    """The message is durable before it is sent, and no answer is not failure."""
    base = tempfile.mkdtemp(prefix="aamio-outbox-")
    home = os.path.join(base, "sender")
    sender = Runtime(home=home, archive=False)
    receiver = Runtime(home=os.path.join(base, "receiver"), archive=False)
    try:
        inbox = receiver.ensure_inbox()
        sender.peers[inbox.w] = receiver.keys.public
        sent = sender.send(inbox.w, "delivered")
        entry = sender.outbox[sent["message_id"]]
        assert entry["status"] == "delivered" and entry["attempts"] == 1, entry
        assert json.load(open(os.path.join(home, "outbox.json"), encoding="utf-8"))[sent["message_id"]]["status"] == "delivered"
        assert sender.outbox_pending() == []

        # A host that answers nothing: the runtime must not call this failure.
        host = sender.client.host
        sender.client.host = "http://127.0.0.1:9"
        sender.client.timeout = 3
        try:
            sender.send(inbox.w, "maybe delivered, maybe not")
            raise AssertionError("a send with no answer must raise")
        except SendFailed as error:
            assert error.outcome == "unknown" and error.status == 0, (error.outcome, error.status)
            unknown_id = error.message_id

        pending = sender.outbox_pending()
        assert [p["id"] for p in pending] == [unknown_id], pending
        assert json.load(open(os.path.join(home, "outbox.json"), encoding="utf-8"))[unknown_id]["status"] == "unknown"

        # The same bytes go out when the host comes back, and the receiver
        # decides what a second copy means.
        sender.client.host = host
        sender.client.timeout = 60
        again = sender.outbox_retry(unknown_id)
        assert again and again[0]["status"] == "delivered", again
        assert sender.outbox_pending() == []

        # A refusal is a refusal: an expired thread is not retried forever.
        short = receiver.open_channel("short", 30)
        sender.peers[short["w"]] = receiver.keys.public
        receiver.close_channel("short")
        try:
            sender.send(short["w"], "into a closed channel")
        except SendFailed as error:
            assert error.outcome == "refused", error.outcome
        print("ok: the outbox holds the bytes, and no answer stays unknown")
    finally:
        shut(sender, receiver)
        shutil.rmtree(base, ignore_errors=True)


def test_one_runtime_per_home():
    """Two sidecars on one home would overwrite each other's state."""
    base = tempfile.mkdtemp(prefix="aamio-lock-")
    home = os.path.join(base, "one")
    first = Runtime(home=home, archive=False)
    try:
        try:
            Runtime(home=home, archive=False)
            raise AssertionError("a second runtime on the same home must refuse")
        except RuntimeError as error:
            assert "another aamio" in str(error), error

        # Once the first lets go, the home is free again.
        first.close()
        second = Runtime(home=home, archive=False)
        assert second.keys.public == first.keys.public
        second.close()

        # A lock left by a process that is gone does not block anyone.
        json.dump({"pid": 999999, "at": int(time.time())}, open(os.path.join(home, "lock"), "w", encoding="utf-8"))
        third = Runtime(home=home, archive=False)
        third.close()
        print("ok: one runtime per home, and a stale lock does not block")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_effects_are_carried_out_once():
    """The register the application uses so a redelivered request acts once."""
    base = tempfile.mkdtemp(prefix="aamio-effects-")
    home = os.path.join(base, "one")
    runtime = Runtime(home=home, archive=False)
    try:
        key = "release:ARC-4471:from:" + runtime.keys.hash[:8]
        assert runtime.effect(key)["state"] == "new"
        runtime.effect_done(key, {"released": True}, fingerprint="abc")
        done = runtime.effect(key, "abc")
        assert done["state"] == "done" and done["result"] == {"released": True}, done
        assert runtime.effect(key, "different")["state"] == "conflict"

        # It outlives the process, or it protects nothing.
        runtime.close()
        again = Runtime(home=home, archive=False)
        assert again.effect(key, "abc")["state"] == "done"
        again.close()
        print("ok: an operation key survives a restart, and a changed payload is a conflict")
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    test_one_runtime_per_home()
    test_effects_are_carried_out_once()
    test_replay_survives_a_restart()
    test_outbox_and_unknown_outcome()
