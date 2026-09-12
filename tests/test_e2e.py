"""Two runtimes, two homes, one aamio. Runs against AAMIO_HOST (default https://aamio.at).

    python -m pytest aamio-listen/tests -q      or      python aamio-listen/tests/test_e2e.py
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from aamio_listen.crypto import Keys, is_envelope, key_hash  # noqa: E402
from aamio_listen.runtime import Runtime  # noqa: E402


def test_crypto_roundtrip():
    a, b = Keys.generate(), Keys.generate()
    envelope = a.seal(b.public, b'{"text":"hei"}')
    assert is_envelope(envelope)
    assert b.open(a.public, envelope) == b'{"text":"hei"}'
    try:
        Keys.generate().open(a.public, envelope)
        assert False, "wrong key opened the envelope"
    except Exception:
        pass
    assert len(key_hash(a.public)) == 64


def test_two_runtimes_talk():
    base = tempfile.mkdtemp(prefix="aamio-listen-")
    try:
        alice = Runtime(home=os.path.join(base, "alice"), tags=["test.alice"], log=lambda l: print("alice:", l))
        bob = Runtime(home=os.path.join(base, "bob"), tags=["test.bob"], log=lambda l: print("bob:", l))
        alice.partner_add("Bob", bob.keys.public)
        bob.partner_add("Alice", alice.keys.public)
        # Partners known -> inboxes open with allowlists.
        alice.ensure_inbox()
        bob.ensure_inbox()
        assert alice.whoami()["inbox"] and bob.whoami()["inbox"]

        seen = alice.lookup(["Bob"])
        assert [o["name"] for o in seen["online"]] == ["Bob"], seen

        bob.start()
        sent = alice.send("Bob", "Hei Bob", {"n": 1})
        assert sent["seq"] == 1
        got = bob.read(wait=20)
        assert len(got) == 1 and got[0]["sender"] == "Alice" and got[0]["verified"] and got[0]["body"]["text"] == "Hei Bob", got
        assert got[0]["body"]["data"] == {"n": 1}

        # Bob answers to the reply_to address without a lookup.
        reply = bob.send(got[0]["body"]["reply_to"], "Hei Alice", None)
        assert reply["seq"] == 1
        alice.start()
        got2 = alice.read(wait=20)
        assert len(got2) == 1 and got2[0]["sender"] == "Bob" and got2[0]["body"]["text"] == "Hei Alice", got2

        # Receipts match local computation on both sides.
        ra = alice.receipt("inbox")
        rb = bob.receipt("inbox")
        assert ra["count"] == 1 and ra["local_root_matches"], ra
        assert rb["count"] == 1 and rb["local_root_matches"], rb
        assert ra["commitment"].startswith("sha256:")

        # A channel with a short life and an allowlist.
        channel = alice.open_channel("tender", 60, ["Bob"])
        assert channel["allow"] == ["Bob"]
        alice.peers[channel["w"]] = bob.keys.public  # not needed for bob; alice just records it
        # Bob writes into alice's channel: needs alice's key for that address.
        bob.peers[channel["w"]] = alice.keys.public
        bob.send(channel["w"], "tilbud 100")
        time.sleep(1)
        got3 = alice.read(wait=20)
        assert any(m["channel"] == "tender" and m["body"]["text"] == "tilbud 100" for m in got3), got3
        rc = alice.receipt("tender")
        assert rc["count"] == 1 and rc["local_root_matches"]
        assert alice.close_channel("tender")["deleted"]

        # State survives a restart: same key, same inbox.
        alice.close()
        alice2 = Runtime(home=os.path.join(base, "alice"))
        assert alice2.keys.public == alice.keys.public
        assert alice2.whoami()["inbox"] == alice.whoami()["inbox"]
        bob.close()
        print("ok: two runtimes exchanged encrypted, signed mail and matching receipts")
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    test_crypto_roundtrip()
    print("ok: crypto")
    test_two_runtimes_talk()
