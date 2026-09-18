"""A gate kept for an address, and what happens when the address has a new life.

Found by an outside review on 18 September 2026. A gate is read once per
address and kept, since it never changes while its thread lives. But an
address can have more than one life: the thread expires or is closed, and a
new one opens there with other conditions or none. The time a kept gate said
counted down to nothing and stayed there, and a send to the new inbox was
refused on the old one's terms without the service ever being asked.

Also here: a sent archive that cannot be written after a 201 took the outcome
with it, and work that never finished before the process stopped stayed
"working" for good.
"""

import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio.crypto import Keys
from aamio.gate import GateStop
from aamio.runtime import Channel, Runtime


def runtime_with(gates, post):
    """A runtime whose client hands out the gates in turn, one per read, and
    counts the reads."""
    runtime = object.__new__(Runtime)
    runtime.keys = Keys.generate()
    runtime.host = "https://fake.test"
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.outbox = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.log = lambda line: None
    runtime.save_outbox = lambda: None
    runtime.save_state = lambda: None
    runtime.archive = lambda label, record: None
    runtime.name_for_key = lambda key: "Deep"
    runtime.channels = {"inbox": Channel("inbox", "r", "i" * 20, time.time() + 3600)}
    runtime.ensure_inbox = lambda: runtime.channels["inbox"]
    runtime.reads = 0

    def gate_timed(w):
        runtime.reads += 1
        return gates[min(runtime.reads, len(gates)) - 1]

    runtime.client = SimpleNamespace(gate_timed=gate_timed, post=post)
    return runtime


def posting(posted):
    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        posted.append(work)
        return 201, {"seq": 1, "at": 1, "sha256": "h", "expire_at": 2}
    return post


def test_a_new_inbox_at_an_old_address_is_asked_about_before_a_no():
    posted = []
    # The first life: 17 bits, and the time it had left has run out. The new
    # life at the same address asks for nothing.
    runtime = runtime_with([(200, {"require": {"pow": {"bits": 17, "covers": 1}}}, 0), (200, {}, 600)], posting(posted))
    runtime._gate_for("q" * 20)

    sent = runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert sent["seq"] == 1 and posted == [None]
    assert runtime.reads == 2, "one more read of the gate, and only one"


def test_a_real_no_is_still_a_no_after_one_more_read():
    posted = []
    closed = (200, {"require": {"pow": {"bits": 30, "covers": 1}}}, 0)
    runtime = runtime_with([closed, closed], posting(posted))
    runtime._gate_for("q" * 20)

    with pytest.raises(GateStop):
        runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert posted == [] and runtime.reads == 2 and runtime.outbox == {}


def test_an_inbox_that_answers_410_takes_its_gate_with_it():
    runtime = runtime_with([(200, {"advise": {"pow": {"bits": 4, "covers": 1}}}, 600)], lambda *a, **k: (410, {"error": "Thread has expired"}))

    with pytest.raises(Exception):
        runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert "q" * 20 not in runtime.gates and "q" * 20 not in runtime._gate_clock()


def test_a_sent_archive_that_fails_after_a_201_does_not_take_the_outcome_with_it():
    posted = []
    runtime = runtime_with([(200, {}, 600)], posting(posted))

    def broken(label, record):
        raise OSError("disk full")

    runtime.archive = broken
    sent = runtime._send("q" * 20, Keys.generate().public, None, "hello")

    # Delivered, said so, and the archive's trouble beside it: never an error
    # for a message that went, which a caller might send again as new bytes.
    assert sent["seq"] == 1 and "disk full" in sent["archive_error"] and len(posted) == 1


def test_the_note_after_background_work_survives_a_failed_archive():
    done = threading.Event()

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        done.set()
        return 201, {"seq": 7, "at": 1, "sha256": "h", "expire_at": 2}

    runtime = runtime_with([(200, {"require": {"pow": {"bits": 17, "covers": 1}}}, 3600)], post)
    runtime.work_budget = 0.000001

    def broken(label, record):
        raise OSError("disk full")

    runtime.archive = broken
    answer = runtime._send("q" * 20, Keys.generate().public, None, "hello")
    assert answer["status"] == "working" and done.wait(30)

    deadline = time.time() + 5
    told = []
    while time.time() < deadline and not told:
        told = [a for a in runtime.attention_taken() if a["state"] == "delivered"]
        time.sleep(0.05)
    assert told and "seq 7" in told[0]["what"] and "disk full" in told[0]["what"]


def test_work_that_never_finished_is_known_not_sent_after_a_restart():
    """A runtime that stops during the work leaves the entry working. The next
    one knows the post never happened, since the work comes first, and says so
    on the first read."""
    import tempfile

    home = tempfile.mkdtemp(prefix="aamio-restart-")
    first = Runtime(home, "https://fake.test", archive=False)
    first.outbox["m-1"] = {"id": "m-1", "w": "q" * 20, "status": "working", "attempts": 1, "envelope": "{}", "to_key": "k", "created_at": 1}
    first.save_outbox()
    first.close()

    again = Runtime(home, "https://fake.test", archive=False)
    try:
        entry = again.outbox["m-1"]
        told = again.attention_taken()
        assert entry["status"] == "stopped" and "nothing was sent" in entry["note"]
        assert [(a["channel"], a["state"]) for a in told] == [("send m-1", "stopped")]
        assert again.outbox_pending() == [], "a message known not sent is settled, not pending"
    finally:
        again.close()
