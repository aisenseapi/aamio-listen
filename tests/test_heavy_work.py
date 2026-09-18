"""Work up to 32 bits, for an inbox that means to meet only writers with compute.

The ceiling went from 20 to 32 on 18 September 2026. 32 bits takes this client
more than an hour, and an inbox lives an hour at most, so a slow writer must not
find out from a 410 after an hour of work. Three things keep that from
happening: the time left is read from X-Seconds-Left on the gate, work that
would not be done by then is not started, and work that runs over is stopped.
And a model on MCP, whose host cuts a tool call after a minute or so, is not
held for work that takes longer: it runs in the background, and the next read
says how it ended.
"""

import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio import gate as gatemod
from aamio.client import AamioClient
from aamio.crypto import Keys
from aamio.gate import GateStop, describe, expected_seconds, plan, solve
from aamio.runtime import Channel, Runtime


def test_work_that_would_not_be_done_in_time_is_not_started():
    with pytest.raises(GateStop) as stop:
        # A minute: no loop like this one does 32 bits in that, on any machine.
        plan({"require": {"pow": {"bits": 32, "covers": 1}}}, "w" * 20, None, 60)

    assert "32 bits" in stop.value.reason and "not started" in stop.value.reason and "nothing was sent" in stop.value.reason
    assert "machine with more compute" in stop.value.fix


def test_work_that_fits_goes_ahead_and_says_how_long():
    advice = plan({"require": {"pow": {"bits": 20, "covers": 1}}}, "w" * 20, None, 3600)

    assert advice["bits"] == 20 and 0 < advice["expected_seconds"] < 3600 and advice["seconds_left"] == 3600


def test_a_few_seconds_left_stops_even_modest_work():
    with pytest.raises(GateStop):
        plan({"require": {"pow": {"bits": 24, "covers": 1}}}, "w" * 20, None, 2)


def test_the_estimate_is_the_solvers_own_speed():
    # 2 ** bits attempts on average, at the rate solve itself runs here.
    assert expected_seconds(20) == pytest.approx((2 ** 20) / gatemod.hash_rate())
    assert expected_seconds(21) == pytest.approx(2 * expected_seconds(20))


def test_work_past_its_deadline_is_stopped():
    started = time.monotonic()
    nonce = solve("w" * 20, "k" * 43, b"body", 60, time.monotonic() + 0.3)

    assert nonce is None and time.monotonic() - started < 3


def test_a_time_reads_as_a_time():
    assert describe(5) == "5 seconds" and describe(600) == "10 minutes" and describe(7200) == "2.0 hours"


def test_the_client_reads_the_seconds_left_from_the_gate():
    client = AamioClient("https://fake.test")
    client.http = lambda method, url, body=None, headers=None, timeout=None, with_headers=False: (200, {"require": {"pow": {"bits": 24, "covers": 1}}}, {"x-seconds-left": "1234"})

    assert client.gate_timed("w" * 20) == (200, {"require": {"pow": {"bits": 24, "covers": 1}}}, 1234)

    client.http = lambda method, url, body=None, headers=None, timeout=None, with_headers=False: (200, {}, {})
    assert client.gate_timed("w" * 20)[2] is None


def runtime_facing(gate, left, post):
    """A runtime whose client answers the gate and every post as the test says."""
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
    runtime.client = SimpleNamespace(gate_timed=lambda w: (200, gate, left), post=post)

    return runtime


def test_long_work_over_mcp_runs_in_the_background_and_the_next_read_says_how_it_ended():
    posted = []
    done = threading.Event()

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        posted.append(work)
        done.set()
        return 201, {"seq": 7, "at": 1, "sha256": "h", "expire_at": 2, "met": {"pow": 17}, "proof_id": "p"}

    other = Keys.generate()
    runtime = runtime_facing({"require": {"pow": {"bits": 17, "covers": 1}}}, 3600, post)
    runtime.work_budget = 0.000001

    answer = runtime._send("q" * 20, other.public, None, "hello")

    assert answer["status"] == "working" and answer["work"]["bits"] == 17 and "aamio_pending" in answer["note"]
    assert done.wait(30), "the work was never finished"
    # The outcome is told on the next read, where the model will look.
    deadline = time.time() + 5
    told = []
    while time.time() < deadline and not told:
        told = [a for a in runtime.attention_taken() if a["state"] == "delivered"]
        time.sleep(0.05)
    assert told and "seq 7" in told[0]["what"] and posted[0] is not None


def test_without_a_budget_the_work_is_done_in_the_call():
    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        return 201, {"seq": 1, "at": 1, "sha256": "h", "expire_at": 2}

    runtime = runtime_facing({"require": {"pow": {"bits": 8, "covers": 1}}}, 3600, post)
    answer = runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert answer.get("status") != "working" and answer["seq"] == 1


def test_an_inbox_that_closes_too_soon_stops_the_send_before_anything_is_stored():
    runtime = runtime_facing({"require": {"pow": {"bits": 30, "covers": 1}}}, 60, lambda *a, **k: (201, {}))

    with pytest.raises(GateStop):
        runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert runtime.outbox == {}
