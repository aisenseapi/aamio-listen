"""Gate from the writer's side: what this client does about an inbox's conditions.

Checked against the vectors the service and the JS client share, and against a
runtime whose network is a fake that answers as told and records what was sent.

The rules come from the gate specification, 16 September 2026:

- advised work at 18 bits or fewer is done without asking;
- required work at 20 bits or fewer is done, and a 428 is answered once;
- a requirement over the ceiling stops, and says why;
- an unknown condition stops under require and is passed over under advise;
- never more than one more attempt after a 428.
"""

import hashlib
import shutil
import sys
import tempfile
import threading
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio import mcp_server
from aamio.gate import GateStop, POW_ADVISE_MAX_BITS, POW_REQUIRE_MAX_BITS, plan, pow_digest, pow_input, solve, zero_bits
from aamio.runtime import Runtime, send_advice

W = "b4netymg7r5nnt2yiscp"
KEY = "A" * 43
BODY = '{"post":"abc","reply_to":"xyz","text":"hei"}'
BODY_SHA256 = "36751f20147f74e3dfbaf829fb8f04ea9ed596268bd685a69fdfa5992fddd6b8"
REQUIRE_8 = {"require": {"pow": {"bits": 8, "covers": 1}}}


# ------------------------------------------------------------------ vectors --

def test_the_shared_vectors():
    assert hashlib.sha256(BODY.encode("utf-8")).hexdigest() == BODY_SHA256

    signed = pow_digest(W, KEY, BODY_SHA256, "7036")
    unsigned = pow_digest(W, "", BODY_SHA256, "91617")

    assert signed.hex() == "00003a2ac769f2265d621969d9ff1feaaa2b9dcc6f006b6adae1d22c2db8a842"
    assert zero_bits(signed) == 18
    assert unsigned.hex() == "000018b5cc286cf27d2c97296aff9e2e60db0c165e7cf3af7a44857423c08612"
    assert zero_bits(unsigned) == 19


def test_an_unsigned_message_has_an_empty_key_and_two_line_breaks_meet():
    assert "\n\n" in pow_input(W, "", BODY_SHA256, "91617")
    assert pow_input(W, None, BODY_SHA256, "1") == pow_input(W, "", BODY_SHA256, "1")


def test_zero_bits_count_from_the_top_bit_of_the_first_byte():
    assert zero_bits(bytes(32)) == 256
    assert zero_bits(b"\x00\x0f" + b"\xff" * 30) == 12
    assert zero_bits(b"\x80" + bytes(31)) == 0
    assert zero_bits(b"\x01" + b"\xff" * 31) == 7


def test_solve_gives_the_first_nonce_that_reaches_the_bits():
    nonce = solve(W, KEY, BODY, 8)

    assert zero_bits(pow_digest(W, KEY, BODY_SHA256, nonce)) >= 8
    assert all(zero_bits(pow_digest(W, KEY, BODY_SHA256, str(n))) < 8 for n in range(int(nonce)))


def test_the_ceilings_are_the_services():
    assert (POW_REQUIRE_MAX_BITS, POW_ADVISE_MAX_BITS) == (20, 18)


# --------------------------------------------------------------------- plan --

def test_no_gate_asks_for_nothing():
    assert plan({}) == {"bits": None, "required": False, "notes": []}
    assert plan(None) == {"bits": None, "required": False, "notes": []}


def test_advised_work_at_the_ceiling_is_done_without_asking():
    assert plan({"advise": {"pow": {"bits": 18, "covers": 1}}}) == {"bits": 18, "required": False, "notes": []}


def test_required_work_at_the_ceiling_is_done():
    assert plan({"require": {"pow": {"bits": 20, "covers": 1}}}) == {"bits": 20, "required": True, "notes": []}


def test_a_requirement_over_the_ceiling_stops_and_says_why():
    with pytest.raises(GateStop) as stop:
        plan({"require": {"pow": {"bits": 21, "covers": 1}}})

    assert "21" in stop.value.reason and "20" in stop.value.reason
    assert stop.value.fix


def test_advice_over_the_ceiling_is_passed_over_and_mentioned():
    advice = plan({"advise": {"pow": {"bits": 19, "covers": 1}}})

    assert advice["bits"] is None
    assert any("19" in note for note in advice["notes"])


def test_an_unknown_condition_under_require_stops():
    with pytest.raises(GateStop) as stop:
        plan({"require": {"toll": "any"}}, W)

    assert "toll" in stop.value.reason
    assert W in stop.value.fix


def test_an_unknown_condition_under_advise_goes_ahead_and_says_so():
    advice = plan({"advise": {"pow": {"bits": 8, "covers": 1}, "fresh": 60}})

    assert advice["bits"] == 8
    assert any("fresh" in note for note in advice["notes"])


def test_an_unknown_bucket_stops():
    with pytest.raises(GateStop):
        plan({"demand": {"pow": {"bits": 8}}})


def test_the_hard_limits_need_no_work():
    assert plan({"require": {"per_key": 1, "write_until": 1800000000}}) == {"bits": None, "required": False, "notes": []}


# ------------------------------------------------------------------ runtime --

@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-gate-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def build(home, gate, answers):
    """A runtime with a fake network: gate() answers the gate given, post() the answers in order."""
    runtime = object.__new__(Runtime)
    runtime.home = home
    runtime.lock = threading.RLock()
    runtime.keys = SimpleNamespace(public=KEY, hash="0" * 64, sign=lambda text: "sig")
    runtime.outbox = {}
    runtime.save_outbox = lambda: None
    posts = []

    def post(w, body, key, signature, content_type="text/plain", work=None):
        posts.append({"w": w, "body": body, "key": key, "work": work})
        return answers.pop(0) if answers else (201, {"seq": len(posts), "at": 1})

    def gate_of(w):
        return (200, gate) if gate is not None else (404, {"error": "No thread", "fix": "open it"})

    runtime.client = SimpleNamespace(gate=gate_of, post=post)

    return runtime, posts


def entry(body="sealed bytes"):
    return {"id": "m-1", "w": W, "envelope": body, "attempts": 0, "status": "sending"}


def reaches(post, bits):
    return zero_bits(pow_digest(post["w"], post["key"], hashlib.sha256(post["body"].encode("utf-8")).hexdigest(), post["work"])) >= bits


def refused_with_gate(gate):
    return (428, {"error": "This inbox requires proof of work of 8 bits", "bits": 8, "fix": "do the work", "gate": gate})


def test_advised_work_goes_out_with_the_message(home):
    runtime, posts = build(home, {"advise": {"pow": {"bits": 8, "covers": 1}}}, [])

    status, _ = runtime._deliver(entry())

    assert status == 201
    assert len(posts) == 1 and reaches(posts[0], 8)


def test_an_inbox_without_a_gate_gets_no_work(home):
    runtime, posts = build(home, {}, [])

    runtime._deliver(entry())

    assert posts[0]["work"] is None


def test_a_428_is_answered_with_the_work_once(home):
    # The gate could not be read up front, so the first write goes out bare and
    # the refusal is what carries the gate.
    runtime, posts = build(home, None, [refused_with_gate(REQUIRE_8)])

    status, _ = runtime._deliver(entry())

    assert status == 201
    assert len(posts) == 2
    assert posts[0]["work"] is None and reaches(posts[1], 8)


def test_never_more_than_one_more_attempt(home):
    runtime, posts = build(home, None, [refused_with_gate(REQUIRE_8), refused_with_gate(REQUIRE_8), (201, {"seq": 1, "at": 1})])
    record = entry()

    status, _ = runtime._deliver(record)

    assert status == 428
    assert len(posts) == 2
    assert record["status"] == "refused"


def test_work_done_and_refused_anyway_is_not_done_again(home):
    # The same bytes give the same nonce and the same refusal: a second try
    # would spend a place in the rate window to learn nothing.
    runtime, posts = build(home, REQUIRE_8, [refused_with_gate(REQUIRE_8)])

    status, _ = runtime._deliver(entry())

    assert status == 428
    assert len(posts) == 1


def test_a_requirement_the_client_cannot_meet_sends_nothing(home):
    runtime, posts = build(home, {"require": {"toll": "any"}}, [])
    record = entry()

    with pytest.raises(GateStop):
        runtime._deliver(record)

    assert posts == []
    assert record["status"] == "refused" and "toll" in record["error"]


def test_advice_this_client_passes_over_is_noted_on_the_entry(home):
    runtime, posts = build(home, {"advise": {"pow": {"bits": 8, "covers": 1}, "fresh": 60}}, [])
    record = entry()

    runtime._deliver(record)

    assert reaches(posts[0], 8)
    assert any("fresh" in note for note in record["gate_notes"])


def test_the_gate_is_read_once_per_address(home):
    runtime, posts = build(home, {"advise": {"pow": {"bits": 4, "covers": 1}}}, [])
    reads = []
    original = runtime.client.gate
    runtime.client.gate = lambda w: reads.append(w) or original(w)

    runtime._deliver(entry("one"))
    runtime._deliver(entry("two"))

    assert reads == [W]


def test_a_428_after_the_client_did_its_work_is_not_worth_retrying():
    retryable, fix = send_advice("refused", 428)

    assert retryable is False and fix


def test_a_stopped_send_reaches_the_model_with_a_fix():
    runtime = SimpleNamespace(send=lambda *args: (_ for _ in ()).throw(GateStop("This inbox requires toll.", "Update the client.")))

    result = mcp_server.dispatch(runtime, "aamio_send", {"to": "Partner", "text": "hello"})

    assert result["isError"] is True
    assert result["structuredContent"]["error_code"] == "gate"
    assert result["structuredContent"]["fix"] == "Update the client."


# -------------------------------------------------------------------- board --

from aamio.gate import board_advised_bits, board_pow_digest, board_pow_input, solve_board


def board_runtime(home, descriptor):
    """A runtime whose board is a fake: the descriptor given, posts recorded, a find that echoes its body."""
    import time

    runtime = object.__new__(Runtime)
    runtime.home = home
    runtime.lock = threading.RLock()
    runtime.peers = {}
    runtime.keys = SimpleNamespace(public=KEY, hash="0" * 64, sign=lambda text: "sig")
    runtime.log = lambda line: None
    runtime.archive = lambda label, record: None
    runtime.ensure_board_inbox = lambda ttl: SimpleNamespace(w="w" * 20, expire_at=time.time() + 3600)
    posts = []
    reads = []

    def board_post(body, key, signature, work=None):
        posts.append({"body": body, "key": key, "work": work})
        return 201, {"id": "p1", "work_bits": 4}

    def board_descriptor():
        reads.append(1)
        return (200, descriptor) if descriptor is not None else (404, {"error": "no"})

    runtime.client = SimpleNamespace(board_post=board_post, board_descriptor=board_descriptor, board_find=lambda body, wait=0: (200, {"posts": [], "next": 0, "count": 0, "live": 0, "sent": body}))

    return runtime, posts, reads


def board_reaches(post, bits):
    return zero_bits(board_pow_digest(post["key"], hashlib.sha256(post["body"].encode("utf-8")).hexdigest(), post["work"])) >= bits


def test_the_board_input_is_its_own_string():
    assert board_pow_input("k", "h", "n") == "aamio-board-pow-v1\nk\nh\nn"
    assert "aamio-board-v1\n" not in board_pow_input("k", "h", "n")


def test_solve_board_reaches_the_bits():
    nonce = solve_board(KEY, BODY, 8)

    assert zero_bits(board_pow_digest(KEY, BODY_SHA256, nonce)) >= 8


def test_the_advised_bits_come_from_the_descriptor_and_stop_at_the_ceiling():
    assert board_advised_bits({"work": {"advise_bits": 16}}) == 16
    assert board_advised_bits({"work": {"advise_bits": 18}}) == 18
    assert board_advised_bits({"work": {"advise_bits": 19}}) == 0
    assert board_advised_bits({"work": {"advise_bits": 0}}) == 0
    assert board_advised_bits({"limits": {}}) == 0
    assert board_advised_bits(None) == 0


def test_a_post_carries_the_work_the_board_advises(home):
    runtime, posts, _ = board_runtime(home, {"work": {"advise_bits": 4}})

    runtime.board_post("need", "t", "x")

    assert len(posts) == 1 and posts[0]["work"] is not None
    assert board_reaches(posts[0], 4)


def test_a_board_that_advises_nothing_gets_no_header(home):
    runtime, posts, _ = board_runtime(home, {"limits": {}})

    runtime.board_post("need", "t", "x")

    assert posts[0]["work"] is None


def test_a_board_that_advises_more_than_the_ceiling_is_passed_over(home):
    runtime, posts, _ = board_runtime(home, {"work": {"advise_bits": 19}})

    runtime.board_post("need", "t", "x")

    assert posts[0]["work"] is None


def test_a_descriptor_that_cannot_be_read_means_no_work(home):
    runtime, posts, _ = board_runtime(home, None)

    runtime.board_post("need", "t", "x")

    assert posts[0]["work"] is None


def test_the_descriptor_is_read_once(home):
    runtime, posts, reads = board_runtime(home, {"work": {"advise_bits": 4}})

    runtime.board_post("need", "one", "x")
    runtime.board_post("need", "two", "x")

    assert len(posts) == 2 and reads == [1]


def test_min_work_bits_is_sent_only_when_asked_for(home):
    runtime, _, _ = board_runtime(home, {"work": {"advise_bits": 4}})

    assert "min_work_bits" not in runtime.board_find()["sent"]
    assert runtime.board_find(min_work_bits=16)["sent"]["min_work_bits"] == 16
