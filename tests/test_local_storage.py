"""What stays on this machine, who can read it, and for how long.

From an outside assessment of aamio in use, 18 September 2026 (AAM-005, 006,
025). The service forgets a thread when it expires and this runtime does not:
it kept decrypted messages in archive/ with the default file mode, wrote
effects.json and partners.json the same way, and had no lifetime for any of
it. "Ephemeral" was easy to read as a promise about the whole system.
"""

import json
import os
import shutil
import sys
import tempfile
import time

import pytest

sys.path.insert(0, "src")

from aamio import cli, storage
from aamio.runtime import Runtime


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-storage-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def opened_modes(monkeypatch, home):
    """Every os.open under the home, with the mode it asked for."""
    seen = {}
    real = os.open

    def recording(path, flags, mode=0o777, *args, **kwargs):
        text = os.fspath(path)

        if isinstance(text, str) and text.startswith(home) and flags & os.O_CREAT:
            seen[os.path.relpath(text, home).replace(os.sep, "/")] = mode

        return real(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording)

    return seen


def test_everything_the_runtime_writes_is_opened_private(home, monkeypatch):
    modes = opened_modes(monkeypatch, home)
    runtime = Runtime(home=home)

    try:
        runtime.partner_add("alice", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
        runtime.effect("order-1", "fingerprint")
        runtime.save_effects()
        runtime.save_state()
        runtime.save_outbox()
        runtime.archive("inbox", {"kind": "received", "at": time.time(), "body": {"text": "decrypted"}})
    finally:
        runtime.close()

    written = {name: mode for name, mode in modes.items() if not name.endswith("lock") and not name.endswith("lock.tmp")}

    assert {"key", "effects.json.tmp", "partners.json.tmp", "state.json.tmp", "outbox.json.tmp", "archive/inbox.jsonl"} <= set(written), sorted(written)
    assert {name for name, mode in written.items() if mode != 0o600} == set(), "opened with a mode others can read"


def test_the_archive_is_a_choice_and_off_writes_nothing_decrypted(home):
    storage.make_private_dir(home)
    Runtime(home=home).close()

    assert storage.read_policy(home) == {"mode": "keep", "days": None, "max_mb": None}, "no file means keep, as every version did"

    printed = []
    original, cli.out = cli.out, printed.append

    try:
        runtime = Runtime(home=home)

        try:
            assert cli.run(_args("archive", policy="off", max_mb=None), runtime) in (None, 0)
        finally:
            runtime.close()
    finally:
        cli.out = original

    assert storage.read_policy(home)["mode"] == "off" and "Nothing decrypted is written" in printed[0]["means"]

    runtime = Runtime(home=home)

    try:
        assert runtime.archive_enabled is False, "the home's own choice, without a flag on every command"
        runtime.archive("inbox", {"kind": "received", "at": time.time(), "body": {"text": "decrypted"}})
    finally:
        runtime.close()

    assert not os.path.exists(os.path.join(home, "archive", "inbox.jsonl"))


def _args(command, **more):
    from types import SimpleNamespace

    return SimpleNamespace(command=command, **more)


def test_days_gives_the_archive_a_lifetime_and_what_cannot_be_dated_is_kept(home):
    folder = os.path.join(home, "archive")
    os.makedirs(folder)
    now = 1_800_000_000
    lines = [{"kind": "received", "at": now - 40 * 86400, "n": "old"}, {"kind": "received", "at": now - 86400, "n": "new"}, {"kind": "received", "n": "undated"}]

    with open(os.path.join(folder, "inbox.jsonl"), "w", encoding="utf-8") as handle:
        handle.write("".join(json.dumps(line) + "\n" for line in lines))
        handle.write('{"kind": "received", "at": 5, "n": "torn')

    result = storage.prune(home, storage.parse_policy("days:30"), now=now)
    kept = [json.loads(line).get("n") for line in open(os.path.join(folder, "inbox.jsonl"), encoding="utf-8") if line.strip().endswith("}")]

    assert result["removed"] == 1 and kept == ["new", "undated"]
    assert not os.path.exists(os.path.join(folder, "inbox.jsonl.tmp"))
    assert storage.prune(home, storage.parse_policy("keep"), now=now)["removed"] == 0


def test_a_ceiling_on_size_lets_the_oldest_go_first_across_channels(home):
    folder = os.path.join(home, "archive")
    os.makedirs(folder)

    for name, first in (("inbox", 100), ("board", 200)):
        with open(os.path.join(folder, name + ".jsonl"), "w", encoding="utf-8") as handle:
            handle.write("".join(json.dumps({"at": first + n, "pad": "x" * 1000}) + "\n" for n in range(100)))

    result = storage.prune(home, storage.parse_policy("keep", max_mb=0.1), now=1000)

    assert result["bytes"] <= 0.1 * 1024 * 1024 and result["removed"] > 0
    oldest_left = min(json.loads(line)["at"] for name in ("inbox", "board") for line in open(os.path.join(folder, name + ".jsonl"), encoding="utf-8") if line.strip())
    assert oldest_left >= 190, "what went was the oldest, whichever channel it was on: %d" % oldest_left


def test_a_runtime_with_a_lifetime_prunes_when_it_starts(home):
    storage.make_private_dir(os.path.join(home, "archive"))

    with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as handle:
        json.dump({"archive": {"mode": "days", "days": 7}}, handle)

    with open(os.path.join(home, "archive", "inbox.jsonl"), "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": "received", "at": time.time() - 30 * 86400, "n": "old"}) + "\n" + json.dumps({"kind": "received", "at": time.time(), "n": "new"}) + "\n")

    Runtime(home=home).close()
    left = [json.loads(line)["n"] for line in open(os.path.join(home, "archive", "inbox.jsonl"), encoding="utf-8")]

    assert left == ["new"]


def test_a_policy_that_is_not_one_is_refused_with_the_three_that_are():
    with pytest.raises(ValueError, match="keep, off or days:N"):
        storage.parse_policy("forever")

    with pytest.raises(ValueError):
        storage.parse_policy("days:0")


def test_on_windows_it_is_the_access_list_that_says_who_can_read():
    me = "S-1-5-21-1-2-3-1001"
    rules = [me + "|FullControl|Allow", "S-1-5-18|FullControl|Allow", "S-1-5-32-544|FullControl|Allow", "S-1-5-32-545|ReadAndExecute, Synchronize|Allow", "S-1-1-0|Read|Deny", "S-1-5-11|Modify|Allow"]
    found = storage.windows_acl_findings(rules, me)

    assert [finding["who"] for finding in found] == ["Users", "Authenticated Users"], "you, the system and the administrators are expected, a deny rule grants nothing"
    assert storage.windows_acl_findings([me + "|FullControl|Allow"], me) == []


def test_the_check_never_calls_something_private_that_it_could_not_check(home):
    assert storage.check(os.path.join(home, "not-there"))["private"] is None

    storage.make_private_dir(home)
    found = storage.check(home)

    assert found["private"] in (True, False, None) and found["how"]
    assert (found["private"] is False) == bool(found["findings"])


def test_doctor_says_it_all_in_one_answer(home):
    printed = []
    original, cli.out = cli.out, printed.append
    runtime = Runtime(home=home)
    runtime.client.health = lambda: (200, {"status": "ok", "version": "0.7.1", "revision": "abc"})
    runtime.client.descriptor = lambda: (200, {"version": "0.7.1", "protocol": {"version": 1, "capabilities": ["threads", "signing", "long-poll"]}})

    try:
        cli.run(_args("doctor"), runtime)
    finally:
        cli.out = original
        runtime.close()

    told = printed[0]

    assert told["service"]["version"] == "0.7.1" and told["compatibility"]["verdict"] == "partial"
    assert told["storage"]["home"] == home and "private" in told["storage"]
    assert told["archive"]["policy"]["mode"] == "keep" and told["archive"]["means"]
    assert told["outbox_pending"] == 0 and told["client"]["version"]
