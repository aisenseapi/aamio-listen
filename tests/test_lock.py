"""The lock on a home, found by a health check on 17 September 2026.

The command line took the lock and never let go, so the next command read a
pid from the lock file and asked whether it lived with os.kill(pid, 0). On
Windows that call is TerminateProcess. Windows hands pids out again quickly, so
the process it ended was as often some other program as an old aamio, and the
command then refused to start because the pid had answered.

A second round the same day found three more. Letting go of the lock on the
way out saved state.json and outbox.json after commands that only read them. A
lock whose pid had since gone to another program was refused for as long as
that program ran. And the MCP server closed twice.
"""

import os
import subprocess
import sys
import tempfile
import shutil
import time

import pytest

sys.path.insert(0, "src")

from aamio import cli
from aamio.runtime import Runtime, pid_alive, process_started_at


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-lock-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def test_asking_whether_a_pid_lives_leaves_the_process_running():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    try:
        time.sleep(0.3)
        assert pid_alive(child.pid) is True
        time.sleep(0.3)
        assert child.poll() is None, "the check ended the process it asked about"
    finally:
        child.kill()
        child.wait()

    assert pid_alive(child.pid) is False
    assert pid_alive(os.getpid()) is True


def test_a_command_lets_go_of_the_lock_when_it_is_done(home, capsys):
    assert cli.main(["--home", home, "whoami"]) == 0
    assert not os.path.exists(os.path.join(home, "lock"))

    # And the next command starts, twice over, with no lock to argue with.
    assert cli.main(["--home", home, "scope", "list"]) == 0
    assert cli.main(["--home", home, "whoami"]) == 0
    assert '"key"' in capsys.readouterr().out


def test_a_lock_left_by_a_process_that_is_gone_is_taken_over(home):
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    with open(os.path.join(home, "lock"), "w", encoding="utf-8") as handle:
        handle.write('{"pid": %d, "at": 1}' % child.pid)

    runtime = Runtime(home=home)

    try:
        assert runtime.owns_lock is True
    finally:
        runtime.close()


def test_a_lock_held_by_a_live_runtime_is_still_refused(home):
    holder = subprocess.Popen([sys.executable, "-c", "import sys, time; sys.path.insert(0, 'src'); from aamio.runtime import Runtime; r = Runtime(home=sys.argv[1]); print('held', flush=True); time.sleep(30)", home], stdout=subprocess.PIPE, text=True)

    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(RuntimeError, match="another aamio"):
            Runtime(home=home)
        assert holder.poll() is None, "asking about the holder ended it"
    finally:
        holder.kill()
        holder.wait()


def test_a_command_that_only_reads_leaves_the_files_it_read_as_they_were(home, capsys):
    state = os.path.join(home, "state.json")
    written = '{"tags":["kept.as.written"],"peers":{},"channels":[]}'

    with open(state, "w", encoding="utf-8") as handle:
        handle.write(written)

    assert cli.main(["--home", home, "scope", "list"]) == 0
    assert cli.main(["--home", home, "whoami"]) == 0
    assert open(state, encoding="utf-8").read() == written
    assert not os.path.exists(os.path.join(home, "outbox.json"))
    assert "kept.as.written" in capsys.readouterr().out


def test_a_home_whose_files_cannot_be_read_is_refused_by_the_command_line_with_the_reason(home, capsys):
    state = os.path.join(home, "state.json")

    with open(state, "w", encoding="utf-8") as handle:
        handle.write("{not json")

    assert cli.main(["--home", home, "whoami"]) == 1
    assert "state.json could not be read" in capsys.readouterr().err
    assert open(state, encoding="utf-8").read() == "{not json"
    assert not os.path.exists(os.path.join(home, "lock"))


def test_a_lock_whose_pid_went_to_a_later_process_is_taken_over(home):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])

    try:
        time.sleep(0.3)
        started = process_started_at(child.pid)

        if started is None:
            pytest.skip("this system does not say when a process started")

        assert 0 <= time.time() - started < 60

        with open(os.path.join(home, "lock"), "w", encoding="utf-8") as handle:
            handle.write('{"pid": %d, "at": %d}' % (child.pid, int(time.time()) - 3600))

        runtime = Runtime(home=home)

        try:
            assert runtime.owns_lock is True
        finally:
            runtime.close()

        assert child.poll() is None, "taking the lock over ended the process"
    finally:
        child.kill()
        child.wait()


def test_closing_twice_saves_once(home):
    runtime = Runtime(home=home)
    saves = []
    runtime.save_state = lambda: saves.append("state")
    runtime.save_outbox = lambda: saves.append("outbox")
    runtime.close()
    runtime.close()

    assert saves == ["state", "outbox"]
    assert not os.path.exists(os.path.join(home, "lock"))
