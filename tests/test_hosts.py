"""Where the client points: one place for the defaults, the environment over them, and arguments over both.

No network.
"""

from aamio.client import DEFAULT_BOARD, DEFAULT_HOST, VERIFYUM_MCP, AamioClient
from aamio.gate import GateStop, plan

W = "b4netymg7r5nnt2yiscp"
HOST_VARIABLES = ("AAMIO_HOST", "AAMIO_BOARD", "AAMIO_VERIFYUM")


def test_without_the_environment_the_client_uses_the_constants(monkeypatch):
    for name in HOST_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    client = AamioClient()
    assert (client.host, client.board, client.verifyum) == (DEFAULT_HOST, DEFAULT_BOARD, VERIFYUM_MCP)


def test_the_environment_points_it_elsewhere(monkeypatch):
    monkeypatch.setenv("AAMIO_HOST", "https://aamio.example/")
    monkeypatch.setenv("AAMIO_BOARD", "https://board.aamio.example")
    monkeypatch.setenv("AAMIO_VERIFYUM", "https://verifyum.example/mcp/")
    client = AamioClient()
    assert (client.host, client.board, client.verifyum) == ("https://aamio.example", "https://board.aamio.example", "https://verifyum.example/mcp")


def test_arguments_win_over_the_environment(monkeypatch):
    for name in HOST_VARIABLES:
        monkeypatch.setenv(name, "https://from.environment.example")
    client = AamioClient("https://aamio.other.example", board="https://board.other.example", verifyum="https://verifyum.other.example/mcp")
    assert (client.host, client.board, client.verifyum) == ("https://aamio.other.example", "https://board.other.example", "https://verifyum.other.example/mcp")


def test_anchor_and_proof_go_to_the_verifyum_the_client_was_given(monkeypatch):
    client = AamioClient(verifyum="https://verifyum.example/mcp")
    urls = []

    def http(method, url, body=None, headers=None, timeout=None):
        urls.append(url)
        return 200, {}

    monkeypatch.setattr(client, "http", http)
    client.anchor("00" * 32, "idempotency")
    client.proof("proof")
    assert urls == ["https://verifyum.example/mcp", "https://verifyum.example/mcp"]


def test_a_gate_refusal_names_the_host_the_inbox_is_on():
    def fix_for(*host):
        try:
            plan({"require": {"toll": "any"}}, W, *host)
        except GateStop as stop:
            return stop.fix
        raise AssertionError("an unknown requirement must stop the send")

    assert "GET https://aamio.example/%s/gate" % W in fix_for("https://aamio.example/")
    assert "GET %s/%s/gate" % (DEFAULT_HOST, W) in fix_for()
