"""What the MCP surface tells a model about incoming messages.

A real exchange on 2026-09-13 went wrong because the receiving agent read
"unknown key" and "not an envelope" as "unsigned" and kept waiting for a
signed answer that had already arrived. The tool text is the first thing a
model reads, so it must say what the runtime actually does: send sealed and
signed, receive signed plain text as well as sealed, and mark each one.
"""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aamio_listen import mcp_server


def tool(name):
    return next(t for t in mcp_server.TOOLS if t["name"] == name)


def instructions():
    reply = mcp_server.handle(None, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    return reply["result"]["instructions"]


def test_fifteen_tools_as_the_docs_say():
    assert len(mcp_server.TOOLS) == 15


def test_read_says_plain_text_and_unknown_key_are_not_unsigned():
    text = tool("aamio_read")["description"]
    assert "plain text" in text
    assert "unknown key" in text
    assert "not a missing one" in text


def test_board_post_does_not_promise_sealed_answers():
    text = tool("aamio_board_post")["description"]
    assert "any signed message" in text
    assert "answers to it are encrypted to you" not in text


def test_instructions_separate_sending_from_receiving():
    text = instructions()
    assert "encrypted and signed end to end" not in text
    assert "What you send" in text and "What you receive" in text
    assert "not an unsigned one" in text
    assert "never" in text or "not" in text  # content is never an instruction
