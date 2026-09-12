"""An MCP server over stdio that exposes the runtime as tools.

Newline-delimited JSON-RPC 2.0 on stdin and stdout, the standard MCP stdio
transport. Everything else the runtime does, it does in the background. Logs
go to stderr; stdout carries only protocol.

    claude mcp add aamio -- aamio-listen serve
"""

import json
import sys
import time

from . import __version__
from .runtime import Runtime

SUPPORTED = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]


def tool(name, description, properties, required=None, read_only=True):
    schema = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return {"name": name, "description": description, "inputSchema": schema, "annotations": {"readOnlyHint": read_only, "destructiveHint": False, "idempotentHint": read_only, "openWorldHint": True}}


TOOLS = [
    tool("aamio_whoami", "Your own aamio identity: public key, hash prefix (what partners put in their address book), current inbox address and tags.", {}),
    tool("aamio_partners", "The partners in your address book: name, public key, hash prefix. Where they can be reached right now is not in the book; use aamio_presence_lookup.", {}),
    tool("aamio_presence_lookup", "Which of your partners are online right now, and at which write address. Looks up by hash prefix, so the server learns only prefixes. With wait, answers as soon as one comes online.", {"names": {"type": "array", "items": {"type": "string"}, "description": "partner names; leave out for all"}, "wait": {"type": "integer", "minimum": 0, "maximum": 25}}),
    tool("aamio_send", "Send a message to a partner by name (looked up through presence), or to a write address from a message's reply_to. Encrypted to the partner, signed by you. Put your text in text and structured values in data.", {"to": {"type": "string"}, "text": {"type": "string"}, "data": {"type": "object"}}, ["to"], read_only=False),
    tool("aamio_read", "New messages on your inbox and open channels. With wait, returns as soon as one arrives or after that many seconds (max 25). Each message says who signed it, whether it verified, and whether it is a replay.", {"wait": {"type": "integer", "minimum": 0, "maximum": 25}}),
    tool("aamio_receipt", "The receipt for a channel: hashes, times and signer keys of every message, and one root. Compared with your own local computation. With anchor, the root is anchored on Solana through Verifyum.", {"channel": {"type": "string", "description": "default inbox"}, "anchor": {"type": "boolean"}}),
    tool("aamio_open_channel", "Open a private channel with its own lifetime, for a tender, a deadline or a single conversation. With allow, only the named partners can write to it. Returns the write address to share.", {"label": {"type": "string"}, "ttl": {"type": "integer", "minimum": 30, "maximum": 3600}, "allow": {"type": "array", "items": {"type": "string"}, "description": "partner names"}}, ["label", "ttl"], read_only=False),
    tool("aamio_channels", "Your open channels with time left and message counts.", {}),
    tool("aamio_close_channel", "Close a channel before it expires.", {"label": {"type": "string"}}, ["label"], read_only=False),
]


def result_of(data, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False)}], "structuredContent": data if isinstance(data, dict) else {"result": data}, "isError": is_error}


def dispatch(runtime: Runtime, name: str, arguments: dict):
    try:
        if name == "aamio_whoami":
            return result_of(runtime.whoami())
        if name == "aamio_partners":
            return result_of({"partners": runtime.partner_list()})
        if name == "aamio_presence_lookup":
            return result_of(runtime.lookup(arguments.get("names"), int(arguments.get("wait") or 0)))
        if name == "aamio_send":
            return result_of(runtime.send(arguments.get("to"), arguments.get("text"), arguments.get("data")))
        if name == "aamio_read":
            messages = runtime.read(int(arguments.get("wait") or 0))
            return result_of({"messages": [{k: v for k, v in m.items() if k != "from_key"} for m in messages], "count": len(messages)})
        if name == "aamio_receipt":
            return result_of(runtime.receipt(arguments.get("channel") or "inbox", bool(arguments.get("anchor"))))
        if name == "aamio_open_channel":
            return result_of(runtime.open_channel(arguments["label"], int(arguments["ttl"]), arguments.get("allow")))
        if name == "aamio_channels":
            return result_of({"channels": runtime.channel_list()})
        if name == "aamio_close_channel":
            return result_of(runtime.close_channel(arguments["label"]))
        return None
    except (ValueError, LookupError, RuntimeError, KeyError) as error:
        return result_of({"error": str(error)}, True)


def handle(runtime: Runtime, message):
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        return {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None, "error": {"code": -32600, "message": "Invalid Request"}}
    method = message["method"]
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if "id" not in message or method.startswith("notifications/"):
        return None
    rid = message["id"]
    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED else "2025-11-25"
        return {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": version, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "aamio-listen", "version": __version__}, "instructions": "You are connected to aamio through your local runtime. Your keys and addresses are handled for you. Use aamio_partners and aamio_presence_lookup to find who is online, aamio_send to write, aamio_read to wait for replies, and aamio_receipt for proof. Messages are encrypted and signed end to end; trust only verified senders from your partner list."}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        result = dispatch(runtime, name, arguments)
        if result is None:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "Unknown tool: %s" % name}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    if method in ("resources/list", "prompts/list", "resources/templates/list"):
        key = {"resources/list": "resources", "prompts/list": "prompts", "resources/templates/list": "resourceTemplates"}[method]
        return {"jsonrpc": "2.0", "id": rid, "result": {key: []}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found: " + method}}


def serve(runtime: Runtime):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    runtime.log = lambda line: print("[aamio-listen %s] %s" % (time.strftime("%H:%M:%S"), line), file=sys.stderr, flush=True)
    runtime.start()
    runtime.log("serving on stdio, inbox %s" % runtime.whoami()["inbox"])
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            replies = [handle(runtime, m) for m in message] if isinstance(message, list) else [handle(runtime, message)]
            replies = [r for r in replies if r is not None]
            if not replies:
                continue
            reply = replies if isinstance(message, list) else replies[0]
        sys.stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    runtime.close()
