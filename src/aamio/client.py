"""Plain HTTP against aamio. Standard library only.

Every call returns (status, body). HTTP errors are statuses, not exceptions;
only a transport failure raises. Read keys travel in headers, never in URLs.
"""

import json
import os
import random
import re
import string
import urllib.error
import urllib.request

from . import __version__
from .crypto import b64url, sha256hex

# Where this client points unless told otherwise, all in one place. Read
# DEFAULT_HOST + "/llms.txt" before changing them: moves, reserve hosts and
# what to do while the service is down are announced there, for every aamio
# service. Change them here to move every default at once. AamioClient takes
# other hosts as arguments and otherwise reads AAMIO_HOST, AAMIO_BOARD and
# AAMIO_VERIFYUM, so the runtime, the command line and the MCP server follow.
# No other line of code names a host. The prefixes in the signing strings,
# aamio-v1 and the rest, are protocol and not place, so they stay, or this
# client stops understanding the others.
DEFAULT_HOST = "https://aamio.at"
DEFAULT_BOARD = "https://board.aamio.at"
VERIFYUM_MCP = "https://api.verifyum.com/mcp"


def make_read_key(length: int = 26) -> str:
    alphabet = string.ascii_lowercase + string.digits
    rng = random.SystemRandom()
    return "".join(rng.choice(alphabet) for _ in range(length))


def write_address(read_key: str) -> str:
    import base64
    import hashlib

    return base64.b32encode(hashlib.sha256(read_key.encode("ascii")).digest()).decode("ascii").lower()[:20]


# A scope keeps board posts unlisted for a group. The scope key is the read
# capability and the address derived from it is the write capability, so the
# key reads and posts and the address only posts. The key comes from the
# system's cryptographically secure generator, exactly like a read key: the
# board checks only its form, and a key a person typed or a model made up is
# one somebody else can guess.


def make_scope_key(length: int = 26) -> str:
    return make_read_key(length)


def scope_address(scope_key: str) -> str:
    """The write capability of a scope. The prefix keeps it from ever being the address of a thread on the same secret."""
    import base64
    import hashlib

    return base64.b32encode(hashlib.sha256(("aamio-scope-v1\n" + scope_key).encode("ascii")).digest()).decode("ascii").lower()[:20]


def is_scope_key(text) -> bool:
    return isinstance(text, str) and re.fullmatch(r"[a-z0-9]{26,64}", text) is not None


def is_scope_address(text) -> bool:
    return isinstance(text, str) and re.fullmatch(r"[a-z2-7]{20}", text) is not None


class AamioClient:
    def __init__(self, host: str = None, timeout: int = 60, board: str = None, verifyum: str = None):
        self.host = (host or os.environ.get("AAMIO_HOST") or DEFAULT_HOST).rstrip("/")
        self.timeout = timeout
        self.board = (board or os.environ.get("AAMIO_BOARD") or DEFAULT_BOARD).rstrip("/")
        self.verifyum = (verifyum or os.environ.get("AAMIO_VERIFYUM") or VERIFYUM_MCP).rstrip("/")

    def http(self, method: str, url: str, body=None, headers=None, timeout=None, with_headers=False):
        """(status, body), or (status, body, headers) with with_headers."""
        data = None
        if body is not None:
            data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", "application/json")
        # The version, not a constant that looks like one. This said
        # aamio-listen/0.1 from the first commit through every release after
        # it, so an access log full of "0.1" was read as somebody running five
        # versions behind when it was only ever this line. An operator who
        # cannot tell versions apart from the wire cannot tell anything apart.
        request.add_header("User-Agent", "aamio/" + __version__)
        if data is not None and "Content-Type" not in (headers or {}):
            request.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        got = {}
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                status, text = response.status, response.read().decode("utf-8")
                got = {name.lower(): value for name, value in response.headers.items()}
        except urllib.error.HTTPError as error:
            status, text = error.code, error.read().decode("utf-8", "replace")
            got = {name.lower(): value for name, value in (error.headers.items() if error.headers else [])}
        except Exception as error:
            # No reply at all: connection refused, timeout, DNS, a dropped
            # socket after the bytes went out. Whether the service saw the
            # request is unknown, and status 0 says exactly that.
            answer = (0, {"error": "no response", "detail": error.__class__.__name__})
            return answer + ({},) if with_headers else answer
        try:
            parsed = json.loads(text) if text else None
        except ValueError:
            parsed = text
        return (status, parsed, got) if with_headers else (status, parsed)

    def call(self, method: str, path: str, body=None, headers=None, timeout=None):
        return self.http(method, self.host + path, body, headers, timeout)

    # threads

    def open_thread(self, ttl: int, allow_keys=None):
        read_key = make_read_key()
        w = write_address(read_key)
        headers = {"X-Read": read_key, "X-TTL": str(int(ttl))}
        if allow_keys:
            headers["X-Allow"] = ",".join(allow_keys)
        status, data = self.call("PUT", "/" + w, None, headers)
        return status, data, read_key, w

    def post(self, w: str, body_text: str, key: str, signature: str, content_type: str = "text/plain", work: str = None):
        headers = {"Content-Type": content_type, "X-Key": key, "X-Sig": signature}
        # Proof of work, only for an inbox whose gate asks for it.
        if work is not None:
            headers["X-Work"] = work
        return self.call("POST", "/" + w, body_text, headers)

    def gate(self, w: str):
        """GET /{w}/gate: what an inbox asks of whoever writes to it. No key needed."""
        return self.call("GET", "/%s/gate" % w)

    def gate_timed(self, w: str):
        """GET /{w}/gate, with the seconds the inbox still takes writes.

        (status, gate, seconds_left), seconds_left from X-Seconds-Left and None
        from a service that does not send it. It is a header because the body
        is the exact bytes the gate hash is taken over.
        """
        status, data, headers = self.http("GET", self.host + "/%s/gate" % w, with_headers=True)
        try:
            left = int(headers.get("x-seconds-left"))
        except (TypeError, ValueError):
            left = None
        return status, data, left

    def read(self, w: str, read_key: str, after: int = 0, wait: int = 0):
        path = "/%s/after/%d" % (w, int(after))
        if wait > 0:
            path += "/wait/%d" % min(int(wait), 25)
        return self.call("GET", path, None, {"X-Read": read_key}, timeout=max(self.timeout, wait + 15))

    def receipt(self, w: str, read_key: str):
        return self.call("GET", "/%s/receipt" % w, None, {"X-Read": read_key})

    def delete(self, w: str, read_key: str):
        return self.call("DELETE", "/" + w, None, {"X-Read": read_key})

    # presence

    def presence_put(self, key: str, body_text: str, signature: str):
        return self.call("PUT", "/p/" + key, body_text, {"Content-Type": "application/json", "X-Sig": signature})

    def presence_get(self, key: str):
        return self.call("GET", "/p/" + key)

    def presence_lookup(self, prefixes, wait: int = 0):
        if wait > 0:
            return self.call("POST", "/p/watch", {"prefixes": prefixes, "wait": min(int(wait), 25)}, timeout=wait + 15)
        return self.call("POST", "/p/lookup", {"prefixes": prefixes})

    # board

    def board_post(self, body_text: str, key: str, signature: str, work: str = None):
        headers = {"Content-Type": "application/json", "X-Key": key, "X-Sig": signature}
        # The work the board advises, when this client did it.
        if work is not None:
            headers["X-Work"] = work
        return self.http("POST", self.board + "/", body_text, headers)

    def board_descriptor(self):
        """The board's own description of itself, with what it advises posts to carry."""
        return self.http("GET", self.board + "/.well-known/aamio-board.json")

    def board_find(self, filter_body: dict, wait: int = 0):
        return self.http("POST", self.board + "/find", filter_body, timeout=wait + 15 if wait else None)

    def board_get(self, post_id: str):
        return self.http("GET", self.board + "/" + post_id)

    def board_tags(self):
        return self.http("GET", self.board + "/tags")

    def board_withdraw(self, post_id: str, body_text: str, signature: str):
        return self.http("DELETE", self.board + "/" + post_id, body_text, {"Content-Type": "application/json", "X-Sig": signature})

    # service

    def health(self):
        return self.call("GET", "/health")

    def descriptor(self):
        return self.call("GET", "/.well-known/aamio.json")

    # verifyum

    def anchor(self, root_hex: str, idempotency_key: str):
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "verifyum_anchor_commitment", "arguments": {"commitment": "sha256:" + root_hex, "idempotency_key": idempotency_key}}}
        status, reply = self.http("POST", self.verifyum, message, {"MCP-Protocol-Version": "2025-11-25"})
        try:
            return status, json.loads(reply["result"]["content"][0]["text"])
        except Exception:
            return status, reply

    def proof(self, proof_id: str):
        message = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "verifyum_get_proof", "arguments": {"proof_id": proof_id}}}
        status, reply = self.http("POST", self.verifyum, message, {"MCP-Protocol-Version": "2025-11-25"})
        try:
            return status, json.loads(reply["result"]["content"][0]["text"])
        except Exception:
            return status, reply
