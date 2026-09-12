"""Plain HTTP against aamio. Standard library only.

Every call returns (status, body). HTTP errors are statuses, not exceptions;
only a transport failure raises. Read keys travel in headers, never in URLs.
"""

import json
import random
import string
import urllib.error
import urllib.request

from .crypto import b64url, sha256hex

DEFAULT_HOST = "https://aamio.at"
VERIFYUM_MCP = "https://api.verifyum.com/mcp"


def make_read_key(length: int = 26) -> str:
    alphabet = string.ascii_lowercase + string.digits
    rng = random.SystemRandom()
    return "".join(rng.choice(alphabet) for _ in range(length))


def write_address(read_key: str) -> str:
    import base64
    import hashlib

    return base64.b32encode(hashlib.sha256(read_key.encode("ascii")).digest()).decode("ascii").lower()[:20]


class AamioClient:
    def __init__(self, host: str = DEFAULT_HOST, timeout: int = 60):
        self.host = host.rstrip("/")
        self.timeout = timeout

    def http(self, method: str, url: str, body=None, headers=None, timeout=None):
        data = None
        if body is not None:
            data = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", "aamio-listen/0.1")
        if data is not None and "Content-Type" not in (headers or {}):
            request.add_header("Content-Type", "application/json")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                status, text = response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            status, text = error.code, error.read().decode("utf-8", "replace")
        try:
            return status, (json.loads(text) if text else None)
        except ValueError:
            return status, text

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

    def post(self, w: str, body_text: str, key: str, signature: str, content_type: str = "text/plain"):
        return self.call("POST", "/" + w, body_text, {"Content-Type": content_type, "X-Key": key, "X-Sig": signature})

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

    # service

    def health(self):
        return self.call("GET", "/health")

    def descriptor(self):
        return self.call("GET", "/.well-known/aamio.json")

    # verifyum

    def anchor(self, root_hex: str, idempotency_key: str):
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "verifyum_anchor_commitment", "arguments": {"commitment": "sha256:" + root_hex, "idempotency_key": idempotency_key}}}
        status, reply = self.http("POST", VERIFYUM_MCP, message, {"MCP-Protocol-Version": "2025-11-25"})
        try:
            return status, json.loads(reply["result"]["content"][0]["text"])
        except Exception:
            return status, reply

    def proof(self, proof_id: str):
        message = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "verifyum_get_proof", "arguments": {"proof_id": proof_id}}}
        status, reply = self.http("POST", VERIFYUM_MCP, message, {"MCP-Protocol-Version": "2025-11-25"})
        try:
            return status, json.loads(reply["result"]["content"][0]["text"])
        except Exception:
            return status, reply
