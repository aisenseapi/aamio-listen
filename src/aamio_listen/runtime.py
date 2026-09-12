"""The runtime: what a sidecar does for an agent so the model never touches a secret.

State lives under AAMIO_HOME (default ~/.aamio):

    key              32-byte seed, hex, mode 600. The runtime's identity.
    partners.json    [{"name": ..., "key": ...}] from the contract. Keys, not addresses.
    state.json       open channels (read keys, mode 600), learned peers, tags.
    archive/*.jsonl  decrypted messages and receipts, per channel. The party's own record.

The inbox is a thread with the maximum lifetime. Before it expires the runtime
opens a new one and republishes presence, so partners keep finding it.
"""

import json
import os
import queue
import re
import threading
import time

from .client import AamioClient, DEFAULT_HOST
from .crypto import Keys, is_envelope, is_key, key_hash, presence_signing_input, sha256hex, thread_signing_input, unb64url

INBOX_TTL = 3600
PRESENCE_TTL = 120
PRESENCE_REFRESH = 60
RENEW_BEFORE = 180


def home_dir() -> str:
    return os.environ.get("AAMIO_HOME") or os.path.join(os.path.expanduser("~"), ".aamio")


class Channel:
    def __init__(self, label, read_key, w, expire_at, allow=None, after=0):
        self.label = label
        self.read_key = read_key
        self.w = w
        self.expire_at = int(expire_at)
        self.allow = list(allow or [])
        self.after = int(after)
        self.seen = set()
        self.received = []
        self.lock = threading.Lock()
        self.poller = None
        self.closed = False

    def to_state(self):
        return {"label": self.label, "read_key": self.read_key, "w": self.w, "expire_at": self.expire_at, "allow": self.allow, "after": self.after}

    @classmethod
    def from_state(cls, item):
        return cls(item["label"], item["read_key"], item["w"], item["expire_at"], item.get("allow"), item.get("after", 0))


class Runtime:
    def __init__(self, home=None, host=None, tags=None, archive=True, log=None):
        self.home = home or home_dir()
        self.host = host or os.environ.get("AAMIO_HOST") or DEFAULT_HOST
        self.client = AamioClient(self.host)
        self.archive_enabled = archive
        self.log = log or (lambda line: None)
        os.makedirs(self.home, exist_ok=True)
        os.makedirs(os.path.join(self.home, "archive"), exist_ok=True)
        self.keys = self._load_or_create_keys()
        self.partners = self._load_json("partners.json", [])
        state = self._load_json("state.json", {})
        self.tags = tags if tags is not None else state.get("tags") or [t for t in (os.environ.get("AAMIO_TAGS") or "").split(",") if t]
        self.peers = dict(state.get("peers") or {})          # write address -> partner key
        self.channels = {}
        for item in state.get("channels") or []:
            channel = Channel.from_state(item)
            if channel.expire_at > time.time():
                self.channels[channel.label] = channel
        self.presence_at = 0.0
        self.inbound = queue.Queue()
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.listener = None

    # ----------------------------------------------------------- storage --

    def _path(self, name):
        return os.path.join(self.home, name)

    def _load_json(self, name, default):
        try:
            with open(self._path(name), "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, ValueError):
            return default

    def _save_json(self, name, value, private=False):
        path = self._path(name)
        with open(path + ".tmp", "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
        os.replace(path + ".tmp", path)
        if private:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def _load_or_create_keys(self):
        path = self._path("key")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return Keys(bytes.fromhex(handle.read().strip()))
        except (OSError, ValueError):
            keys = Keys.generate()
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(keys.seed.hex() + "\n")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return keys

    def save_state(self):
        with self.lock:
            self._save_json("state.json", {"tags": self.tags, "peers": self.peers, "channels": [c.to_state() for c in self.channels.values()]}, private=True)

    def archive(self, label, record):
        if not self.archive_enabled:
            return
        with open(os.path.join(self.home, "archive", "%s.jsonl" % label), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    # ---------------------------------------------------------- partners --

    def whoami(self):
        inbox = self.channels.get("inbox")
        return {"key": self.keys.public, "hash": self.keys.hash, "hash_prefix": self.keys.hash[:8], "inbox": inbox.w if inbox else None, "inbox_expires_at": inbox.expire_at if inbox else None, "host": self.host, "tags": self.tags}

    def partner_add(self, name, key):
        if not is_key(key):
            raise ValueError("not a base64url Ed25519 public key of 32 bytes")
        self.partners = [p for p in self.partners if p["name"] != name and p["key"] != key]
        self.partners.append({"name": name, "key": key})
        self._save_json("partners.json", self.partners)

    def partner_remove(self, name):
        self.partners = [p for p in self.partners if p["name"] != name]
        self._save_json("partners.json", self.partners)

    def partner_list(self):
        return [{"name": p["name"], "key": p["key"], "hash_prefix": key_hash(p["key"])[:8]} for p in self.partners]

    def partner_by_name(self, name):
        for p in self.partners:
            if p["name"].lower() == str(name).lower():
                return p
        return None

    def partner_by_key(self, key):
        for p in self.partners:
            if p["key"] == key:
                return p
        return None

    def name_for_key(self, key):
        p = self.partner_by_key(key)
        return p["name"] if p else None

    # ------------------------------------------------------------ inbox --

    def ensure_inbox(self):
        inbox = self.channels.get("inbox")
        if inbox and inbox.expire_at - time.time() > RENEW_BEFORE:
            return inbox
        allow = [p["key"] for p in self.partners] if self.partners else None
        status, data, read_key, w = self.client.open_thread(INBOX_TTL, allow)
        if status != 201:
            raise RuntimeError("could not open inbox: %s %s" % (status, data))
        old = inbox
        inbox = Channel("inbox", read_key, w, data["expire_at"], allow)
        with self.lock:
            if old is not None:
                # Keep reading the old one until it dies; partners may still write there.
                self.channels["inbox-%d" % old.expire_at] = old
            self.channels["inbox"] = inbox
        self.save_state()
        self.log("inbox %s until %d%s" % (w, inbox.expire_at, " (allowlist %d keys)" % len(allow) if allow else ""))
        self.publish_presence(force=True)
        return inbox

    def publish_presence(self, force=False):
        if not force and time.time() - self.presence_at < PRESENCE_REFRESH:
            return None
        inbox = self.channels.get("inbox")
        if inbox is None:
            return None
        body = json.dumps({"w": inbox.w, "tags": self.tags[:8], "ttl": PRESENCE_TTL}, separators=(",", ":"))
        status, data = self.client.presence_put(self.keys.public, body, self.keys.sign(presence_signing_input(self.keys.public, body)))
        self.presence_at = time.time()
        if status != 200:
            self.log("presence failed: %s %s" % (status, data))
        return status == 200

    # --------------------------------------------------------- channels --

    def open_channel(self, label, ttl, allow_names=None):
        if label in self.channels or label.startswith("inbox"):
            raise ValueError("channel exists or reserved: " + label)
        keys = []
        for name in allow_names or []:
            partner = self.partner_by_name(name)
            if partner is None:
                raise ValueError("unknown partner: " + str(name))
            keys.append(partner["key"])
        status, data, read_key, w = self.client.open_thread(int(ttl), keys or None)
        if status != 201:
            raise RuntimeError("could not open channel: %s %s" % (status, data))
        channel = Channel(label, read_key, w, data["expire_at"], keys)
        with self.lock:
            self.channels[label] = channel
        self.save_state()
        return {"label": label, "w": w, "expire_at": channel.expire_at, "allow": [self.name_for_key(k) or k for k in keys]}

    def close_channel(self, label):
        channel = self.channels.get(label)
        if channel is None:
            raise ValueError("no such channel: " + label)
        status, data = self.client.delete(channel.w, channel.read_key)
        channel.closed = True
        with self.lock:
            self.channels.pop(label, None)
        self.save_state()
        return {"label": label, "status": status, "deleted": status == 200}

    def channel_list(self):
        return [{"label": c.label, "w": c.w, "expire_at": c.expire_at, "seconds_left": max(0, int(c.expire_at - time.time())), "allow": [self.name_for_key(k) or k for k in c.allow], "received": len(c.received)} for c in self.channels.values()]

    # ----------------------------------------------------------- lookup --

    def lookup(self, names=None, wait=0):
        partners = self.partners if not names else [p for p in self.partners if p["name"].lower() in [str(n).lower() for n in names]]
        if not partners:
            return {"online": [], "offline": [], "error": "no partners to look up"}
        prefixes = [key_hash(p["key"])[:8] for p in partners]
        status, data = self.client.presence_lookup(prefixes, wait)
        if status != 200:
            return {"online": [], "offline": [p["name"] for p in partners], "error": "lookup failed: %s %s" % (status, data)}
        online = []
        found = set()
        for match in data.get("matches", []):
            partner = self.partner_by_key(match.get("key"))
            if partner is None:
                continue
            found.add(partner["name"])
            with self.lock:
                self.peers[match["w"]] = partner["key"]
            online.append({"name": partner["name"], "w": match["w"], "tags": match.get("tags", []), "expires_at": match.get("expire_at")})
        self.save_state()
        return {"online": online, "offline": [p["name"] for p in partners if p["name"] not in found]}

    def address_for(self, name):
        """The write address a partner currently answers on, from presence."""
        partner = self.partner_by_name(name)
        if partner is None:
            raise ValueError("unknown partner: " + str(name))
        result = self.lookup([name])
        for entry in result["online"]:
            return entry["w"], partner["key"]
        raise LookupError("%s is not online right now" % partner["name"])

    # ------------------------------------------------------------- send --

    def send(self, to, text=None, data=None, reply_to=None):
        """to: a partner name, or a write address learned from presence or from a message."""
        if is_key(str(to)):
            partner = self.partner_by_key(to)
            if partner is None:
                raise ValueError("key is not in partners")
            to = partner["name"]
        if isinstance(to, str) and re.fullmatch(r"[a-z2-7]{20}", to):
            w = to
            key = self.peers.get(w)
            if key is None:
                raise LookupError("no key known for address %s; look the partner up or reply to a message" % w)
        else:
            w, key = self.address_for(to)
        inbox = self.ensure_inbox()
        body = {"from": self.keys.hash[:8], "reply_to": reply_to or inbox.w}
        if text is not None:
            body["text"] = str(text)
        if data is not None:
            body["data"] = data
        plaintext = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        envelope = self.keys.seal(key, plaintext)
        signature = self.keys.sign(thread_signing_input(w, envelope))
        status, result = self.client.post(w, envelope, self.keys.public, signature)
        if status in (404, 410) and not (isinstance(to, str) and to == w):
            # The partner may have renewed its inbox. Ask presence again, once.
            w, key = self.address_for(to)
            envelope = self.keys.seal(key, plaintext)
            signature = self.keys.sign(thread_signing_input(w, envelope))
            status, result = self.client.post(w, envelope, self.keys.public, signature)
        record = {"kind": "sent", "at": time.time(), "to": self.name_for_key(key) or key, "w": w, "status": status, "seq": (result or {}).get("seq") if isinstance(result, dict) else None, "sha256": (result or {}).get("sha256") if isinstance(result, dict) else None, "body": body}
        self.archive("sent", record)
        if status != 201:
            raise RuntimeError("send failed: %s %s" % (status, result))
        return {"to": record["to"], "w": w, "seq": result["seq"], "at": result["at"], "sha256": result["sha256"], "expire_at": result["expire_at"]}

    # ------------------------------------------------------------- read --

    def _open(self, message):
        if not message.get("verified") or not message.get("from"):
            return {"undecryptable": "unsigned"}
        if not is_envelope(message["body"]):
            return {"undecryptable": "not an envelope", "text": message["body"][:500]}
        try:
            plaintext = self.keys.open(message["from"], message["body"])
            return json.loads(plaintext.decode("utf-8"))
        except Exception as error:
            return {"undecryptable": error.__class__.__name__}

    def poll(self, channel, wait=0):
        status, data = self.client.read(channel.w, channel.read_key, channel.after, wait)
        if status == 410:
            return "expired", []
        if status != 200:
            return "error", []
        entries = []
        for message in data.get("messages", []):
            entry = {"channel": channel.label, "seq": message["seq"], "at": message["at"], "verified": message["verified"], "from_key": message["from"], "sender": self.name_for_key(message["from"]) or ("unknown key" if message["from"] else "unsigned"), "sha256": message["sha256"], "replay": message["sha256"] in channel.seen}
            channel.seen.add(message["sha256"])
            entry["body"] = self._open(message)
            if isinstance(entry["body"], dict) and isinstance(entry["body"].get("reply_to"), str) and message["from"]:
                with self.lock:
                    self.peers[entry["body"]["reply_to"]] = message["from"]
            entries.append(entry)
            with channel.lock:
                channel.received.append(entry)
            self.archive(channel.label, dict(entry, kind="received"))
        if entries:
            channel.after = max(channel.after, entries[-1]["seq"])
            self.save_state()
        return "ok", entries

    def _poll_loop(self, channel):
        """One long-poll loop per channel, so mail on any channel is seen at once."""
        while not self.stop.is_set() and not channel.closed and channel.expire_at > time.time():
            try:
                state, entries = self.poll(channel, 20)
                if state == "expired":
                    break
                if state == "error":
                    time.sleep(2)
                for entry in entries:
                    self.inbound.put(entry)
            except Exception as error:
                self.log("poller %s: %s" % (channel.label, error))
                time.sleep(3)
        channel.poller = None

    def _listen(self):
        """Keeps the inbox alive and presence fresh, and gives every channel a poller."""
        while not self.stop.is_set():
            try:
                self.ensure_inbox()
                self.publish_presence()
                for label, channel in list(self.channels.items()):
                    if channel.expire_at <= time.time():
                        channel.closed = True
                        if label != "inbox":
                            with self.lock:
                                self.channels.pop(label, None)
                        continue
                    if channel.poller is None:
                        channel.poller = threading.Thread(target=self._poll_loop, args=(channel,), daemon=True)
                        channel.poller.start()
            except Exception as error:
                self.log("listener: %s" % error)
            self.stop.wait(2)

    def start(self):
        if self.listener is None:
            self.ensure_inbox()
            self.listener = threading.Thread(target=self._listen, daemon=True)
            self.listener.start()
        return self

    def read(self, wait=0, limit=50):
        """Messages the listener has received and nobody has read yet."""
        if self.listener is None:
            # No background listener: poll directly.
            self.ensure_inbox()
            self.publish_presence()
            collected = []
            first = True
            for channel in list(self.channels.values()):
                state, entries = self.poll(channel, wait if first else 0)
                first = False
                collected.extend(entries)
            return collected[:limit]
        collected = []
        deadline = time.time() + max(0, int(wait))
        while len(collected) < limit:
            remaining = deadline - time.time()
            try:
                collected.append(self.inbound.get(timeout=max(0.0, remaining) if not collected else 0.05))
            except queue.Empty:
                if collected or remaining <= 0:
                    break
        return collected

    # ---------------------------------------------------------- receipt --

    def receipt(self, label="inbox", anchor=False):
        channel = self.channels.get(label)
        if channel is None:
            raise ValueError("no such channel: " + label)
        status, data = self.client.receipt(channel.w, channel.read_key)
        if status != 200:
            raise RuntimeError("receipt failed: %s %s" % (status, data))
        with channel.lock:
            entries = sorted(channel.received, key=lambda e: e["seq"])
        lines = "".join("%d\t%d\t%s\t%s\n" % (e["seq"], e["at"], e["sha256"], e["from_key"] or "-") for e in entries)
        local_root = sha256hex(lines)
        # Sign what we took, so partners can exchange receipts and compare
        # without trusting the network's word alone.
        attestation = "aamio-receipt-v1\n%s\n%s\n%d\n%d" % (channel.w, data["root"], data["count"], data.get("issued_at", 0))
        result = {"label": label, "w": channel.w, "root": data["root"], "commitment": data.get("commitment"), "count": data["count"], "keys": [self.name_for_key(k) or k for k in data.get("keys", [])], "local_root_matches": local_root == data["root"], "signed_by": self.keys.public, "signature": self.keys.sign(attestation), "signed_text": attestation, "receipt": data}
        if anchor:
            idem = sha256hex("aamio-listen:%s:%s" % (self.keys.hash, data["root"]))[:32]
            status, proof = self.client.anchor(data["root"], idem)
            result["anchor"] = proof if status == 200 else {"error": status, "detail": proof}
        self.archive(label, {"kind": "receipt", "at": time.time(), "result": result})
        return result

    def close(self):
        self.stop.set()
        self.save_state()
