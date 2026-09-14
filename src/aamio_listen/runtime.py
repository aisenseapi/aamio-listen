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
from .crypto import Keys, board_delete_signing_input, board_signing_input, is_envelope, is_key, key_hash, presence_signing_input, sha256hex, thread_signing_input, unb64url

INBOX_TTL = 3600
# The board's own default, mirrored here so an ordinary post gets the same
# lifetime whether the field is sent or left out. The board decides; this is a
# copy, and it is the only copy in this client.
BOARD_TTL = 1800
PRESENCE_TTL = 120
PRESENCE_REFRESH = 60
RENEW_BEFORE = 180


def home_dir() -> str:
    return os.environ.get("AAMIO_HOME") or os.path.join(os.path.expanduser("~"), ".aamio")


# Homes locked by this process. The file on disk catches another process;
# this catches two runtimes in one, which is just as bad for the state.
_LOCKED_HOMES = set()


class SendFailed(RuntimeError):
    """A send that did not end in a stored message.

    outcome is refused when aamio answered and said no, and unknown when no
    answer came back at all. Unknown is not failure: the message may be on
    the other side. The entry stays in the outbox under message_id.
    """

    def __init__(self, outcome, message_id, status, detail):
        super().__init__("send %s (http %s): %s" % (outcome, status, detail))
        self.outcome = outcome
        self.message_id = message_id
        self.status = status
        self.detail = detail


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
        # seen travels with the channel: without it a restart cannot tell a
        # redelivered message from a new one, and the model may act twice.
        return {"label": self.label, "read_key": self.read_key, "w": self.w, "expire_at": self.expire_at, "allow": self.allow, "after": self.after, "seen": sorted(self.seen)}

    @classmethod
    def from_state(cls, item):
        channel = cls(item["label"], item["read_key"], item["w"], item["expire_at"], item.get("allow"), item.get("after", 0))
        channel.seen = set(item.get("seen") or [])

        return channel


class Runtime:
    def __init__(self, home=None, host=None, tags=None, archive=True, log=None):
        self.home = home or home_dir()
        self.host = host or os.environ.get("AAMIO_HOST") or DEFAULT_HOST
        self.client = AamioClient(self.host)
        self.archive_enabled = archive
        self.log = log or (lambda line: None)
        os.makedirs(self.home, exist_ok=True)
        os.makedirs(os.path.join(self.home, "archive"), exist_ok=True)
        self.owns_lock = self._take_lock()
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
        self.outbox = self._load_json("outbox.json", {})
        self.effects = self._load_json("effects.json", {})
        # Anything still pending was in flight when the last process stopped.
        # Whether it reached aamio is unknown, and it stays unknown until
        # somebody looks. Retrying is a decision, not a default.
        for entry in self.outbox.values():
            if entry.get("status") == "sending":
                entry["status"] = "unknown"
                entry["note"] = "the process stopped while this was in flight"
        self.presence_at = 0.0
        self.inbound = queue.Queue()
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.listener = None

    # -------------------------------------------------------------- lock --

    def _take_lock(self):
        """One live runtime per home. Two would overwrite each other's state.

        The file holds the pid, and a pid that is gone is not an owner. This
        catches the ordinary mistake, two sidecars on one home, not a shared
        network filesystem.
        """
        real = os.path.realpath(self.home)

        if real in _LOCKED_HOMES:
            raise RuntimeError("another aamio-listen in this process is already using %s" % self.home)

        held = self._load_json("lock", None)

        if isinstance(held, dict) and isinstance(held.get("pid"), int) and held["pid"] != os.getpid():
            alive = True
            try:
                os.kill(held["pid"], 0)
            except OSError:
                alive = False
            except Exception:
                alive = True

            if alive:
                raise RuntimeError(
                    "another aamio-listen (pid %s) is using %s. Stop it, or use a different AAMIO_HOME." % (held["pid"], self.home)
                )

        self._save_json("lock", {"pid": os.getpid(), "at": int(time.time()), "host": self.host})
        _LOCKED_HOMES.add(real)

        return True

    def _release_lock(self):
        if not getattr(self, "owns_lock", False):
            return
        held = self._load_json("lock", None)
        if isinstance(held, dict) and held.get("pid") == os.getpid():
            try:
                os.unlink(self._path("lock"))
            except OSError:
                pass
        _LOCKED_HOMES.discard(os.path.realpath(self.home))
        self.owns_lock = False

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
            handle.flush()
            # The rename is atomic, but only over bytes that reached the disk.
            os.fsync(handle.fileno())
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

    def save_outbox(self):
        with self.lock:
            self._save_json("outbox.json", self.outbox, private=True)

    def save_effects(self):
        with self.lock:
            self._save_json("effects.json", self.effects)

    def archive(self, label, record):
        if not self.archive_enabled:
            return
        # ensure_ascii=False so ordinary non-English text stays readable in the
        # file. Some text cannot be written that way at all: JSON can carry a
        # lone surrogate, Python will happily parse it into a str, and UTF-8
        # cannot encode it. It arrives as plain ASCII on the wire, so it is the
        # sender who decides which of the two kinds of text this is. That one
        # record gets escaped instead, which loses nothing and keeps every other
        # record readable.
        line = json.dumps(record, ensure_ascii=False)
        try:
            line.encode("utf-8")
        except UnicodeEncodeError:
            line = json.dumps(record, ensure_ascii=True)
        with open(os.path.join(self.home, "archive", "%s.jsonl" % label), "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

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


    # ------------------------------------------------------------ board --

    def ensure_board_inbox(self, seconds=900):
        """An inbox for board answers: any key, signed only. Reused while it lasts.

        It cannot have an allowlist of partners: whoever answers a post is by
        definition someone we have not met. X-Allow: * is the middle ground,
        and the answers themselves are sealed to our key, so the open address
        does not mean an open conversation.
        """
        held = self.channels.get("board")
        if held and held.expire_at - time.time() > seconds:
            return held
        ttl = min(INBOX_TTL, max(int(seconds) + 60, 900))
        status, data, read_key, w = self.client.open_thread(ttl, ["*"])
        if status != 201:
            raise RuntimeError("could not open the board inbox: %s %s" % (status, data))
        channel = Channel("board", read_key, w, data["expire_at"], ["*"])
        with self.lock:
            if held is not None:
                self.channels["board-%d" % held.expire_at] = held
            self.channels["board"] = channel
        self.save_state()
        self.log("board inbox %s until %d (any key, signed only)" % (w, channel.expire_at))
        if self.listener is not None:
            self._start_poller(channel)
        return channel

    def board_post(self, kind, title, text, tags=None, ttl=BOARD_TTL, lang=None, deadline=None):
        """Put a need or an offer on the board. The reply inbox is opened for you."""
        channel = self.ensure_board_inbox(int(ttl))
        # The board refuses a post that would outlive the inbox behind it, so
        # that an address on the board is always an address that still works.
        # At the top of the range the inbox cannot be opened for longer than
        # the post asked for, so the post gives way, not the promise.
        life = min(int(ttl), int(channel.expire_at - time.time()))
        if life < int(ttl):
            self.log("board post shortened to %ds to stay inside the inbox" % life)
        fields = {"kind": kind, "title": title, "text": text, "w": channel.w, "ttl": life}
        if tags:
            fields["tags"] = list(tags)[:8]
        if lang:
            fields["lang"] = lang
        if deadline:
            fields["deadline"] = deadline
        body = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
        status, data = self.client.board_post(body, self.keys.public, self.keys.sign(board_signing_input(self.keys.public, body)))
        if status not in (200, 201):
            raise RuntimeError("board post failed: %s %s" % (status, data))
        self.archive("board", {"kind": "posted", "at": time.time(), "post": data})
        return {"post": data, "inbox": channel.w, "answers_arrive_on": "board"}

    def board_find(self, kind=None, tags=None, lang=None, key=None, after=0, wait=0):
        """Live posts that match. A tag covers its dotted children."""
        body = {"after": int(after)}
        if kind:
            body["kind"] = kind
        if tags:
            body["tags"] = list(tags)[:20]
        if lang:
            body["lang"] = lang
        if key:
            body["key"] = key
        if wait:
            body["wait"] = min(int(wait), 25)
        status, data = self.client.board_find(body, int(wait or 0))
        if status != 200:
            raise RuntimeError("board find failed: %s %s" % (status, data))
        for post in data.get("posts", []):
            if post.get("w") and post.get("key"):
                with self.lock:
                    self.peers[post["w"]] = post["key"]
        return data

    def board_get(self, post_id):
        status, data = self.client.board_get(post_id)
        return data if status == 200 else None

    def board_tags(self):
        status, data = self.client.board_tags()
        if status != 200:
            raise RuntimeError("board tags failed: %s %s" % (status, data))
        return data

    def board_withdraw(self, post_id):
        body = json.dumps({"at": int(time.time())}, separators=(",", ":"))
        status, data = self.client.board_withdraw(post_id, body, self.keys.sign(board_delete_signing_input(post_id, body)))
        if status != 200:
            raise RuntimeError("withdraw failed: %s %s" % (status, data))
        self.archive("board", {"kind": "withdrawn", "at": time.time(), "id": post_id})
        return data

    def board_answer(self, post, text=None, data=None):
        """Answer a post, sealed to the poster's key and signed by ours.

        The message carries the post id and our reply address, so the poster
        can sort answers by post and write back.
        """
        if isinstance(post, str):
            post = self.board_get(post)
            if post is None:
                raise LookupError("no live post with that id")
        channel = self.ensure_board_inbox()
        own_post = post.get("key") == self.keys.public
        if own_post:
            self.log("this post is signed by your own key, so the answer is sealed to you and nobody else will read it")
        with self.lock:
            self.peers[post["w"]] = post["key"]
        body = {"post": post["id"], "reply_to": channel.w, "from": self.keys.hash[:8]}
        if text is not None:
            body["text"] = str(text)
        if data is not None:
            body["data"] = data
        plaintext = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        envelope = self.keys.seal(post["key"], plaintext)
        status, result = self.client.post(post["w"], envelope, self.keys.public, self.keys.sign(thread_signing_input(post["w"], envelope)))
        self.archive("board", {"kind": "answered", "at": time.time(), "post": post["id"], "w": post["w"], "status": status, "body": body})
        if status != 201:
            raise RuntimeError("answer failed: %s %s" % (status, result))
        answer = {"post": post["id"], "w": post["w"], "seq": result["seq"], "at": result["at"], "replies_arrive_on": "board", "reply_to": channel.w}
        if own_post:
            answer["warning"] = "You answered your own post. The answer is sealed to your own key, so it reaches nobody but you."
        return answer

    def board_replies(self, post_id=None):
        """Answers received on the board inbox, decrypted and verified, newest last."""
        out = []
        for label, channel in list(self.channels.items()):
            on_the_board = label.startswith("board")
            with channel.lock:
                for entry in channel.received:
                    body = entry.get("body")
                    if not isinstance(body, dict):
                        continue
                    if post_id is not None:
                        if body.get("post") == post_id:
                            out.append(entry)
                    elif on_the_board or "post" in body:
                        # Everything on the board inbox, and elsewhere only
                        # what names a post, so a private thread does not turn
                        # into a list of board answers.
                        out.append(entry)
        return sorted(out, key=lambda e: e["at"])

    def open_channel_with(self, key, ttl=900, label=None, reply_to=None, note=None):
        """A private channel only that key may write to, with its address handed over.

        This is how a conversation leaves the open board inbox: one answer
        there, then everything else in a thread nobody else can write to.
        """
        if not is_key(str(key)):
            partner = self.partner_by_name(str(key))
            if partner is None:
                raise ValueError("not a key and not a known partner: " + str(key))
            key = partner["key"]
        label = label or ("with-" + key_hash(key)[:8])
        if label in self.channels:
            label = "%s-%d" % (label, int(time.time()))
        status, data, read_key, w = self.client.open_thread(int(ttl), [key])
        if status != 201:
            raise RuntimeError("could not open channel: %s %s" % (status, data))
        channel = Channel(label, read_key, w, data["expire_at"], [key])
        with self.lock:
            self.channels[label] = channel
        self.save_state()
        if self.listener is not None:
            self._start_poller(channel)
        handed = None
        if reply_to:
            body = {"channel": w, "expire_at": channel.expire_at}
            if note:
                body["text"] = str(note)
            envelope = self.keys.seal(key, json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            status, handed = self.client.post(reply_to, envelope, self.keys.public, self.keys.sign(thread_signing_input(reply_to, envelope)))
            if status != 201:
                raise RuntimeError("channel opened but the address could not be handed over: %s %s" % (status, handed))
        return {"label": label, "w": w, "expire_at": channel.expire_at, "with": self.name_for_key(key) or key, "address_sent_to": reply_to}

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
        # The entry exists before the first attempt, and every retry sends the
        # same bytes. The recipient hashes those bytes, so a message that
        # lands twice is marked a replay there instead of acted on twice.
        entry = self._outbox_add(w, key, envelope, body)
        status, result = self._deliver(entry)

        if status in (404, 410) and not (isinstance(to, str) and to == w):
            # The partner may have renewed its inbox. Ask presence again, once.
            # A new address means new bytes, so this is a new outbox entry.
            w, key = self.address_for(to)
            envelope = self.keys.seal(key, plaintext)
            entry = self._outbox_add(w, key, envelope, body, replaces=entry["id"])
            status, result = self._deliver(entry)

        record = {"kind": "sent", "at": time.time(), "to": self.name_for_key(key) or key, "w": entry["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "seq": (result or {}).get("seq") if isinstance(result, dict) else None, "sha256": (result or {}).get("sha256") if isinstance(result, dict) else None, "body": body}
        self.archive("sent", record)

        if status != 201:
            raise SendFailed(entry["status"], entry["id"], status, result)

        return {"to": record["to"], "w": entry["w"], "message_id": entry["id"], "seq": result["seq"], "at": result["at"], "sha256": result["sha256"], "expire_at": result["expire_at"]}


    # ----------------------------------------------------------- outbox --

    def _outbox_add(self, w, key, envelope, body, replaces=None):
        """One durable entry per logical message, written before the first attempt."""
        entry = {
            "id": "m-" + sha256hex("%s|%s|%s" % (self.keys.public, w, envelope))[:16],
            "w": w,
            "to_key": key,
            "envelope": envelope,
            "summary": {k: v for k, v in body.items() if k in ("post", "reply_to", "channel")},
            "created_at": int(time.time()),
            "attempts": 0,
            "status": "sending",
            "last_status": None,
            "replaces": replaces,
        }
        with self.lock:
            self.outbox[entry["id"]] = entry
        self.save_outbox()

        return entry

    def _deliver(self, entry):
        """Send the stored bytes once, and record what the answer allows us to claim."""
        entry["attempts"] += 1
        entry["status"] = "sending"
        self.save_outbox()
        signature = self.keys.sign(thread_signing_input(entry["w"], entry["envelope"]))
        status, result = self.client.post(entry["w"], entry["envelope"], self.keys.public, signature)
        entry["last_status"] = status
        entry["last_at"] = int(time.time())

        if status == 201:
            entry["status"] = "delivered"
            entry["seq"] = (result or {}).get("seq") if isinstance(result, dict) else None
        elif status == 0:
            # No reply. The bytes may have arrived, so this is not a failure
            # we are allowed to call a failure.
            entry["status"] = "unknown"
        else:
            entry["status"] = "refused"
            entry["error"] = (result or {}).get("error") if isinstance(result, dict) else str(result)[:200]

        self.save_outbox()

        return status, result

    def outbox_pending(self):
        """Messages whose fate is not settled: in flight, or unknown after a stop."""
        return [dict(e) for e in self.outbox.values() if e["status"] in ("sending", "unknown")]

    def outbox_retry(self, message_id=None):
        """Send the same bytes again for entries that never got a clear answer.

        The recipient marks a second copy as a replay, so this is safe for the
        transport. Whether the action behind the message is safe to repeat is
        the application's contract, not this function's.
        """
        out = []
        for entry in list(self.outbox.values()):
            if message_id is not None and entry["id"] != message_id:
                continue
            if entry["status"] not in ("unknown", "refused"):
                continue
            if entry["status"] == "refused" and entry.get("last_status") in (403, 410, 413, 415):
                continue
            status, _ = self._deliver(entry)
            out.append({"id": entry["id"], "w": entry["w"], "status": entry["status"], "http": status})

        return out

    def outbox_forget(self, message_id):
        """Drop an entry once its fate no longer matters. Nothing is retried after this."""
        with self.lock:
            entry = self.outbox.pop(message_id, None)
        self.save_outbox()

        return {"id": message_id, "forgotten": entry is not None}

    # ---------------------------------------------------------- effects --

    def effect(self, key, fingerprint=None):
        """Has this operation already been carried out here?

        The key is the application's, not a guess from the text: something
        that names the sender, the task and the action. Returns new, done or
        conflict, and the stored result when there is one.
        """
        record = self.effects.get(str(key))

        if record is None:
            return {"state": "new", "key": key}

        if fingerprint is not None and record.get("fingerprint") not in (None, fingerprint):
            return {"state": "conflict", "key": key, "stored_fingerprint": record.get("fingerprint"), "result": record.get("result")}

        return {"state": "done", "key": key, "result": record.get("result"), "at": record.get("at")}

    def effect_done(self, key, result=None, fingerprint=None):
        """Record that it was carried out, before telling anyone it was."""
        with self.lock:
            self.effects[str(key)] = {"fingerprint": fingerprint, "result": result, "at": int(time.time())}
        self.save_effects()

        return {"state": "done", "key": key, "result": result}

    # ------------------------------------------------------------- read --

    # Only the spellings seen in the wild, and only for an answer to a post.
    # A blanket id -> post or w -> reply_to would rewrite other message kinds
    # into something they are not.
    ANSWER_ALIASES = {
        "post": ("post_id", "postId"),
        "reply_to": ("replyTo", "w", "reply_address"),
        "text": ("reply", "message"),
    }

    @classmethod
    def _canonical(cls, body):
        """The documented field names, from whatever a sender called them.

        The shape is written down in several places and still gets guessed at.
        A signed, useful answer that says post_id instead of post is not worth
        dropping on the floor. We stay strict in what we send.

        Returns the body and a note of what was renamed, kept apart from the
        body so a sender cannot put anything of ours in it.
        """
        if not isinstance(body, dict):
            return body, {}

        # Normalise an answer to a post, nothing else: without a post id in
        # some spelling this is a different kind of message and is left alone.
        if not any(name in body for name in ("post",) + cls.ANSWER_ALIASES["post"]):
            return body, {}

        renamed, conflicts = {}, {}

        for canonical, spellings in cls.ANSWER_ALIASES.items():
            present = [s for s in spellings if isinstance(body.get(s), (str, int))]

            if canonical in body:
                # Both spellings, disagreeing: the canonical one wins and the
                # disagreement is reported rather than quietly dropped. Two
                # values are only comparable when both are scalars; a field
                # holding an object is left exactly as the sender wrote it.
                if isinstance(body[canonical], (str, int)):
                    conflicts.update({s: body[s] for s in present if str(body[s]) != str(body[canonical])})
                continue

            if present:
                body[canonical] = body[present[0]]
                renamed[present[0]] = canonical
                # Two spellings carrying the same value are not a
                # disagreement. Reporting them as one asks a caller to weigh a
                # conflict that is not there.
                conflicts.update({s: body[s] for s in present[1:] if str(body[s]) != str(body[present[0]])})

        meta = {}

        if renamed:
            meta["renamed"] = renamed

        if conflicts:
            meta["conflicting_fields"] = conflicts

        return body, meta

    def _open(self, message):
        """What was said, and separately, what can be trusted about it.

        The two used to be one dict, so a plaintext JSON answer arrived as a
        wrapper with the real object stranded inside a string. Nothing
        downstream could see the fields, the answer was never matched to its
        post, and the reply address was never learned. Keeping the content and
        the metadata apart also means no sender can set a field of ours.
        """
        raw = message["body"]

        if not message.get("verified") or not message.get("from"):
            return {"text": raw}, {"signed": False, "encrypted": False, "format": "unsigned"}

        if not is_envelope(raw):
            try:
                parsed = json.loads(raw)
            except ValueError:
                return {"text": raw}, {"signed": True, "encrypted": False, "format": "text"}

            if isinstance(parsed, dict):
                content, extra = self._canonical(parsed)
                return content, dict({"signed": True, "encrypted": False, "format": "json"}, **extra)

            return {"text": raw}, {"signed": True, "encrypted": False, "format": "json"}

        try:
            plaintext = self.keys.open(message["from"], raw)
            parsed = json.loads(plaintext.decode("utf-8"))
        except Exception as error:
            return {"text": None}, {"signed": True, "encrypted": True, "format": "unreadable", "error": error.__class__.__name__}

        if isinstance(parsed, dict):
            content, extra = self._canonical(parsed)
            return content, dict({"signed": True, "encrypted": True, "format": "json"}, **extra)

        return {"text": parsed}, {"signed": True, "encrypted": True, "format": "json"}

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
            try:
                body, meta = self._open(message)
            except Exception as error:
                # Whatever went wrong belongs to this message alone. Losing the
                # rest of the batch to it would be the expensive mistake.
                body, meta = {"text": message.get("body")}, {"signed": bool(message.get("from")), "encrypted": False, "format": "undecodable", "error": error.__class__.__name__}
            entry["body"] = body
            entry.update(meta)
            if isinstance(entry["body"], dict) and isinstance(entry["body"].get("reply_to"), str) and message["from"]:
                with self.lock:
                    self.peers[entry["body"]["reply_to"]] = message["from"]
            entries.append(entry)
            with channel.lock:
                channel.received.append(entry)
            # Received, readable, archived and handled are four different
            # things, and a failure at one must not be reported as the others.
            # The message above is delivered already; whether it also reached
            # the file on disk is recorded here, and is never allowed to cost
            # the rest of the batch, which is what a full disk would otherwise
            # do. Nor is it swallowed: it stays on the entry and in the log,
            # because a storage failure is worth knowing about.
            try:
                self.archive(channel.label, dict(entry, kind="received"))
                entry["archived"] = True
            except Exception as error:
                entry["archived"] = False
                entry["archive_error"] = "%s: %s" % (error.__class__.__name__, error)
                self.log("archive %s seq %s: %s" % (channel.label, entry["seq"], error))
        if entries:
            # The cursor moves and the hashes are stored in the same save, and
            # that save happens before the caller sees a single message. A
            # crash after this point redelivers nothing; a crash before it
            # redelivers everything, and the stored hashes mark those replays.
            #
            # It moves past a message the archive refused as well. The archive
            # is a record of what was delivered, not the delivery itself:
            # holding the cursor back would re-read that message forever while
            # the disk stayed full, and redeliver everything after it.
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

    def _start_poller(self, channel):
        """One poller for a channel opened after the listener started."""
        if channel.poller is not None and channel.poller.is_alive():
            return
        poller = threading.Thread(target=self._poll_loop, args=(channel,), daemon=True)
        channel.poller = poller
        poller.start()

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
        self.save_outbox()
        self._release_lock()
