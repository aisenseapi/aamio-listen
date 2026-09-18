"""The runtime: what a sidecar does for an agent so the model never touches a secret.

State lives under AAMIO_HOME (default ~/.aamio):

    key              32-byte seed, hex, mode 600. The runtime's identity.
    partners.json    [{"name": ..., "key": ...}] from the contract. Keys, not addresses.
    scopes.json      [{"name": ..., "key": ..., "address": ...}], mode 600. Scope keys stay here.
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

from .client import AamioClient, DEFAULT_HOST, is_scope_address, is_scope_key, make_scope_key, scope_address
from .gate import GateStop, board_advised_bits, describe as describe_seconds, plan as gate_plan, solve as gate_solve, solve_board
from .crypto import Keys, board_delete_signing_input, board_signing_input, check_message, is_envelope, is_key, key_hash, presence_signing_input, sha256hex, thread_signing_input, unb64url

INBOX_TTL = 3600
# The board's own default, mirrored here so an ordinary post gets the same
# lifetime whether the field is sent or left out. The board decides; this is a
# copy, and it is the only copy in this client.
BOARD_TTL = 1800
# How much longer than the post itself a reply address should live. The poster
# reads answers on their own schedule, and a minute either way is the
# difference between a conversation and a dead end.
ANSWER_MARGIN = 600
PRESENCE_TTL = 120
PRESENCE_REFRESH = 60
RENEW_BEFORE = 180


def home_dir() -> str:
    return os.environ.get("AAMIO_HOME") or os.path.join(os.path.expanduser("~"), ".aamio")


def pid_alive(pid):
    """Whether a process with this pid is running, without touching it.

    os.kill(pid, 0) asks that on POSIX. On Windows it is TerminateProcess:
    it ended whatever process held the pid, and then reported it as alive.
    A lock file outlives its process and Windows hands pids out again
    quickly, so the process ended was as often somebody else's program as
    an old aamio. There the question goes to OpenProcess instead.
    """
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            # Access denied means the process is there and not ours to look at.
            return ctypes.get_last_error() == 5
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def process_started_at(pid):
    """When the process with this pid started, in Unix seconds, or None where that cannot be asked cheaply.

    A pid is handed out again once its process is gone, so a live pid in a
    lock file is not proof of a live owner. A process that started after the
    lock was written is some other program that got the number.
    """
    try:
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.restype = ctypes.c_void_p
            handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
            if not handle:
                return None
            try:
                created, ignored = ctypes.c_ulonglong(), (ctypes.c_ulonglong * 3)()
                if not kernel32.GetProcessTimes(ctypes.c_void_p(handle), ctypes.byref(created), ctypes.byref(ignored, 0), ctypes.byref(ignored, 8), ctypes.byref(ignored, 16)):
                    return None
                # 100 nanosecond steps since 1601.
                return created.value / 1e7 - 11644473600
            finally:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
        with open("/proc/%d/stat" % int(pid), encoding="ascii", errors="replace") as handle:
            ticks = int(handle.read().rsplit(")", 1)[1].split()[19])
        with open("/proc/stat", encoding="ascii", errors="replace") as handle:
            boot = next(int(line.split()[1]) for line in handle if line.startswith("btime "))
        return boot + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, StopIteration, AttributeError):
        return None


# Homes locked by this process. The file on disk catches another process;
# this catches two runtimes in one, which is just as bad for the state.
_LOCKED_HOMES = set()


# What an HTTP status says about sending the same bytes again.
#
# outbox_retry already had to know this and carried its own list inline. The
# MCP error handler then grew a second answer that disagreed with it: every
# refusal became "change the request", including 429, which is a rate window
# and needs no change at all. Two places knowing the same thing differently is
# how advice ends up contradicting the mechanism meant to act on it.
#
# Deterministic: the same bytes will be refused again, so repeating is waste.
# Later: nothing about the message is wrong, only the moment.
# Anything else answered by the server is left undecided on purpose. It told us
# it failed, but not whether it had already stored the message.
SEND_DETERMINISTIC = (400, 403, 410, 413, 415, 422, 428, 501)
SEND_TRY_LATER = (429, 503)


def send_advice(outcome, status):
    """(retryable, fix) for one send outcome. retryable is about the same
    stored bytes, and is never a permission to repeat something automatically.

    False  the same message will fail the same way
    True   the message is fine; the moment was not
    None   it cannot be decided from what we know
    """
    if outcome == "unknown":
        return None, (
            "No answer came back, so this message may already have been delivered. Keep its message_id. "
            "aamio_pending lists what has no settled outcome on this machine; it does not confirm delivery, "
            "and nothing here can, because the address it went to is not yours to read. This interface has no "
            "retry-by-id tool: do not pass the message_id to aamio_send and do not compose a replacement. "
            "An approved retry sends the stored bytes again through the runtime's own outbox retry."
        )

    if status in SEND_TRY_LATER:
        return True, (
            "aamio declined this for now, not because of the message: %d is a rate window or a busy service. "
            "Do not change the content. Wait, then send the stored message again through the runtime's outbox "
            "retry rather than composing a new one." % status
        )

    if status in SEND_DETERMINISTIC:
        return False, (
            "aamio refused this and will refuse the same bytes again. Read the error, correct the request, and "
            "send the corrected one as a new message."
        )

    return None, (
        "aamio answered %s, which this client does not classify. It may or may not have stored the message "
        "before failing, so treat delivery as unsettled: keep the message_id, read the error, and do not "
        "resend blindly." % status
    )


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
    def __init__(self, label, read_key, w, expire_at, allow=None, after=0, created_at=None):
        self.label = label
        self.read_key = read_key
        self.w = w
        self.expire_at = int(expire_at)
        self.allow = list(allow or [])
        self.after = int(after)
        # Which thread at this address the cursor and the hashes belong to. A
        # restart can take the thread and a write can open a new one at the
        # same address, counting from one again, and created_at is the only
        # thing that tells the two apart.
        self.created_at = created_at
        self.gone = False
        self.seen = set()
        self.received = []
        self.lock = threading.Lock()
        self.poller = None
        self.closed = False

    def forget_thread(self):
        """The cursor belonged to a thread that is not there now. The hashes stay.

        They are what this reader has been handed, whichever thread carried it.
        They used to be cleared here with the cursor, and that lost the replay
        mark at the one moment it is most needed: after the service loses its
        store, every sender whose message went with it sends the same bytes
        again, and a reader that had already acted on them acted twice.
        """
        self.after = 0
        self.created_at = None

    def to_state(self):
        # seen travels with the channel: without it a restart cannot tell a
        # redelivered message from a new one, and the model may act twice.
        return {"label": self.label, "read_key": self.read_key, "w": self.w, "expire_at": self.expire_at, "allow": self.allow, "after": self.after, "created_at": self.created_at, "seen": sorted(self.seen)}

    @classmethod
    def from_state(cls, item):
        channel = cls(item["label"], item["read_key"], item["w"], item["expire_at"], item.get("allow"), item.get("after", 0), item.get("created_at"))
        channel.seen = set(item.get("seen") or [])

        return channel


class Runtime:
    # Files a runtime writes back. One that is there and cannot be read stops
    # the runtime before anything is saved over it: a save is how a broken
    # file becomes a lost one, with the channels, partners or scope keys in it.
    KEPT_FILES = ("partners.json", "scopes.json", "state.json", "outbox.json", "effects.json")

    def __init__(self, home=None, host=None, tags=None, archive=True, log=None):
        self.home = home or home_dir()
        self.host = host or os.environ.get("AAMIO_HOST") or DEFAULT_HOST
        self.client = AamioClient(self.host)
        self.archive_enabled = archive
        self.log = log or (lambda line: None)
        self.closed = False
        os.makedirs(self.home, exist_ok=True)
        os.makedirs(os.path.join(self.home, "archive"), exist_ok=True)
        self.owns_lock = self._take_lock()
        try:
            self._load(tags)
        except BaseException:
            self._release_lock()
            raise

    def _load(self, tags):
        self.keys = self._load_or_create_keys()
        self.partners = self._load_json("partners.json", [])
        self.scopes, self.scopes_aside = self._usable_scopes(self._load_json("scopes.json", []))
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
        self.gates = {}                                       # write address -> the gate it was opened with
        # Anything still pending was in flight when the last process stopped.
        # Whether it reached aamio is unknown, and it stays unknown until
        # somebody looks. Retrying is a decision, not a default.
        for entry in self.outbox.values():
            if entry.get("status") == "sending":
                entry["status"] = "unknown"
                entry["note"] = "the process stopped while this was in flight"
            # The proof of work comes before the post, so work that never
            # finished was never sent. It used to stay working for good, with
            # nothing working on it, and the outcome promised to the caller
            # never came.
            elif entry.get("status") == "working":
                entry["status"] = "stopped"
                entry["note"] = "the process stopped before its proof of work was done, so nothing was sent"
        self.presence_at = 0.0
        # What a read could not do, kept by channel and state until it is
        # handed to a caller. An empty read means nothing arrived. An empty
        # read on a thread that has expired, or that the service would not
        # answer for, means something else entirely, and both used to look
        # exactly the same from outside.
        self.attention = {}
        self.inbound = queue.Queue()
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.listener = None
        # Told once, on the first read after the restart, since the caller was
        # promised how the send would end.
        untold = [e for e in self.outbox.values() if e.get("status") == "stopped" and not e.get("told")]
        for entry in untold:
            self._note_trouble("send %s" % entry["id"], "stopped", "the message to %s was not sent: the process stopped before its proof of work was done. Send it again if it still matters." % entry.get("w"))
            entry["told"] = True
        if untold:
            # So the next restart does not say it again.
            self.save_outbox()

    # -------------------------------------------------------------- lock --

    def _take_lock(self):
        """One live runtime per home. Two would overwrite each other's state.

        The file holds the pid, and a pid that is gone is not an owner. This
        catches the ordinary mistake, two sidecars on one home, not a shared
        network filesystem.
        """
        real = os.path.realpath(self.home)

        if real in _LOCKED_HOMES:
            raise RuntimeError("another aamio in this process is already using %s" % self.home)

        held = self._load_json("lock", None)

        if isinstance(held, dict) and isinstance(held.get("pid"), int) and held["pid"] != os.getpid():
            try:
                alive = pid_alive(held["pid"])
            except Exception:
                alive = True

            if alive and isinstance(held.get("at"), (int, float)):
                # The lock is written after its owner started. A process that
                # started later got the pid after the owner was gone.
                started = process_started_at(held["pid"])
                if started is not None and started > held["at"] + 2:
                    alive = False

            if alive:
                raise RuntimeError(
                    "another aamio (pid %s) is using %s. Stop it, or use a different AAMIO_HOME. If no aamio is running, "
                    "the one that took the lock stopped without letting go of it: delete %s and start again." % (held["pid"], self.home, self._path("lock"))
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
        """What a file holds, or default when it is not there or empty.

        A file in KEPT_FILES that is there and cannot be read, or holds
        something other than the list or object it should, raises instead.
        """
        try:
            with open(self._path(name), "rb") as handle:
                text = handle.read().decode("utf-8")
            value = json.loads(text) if text.strip() else default
        except FileNotFoundError:
            return default
        except (OSError, ValueError) as error:
            if name not in self.KEPT_FILES:
                return default
            why = "not UTF-8 JSON" if isinstance(error, ValueError) else error.__class__.__name__
            raise RuntimeError(self._unreadable(name, why)) from None
        if name in self.KEPT_FILES and not isinstance(value, type(default)):
            raise RuntimeError(self._unreadable(name, "not a JSON %s" % ("list" if isinstance(default, list) else "object")))
        return value

    def _unreadable(self, name, why):
        return (
            "%s could not be read (%s), so this runtime stops here rather than save over it. Repair the file, "
            "or move it away to start without what was in it." % (self._path(name), why)
        )

    def _save_json(self, name, value, private=False):
        path = self._path(name)
        # Private from the first byte. Made 600 after the rename, the file was
        # readable by anyone for a moment, and the temporary one for longer.
        handle = os.fdopen(os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o666), "w", encoding="utf-8")
        with handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            # The rename is atomic, but only over bytes that reached the disk.
            os.fsync(handle.fileno())
        if private:
            try:
                os.chmod(path + ".tmp", 0o600)
            except OSError:
                pass
        os.replace(path + ".tmp", path)

    def _load_or_create_keys(self):
        path = self._path("key")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read().strip()
        except FileNotFoundError:
            text = ""
        except (OSError, ValueError) as error:
            raise RuntimeError(self._unreadable("key", error.__class__.__name__)) from None
        if text:
            # A new key over it would be a new identity, and the old one gone
            # for good. Partners know this runtime by that key.
            if re.fullmatch(r"[0-9a-f]{64}", text) is None:
                raise RuntimeError(self._unreadable("key", "not a 64 character hex seed"))
            return Keys(bytes.fromhex(text))
        keys = Keys.generate()
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as handle:
            handle.write(keys.seed.hex() + "\n")
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

    # ----------------------------------------------------------- scopes --
    #
    # A scope keeps board posts unlisted for a group. Here each one has a name,
    # and the name is all a caller passes or sees. The key is the read
    # capability: it stays in scopes.json, and scope_share hands it to a partner
    # sealed, so no model has to hold it. The address is the write capability
    # and is no secret. Unlisted is not private.

    SCOPE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

    def _usable_scopes(self, entries):
        """The entries of scopes.json this runtime can use, and the rest.

        The rest are never dropped. They go back into the file on every save
        as they were, so a hand edit with a typo is there to be corrected
        rather than gone with the key in it.
        """
        usable, aside, names = [], [], set()
        for entry in entries:
            key = entry.get("key") if isinstance(entry, dict) else None
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("name"), str)
                and self.SCOPE_NAME.fullmatch(entry["name"]) is not None
                and entry["name"].lower() not in names
                and is_scope_address(entry.get("address"))
                and (key is None or (is_scope_key(key) and scope_address(key) == entry["address"]))
            ):
                usable.append(entry)
                names.add(entry["name"].lower())
            else:
                aside.append(entry)
        if aside:
            self.log("scopes.json: %d entries are not scopes this runtime can use, and stay in the file as they are" % len(aside))
        return usable, aside

    def _save_scopes(self, scopes):
        """Writes the scopes, and only then holds them: a save that fails changes nothing."""
        with self.lock:
            self._save_json("scopes.json", scopes + getattr(self, "scopes_aside", []), private=True)
            self.scopes = scopes

    def _scope(self, name):
        for entry in self.scopes:
            if entry["name"].lower() == str(name).lower():
                return entry
        return None

    def _scope_named(self, name):
        entry = self._scope(name)
        if entry is None:
            raise LookupError("no scope called %s here. The scope list shows the ones this runtime holds" % name)
        return entry

    @staticmethod
    def _scope_view(entry):
        return {"name": entry["name"], "address": entry["address"], "can_read": bool(entry.get("key"))}

    def _scope_name_ok(self, name):
        if not isinstance(name, str) or self.SCOPE_NAME.fullmatch(name) is None:
            raise ValueError("a scope name is 1 to 64 letters, digits, dots, dashes and underscores, starting with a letter or a digit")

    def scope_new(self, name):
        """A new scope, its key from the system's secure generator. The key stays here."""
        self._scope_name_ok(name)
        with self.lock:
            if self._scope(name) is not None:
                raise ValueError("there is a scope called %s already" % name)
            key = make_scope_key()
            entry = {"name": name, "key": key, "address": scope_address(key)}
            self._save_scopes(self.scopes + [entry])
        return self._scope_view(entry)

    def scope_add(self, name, key=None, address=None):
        """A scope made elsewhere: the key, to read and post, or the address, to post only."""
        self._scope_name_ok(name)
        if key is None and address is None:
            raise ValueError("give the key, to read and post, or the address, to post only")
        if key is not None and not is_scope_key(key):
            raise ValueError("a scope key is 26 to 64 characters of a-z and 0-9. The 20 character address goes in address")
        if address is not None and not is_scope_address(address):
            raise ValueError("a scope address is the 20 characters of a-z and 2-7 that go on a post")
        derived = scope_address(key) if key is not None else address
        if address is not None and derived != address:
            raise ValueError("that key does not give that address, so one of the two is wrong")
        with self.lock:
            named = self._scope(name)
            if named is not None and named["address"] != derived:
                raise ValueError("there is a scope called %s already, with another address. Remove it or choose another name" % name)
            held = named or next((s for s in self.scopes if s["address"] == derived), None)
            if held is None:
                held = {"name": name, "key": key, "address": derived}
                self._save_scopes(self.scopes + [held])
            elif key is not None and not held.get("key"):
                # Held to post only until now. The key adds reading.
                before, held = held, dict(held, key=key)
                self._save_scopes([held if s is before else s for s in self.scopes])
        return self._scope_view(held)

    def scope_list(self):
        return [self._scope_view(entry) for entry in self.scopes]

    def scope_remove(self, name):
        with self.lock:
            entry = self._scope_named(name)
            self._save_scopes([s for s in self.scopes if s is not entry])
        return {"removed": entry["name"]}

    def scope_key(self, name):
        """The key itself, for a person to pass on by hand. The MCP server never calls this."""
        entry = self._scope_named(name)
        if not entry.get("key"):
            raise ValueError("scope %s is held to post only, so there is no key here" % entry["name"])
        return {"name": entry["name"], "key": entry["key"], "address": entry["address"]}

    def scope_share(self, name, to, access):
        """Hand a scope to a partner in a sealed message. read gives the key, write only the address.

        Only to a partner in the address book, by name or key. An address is
        learned from the board and from messages, so it can be anyone's, and
        the key would be sealed to whoever it was learned from: a post asking
        for a scope would get it.
        """
        entry = self._scope_named(name)
        if access not in ("read", "write"):
            raise ValueError("access is read, which gives the key to read and post, or write, which gives the address to post only")
        if access == "read" and not entry.get("key"):
            raise ValueError("scope %s is held to post only, so it can only be shared with access write" % entry["name"])
        partner = self.partner_by_key(to) if is_key(str(to)) else self.partner_by_name(to)
        if partner is None:
            raise ValueError("a scope is shared only with a partner in your address book, by name. Never with an address, which can be anyone's")
        share = {"name": entry["name"], "key": entry["key"]} if access == "read" else {"name": entry["name"], "address": entry["address"]}
        w, key = self.address_for(partner["name"])
        # The archive keeps what was shared and with whom, never the key.
        sent = self._send(w, key, partner["name"], "Scope %s, shared to %s." % (entry["name"], "read and post" if access == "read" else "post only"), {"aamio_scope": share}, archived_data={"aamio_scope": {"name": entry["name"], "access": access}})
        return dict(sent, scope=entry["name"], access=access)

    def _shared_scope_name(self, partner, name):
        """The name a scope from a partner is kept under: the partner's name, a dot and the scope's.

        A partner names its own scopes, and a name is where posts go. Kept
        under the bare name, a partner could take review before review was
        made here, and the posts meant for it would go where that partner reads.
        """
        self._scope_name_ok(name)
        prefix = re.sub(r"[^A-Za-z0-9._-]+", "-", partner["name"]).strip("._-")[:24] or key_hash(partner["key"])[:8]
        return ("%s.%s" % (prefix, name))[:64]

    def _take_scope_share(self, entry):
        """A scope in an incoming message. Kept only when it came sealed and
        verified from a partner in the address book, and not seen before. The
        key is taken out of the message either way, and aamio_scope is replaced
        whatever it holds and wherever it sits, so whoever reads the message
        never sees a key in it."""
        body = entry.get("body")
        if not isinstance(body, dict):
            return
        if "aamio_scope" in body:
            body["aamio_scope"] = {"kept": False, "note": "not kept: a scope is shared in data.aamio_scope"}
        data = body.get("data")
        if not isinstance(data, dict) or "aamio_scope" not in data:
            return
        share = data["aamio_scope"]
        if not isinstance(share, dict):
            data["aamio_scope"] = {"kept": False, "note": "not kept: data.aamio_scope is an object with name, and key or address"}
            return
        key = share.get("key")
        view = {"shared_as": share.get("name") if isinstance(share.get("name"), str) else None, "can_read": key is not None, "kept": False}
        partner = self.partner_by_key(entry.get("from_key")) if entry.get("from_key") else None
        if not (entry.get("verified") and entry.get("encrypted") and entry.get("known_contact") and partner is not None):
            view["note"] = "not kept: a scope is only taken when it comes sealed from a partner in your address book"
        elif entry.get("replay"):
            view["note"] = "not kept again: this message arrived before, and a scope removed since stays removed"
        else:
            try:
                local = self._shared_scope_name(partner, share.get("name"))
                view.update(self.scope_add(local, key=key, address=None if key is not None else share.get("address")), kept=True)
            except Exception as error:
                # This share alone, and nothing held that was not saved. The
                # rest of the messages are delivered either way.
                view["note"] = "not kept: %s" % error
        data["aamio_scope"] = view

    # ------------------------------------------------------------ inbox --

    def ensure_inbox(self):
        inbox = self.channels.get("inbox")
        # A gone inbox is opened again at once. A write to the old address
        # opens a thread there with none of this inbox's allowlist, so the
        # partners are pointed at a new one that has it. The old address is
        # still read until its time runs out, for whoever writes there anyway.
        if inbox and inbox.expire_at - time.time() > RENEW_BEFORE and not inbox.gone:
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

    def board_post(self, kind, title, text, tags=None, ttl=BOARD_TTL, lang=None, deadline=None, scope=None):
        """Put a need or an offer on the board. The reply inbox is opened for you.

        With scope, the name of a scope held here, the post carries that
        scope's address and is unlisted: only a find with the scope's key
        returns it. Unlisted is not private.
        """
        # Before the inbox is opened, so a name that is not here costs nothing.
        held = self._scope_named(scope) if scope is not None else None
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
        if held is not None:
            # Inside the signed body, so nobody can post the same bytes without it.
            fields["scope"] = held["address"]
        body = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
        # The work the board advises is done without asking, as on an inbox,
        # over the same bytes that are signed. The number is the board's, read
        # from its descriptor once, never a constant of ours: a board that
        # advises none gets no header.
        bits = self._board_advised_bits()
        work = solve_board(self.keys.public, body, bits) if bits else None
        status, data = self.client.board_post(body, self.keys.public, self.keys.sign(board_signing_input(self.keys.public, body)), work)
        if status not in (200, 201):
            raise RuntimeError("board post failed: %s %s" % (status, data))
        self.archive("board", {"kind": "posted", "at": time.time(), "post": data})
        # Where the answers go, and how to read them, in the answer itself. An
        # agent took board replies for the whole inbox, got nothing back, and
        # spent an hour decrypting by hand what read would have shown at once.
        posted = {"post": data, "inbox": channel.w, "answers_arrive_on": "board", "read_them_with": "Read them with read, aamio read on the command line and aamio_read over MCP, which shows every message on your inboxes. board replies lists only the answers, the messages that name a post of yours or arrived on a board inbox, and says how many it left out."}
        if held is not None:
            posted["scope"] = held["name"]
        return posted

    def _board_advised_bits(self):
        """What the board advises posts to carry, read from its descriptor once per runtime."""
        cached = getattr(self, "board_advised_bits", None)

        if cached is not None:
            return cached

        try:
            status, descriptor = self.client.board_descriptor()
        except Exception:
            status, descriptor = 0, None

        self.board_advised_bits = board_advised_bits(descriptor) if status == 200 else 0

        return self.board_advised_bits

    def board_find(self, kind=None, tags=None, lang=None, key=None, after=0, wait=0, min_work_bits=0, scope=None):
        """Live posts that match. A tag covers its dotted children. min_work_bits keeps only posts whose work_bits is at least that.

        With scope, the name of a scope held here with its key, the find reads
        that scope instead of the public board.
        """
        held = self._scope_named(scope) if scope is not None else None
        if held is not None and not held.get("key"):
            raise ValueError("scope %s is held to post only. Reading it takes the key, which a partner can share with access read" % held["name"])
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
        if min_work_bits:
            body["min_work_bits"] = int(min_work_bits)
        if held is not None:
            # In the body and nowhere else. A board older than scopes answers
            # 400 to the field, so it never reads the public board instead.
            body["scope_key"] = held["key"]
        status, data = self.client.board_find(body, int(wait or 0))
        if status != 200:
            raise RuntimeError("board find failed: %s %s" % (status, data))
        if held is not None:
            # The answer names the scope it read. Without that it did not read this one.
            if data.get("scope") != held["address"]:
                raise RuntimeError("the board did not say it read scope %s, so these posts are not shown" % held["name"])
            data["scope_name"] = held["name"]
        for post in data.get("posts", []):
            if post.get("w") and post.get("key"):
                with self.lock:
                    self.peers[post["w"]] = post["key"]
        return data

    def board_get(self, post_id):
        """The post, or None when the board says there is none. Anything else raises.

        Every status but 200 used to be None, and the caller turned None into
        "no live post with that id". A board that was down, rate limiting or
        unreachable was therefore reported as a post that does not exist, which
        is the opposite of what a reader should do about it.
        """
        status, data = self.client.board_get(post_id)
        if status == 200:
            return data
        if status in (404, 410):
            return None
        raise RuntimeError("the board answered %s for post %s, so whether that post is live is unknown. Ask again rather than treating it as gone" % (status, post_id))

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

    def board_answer(self, post, text=None, data=None, scope=None):
        """Answer a post, sealed to the poster's key and signed by ours.

        The message carries the post id and our reply address, so the poster
        can sort answers by post and write back. A post in a scope is never
        served by id alone, so with scope the post is looked up in that scope.
        """
        if isinstance(post, str):
            post_id = post
            post = self.board_get(post_id) if scope is None else None
            after = 0
            # A page holds up to 200 posts, and a scope can hold more. The
            # cursor goes on until the post turns up or the pages run out.
            for _ in range(50 if scope is not None else 0):
                page = self.board_find(scope=scope, after=after)
                post = next((p for p in page.get("posts", []) if p.get("id") == post_id), None)
                if post is not None or not page.get("posts") or int(page.get("next") or 0) <= after:
                    break
                after = int(page["next"])
            if post is None:
                raise LookupError("no live post with that id" + (" in scope %s" % scope if scope is not None else ". A post in a scope is found with the scope's name"))
        # The address on this answer has to outlive the post it answers.
        #
        # It did not. ensure_board_inbox() defaults to 900, which opens a
        # sixteen minute inbox, and a board post lives up to sixty. Measured in
        # the wild: an answer went out at 13:11:39 with a return address that
        # died at 13:27:39, and the poster's agent read it at 13:35:35 and
        # could not write back. Everything worked; the door had simply closed.
        #
        # The service already refuses a *post* whose reply address is shorter
        # than the post -- "a post whose address is dead reaches nobody" -- and
        # we were breaking the same rule in the other direction, in our own
        # client, with nothing checking it.
        remaining = max(0, int(post.get("expire_at") or 0) - int(time.time()))
        channel = self.ensure_board_inbox(remaining + ANSWER_MARGIN)
        own_post = post.get("key") == self.keys.public

        if channel.expire_at < (post.get("expire_at") or 0):
            self.log(
                "your reply address expires %d s before the post does, so an answer that arrives late "
                "cannot be answered back" % ((post.get("expire_at") or 0) - channel.expire_at)
            )
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
        notes = []
        status, result = self._post(post["w"], envelope, notes)
        self.archive("board", {"kind": "answered", "at": time.time(), "post": post["id"], "w": post["w"], "status": status, "body": body})
        if status != 201:
            raise RuntimeError("answer failed: %s %s" % (status, result))
        answer = {"post": post["id"], "w": post["w"], "seq": result["seq"], "at": result["at"], "replies_arrive_on": "board", "reply_to": channel.w}
        if "met" in result:
            answer["met"] = result["met"]
            answer["proof_id"] = result.get("proof_id")
        if notes:
            answer["notes"] = notes
        if own_post:
            answer["warning"] = "You answered your own post. The answer is sealed to your own key, so it reaches nobody but you."
        return answer

    def board_replies(self, post_id=None):
        """Answers received on the board inbox, decrypted and verified, newest last.

        Reads the archive as well as this process's memory. `received` lives in
        the process that polled, and the command line is one process per call,
        so a run of `board replies` used to show only what arrived inside its
        own wait -- everything from before was past the cursor and invisible,
        though it was on disk the whole time. That is how a real answer went
        unread and the silence got blamed on the sender.
        """
        out = []
        seen = set()
        skipped = []

        def wanted(entry):
            body = entry.get("body")

            if post_id is not None:
                return isinstance(body, dict) and body.get("post") == post_id

            # An answer names the post it answers, and most do. One that does
            # not is still an answer if it arrived on the address a post gave
            # out, and it used to be dropped here: the command reported no
            # replies while the inbox held two, which reads as silence from
            # the other side rather than as a filter of ours.
            if str(entry.get("channel") or "").startswith("board"):
                return True

            return isinstance(body, dict) and isinstance(body.get("post"), str)

        # Every channel, not only the ones named board: an answer can arrive on
        # a private channel opened for the conversation, and scoping this to
        # "board" once hid exactly those. That is a separate fix and it stays.
        for channel in list(self.channels.values()):
            with channel.lock:
                for entry in channel.received:
                    seen.add(entry.get("sha256"))
                    if wanted(entry):
                        out.append(entry)
                    else:
                        skipped.append(entry)

        # A board inbox is renewed while the old one still holds answers, and
        # the old one keeps its own label and its own archive. Once that
        # channel expires it leaves self.channels, and reading only the
        # channels this process holds made those answers vanish from here
        # although they had arrived, been decrypted and been written down.
        for label in sorted(self._archive_labels() | set(self.channels) | {"board"}):
            for entry in self._archived(label, "received"):
                if entry.get("sha256") in seen:
                    continue
                seen.add(entry.get("sha256"))
                if wanted(entry):
                    out.append(dict(entry, from_archive=True))
                else:
                    skipped.append(entry)

        out.sort(key=lambda e: (e.get("at") or 0, e.get("seq") or 0))
        self.board_replies_left_out = len(skipped)

        # An empty list here used to be read as an empty inbox, and the reader
        # went looking for the fault at the other end. Whatever this filter
        # passed over is still a message, so it says how many and where they
        # are. An agent that is told this does not leave the client.
        if skipped and not out:
            unopened = sum(1 for entry in skipped if not entry.get("verified"))
            unread = ", and %d of them arrived unsigned, so the body was never opened" % unopened if unopened else ""

            if post_id is not None:
                self._note_trouble("board replies", "filtered", "Nothing here answers post %s, but %d other message(s) are on your channels%s. Run board replies without a post, or read, to see them." % (post_id, len(skipped), unread))
            else:
                self._note_trouble("board replies", "filtered", "%d message(s) are here and none of them looks like a board answer, because they name no post and did not arrive on a board inbox%s. Run read to see them." % (len(skipped), unread))

        return out

    def _archive_labels(self, prefix=""):
        """Labels this runtime has an archive for, the ones a board inbox uses."""
        home = getattr(self, "home", None)

        if not home or not getattr(self, "archive_enabled", False):
            return set()

        try:
            names = os.listdir(os.path.join(home, "archive"))
        except OSError as error:
            self._note_trouble("archive", "unread", "the archive could not be listed (%s), so answers written down earlier are not in this result" % error.__class__.__name__)
            return set()

        return {name[: -len(".jsonl")] for name in names if name.endswith(".jsonl") and name.startswith(prefix)}

    def _archived(self, label, kind):
        """Entries this client wrote down for a channel, oldest first. Silent
        when archiving is off or the file is not there: an empty archive is not
        an error, it is a client that was told not to keep one."""
        home = getattr(self, "home", None)

        if not home or not getattr(self, "archive_enabled", False):
            return []

        path = os.path.join(home, "archive", "%s.jsonl" % label)

        if not os.path.isfile(path):
            return []

        found = []

        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    record = json.loads(line)
                except ValueError:
                    continue

                if isinstance(record, dict) and record.get("kind") == kind:
                    found.append(record)

        return found

    def board_reply_address(self):
        """Where answers to our answers would arrive, and whether it is still
        open. A board inbox that has expired is the difference between "nobody
        replied" and "nobody could"."""
        channel = self.channels.get("board")

        if channel is None:
            return {"w": None, "open": False, "why": "No board inbox on this machine. One is opened when you answer or post."}

        left = int(channel.expire_at - time.time())

        if left > 0:
            return {"w": channel.w, "open": True, "expires_at": int(channel.expire_at), "seconds_left": left}

        return {
            "w": channel.w,
            "open": False,
            "expires_at": int(channel.expire_at),
            "why": "The address you answered from closed %d s ago. Anything sent to it after that was refused at the door, "
                   "so an empty result here does not mean nobody wrote back." % -left,
        }

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
            status, handed = self._post(reply_to, envelope, [])
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
            key = self.peers.get(to)
            if key is None:
                raise LookupError("no key known for address %s; look the partner up or reply to a message" % to)
            return self._send(to, key, None, text, data, reply_to)
        w, key = self.address_for(to)
        return self._send(w, key, to, text, data, reply_to)

    def _send(self, w, key, partner, text=None, data=None, reply_to=None, archived_data=None):
        """One message sealed to key and written to w.

        partner is the name presence is asked again with when that address has
        gone, and None for an address given as it is. archived_data stands in
        for data in the archive, for a message carrying what no file should.
        """
        # What the inbox asks of writers is read before anything is stored, so
        # a requirement this client cannot meet stops here with its reason,
        # rather than as an outbox entry that can never be delivered.
        advice = self._plan_for(w)
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

        # A caller with a time limit, a model on MCP whose host cuts a tool call
        # after a minute or so, is not held for work that takes longer. The work
        # goes on here, the answer comes at once, and how it ends is told on
        # the next read, where it would otherwise be a call that timed out
        # with nobody knowing whether the message went.
        budget = getattr(self, "work_budget", None)
        if budget is not None and advice.get("expected_seconds", 0) > budget:
            entry["status"] = "working"
            entry["work"] = {"bits": advice["bits"], "expected_seconds": int(advice["expected_seconds"]), "seconds_left": None if advice.get("seconds_left") is None else int(advice["seconds_left"])}
            self.save_outbox()
            threading.Thread(target=self._deliver_after_work, args=(entry, body, key, archived_data), daemon=True).start()
            return {
                "to": self.name_for_key(key) or key,
                "w": w,
                "message_id": entry["id"],
                "status": "working",
                "work": entry["work"],
                "note": "This inbox asks for %d bits of proof of work, about %s here, so it is being done in the background and the message is sent when it is done. aamio_pending shows it until then, and the next aamio_read says how it ended." % (advice["bits"], describe_seconds(advice["expected_seconds"])),
            }

        status, result = self._deliver(entry)

        if status in (404, 410) and partner is not None:
            # The partner may have renewed its inbox. Ask presence again, once.
            # A new address means new bytes, so this is a new outbox entry.
            w, key = self.address_for(partner)
            envelope = self.keys.seal(key, plaintext)
            entry = self._outbox_add(w, key, envelope, body, replaces=entry["id"])
            status, result = self._deliver(entry)

        archived = body if archived_data is None else dict(body, data=archived_data)
        record = {"kind": "sent", "at": time.time(), "to": self.name_for_key(key) or key, "w": entry["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "seq": (result or {}).get("seq") if isinstance(result, dict) else None, "sha256": (result or {}).get("sha256") if isinstance(result, dict) else None, "body": archived}
        # The archive is a record of the send, not the send. A full disk after
        # a 201 raised here, and the caller heard an error for a message that
        # was delivered, and might send it again as new bytes: a real duplicate.
        archive_error = self._archive_sent(record)

        if status != 201:
            raise SendFailed(entry["status"], entry["id"], status, result)

        sent = {"to": record["to"], "w": entry["w"], "message_id": entry["id"], "seq": result["seq"], "at": result["at"], "sha256": result["sha256"], "expire_at": result["expire_at"]}
        # Only from an inbox with a gate: what it found, and what the caller
        # should hear although the message went out.
        if "met" in result:
            sent["met"] = result["met"]
            sent["proof_id"] = result.get("proof_id")
        if entry.get("gate_notes"):
            sent["notes"] = entry["gate_notes"]
        if archive_error is not None:
            sent["archive_error"] = archive_error
        return sent

    def _archive_sent(self, record):
        """Write a sent record, and say what went wrong instead of raising it."""
        try:
            self.archive("sent", record)
        except Exception as error:
            self.log("archive sent %s: %s" % (record.get("message_id"), error))
            return "%s: %s" % (error.__class__.__name__, error)
        return None


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

    # ------------------------------------------------------------- gate --

    def _gate_for(self, w):
        """What an inbox asks of writers, read once per address.

        A gate never changes while its thread lives, so one read is enough. An
        inbox without a gate, or one whose gate cannot be read right now, gives
        {}: the message then goes out without work, and if the inbox did require
        some, its 428 carries the gate and is answered once.
        """
        gates = getattr(self, "gates", None)

        if gates is None:
            gates = self.gates = {}

        if w in gates:
            return gates[w]

        left = None
        try:
            if hasattr(self.client, "gate_timed"):
                status, data, left = self.client.gate_timed(w)
            else:
                status, data = self.client.gate(w)
        except Exception:
            status, data = 0, None

        # Only a gate that was actually read is kept. A 404 is an inbox nobody
        # has opened yet, and it may be opened with a gate a moment later.
        if status == 200 and isinstance(data, dict):
            gates[w] = data
            if left is not None:
                self._gate_clock()[w] = (left, time.monotonic())
            return data

        return {}

    def _forget_gate(self, w):
        """The gate read for w, and the time it said, may belong to an inbox that is not there now."""
        getattr(self, "gates", {}).pop(w, None)
        self._gate_clock().pop(w, None)

    def _plan_for(self, w):
        """What the gate of w asks, read again once before a no that rests on a gate read earlier.

        A gate never changes while its thread lives, which is why it is kept.
        But an address can have more than one life. The time a kept gate said
        counted down to nothing and stayed there, and a new inbox at the same
        address, with no gate at all, was refused on the old one's terms
        without the service ever being asked. One more read, only when the
        answer would be no, is what that costs.
        """
        cached = w in getattr(self, "gates", {})
        try:
            return gate_plan(self._gate_for(w), w, self.host, self._seconds_left(w))
        except GateStop:
            if not cached:
                raise
            self._forget_gate(w)
            return gate_plan(self._gate_for(w), w, self.host, self._seconds_left(w))

    def _gate_clock(self):
        clock = getattr(self, "gate_clock", None)
        if clock is None:
            clock = self.gate_clock = {}
        return clock

    def _seconds_left(self, w):
        """How long w still takes writes, counted down from what its gate said, or None."""
        said = self._gate_clock().get(w)
        if said is None:
            return None
        left, at = said
        return max(0, left - (time.monotonic() - at))

    def _post(self, w, body_text, notes, entry=None):
        """POST to an inbox with the work its gate asks for, answering a 428 once.

        Never more than one more attempt. Each costs a place in the rate window,
        and a 428 after that means the inbox wants something this client cannot
        give it. Work already done and refused anyway is not done again: the
        same bytes give the same nonce and the same refusal. notes collects what
        the caller should hear although the message went out.
        """
        signature = self.keys.sign(thread_signing_input(w, body_text))
        advice = self._plan_for(w)
        notes.extend(advice["notes"])
        status, result = self._post_with_work(w, body_text, signature, advice["bits"], self._seconds_left(w), entry)

        if status == 428 and isinstance(result, dict) and isinstance(result.get("gate"), dict):
            self.gates[w] = result["gate"]
            left = result.get("seconds_left") if isinstance(result.get("seconds_left"), int) else None
            if left is not None:
                self._gate_clock()[w] = (left, time.monotonic())
            asked = gate_plan(result["gate"], w, self.host, left)
            notes.extend(note for note in asked["notes"] if note not in notes)

            if asked["bits"] and asked["bits"] != advice["bits"]:
                status, result = self._post_with_work(w, body_text, signature, asked["bits"], left, entry)

        return status, result

    def _post_with_work(self, w, body_text, signature, bits, seconds_left=None, entry=None):
        if not bits:
            return self.client.post(w, body_text, self.keys.public, signature)

        # While the work runs nothing has been sent, and the entry says so, so
        # a process that stops here leaves a message it knows was not sent
        # rather than one whose fate is unknown.
        if entry is not None:
            entry["status"] = "working"
            self.save_outbox()

        # The work stops when the inbox would close, less a few seconds for the
        # post itself: past that point a nonce buys nothing but a 410.
        deadline = None if seconds_left is None else time.monotonic() + max(0, seconds_left - 5)
        nonce = gate_solve(w, self.keys.public, body_text, bits, deadline)

        if entry is not None:
            entry["status"] = "sending"
            self.save_outbox()

        if nonce is None:
            raise GateStop(
                "The proof of work of %d bits was not done before the inbox stops taking writes, so the work was stopped and nothing was sent." % bits,
                "The estimate before it started said it would fit, and this time it took longer, which happens: the work is a lottery. Ask the owner for a longer inbox, or send from a machine with more compute.",
            )

        return self.client.post(w, body_text, self.keys.public, signature, "text/plain", nonce)

    # ----------------------------------------------------------- deliver --

    def _deliver(self, entry):
        """Send the stored bytes once, and record what the answer allows us to claim."""
        entry["attempts"] += 1
        entry["status"] = "sending"
        self.save_outbox()
        notes = []

        try:
            status, result = self._post(entry["w"], entry["envelope"], notes, entry)
        except GateStop as stop:
            # Nothing left this machine and nothing will: the entry is refused,
            # not pending, and says why.
            entry["status"] = "refused"
            entry["error"] = stop.reason
            entry["last_at"] = int(time.time())
            self.save_outbox()
            raise

        if notes:
            entry["gate_notes"] = notes
        entry["last_status"] = status
        entry["last_at"] = int(time.time())

        # An inbox that is not there, or has expired, takes its gate with it:
        # the next send to this address reads the gate of whatever is there then.
        if status in (404, 410):
            self._forget_gate(entry["w"])

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
        """Messages whose fate is not settled: working, in flight, or unknown after a stop."""
        return [dict(e) for e in self.outbox.values() if e["status"] in ("working", "sending", "unknown")]

    def _deliver_after_work(self, entry, body, key, archived_data=None):
        """The background half of a send whose work was too long to wait for.

        Every way it can end is told on the next read, since the caller was
        answered long before, and an outcome nobody hears about is a message
        that silently did or did not go.
        """
        where = "send %s" % entry["id"]
        try:
            status, result = self._deliver(entry)
        except GateStop as stop:
            self._note_trouble(where, "refused", "the message to %s was not sent: %s" % (self.name_for_key(key) or entry["w"], stop.reason))
            return
        except Exception as error:
            self._note_trouble(where, "unknown", "the message to %s may or may not have been sent: %s. aamio_pending shows it." % (self.name_for_key(key) or entry["w"], error.__class__.__name__))
            return

        archived = body if archived_data is None else dict(body, data=archived_data)
        # A failed archive write is said beside the outcome, never instead of
        # it: it used to raise here and take the promised note with it.
        archive_error = self._archive_sent({"kind": "sent", "at": time.time(), "to": self.name_for_key(key) or key, "w": entry["w"], "status": status, "message_id": entry["id"], "outcome": entry["status"], "seq": (result or {}).get("seq") if isinstance(result, dict) else None, "sha256": (result or {}).get("sha256") if isinstance(result, dict) else None, "body": archived})
        tail = "" if archive_error is None else ". It could not be written to the sent archive (%s), which changes nothing about the delivery" % archive_error

        if status == 201:
            self._note_trouble(where, "delivered", "the message to %s, which needed %d bits of proof of work, was delivered as seq %s%s" % (self.name_for_key(key) or entry["w"], (entry.get("work") or {}).get("bits") or 0, (result or {}).get("seq"), tail))
        else:
            self._note_trouble(where, entry["status"], "the message to %s ended %s after its proof of work, http %s%s" % (self.name_for_key(key) or entry["w"], entry["status"], status, tail))

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
            if entry["status"] == "refused" and entry.get("last_status") in SEND_DETERMINISTIC:
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

    def _note(self, channel, state, what):
        """Something a caller has to hear about, even though the read returned no messages."""
        self._note_trouble(channel.label, state, what, w=channel.w)

    def _note_trouble(self, where, state, what, w=None):
        note = {"channel": where, "w": w, "state": state, "what": what, "at": int(time.time())}
        with self.lock:
            if not hasattr(self, "attention"):
                self.attention = {}
            self.attention[(where, state)] = note
        self.log("%s: %s" % (where, what))

    def attention_taken(self):
        """What the reads since the last call could not do, once, and then cleared."""
        with self.lock:
            taken = sorted(getattr(self, "attention", {}).values(), key=lambda note: (note["at"], note["channel"]))
            self.attention = {}
        return taken

    def poll(self, channel, wait=0):
        status, data = self.client.read(channel.w, channel.read_key, channel.after, wait)
        if status == 410:
            self._note(channel, "expired", "the thread at this address has expired, so anything written to it before now is gone and nothing more will arrive here")
            return "expired", []
        if status != 200:
            self._note(channel, "unread", "the service answered %s, so this channel was not read and there may be messages waiting" % status)
            return "error", []
        # Three answers that used to read as a quiet inbox. No thread at the
        # address: never written to, swept after expiry, or taken by a
        # restart. A reset: the cursor was past everything the thread holds, so
        # the service read from the start. And a created_at that is not the one
        # this channel knew: a new thread at the same address whose count has
        # already passed the old cursor, which the service cannot flag, since
        # it does not know what this channel has seen. In all three the old
        # cursor and the old hashes belong to another thread.
        if data.get("exists") is False:
            if not channel.gone:
                self._note(channel, "gone", "there is no thread at this address any more. It expired and was swept, or the service restarted and it went with it. A write opens a new one here with the default lifetime and without the allowlist or gate this channel was opened with" + (", so a new inbox is opened for the partners" if channel.label == "inbox" else ""))
            channel.gone = True
            channel.forget_thread()
            self.save_state()
            return "gone", []
        channel.gone = False
        created = data.get("created_at")
        reset = data.get("reset")
        if channel.created_at is not None and created is not None and created != channel.created_at and not reset:
            self._note(channel, "restarted", "the thread at this address is a new one, opened at %s where this channel knew one opened at %s, so it is read again from the start" % (created, channel.created_at))
            channel.forget_thread()
            return self.poll(channel, 0)
        if reset:
            self._note(channel, "restarted", (reset.get("what") if isinstance(reset, dict) else None) or "the service read this thread from the start")
        channel.created_at = created
        entries = []
        kept_out = []
        last_seq = None
        for message in data.get("messages", []):
            last_seq = message["seq"] if last_seq is None else max(last_seq, message["seq"])
            # What the service says about a message is the service's word. The
            # hash and the signature are checked here, and everything below
            # goes by that: whose message it is, whether it is opened, and
            # whether this channel takes it at all.
            verified, why_not, digest = check_message(channel.w, message)
            sender_key = message.get("from") if verified else None
            if why_not is not None and message.get("verified"):
                self._note(channel, "unverified", "message %s on this channel was called verified by the service and does not check out here: %s. It is handed over as unverified. That is a fault in the service or an operator that lies, and whoever runs it should hear of it." % (message["seq"], why_not))
            # The allowlist is this channel's too. The service enforces it for
            # as long as it holds the thread, and it holds it in memory: when
            # the store is emptied, a write to the address opens a thread with
            # no list at all. What the channel was opened for is kept with its
            # read key, and applied to what it reads.
            if channel.allow and not (verified and (channel.allow == ["*"] or sender_key in channel.allow)):
                kept_out.append(message["seq"])
                continue
            message = dict(message, verified=verified, sha256=digest or message.get("sha256"), **{"from": sender_key})
            # sender is a name when we know the key and a label when we do
            # not, which reads well and answers the wrong question. Whether a
            # signature checked out, which key made it, and whether that key is
            # someone we have met are three separate facts, and a reader has to
            # be able to act on each: a verified stranger is not a contact, and
            # a contact can still send something not to be trusted.
            known = self.name_for_key(message["from"])
            entry = {"channel": channel.label, "seq": message["seq"], "at": message["at"], "verified": message["verified"], "from_key": message["from"], "known_contact": known is not None, "sender": known or ("unknown key" if message["from"] else "unsigned"), "sha256": message["sha256"], "replay": message["sha256"] in channel.seen}
            if why_not is not None:
                entry["unverified_because"] = why_not
            channel.seen.add(message["sha256"])
            try:
                body, meta = self._open(message)
            except Exception as error:
                # Whatever went wrong belongs to this message alone. Losing the
                # rest of the batch to it would be the expensive mistake.
                body, meta = {"text": message.get("body")}, {"signed": bool(message.get("from")), "encrypted": False, "format": "undecodable", "error": error.__class__.__name__}
            entry["body"] = body
            entry.update(meta)
            # Before the message is kept, archived or shown: a scope key in it
            # goes to scopes.json or nowhere, never to the reader.
            self._take_scope_share(entry)
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
        if kept_out:
            # Past them as well, or the same messages are read and kept out on
            # every call. And said, since a message that does not arrive has to
            # be told from one that was never sent.
            channel.after = max(channel.after, last_seq)
            self.save_state()
            opened_for = "any key, signed only" if channel.allow == ["*"] else "%d named key(s)" % len(channel.allow)
            self._note(channel, "kept_out", "%d message(s) were kept out of this channel (seq %s%s): it was opened for %s, and these were not signed by a key it allows, as checked here. The service enforces the list while it holds the thread; a thread written to after the service lost its store has none, which is how they got this far. They are not handed over and not archived." % (len(kept_out), ", ".join(str(seq) for seq in kept_out[:10]), " and more" if len(kept_out) > 10 else "", opened_for))
        # After a reset the service's next is the cursor, and it is lower than
        # the one this channel held. Keeping the higher of the two would ask
        # past the new thread on every call and hand the same messages over
        # each time.
        if reset and isinstance(data.get("next"), int):
            channel.after = data["next"]
            self.save_state()
        return "ok", entries

    def _poll_loop(self, channel):
        """One long-poll loop per channel, so mail on any channel is seen at once."""
        while not self.stop.is_set() and not channel.closed and channel.expire_at > time.time():
            try:
                state, entries = self.poll(channel, 20)
                if state == "expired":
                    break
                if state in ("error", "gone"):
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
            waited = False
            for channel in list(self.channels.values()):
                state, entries = self.poll(channel, 0 if waited else wait)
                # A channel that answered 410 or nothing at all used to eat the
                # whole wait, so a read with wait 25 came back at once and the
                # inbox was only ever asked with wait 0. A gone one did wait:
                # the service holds a read of a missing thread for a write.
                waited = waited or state in ("ok", "gone")
                collected.extend(entries)
            if len(collected) > limit:
                # The cursor has already moved past all of them. The surplus is
                # in the archive, and a read will not hand it over again, so
                # saying nothing here loses messages the runtime did receive.
                self._note_trouble("read", "truncated", "%d more messages were read than this call hands over, and the cursor has moved past them. They are in the archive, and another read will not bring them back. Ask for a higher limit to see them here." % (len(collected) - limit))
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
        # Two different checks, and they used to be reported as one.
        #
        # The receipt's own arithmetic can always be checked: hash the lines it
        # itself lists and see whether that is the root it claims. That catches
        # a receipt that does not add up, and it needs nothing from us.
        #
        # Whether it agrees with what we saw is a stronger claim, and one we
        # can only make when we hold every message it counts. `received` lives
        # in this process and nowhere else, so a one-shot `aamio-listen
        # receipt` holds none of them and the old field said False: a good
        # receipt reported as a mismatch, which is the one thing a proof must
        # never do. It says None now, with the count, so "not compared" cannot
        # be read as "did not match".
        with channel.lock:
            entries = sorted(channel.received, key=lambda e: e["seq"])
        held = len(entries)
        line = "%d\t%d\t%s\t%s\n"
        listed = "".join(line % (m["seq"], m["at"], m["sha256"], m.get("from") or "-") for m in (data.get("messages") or []))
        ours = "".join(line % (e["seq"], e["at"], e["sha256"], e["from_key"] or "-") for e in entries)
        comparable = held == data["count"]
        # Sign what we took, so partners can exchange receipts and compare
        # without trusting the network's word alone.
        attestation = "aamio-receipt-v1\n%s\n%s\n%d\n%d" % (channel.w, data["root"], data["count"], data.get("issued_at", 0))
        result = {"label": label, "w": channel.w, "root": data["root"], "commitment": data.get("commitment"), "count": data["count"], "keys": [self.name_for_key(k) or k for k in data.get("keys", [])], "root_adds_up": sha256hex(listed) == data["root"], "held_locally": held, "local_root_matches": (sha256hex(ours) == data["root"]) if comparable else None, "signed_by": self.keys.public, "signature": self.keys.sign(attestation), "signed_text": attestation, "receipt": data}

        if not comparable:
            result["local_check"] = ("Not compared: this process holds %d of the %d messages the receipt counts, so a local root would differ for a reason that is not the receipt's. "
                "The receipt stands on root_adds_up and the signature. For the independent check, take the receipt in the process that read the messages." % (held, data["count"]))
        if anchor:
            idem = sha256hex("aamio-listen:%s:%s" % (self.keys.hash, data["root"]))[:32]
            status, proof = self.client.anchor(data["root"], idem)
            result["anchor"] = proof if status == 200 else {"error": status, "detail": proof}
        self.archive(label, {"kind": "receipt", "at": time.time(), "result": result})
        return result

    def close(self):
        """Stops the listener, saves what it holds and lets go of the home, once."""
        if getattr(self, "closed", False):
            return
        self.closed = True
        self.stop.set()
        try:
            self.save_state()
            self.save_outbox()
        finally:
            self._release_lock()

    def release(self):
        """Lets go of the home without saving, for a command that saved what it changed as it went."""
        self._release_lock()
