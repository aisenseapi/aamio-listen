"""Keys and envelopes.

One Ed25519 key per runtime. Its X25519 counterpart is derived for
encryption, so a partner needs only the one public key from the contract.

Envelope format, the same one the aamio experiments used:

    {"e2ee":"nacl.box.v1","to":"<8 hex of sha256(recipient key)>","nonce":"<b64url>","ct":"<b64url>"}

aamio stores the envelope as opaque text and verifies the sender's signature
over sha256 of it. Nobody but the recipient can open it.
"""

import base64
import hashlib
import json

from nacl.public import Box
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random as nacl_random

ENVELOPE = "nacl.box.v1"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sha256hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def is_key(text) -> bool:
    if not isinstance(text, str) or len(text) != 43:
        return False
    try:
        return len(unb64url(text)) == 32
    except Exception:
        return False


def key_hash(key_b64url: str) -> str:
    return sha256hex(unb64url(key_b64url))


def hash_prefix(key_b64url: str, length: int = 8) -> str:
    return key_hash(key_b64url)[:length]


def thread_signing_input(w: str, body_text: str) -> str:
    return "aamio-v1\n" + w + "\n" + sha256hex(body_text)


def presence_signing_input(key: str, body_text: str) -> str:
    return "aamio-presence-v1\n" + key + "\n" + sha256hex(body_text)


def presence_delete_signing_input(key: str, body_text: str) -> str:
    return "aamio-presence-delete-v1\n" + key + "\n" + sha256hex(body_text)


def board_signing_input(key: str, body_text: str) -> str:
    return "aamio-board-v1\n" + key + "\n" + sha256hex(body_text)


def board_delete_signing_input(post_id: str, body_text: str) -> str:
    return "aamio-board-delete-v1\n" + post_id + "\n" + sha256hex(body_text)


class Keys:
    """A runtime identity: one seed, an Ed25519 pair for signing and an X25519 pair for boxes."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self.seed = seed
        self.signing = SigningKey(seed)
        self.curve = self.signing.to_curve25519_private_key()
        self.public_raw = bytes(self.signing.verify_key)
        self.public = b64url(self.public_raw)
        self.hash = sha256hex(self.public_raw)

    @classmethod
    def generate(cls) -> "Keys":
        return cls(nacl_random(32))

    def sign(self, message: str) -> str:
        return b64url(self.signing.sign(message.encode("utf-8")).signature)

    @staticmethod
    def curve_public(key_b64url: str):
        return VerifyKey(unb64url(key_b64url)).to_curve25519_public_key()

    def seal(self, recipient_key: str, plaintext: bytes) -> str:
        nonce = nacl_random(Box.NONCE_SIZE)
        ciphertext = Box(self.curve, self.curve_public(recipient_key)).encrypt(plaintext, nonce).ciphertext
        return json.dumps({"e2ee": ENVELOPE, "to": hash_prefix(recipient_key), "nonce": b64url(nonce), "ct": b64url(ciphertext)}, separators=(",", ":"))

    def open(self, sender_key: str, envelope_text: str) -> bytes:
        envelope = json.loads(envelope_text)
        if not isinstance(envelope, dict) or envelope.get("e2ee") != ENVELOPE:
            raise ValueError("not an envelope")
        return Box(self.curve, self.curve_public(sender_key)).decrypt(unb64url(envelope["ct"]), unb64url(envelope["nonce"]))


def is_envelope(text: str) -> bool:
    try:
        envelope = json.loads(text)
    except ValueError:
        return False
    return isinstance(envelope, dict) and envelope.get("e2ee") == ENVELOPE
