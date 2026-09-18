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


def verify(key_b64url: str, message: str, signature_b64url: str) -> bool:
    """Whether the signature is that key's over the UTF-8 bytes of message. False for anything malformed, never an exception."""
    try:
        VerifyKey(unb64url(key_b64url)).verify(message.encode("utf-8"), unb64url(signature_b64url))
        return True
    except Exception:
        return False


def check_message(w: str, message: dict):
    """(verified, why_not, sha256) for one message as the service returned it, checked here.

    `verified` in an answer is the service's word, and the trust model says an
    operator cannot forge a signature. That is only true for a reader who
    checks: so the body is hashed here, the hash compared with the one beside
    it, and the signature verified over the address being read. why_not is None
    for a message that verified and for an ordinary unsigned one, and a sentence
    when something that should have held did not.
    """
    body = message.get("body")

    if not isinstance(body, str):
        return False, "the message has no body to check", None

    digest = sha256hex(body)

    if message.get("sha256") != digest:
        return False, "the body does not hash to the sha256 the service gave with it, so these are not the bytes that were stored", digest

    sender, signature = message.get("from"), message.get("sig")

    if not sender or not signature:
        if message.get("verified"):
            return False, "the service calls it verified and gave no key or signature to check", digest

        return False, None, digest

    if verify(sender, thread_signing_input(w, body), signature):
        return True, None, digest

    return False, "the signature does not check out for this key, this address and these bytes" + (", though the service said it did" if message.get("verified") else ""), digest


def is_envelope(text: str) -> bool:
    try:
        envelope = json.loads(text)
    except ValueError:
        return False
    return isinstance(envelope, dict) and envelope.get("e2ee") == ENVELOPE
