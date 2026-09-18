"""Messages as the service hands them to a reader, really signed.

A reader checks the hash and the signature of every message itself, so a test
message has to be one the service could have returned: the sha256 of its body
beside it, and a signature by a real key over the address it sits at. A made-up
key and a made-up hash used to do, while the reader took the service's word.
"""

import hashlib
import sys

sys.path.insert(0, "src")

from aamio.crypto import Keys, thread_signing_input


def keypair(number=1):
    """One of a few fixed identities, the same in every run."""
    return Keys(bytes([number]) * 32)


SENDER = keypair(7)


def stored(w, seq, body, keys=SENDER, at=None, **fields):
    """One message as GET /{w} returns it. keys=None is an unsigned message."""
    message = {
        "seq": seq,
        "at": seq if at is None else at,
        "type": "text",
        "body": body,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "from": None,
        "sig": None,
        "verified": False,
    }

    if keys is not None:
        message.update({"from": keys.public, "sig": keys.sign(thread_signing_input(w, body)), "verified": True})

    message.update(fields)

    return message
