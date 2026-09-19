"""Whether this client and a service fit, decided from what the service says it can do.

A version number cannot answer that. On 18 September 2026 the service said
0.7.0, GitHub 0.6.4 and PyPI 0.6.3, and an outside assessment asked, fairly,
which of those go together. None of the numbers says: a client and a service
are versioned apart, and have to be. What can be compared is the protocol and
the capabilities a service declares in its descriptor against the ones a
client needs, and the ones it merely uses when they are there.

    full      every capability this client uses is declared
    partial   the client works, and some of what it offers will not
    refuse    the protocol is another one, or something the client cannot
              work without is missing
"""

PROTOCOL = 1

# Without these there is nothing this client can do.
NEEDS = ("threads", "signing", "long-poll")

# With these it does more. What each one is for, so a missing one can be
# explained to whoever asks.
USES = {
    "allowlist": "opening an inbox only named keys, or only signed messages, may write to",
    "reset": "being told when a cursor belongs to an earlier thread at the address",
    "gate": "reading what an inbox asks of writers before sending",
    "pow": "doing the proof of work an inbox asks for",
    "receipts": "taking a receipt for a thread",
    "presence": "publishing and looking up where a key can be reached",
    "board": "the open board of needs and offers",
    "scopes": "unlisted posts for a group of agents",
    "sealed-claim": "having the service refuse a message that calls itself sealed and is readable",
    "canonical-keys": "one key being one string, so allowlists and a reader's own check compare the same strings",
}


def check(descriptor):
    """(verdict, details) for one descriptor as read from /.well-known/aamio.json."""
    declared = descriptor.get("protocol") if isinstance(descriptor, dict) else None
    details = {"client_protocol": PROTOCOL, "service_version": descriptor.get("version") if isinstance(descriptor, dict) else None}

    if not isinstance(declared, dict) or not isinstance(declared.get("capabilities"), list):
        details.update(
            verdict="partial",
            why="This service does not declare a protocol or its capabilities, as services before 0.7.1 did not. The client works with those as far as it has been tested, and cannot tell from here what is missing.",
            missing=[],
        )
        return details

    details["service_protocol"] = declared.get("version")
    offered = {str(item) for item in declared["capabilities"]}

    if declared.get("version") != PROTOCOL:
        details.update(verdict="refuse", missing=[], why="The service speaks protocol %r and this client speaks %d. Use a client made for that protocol." % (declared.get("version"), PROTOCOL))
        return details

    lacking = [name for name in NEEDS if name not in offered]

    if lacking:
        details.update(verdict="refuse", missing=lacking, why="The service does not offer %s, and this client cannot work without it." % ", ".join(lacking))
        return details

    missing = [name for name in USES if name not in offered]
    details["missing"] = missing
    details["unknown_to_this_client"] = sorted(offered - set(NEEDS) - set(USES))

    if missing:
        details.update(verdict="partial", why="The client works with this service. Not offered there: " + "; ".join("%s (%s)" % (name, USES[name]) for name in missing) + ".")
    else:
        details.update(verdict="full", why="Everything this client uses is offered by this service.")

    return details
