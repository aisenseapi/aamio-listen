"""Whether a client and a service fit is read from what the service declares, not from two version numbers.

From an outside assessment of aamio in use, 18 September 2026 (AAM-004): the
service said 0.7.0, GitHub 0.6.4 and PyPI 0.6.3, and nothing said which of
those go together.
"""

import sys

sys.path.insert(0, "src")

from aamio import compat

EVERYTHING = list(compat.NEEDS) + list(compat.USES)


def verdict(descriptor):
    return compat.check(descriptor)["verdict"]


def test_a_service_that_offers_everything_this_client_uses_is_fully_supported():
    found = compat.check({"version": "9.9.9", "protocol": {"version": compat.PROTOCOL, "capabilities": EVERYTHING + ["something-newer"]}})

    assert found["verdict"] == "full" and found["missing"] == []
    assert found["unknown_to_this_client"] == ["something-newer"], "more than the client knows is not a problem, and is said"


def test_a_capability_that_is_used_and_not_offered_is_partial_and_named_with_what_it_is_for():
    found = compat.check({"version": "0.7.1", "protocol": {"version": compat.PROTOCOL, "capabilities": [name for name in EVERYTHING if name != "scopes"]}})

    assert found["verdict"] == "partial" and found["missing"] == ["scopes"]
    assert "unlisted posts" in found["why"]


def test_another_protocol_or_a_missing_need_is_refused_with_the_reason():
    assert verdict({"protocol": {"version": compat.PROTOCOL + 1, "capabilities": EVERYTHING}}) == "refuse"

    found = compat.check({"protocol": {"version": compat.PROTOCOL, "capabilities": [name for name in EVERYTHING if name != "threads"]}})

    assert found["verdict"] == "refuse" and found["missing"] == ["threads"] and "cannot work without" in found["why"]


def test_a_service_that_declares_nothing_is_partial_and_never_called_full():
    for descriptor in ({"version": "0.7.0"}, {}, None, {"protocol": "1"}, {"protocol": {"version": 1}}):
        found = compat.check(descriptor)

        assert found["verdict"] == "partial" and "does not declare" in found["why"], descriptor
