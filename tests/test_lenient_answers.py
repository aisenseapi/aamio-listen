"""A signed answer that guessed the field names is still an answer."""

from aamio_listen.runtime import Runtime


def test_common_misspellings_are_taken_and_marked():
    # Exactly what the counterpart sent: post_id for post, w for reply_to,
    # reply for text. Signed and useful, and dropped before this change.
    body = {"post_id": "bbvhsh4tx3qbbycufycb", "w": "mzduruizqfz57oxiyxo3", "reply": "use a 5 minute debounce"}
    out = Runtime._canonical(dict(body))
    assert out["post"] == "bbvhsh4tx3qbbycufycb"
    assert out["reply_to"] == "mzduruizqfz57oxiyxo3"
    assert out["text"] == "use a 5 minute debounce"
    # The difference is recorded, not smoothed away.
    assert out["_renamed"] == {"post_id": "post", "w": "reply_to", "reply": "text"}


def test_the_documented_shape_is_untouched():
    body = {"post": "a", "reply_to": "b", "text": "c"}
    out = Runtime._canonical(dict(body))
    assert out == body
    assert "_renamed" not in out


def test_a_signed_plaintext_answer_is_not_reported_as_a_failure():
    """It is signed, it verified, and the sender chose not to encrypt.

    Calling that "undecryptable" made a correct message look broken, and a
    reader nearly discarded content that was fine.
    """
    runtime = object.__new__(Runtime)
    opened = Runtime._open(runtime, {"verified": True, "from": "somekey", "body": '{"post":"a","text":"hei"}'})
    assert opened["plaintext"] is True
    assert "undecryptable" not in opened
    assert opened["text"] == '{"post":"a","text":"hei"}'


def test_an_unsigned_message_still_says_so():
    runtime = object.__new__(Runtime)
    opened = Runtime._open(runtime, {"verified": False, "from": None, "body": "hei"})
    assert opened["unsigned"] is True
