"""
Pytest test vectors for the shake-aead demo implementation.
The vectors are deterministic because we use a fixed key, a zero nonce,
associated data and a short plaintext. The expected ciphertext and tag
values were obtained by running the implementation once (see the
README for the exact command used).
"""

import pytest
from demo import ODWrap, DeckBO

# Fixed test parameters ----------------------------------------------------
KEY = b"cafecafecafecafecafecafecafecafe"
NONCE = b"\x00" * 32  # 32-byte all-zero nonce
AD = b"test_ad"
PLAINTEXT = b"hello world"

# Expected outputs (generated with the same code)
EXPECTED_ODWRAP_CIPHER = bytes.fromhex("2d978ce617a289a54c0282")
EXPECTED_ODWRAP_TAG = bytes.fromhex("f9dac6e4b924dff4ba2e82802e90a6b5")
EXPECTED_DECKBO_CIPHER = bytes.fromhex("4db4a620dbc5d7e58ed348")
EXPECTED_DECKBO_TAG = bytes.fromhex("0a03ebdb8ae1c691f05053eb66c3a2c4")


def test_odwrap_encrypt_decrypt():
    """Encrypt and decrypt using ODWrap - compare against known vectors."""
    od = ODWrap(KEY, NONCE, AD)
    cipher, tag = od.encrypt(PLAINTEXT)
    assert cipher == EXPECTED_ODWRAP_CIPHER
    assert tag == EXPECTED_ODWRAP_TAG

    # Decrypt with a fresh instance to ensure state reset works
    od2 = ODWrap(KEY, NONCE, AD)
    plain = od2.decrypt(cipher, tag)
    assert plain == PLAINTEXT


def test_odwrap_invalid_tag():
    """Decryption must fail when the authentication tag is wrong."""
    od = ODWrap(KEY, NONCE, AD)
    cipher, tag = od.encrypt(PLAINTEXT)
    bad_tag = b"\x00" * len(tag)
    od2 = ODWrap(KEY, NONCE, AD)
    with pytest.raises(ValueError):
        od2.decrypt(cipher, bad_tag)


def test_deckbo_wrap_unwrap():
    """Encrypt and decrypt using DeckBO – compare against known vectors."""
    sid = b"sess"
    deck = DeckBO(KEY, sid=sid, ad=AD)
    cipher, tag = deck.wrap(PLAINTEXT)
    assert cipher == EXPECTED_DECKBO_CIPHER
    assert tag == EXPECTED_DECKBO_TAG

    deck2 = DeckBO(KEY, sid=sid, ad=AD)
    plain = deck2.unwrap(cipher, tag)
    assert plain == PLAINTEXT


def test_deckbo_invalid_tag():
    """Decryption must raise when the tag does not match."""
    sid = b"sess"
    deck = DeckBO(KEY, sid=sid, ad=AD)
    cipher, tag = deck.wrap(PLAINTEXT)
    bad_tag = b"\x00" * len(tag)
    deck2 = DeckBO(KEY, sid=sid, ad=AD)
    with pytest.raises(ValueError):
        deck2.unwrap(cipher, bad_tag)
