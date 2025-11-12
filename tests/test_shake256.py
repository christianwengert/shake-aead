"""
Pytest tests for the pure-Python SHAKE256 implementation in shake256.py.
They replace the old __main__ sanity-check with proper automated tests.
"""
import hashlib
import os
import pytest

from shake256 import shake256, Shake256


@pytest.mark.parametrize(
    "msg,outlen",
    [
        (b"", 32),
        (b"abc", 88),  # mirrors the old __main__ example
        (b"abc", 64),
        (b"The quick brown fox jumps over the lazy dog", 200),
    ],
)
def test_shake256_oneshot_matches_hashlib(msg: bytes, outlen: int):
    ours = shake256(msg, outlen)
    ref = hashlib.shake_256(msg).digest(outlen)
    assert ours == ref


@pytest.mark.parametrize("chunks", [
    [b"abc"],
    [b"a", b"b", b"c"],
    [b"hello ", b"world"],
    [os.urandom(1), os.urandom(2), os.urandom(3)],
])
@pytest.mark.parametrize("outlen", [1, 2, 31, 32, 64, 88, 137, 200])
def test_streaming_equals_hashlib_and_oneshot(chunks, outlen):
    s = Shake256()
    for c in chunks:
        s.update(c)
    out_stream = s.read(outlen)

    msg = b"".join(chunks)
    out_one = shake256(msg, outlen)
    out_ref = hashlib.shake_256(msg).digest(outlen)

    assert out_stream == out_one == out_ref


def test_multiple_reads_extend_output():
    msg = b"abc"
    s = Shake256().update(msg)
    a = s.read(10)
    b = s.read(10)
    # Ensure concatenation equals a single longer read from reference
    ref = hashlib.shake_256(msg).digest(20)
    assert a + b == ref



def test_digest_matches_hashlib():
    msg = b"abc"
    n = 64
    ours = Shake256().update(msg).digest(n)
    ref = hashlib.shake_256(msg).digest(n)
    assert ours == ref


def test_successive_digest_concatenation():
    msg = b"abc"
    s = Shake256().update(msg)
    a = s.digest(10)
    b = s.digest(10)
    ref = hashlib.shake_256(msg).digest(20)
    assert a + b == ref


def test_hexdigest_matches_hashlib():
    msg = b"hello world"
    n = 33
    ours = Shake256().update(msg).hexdigest(n)
    ref = hashlib.shake_256(msg).hexdigest(n)
    assert ours == ref


def test_read_and_digest_same_behavior():
    msg = os.urandom(50)
    s1 = Shake256().update(msg)
    s2 = Shake256().update(msg)
    assert s1.read(73) == s2.digest(73)
