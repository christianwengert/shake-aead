"""
Simple, pure-Python SHAKE256 (XOF) implementation.

This module implements the SHAKE256 extendable-output function as specified
in FIPS 202 using only Python built-ins. It is intentionally small and easy
to read, with comments that explain the steps in plain language.

The goal is clarity over speed. For production workloads, prefer hashlib's
shake_256 which is implemented in optimized C.
"""
from typing import List


# 64-bit mask (all ones)
_MASK: int = 0xFFFFFFFFFFFFFFFF


# Rotate left on a 64-bit word
# We mask to 64 bits so Python's unbounded ints don't grow beyond 64 bits.
def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


# Round constants for Keccak-f[1600]
_RC: List[int] = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
                  0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
                  0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
                  0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

# Rotation offsets r[x][y]
_RO: List[List[int]] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]

# Not used after fixes but kept for reference of classic Pi permutation order
_PI: List[int] = [0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21]


def _keccak_f(s: List[int]) -> List[int]:
    """Apply the Keccak-f[1600] permutation to the 5x5 state array.

    The state is represented as a flat list of 25 unsigned 64-bit words
    in "lane order": index = x + 5*y for coordinates (x, y) with x,y in 0..4.

    Steps per round in simple terms:
    - Theta: mix each column so every bit depends on neighbors.
    - Rho+Pi: rotate each 64-bit lane, then move it to a new position.
    - Chi: apply a small non-linear rule row-wise (uses AND and NOT).
    - Iota: xor a round constant to break symmetry.

    We mask after operations to keep values within 64 bits.
    """
    for rc in _RC:
        # Theta
        c = [s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            s[i] = (s[i] ^ d[i % 5]) & _MASK
        # Rho and Pi
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                # destination index for flatten order (x + 5*y): (x,y) -> (y, (2x+3y) mod 5)
                dest = y + 5 * ((2 * x + 3 * y) % 5)
                b[dest] = _rol(s[x + 5 * y], _RO[x][y])
        # Chi
        for y in range(5):
            t = [b[x + 5 * y] for x in range(5)]
            for x in range(5):
                s[x + 5 * y] = (t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5])) & _MASK
        # Iota
        s[0] = (s[0] ^ rc) & _MASK
    return s


class Shake256:
    """Streaming SHAKE256 XOF (extendable-output function).

    Simple usage:
      s = Shake256().update(b"hello").update(b" world")
      out = s.digest(64)  # get 64 bytes of output (alias: read)

    Notes:
    - You can call update() many times to absorb more input.
    - Once you call digest()/read(), the instance is finalized; further update() is an error.
    - You may call digest()/read() again to get more output bytes (the XOF can be extended).
    - hexdigest(n) returns a hexadecimal string of length 2*n, matching hashlib's API.
    """

    def __init__(self) -> None:
        # Rate is the number of bytes we absorb/squeeze per permutation for SHAKE256
        self._rate: int = 136  # 1088 bits
        # Domain separation suffix for SHAKE functions per FIPS 202
        self._suffix: int = 0x1F
        # 5x5 lanes of 64-bit words, stored as a flat list of 25 ints
        self._s: List[int] = [0] * 25
        # Buffer of input bytes that haven't filled a whole rate block yet
        self._buf: bytearray = bytearray()
        # Whether padding has been applied and the state is in squeezing mode
        self._finalized: bool = False
        # Offset into the current squeeze block (0..rate). Allows partial reads across calls.
        self._sq_off: int = 0
        # Cached squeeze block to support multi-call reads without repeating bytes
        self._sq_block: bytearray = bytearray(self._rate)

    def update(self, data: bytes) -> "Shake256":
        """Absorb more input bytes into the state.

        - Data is appended to an internal buffer. Whenever a full rate-sized
          block (136 bytes) is available, it is XORed into the state and the
          Keccak permutation is applied.
        - Returns self so you can chain calls: s.update(a).update(b)
        """
        if self._finalized:
            raise ValueError("already finalized")
        if not data:
            return self
        self._buf += data
        r = self._rate
        i = 0
        # Process as many full blocks as we can
        while len(self._buf) - i >= r:
            blk = self._buf[i:i + r]
            # XOR the block into the first r/8 lanes (little-endian)
            for j in range(r // 8):
                self._s[j] ^= int.from_bytes(blk[8 * j:8 * j + 8], 'little')
            _keccak_f(self._s)
            i += r
        # Keep any leftover bytes in the buffer
        if i:
            self._buf = self._buf[i:]
        return self

    def _pad(self) -> None:
        """Apply SHAKE padding to the buffered input and permute once.

        Padding is simple:
        - Append the SHAKE domain suffix (0x1F) to the next byte.
        - Set the highest bit of the last byte of the rate block (0x80).
        """
        r = self._rate
        b = bytearray(r)
        b[:len(self._buf)] = self._buf
        b[len(self._buf)] ^= self._suffix
        b[r - 1] ^= 0x80
        # XOR padded block into the state and permute
        for j in range(r // 8):
            self._s[j] ^= int.from_bytes(b[8 * j:8 * j + 8], 'little')
        _keccak_f(self._s)
        self._buf.clear()
        self._finalized = True
        self._sq_off = 0

    def read(self, n: int) -> bytes:
        """Squeeze n output bytes from the XOF.

        After the first call, the instance is finalized (no more update()).
        If more than one block is requested, we apply the permutation between
        blocks to get fresh output.
        """
        if not self._finalized:
            self._pad()
        out = bytearray()
        r = self._rate
        while n > 0:
            # If starting a new block, serialize the first r/8 lanes (little-endian)
            if self._sq_off == 0:
                self._sq_block = bytearray()
                for j in range(r // 8):
                    self._sq_block += self._s[j].to_bytes(8, 'little')
            # Take from the current block starting at the saved offset
            take = min(n, r - self._sq_off)
            out += self._sq_block[self._sq_off:self._sq_off + take]
            self._sq_off += take
            n -= take
            # If we consumed the whole block and still need more, permute and reset offset
            if self._sq_off == r and n > 0:
                _keccak_f(self._s)
                self._sq_off = 0
        return bytes(out)

    # hashlib-compatible API
    def digest(self, length: int) -> bytes:
        """Return the next 'length' bytes of the XOF output.

        This mirrors hashlib.shake_256(...).digest(length) and advances
        the internal squeeze position so subsequent calls continue the stream.
        """
        return self.read(length)

    def hexdigest(self, length: int) -> str:
        """Return the next 'length' bytes as a hex string (2*length characters).

        Mirrors hashlib.shake_256(...).hexdigest(length) and advances
        the internal squeeze position accordingly.
        """
        return self.digest(length).hex()


def shake256(data: bytes, outlen: int) -> bytes:
    """One-shot SHAKE256: absorb data and return outlen bytes.

    This is a convenience wrapper around the streaming API for simple cases.
    """
    return Shake256().update(data).read(outlen)


