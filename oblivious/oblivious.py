"""Common cryptographic primitives for OT and OPRF.

Python library that serves as an API for common primitives
used to implement OPRF and OT protocols.
"""

from __future__ import annotations
import doctest
import platform
import ctypes
import ctypes.util
import secrets
import ge25519

#
# Use native Python implementations of primitives by default.
#

def _zero(n: bytes) -> bool:
    d = 0
    for b in n:
        d |= b
    return ((d - 1) >> 8) % 2 == 1

_sc25519_is_canonical_L = [ # 2^252+27742317777372353535851937790883648493.
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
]

def _sc25519_is_canonical(s: bytes) -> bool:
    c = 0
    n = 1
    for i in range(31, -1, -1):
        c |= ((s[i] - _sc25519_is_canonical_L[i]) >> 8) & n
        n &= ((s[i] ^ _sc25519_is_canonical_L[i]) - 1) >> 8
    return c != 0

def _ristretto255_is_canonical(s: bytes) -> bool:
    c = ((s[31] & 0x7f) ^ 0x7f) % 256
    for i in range(30, 0, -1):
        c |= (s[i] ^ 0xff) % 256
    c = (c - 1) >> 8
    d = ((0xed - 1 - s[0]) >> 8) % 256
    return (1 - (((c & d) | s[0]) & 1)) == 1

class common():
    """
    Methods shared by wrapper classes.
    """

    @staticmethod
    def scalar(s: bytes) -> bool:
        """Only returns a byte vector if it is a valid scalar."""
        s = list(s)
        s[-1] &= 0x1f
        return _sc25519_is_canonical(s) and not _zero(s)

class native(common):
    """
    Wrapper class for native Python implementations of
    primitive operations.
    """

    @staticmethod
    def rand() -> bytes:
        """Return random non-zero scalar."""
        while True:
            r = bytearray(secrets.token_bytes(32))
            r[-1] &= 0x1f
            if _sc25519_is_canonical(r) and not _zero(r):
                return r

    @staticmethod
    def base(s: bytes) -> bytes:
        """Return base point multiplied by supplied scalar."""
        t = bytearray(s)
        t[31] &= 127

        q = ge25519.ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()
        return None if _zero(q) else q

    @staticmethod
    def mul(s: bytes, p: bytes) -> bytes:
        """Return base point multiplied by supplied scalar."""
        p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        if not _ristretto255_is_canonical(p) or p3 is None:
            return None # pragma: no cover

        t = bytearray(s)
        t[31] &= 127

        q = p3.scalar_mult(t).to_bytes_ristretto255()
        return None if _zero(q) else q

    @staticmethod
    def add(p: bytes, q: bytes) -> bytes:
        """Return sum of two points."""
        p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
        if not _ristretto255_is_canonical(p) or p_p3 is None or\
           not _ristretto255_is_canonical(q) or q_p3 is None:
            return None # pragma: no cover

        q_cached = ge25519.ge25519_cached.from_p3(q_p3)
        r_p1p1 = ge25519.ge25519_p1p1.add(p_p3, q_cached)
        r_p3 = ge25519.ge25519_p3.from_p1p1(r_p1p1)
        return r_p3.to_bytes_ristretto255()

    @staticmethod
    def sub(p: bytes, q: bytes) -> bytes:
        """Return result of subtracting second point from first point."""
        p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
        if not _ristretto255_is_canonical(p) or p_p3 is None or\
           not _ristretto255_is_canonical(q) or q_p3 is None:
            return None # pragma: no cover

        q_cached = ge25519.ge25519_cached.from_p3(q_p3)
        r_p1p1 = ge25519.ge25519_p1p1.sub(p_p3, q_cached)
        r_p3 = ge25519.ge25519_p3.from_p1p1(r_p1p1)
        return r_p3.to_bytes_ristretto255()

# Top-level best-effort synonyms.
scalar = native.scalar
rand = native.rand
base = native.base
mul = native.mul
add = native.add
sub = native.sub

#
# Attempt to load primitives from libsodium, if it is present.
#

try:
    xdll = ctypes.windll if platform.system() == 'Windows' else ctypes.cdll
    _sodium =\
        xdll.LoadLibrary(\
            ctypes.util.find_library('sodium') or\
            ctypes.util.find_library('libsodium')\
        )

    # Ensure the detected version of libsodium has the necessary primitives.
    assert hasattr(_sodium, 'crypto_box_secretkeybytes')
    assert hasattr(_sodium, 'crypto_box_publickeybytes')
    assert hasattr(_sodium, 'crypto_core_ristretto255_bytes')
    assert hasattr(_sodium, 'crypto_core_ristretto255_scalar_random')
    assert hasattr(_sodium, 'crypto_scalarmult_ristretto255_base')
    assert hasattr(_sodium, 'crypto_scalarmult_ristretto255')
    assert hasattr(_sodium, 'crypto_core_ristretto255_add')
    assert hasattr(_sodium, 'crypto_core_ristretto255_sub')

    # Exported symbol.
    class sodium(common):
        '''
        Wrapper class for native Python implementations of
        primitive operations.
        '''

        @staticmethod
        def rand() -> bytes:
            """Return random non-zero scalar."""
            buf = ctypes.create_string_buffer(_sodium.crypto_box_secretkeybytes())
            _sodium.crypto_core_ristretto255_scalar_random(buf)
            return buf.raw

        @staticmethod
        def base(e: bytes) -> bytes:
            """Return base point multiplied by supplied scalar."""
            buf = ctypes.create_string_buffer(_sodium.crypto_box_publickeybytes())
            _sodium.crypto_scalarmult_ristretto255_base(buf, bytes(e))
            return buf.raw

        @staticmethod
        def mul(x: bytes, y: bytes) -> bytes:
            """Return base point multiplied by supplied scalar."""
            buf = ctypes.create_string_buffer(_sodium.crypto_box_secretkeybytes())
            _sodium.crypto_scalarmult_ristretto255(buf, bytes(x), bytes(y))
            return buf.raw

        @staticmethod
        def add(x: bytes, y: bytes) -> bytes:
            """Return sum of two points."""
            buf = ctypes.create_string_buffer(_sodium.crypto_core_ristretto255_bytes())
            _sodium.crypto_core_ristretto255_add(buf, bytes(x), bytes(y))
            return buf.raw

        @staticmethod
        def sub(x: bytes, y: bytes) -> bytes:
            """Return result of subtracting second point from first point."""
            buf = ctypes.create_string_buffer(_sodium.crypto_core_ristretto255_bytes())
            _sodium.crypto_core_ristretto255_sub(buf, bytes(x), bytes(y))
            return buf.raw

    # Top-level best-effort synonyms.
    scalar = sodium.scalar
    rand = sodium.rand
    base = sodium.base
    mul = sodium.mul
    add = sodium.add
    sub = sodium.sub
except: # pragma: no cover
    # Exported symbol.
    sodium = None # pragma: no cover

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
