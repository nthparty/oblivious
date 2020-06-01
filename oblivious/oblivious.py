"""Common cryptographic primitives for OT and OPRF.

Python library that serves as an API for common primitives
used to implement OPRF and OT protocols.
"""

from __future__ import annotations
import secrets
import ge25519
import doctest

#
# Use native Python implementations of primitives by default.
#

def _zero(n: bytes) -> bool:
    d = 0
    for i in range(len(n)):
        d |= n[i]
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
    return 1 == (1 - (((c & d) | s[0]) & 1))

def rand() -> bytes:
    while True:
        r = bytearray(secrets.token_bytes(32))
        r[-1] &= 0x1f
        if _sc25519_is_canonical(r) and not _zero(r):
           return r

def base(n: bytes) -> bytes:
    t = bytearray([b for b in n])
    t[31] &= 127
    q = ge25519.ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()
    return None if _zero(q) else q

def mul(n: bytes, p: bytes) -> bytes:
    P = ge25519.ge25519_p3.from_bytes_ristretto255(p)
    if not _ristretto255_is_canonical(p) or P is None:
        return None

    t = bytearray([b for b in n])
    t[31] &= 127

    q = P.scalar_mult(t).to_bytes_ristretto255()
    return None if _zero(q) else q

def add(p: bytes, q: bytes) -> bytes:
    p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
    q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
    if not _ristretto255_is_canonical(p) or p_p3 is None or\
       not _ristretto255_is_canonical(q) or q_p3 is None:
       return None

    q_cached = ge25519.ge25519_cached.from_p3(q_p3)
    r_p1p1 = ge25519.ge25519_p1p1.add(p_p3, q_cached)
    r_p3 = ge25519.ge25519_p3.from_p1p1(r_p1p1)

    return r_p3.to_bytes_ristretto255()

def sub(p: bytes, q: bytes) -> bytes:
    p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
    q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
    if not _ristretto255_is_canonical(p) or p_p3 is None or\
       not _ristretto255_is_canonical(q) or q_p3 is None:
        return None

    q_cached = ge25519.ge25519_cached.from_p3(q_p3)
    r_p1p1 = ge25519.ge25519_p1p1.sub(p_p3, q_cached)
    r_p3 = ge25519.ge25519_p3.from_p1p1(r_p1p1)

    return r_p3.to_bytes_ristretto255()

#
# Attempt to use primitives from libsodium, if it is present.
#

import ctypes
import ctypes.util

sodium = None
try:
    sodium =\
        ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium') or\
        ctypes.util.find_library('libsodium'))

    # Ensure the detected version of libsodium has the necessary primitives.
    assert(hasattr(sodium, 'crypto_box_secretkeybytes'))
    assert(hasattr(sodium, 'crypto_box_publickeybytes'))
    assert(hasattr(sodium, 'crypto_core_ristretto255_bytes'))
    assert(hasattr(sodium, 'crypto_core_ristretto255_scalar_random'))
    assert(hasattr(sodium, 'crypto_scalarmult_ristretto255_base'))
    assert(hasattr(sodium, 'crypto_scalarmult_ristretto255'))
    assert(hasattr(sodium, 'crypto_core_ristretto255_add'))
    assert(hasattr(sodium, 'crypto_core_ristretto255_sub'))

    def rand() -> bytes:
        buf = ctypes.create_string_buffer(sodium.crypto_box_secretkeybytes())
        sodium.crypto_core_ristretto255_scalar_random(buf)
        return buf.raw

    def base(e: bytes) -> bytes:
        buf = ctypes.create_string_buffer(sodium.crypto_box_publickeybytes())
        sodium.crypto_scalarmult_ristretto255_base(buf, e)
        return buf.raw

    def mul(x: bytes, y: bytes) -> bytes:
        buf = ctypes.create_string_buffer(sodium.crypto_box_secretkeybytes())
        sodium.crypto_scalarmult_ristretto255(buf, x, y)
        return buf.raw

    def add(x: bytes, y: bytes) -> bytes:
        buf = ctypes.create_string_buffer(sodium.crypto_core_ristretto255_bytes())
        sodium.crypto_core_ristretto255_add(buf, x, y)
        return buf.raw
        
    def sub(x: bytes, y: bytes) -> bytes:
        buf = ctypes.create_string_buffer(sodium.crypto_core_ristretto255_bytes())
        sodium.crypto_core_ristretto255_sub(buf, x, y)
        return buf.raw
except:
    pass

if __name__ == "__main__":
    doctest.testmod()
