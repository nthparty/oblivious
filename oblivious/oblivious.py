"""Common cryptographic primitives for OT and OPRF.

Python library that serves as an API for common primitives
used to implement OPRF and OT protocols.
"""

from __future__ import annotations
from typing import Union
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

def _sc25519_mul(a: bytes, b: bytes) -> bytes:
    (a, b) = (int.from_bytes(a, 'little'), int.from_bytes(b, 'little'))
    return ((a * b) % (pow(2, 252) + 27742317777372353535851937790883648493)).to_bytes(32, 'little')

def _sc25519_sqmul(s: bytes, n: int, a: bytes) -> bytes:
    for _ in range(n):
        s = _sc25519_mul(s, s)
    return _sc25519_mul(s, a)

def _sc25519_invert(s: bytes) -> bytes:
    b_10 = _sc25519_mul(s, s)
    b_100 = _sc25519_mul(b_10, b_10)
    b_11 = _sc25519_mul(b_10, s)
    b_101 = _sc25519_mul(b_10, b_11)
    b_111 = _sc25519_mul(b_10, b_101)
    b_1001 = _sc25519_mul(b_10, b_111)
    b_1011 = _sc25519_mul(b_10, b_1001)
    b_1111 = _sc25519_mul(b_100, b_1011)
    recip = _sc25519_mul(b_1111, s)

    recip = _sc25519_sqmul(recip, 123 + 3, b_101)
    recip = _sc25519_sqmul(recip, 2 + 2, b_11)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1111)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1111)
    recip = _sc25519_sqmul(recip, 4, b_1001)
    recip = _sc25519_sqmul(recip, 2, b_11)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1111)
    recip = _sc25519_sqmul(recip, 1 + 3, b_101)
    recip = _sc25519_sqmul(recip, 3 + 3, b_101)
    recip = _sc25519_sqmul(recip, 3, b_111)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1111)
    recip = _sc25519_sqmul(recip, 2 + 3, b_111)
    recip = _sc25519_sqmul(recip, 2 + 2, b_11)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1011)
    recip = _sc25519_sqmul(recip, 2 + 4, b_1011)
    recip = _sc25519_sqmul(recip, 6 + 4, b_1001)
    recip = _sc25519_sqmul(recip, 2 + 2, b_11)
    recip = _sc25519_sqmul(recip, 3 + 2, b_11)
    recip = _sc25519_sqmul(recip, 3 + 2, b_11)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1001)
    recip = _sc25519_sqmul(recip, 1 + 3, b_111)
    recip = _sc25519_sqmul(recip, 2 + 4, b_1111)
    recip = _sc25519_sqmul(recip, 1 + 4, b_1011)
    recip = _sc25519_sqmul(recip, 3, b_101)
    recip = _sc25519_sqmul(recip, 2 + 4, b_1111)
    recip = _sc25519_sqmul(recip, 3, b_101)
    recip = _sc25519_sqmul(recip, 1 + 2, b_11)

    return recip

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
    def scl(s: bytes) -> bytes:
        """
        Return a byte vector if it is a valid scalar;
        otherwise, return `None`.
        """
        s = bytearray(s)
        s[-1] &= 0x1f

        if _sc25519_is_canonical(s) and not _zero(s):
            return bytes(s)

        return None

class native(common):
    """
    Wrapper class for native Python implementations of
    primitive operations.
    """

    @staticmethod
    def rnd() -> bytes:
        """Return random non-zero scalar."""
        while True:
            r = bytearray(secrets.token_bytes(32))
            r[-1] &= 0x1f
            if _sc25519_is_canonical(r) and not _zero(r):
                return r

    @staticmethod
    def inv(s: bytes) -> bytes:
        """
        Return inverse of scalar modulo
        2**252 + 27742317777372353535851937790883648493.
        """
        return _sc25519_invert(s)

    @staticmethod
    def smu(s: bytes, t: bytes) -> bytes:
        """Return scalar multiplied by another scalar."""
        return _sc25519_mul(s, t)

    @staticmethod
    def pnt(h: bytes) -> bytes:
        """Return point from 64-byte hash."""
        return ge25519.ge25519_p3.from_hash_ristretto255(h)

    @staticmethod
    def bas(s: bytes) -> bytes:
        """Return base point multiplied by supplied scalar."""
        t = bytearray(s)
        t[31] &= 127

        q = ge25519.ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()
        return None if _zero(q) else q

    @staticmethod
    def mul(s: bytes, p: bytes) -> bytes:
        """Return point multiplied by supplied scalar."""
        p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        if not _ristretto255_is_canonical(p) or p3 is None:
            return None # pragma: no cover

        t = bytearray(s)
        t[31] &= 127

        q = p3.scalar_mult(t).to_bytes_ristretto255()
        return None if _zero(q) else q

    @staticmethod
    def add(p: bytes, q: bytes) -> bytes:
        """Return sum of the supplied points."""
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
scl = native.scl
rnd = native.rnd
inv = native.inv
smu = native.smu
pnt = native.pnt
bas = native.bas
mul = native.mul
add = native.add
sub = native.sub

#
# Wrapper classes for bytes.
#

class point(bytes):
    """
    Wrapper class for a bytes-like object that corresponds
    to a point.
    """

    @classmethod
    def base(cls, s: scalar) -> point:
        """
        Return base point multiplied by supplied scalar
        if the scalar is valid; otherwise, return `None`.
        """
        p = bas(s)
        return bytes.__new__(cls, p) if p is not None else None

    def __new__(cls, bs: bytes) -> point:
        """Return point object corresponding to supplied bytes object."""
        return bytes.__new__(cls, pnt(bs))

    def __mul__(self: point, other) -> point:
        """A point cannot be a left-hand argument."""
        raise TypeError('point must be on right-hand side of multiplication operator')

    def __rmul__(self: point, other: scalar) -> point:
        """Return point multiplied by supplied scalar."""
        return mul(other, self)

    def __add__(self: point, other: point) -> point:
        """Return sum of the supplied points."""
        return add(self, other)

    def __sub__(self: point, other: point) -> point:
        """Return result of subtracting second point from first point."""
        return sub(self, other)

class scalar(bytes):
    """
    Wrapper class for a bytes-like object that corresponds
    to a scalar.
    """

    @classmethod
    def random(cls) -> scalar:
        """Return random non-zero scalar."""
        return cls(rnd())

    def __new__(cls, bs: bytes) -> scalar:
        """
        Return scalar object corresponding to supplied bytes object
        if it is a valid scalar; otherwise, return `None`.
        """
        s = scl(bs)
        return bytes.__new__(cls, s) if s is not None else None

    def __invert__(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        2**252 + 27742317777372353535851937790883648493.
        """
        return inv(self)

    def inverse(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        2**252 + 27742317777372353535851937790883648493.
        """
        return inv(self)

    # pylint: disable=E1136
    def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point]:
        """Multiply supplied scalar or point by this scalar."""
        if isinstance(other, (native.scalar, sodium.scalar)):
            return smu(self, other)
        return mul(self, other)

    # pylint: disable=E1136
    def __rmul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point]:
        """A scalar cannot be on the right-hand side of a non-scalar."""
        raise TypeError('scalar must be on left-hand side of multiplication operator')

# Access to wrapper classes for bytes.
native.point = point
native.scalar = scalar

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
        """
        Wrapper class for native Python implementations of
        primitive operations.
        """

        @staticmethod
        def rnd() -> bytes:
            """Return random non-zero scalar."""
            buf = ctypes.create_string_buffer(_sodium.crypto_box_secretkeybytes())
            _sodium.crypto_core_ristretto255_scalar_random(buf)
            return buf.raw

        @staticmethod
        def inv(s: bytes) -> bytes:
            """
            Return inverse of scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            buf = ctypes.create_string_buffer(_sodium.crypto_box_secretkeybytes())
            _sodium.crypto_core_ristretto255_scalar_invert(buf, bytes(s))
            return buf.raw

        @staticmethod
        def smu(s: bytes, t: bytes) -> bytes:
            """
            Return scalar multiplied by another scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            buf = ctypes.create_string_buffer(_sodium.crypto_box_secretkeybytes())
            _sodium.crypto_core_ristretto255_scalar_mul(buf, bytes(s), bytes(t))
            return buf.raw

        @staticmethod
        def pnt(h: bytes) -> bytes:
            """Return point from 64-byte hash."""
            buf = ctypes.create_string_buffer(_sodium.crypto_core_ristretto255_bytes())
            _sodium.crypto_core_ristretto255_from_hash(buf, bytes(h))
            return buf.raw

        @staticmethod
        def bas(e: bytes) -> bytes:
            """Return base point multiplied by supplied scalar."""
            buf = ctypes.create_string_buffer(_sodium.crypto_box_publickeybytes())
            _sodium.crypto_scalarmult_ristretto255_base(buf, bytes(e))
            return buf.raw

        @staticmethod
        def mul(s: bytes, p: bytes) -> bytes:
            """Return point multiplied by supplied scalar."""
            buf = ctypes.create_string_buffer(_sodium.crypto_box_secretkeybytes())
            _sodium.crypto_scalarmult_ristretto255(buf, bytes(s), bytes(p))
            return buf.raw

        @staticmethod
        def add(x: bytes, y: bytes) -> bytes:
            """Return sum of the supplied points."""
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
    scl = sodium.scl
    rnd = sodium.rnd
    inv = sodium.inv
    smu = sodium.smu
    pnt = sodium.pnt
    bas = sodium.bas
    mul = sodium.mul
    add = sodium.add
    sub = sodium.sub

    #
    # Wrapper classes for bytes.
    #

    class point(bytes):
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """

        @classmethod
        def base(cls, s: scalar) -> point:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.
            """
            p = bas(s)
            return bytes.__new__(cls, p) if p is not None else None

        def __new__(cls, bs: bytes) -> point:
            """Return point object corresponding to supplied bytes object."""
            return bytes.__new__(cls, pnt(bs))

        def __mul__(self: point, other) -> point:
            """A point cannot be a left-hand argument."""
            raise TypeError('point must be on right-hand side of multiplication operator')

        def __rmul__(self: point, other: scalar) -> point:
            """Return point multiplied by supplied scalar."""
            return mul(other, self)

        def __add__(self: point, other: point) -> point:
            """Return sum of the supplied points."""
            return add(self, other)

        def __sub__(self: point, other: point) -> point:
            """Return result of subtracting second point from first point."""
            return sub(self, other)

    class scalar(bytes):
        """
        Wrapper class for a bytes-like object that corresponds
        to a scalar.
        """

        @classmethod
        def random(cls) -> scalar:
            """Return random non-zero scalar."""
            return cls(rnd())

        def __new__(cls, bs: bytes) -> scalar:
            """
            Return scalar object corresponding to supplied bytes object
            if it is a valid scalar; otherwise, return `None`.
            """
            s = scl(bs)
            return bytes.__new__(cls, s) if s is not None else None

        def __invert__(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            return inv(self)

        def inverse(self: scalar)  -> scalar:
            """
            Return inverse of scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            return inv(self)

        # pylint: disable=E1136
        def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point]:
            """Multiply supplied scalar or point by this scalar."""
            if isinstance(other, (native.scalar, sodium.scalar)):
                return smu(self, other)
            return mul(self, other)

        # pylint: disable=E1136
        def __rmul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point]:
            """A scalar cannot be on the right-hand side of a non-scalar."""
            raise TypeError('scalar must be on left-hand side of multiplication operator')

    # Access to wrapper classes for bytes.
    sodium.point = point
    sodium.scalar = scalar

except: # pragma: no cover
    # Exported symbol.
    sodium = None # pragma: no cover

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
