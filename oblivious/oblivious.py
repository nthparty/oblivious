"""Common cryptographic primitives for OT and OPRF.

Python library that serves as an API for common primitives
used to implement OPRF and OT protocols.
"""

from __future__ import annotations
from typing import Union, Optional
import doctest
import platform
import os
import hashlib
import ctypes
import ctypes.util
import secrets
import base64
import ge25519
import rbcl.bindings

# Add synonyms to deal with variations in capitalization of function names.
setattr(
    rbcl.bindings,
    'crypto_core_ristretto255_scalarbytes',
    lambda: rbcl.bindings.crypto_core_ristretto255_SCALARBYTES
)
setattr(
    rbcl.bindings,
    'crypto_core_ristretto255_bytes',
    lambda: rbcl.bindings.crypto_core_ristretto255_BYTES
)

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
    return (
        (a * b) % (pow(2, 252) + 27742317777372353535851937790883648493)
    ).to_bytes(32, 'little')

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

class native:
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

    @classmethod
    def scl(cls, s: bytes = None) -> Optional[bytes]:
        """
        Return supplied byte vector if it is a valid scalar; otherwise, return
        `None`. If no byte vector is supplied, return a random scalar.
        """
        if s is None:
            return cls.rnd()

        s = bytearray(s)
        s[-1] &= 0x1f

        if _sc25519_is_canonical(s) and not _zero(s):
            return bytes(s)

        return None

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
    def pnt(h: bytes = None) -> bytes:
        """Return point from 64-byte vector (normally obtained via hashing)."""
        return ge25519.ge25519_p3.from_hash_ristretto255(
            hashlib.sha512(native.rnd()).digest() if h is None else h
        )

    @staticmethod
    def bas(s: bytes) -> bytes:
        """Return base point multiplied by supplied scalar."""
        t = bytearray(s)
        t[31] &= 127

        return ge25519.ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()

    @staticmethod
    def mul(s: bytes, p: bytes) -> bytes:
        """Return point multiplied by supplied scalar."""
        p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        if not _ristretto255_is_canonical(p) or p3 is None:
            return bytes(32) # pragma: no cover

        t = bytearray(s)
        t[31] &= 127

        return p3.scalar_mult(t).to_bytes_ristretto255()

    @staticmethod
    def add(p: bytes, q: bytes) -> bytes:
        """Return sum of the supplied points."""
        p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
        if not _ristretto255_is_canonical(p) or p_p3 is None or\
           not _ristretto255_is_canonical(q) or q_p3 is None:
            return bytes(32) # pragma: no cover

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
            return bytes(32) # pragma: no cover

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
    def random(cls) -> point:
        """Return random point object."""
        return bytes.__new__(cls, native.pnt())

    @classmethod
    def bytes(cls, bs: bytes) -> point:
        """Return point object obtained by transforming supplied bytes-like object."""
        return bytes.__new__(cls, native.pnt(bs))

    @classmethod
    def hash(cls, bs: bytes) -> point:
        """Return point object by hashing supplied bytes-like object."""
        return bytes.__new__(cls, native.pnt(hashlib.sha512(bs).digest()))

    @classmethod
    def base(cls, s: scalar) -> Optional[point]:
        """
        Return base point multiplied by supplied scalar
        if the scalar is valid; otherwise, return `None`.
        """
        p = native.bas(s)
        return None if _zero(p) else bytes.__new__(cls, p)

    @classmethod
    def from_base64(cls, s: str) -> point:
        """Convert Base64 UTF-8 string representation of a point to a point instance."""
        return bytes.__new__(cls, base64.standard_b64decode(s))

    def __new__(cls, bs: bytes = None) -> point:
        """
        Return point object corresponding to supplied bytes object.
        No checking is performed to confirm that the bytes-like object
        is a valid point.
        """
        return bytes.__new__(cls, bs) if bs is not None else cls.random()

    def __mul__(self: point, other):
        """A point cannot be a left-hand argument."""
        raise TypeError('point must be on right-hand side of multiplication operator')

    def __rmul__(self: point, other: scalar) -> Optional[point]:
        """Return point multiplied by supplied scalar."""
        p = native.mul(other, self)
        return None if _zero(p) else native.point(p)

    def __add__(self: point, other: point) -> Optional[point]:
        """Return sum of the supplied points."""
        p = native.add(self, other)
        return None if _zero(p) else native.point(p)

    def __sub__(self: point, other: point) -> Optional[point]:
        """Return result of subtracting second point from first point."""
        p = native.sub(self, other)
        return None if _zero(p) else native.point(p)

    def to_base64(self: point) -> str:
        """Convert to equivalent Base64 UTF-8 string representation."""
        return base64.standard_b64encode(self).decode('utf-8')

class scalar(bytes):
    """
    Wrapper class for a bytes-like object that corresponds
    to a scalar.
    """

    @classmethod
    def random(cls) -> scalar:
        """Return random non-zero scalar object."""
        return bytes.__new__(cls, native.rnd())

    @classmethod
    def bytes(cls, bs: bytes) -> Optional[scalar]:
        """
        Return scalar object obtained by transforming supplied bytes-like
        object if it is possible to do; otherwise, return `None`.
        """
        s = native.scl(bs)
        return bytes.__new__(cls, s) if s is not None else None

    @classmethod
    def hash(cls, bs: bytes) -> scalar:
        """Return scalar object by hashing supplied bytes-like object."""
        h = hashlib.sha256(bs).digest()
        s = native.scl(h)
        while s is None:
            h = hashlib.sha256(h).digest()
            s = native.scl(h)
        return bytes.__new__(cls, s)

    @classmethod
    def from_base64(cls, s: str) -> scalar:
        """Convert Base64 UTF-8 string representation of a scalar to a scalar instance."""
        return bytes.__new__(cls, base64.standard_b64decode(s))

    def __new__(cls, bs: bytes = None) -> scalar:
        """
        Return scalar object corresponding to supplied bytes-like object.
        No checking is performed to confirm that the bytes-like object
        is a valid scalar.
        """
        return bytes.__new__(cls, bs) if bs is not None else cls.random()

    def __invert__(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        2**252 + 27742317777372353535851937790883648493.
        """
        return native.scalar(native.inv(self))

    def inverse(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        2**252 + 27742317777372353535851937790883648493.
        """
        return native.scalar(native.inv(self))

    # pylint: disable=E1136
    def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point, None]:
        """Multiply supplied scalar or point by this scalar."""
        if isinstance(other, native.scalar) or\
           (sodium is not None and isinstance(other, sodium.scalar)):
            return native.scalar(native.smu(self, other))
        p = native.mul(self, other)
        return None if _zero(p) else native.point(p)

    # pylint: disable=E1136
    def __rmul__(self: scalar, other: Union[scalar, point]):
        """A scalar cannot be on the right-hand side of a non-scalar."""
        raise TypeError('scalar must be on left-hand side of multiplication operator')

    def to_base64(self: scalar) -> str:
        """Convert to equivalent Base64 UTF-8 string representation."""
        return base64.standard_b64encode(self).decode('utf-8')

# Access to wrapper classes for bytes.
native.point = point
native.scalar = scalar

#
# Attempt to load primitives from libsodium, if it is present;
# otherwise, use the rbcl library.
#

try:
    def _call_variant_unwrapped(length, function, x=None, y=None):
        """
        Wrapper to invoke external function.
        """
        buf = ctypes.create_string_buffer(length)
        if y is not None:
            function(buf, x, y)
        elif x is not None:
            function(buf, x)
        else:
            function(buf)
        return buf.raw

    def _call_variant_wrapped(length, function, x=None, y=None): # pylint: disable=W0613
        """
        Wrapper to invoke external (wrapped) function.
        """
        if y is not None:
            return function(x, y)
        if x is not None:
            return function(x)
        return function()

    _call_variant = _call_variant_unwrapped

    try:
        xdll = ctypes.cdll if platform.system() != 'Windows' else ctypes.windll
        libf = ctypes.util.find_library('sodium') or ctypes.util.find_library('libsodium')
        if libf is not None:
            _sodium = xdll.LoadLibrary(libf)
        else: # pragma: no cover
            # Perform explicit search in case `ld` is not present in environment.
            libf = 'libsodium.so' if platform.system() != 'Windows' else 'libsodium.dll'
            for var in ['PATH', 'LD_LIBRARY_PATH']:
                if var in os.environ:
                    for path in os.environ[var].split(os.pathsep):
                        try:
                            _sodium = ctypes.cdll.LoadLibrary(path + os.path.sep + libf)
                            break
                        except:
                            continue
    except: # pragma: no cover
        _sodium = rbcl.bindings
        _call_variant = _call_variant_wrapped

    # Ensure the chosen version of libsodium (or its substitute) has the necessary primitives.
    assert hasattr(_sodium, 'crypto_core_ristretto255_bytes')
    assert hasattr(_sodium, 'crypto_core_ristretto255_scalarbytes')
    assert hasattr(_sodium, 'crypto_core_ristretto255_scalar_random')
    assert hasattr(_sodium, 'crypto_core_ristretto255_scalar_invert')
    assert hasattr(_sodium, 'crypto_core_ristretto255_scalar_mul')
    assert hasattr(_sodium, 'crypto_core_ristretto255_from_hash')
    assert hasattr(_sodium, 'crypto_scalarmult_ristretto255_base')
    assert hasattr(_sodium, 'crypto_scalarmult_ristretto255')
    assert hasattr(_sodium, 'crypto_core_ristretto255_add')
    assert hasattr(_sodium, 'crypto_core_ristretto255_sub')

    # Exported symbol.
    class sodium:
        """
        Wrapper class for native Python implementations of
        primitive operations.
        """
        _lib = _sodium
        _call_unwrapped = _call_variant_unwrapped
        _call_wrapped = _call_variant_wrapped
        _call = _call_variant

        @staticmethod
        def rnd() -> bytes:
            """Return random non-zero scalar."""
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_random
            )

        @classmethod
        def scl(cls, s: bytes = None) -> Optional[bytes]:
            """
            Return supplied byte vector if it is a valid scalar; otherwise, return
            `None`. If no byte vector is supplied, return a random scalar.
            """
            if s is None:
                return cls.rnd()

            s = bytearray(s)
            s[-1] &= 0x1f

            if _sc25519_is_canonical(s) and not _zero(s):
                return bytes(s)

            return None

        @staticmethod
        def inv(s: bytes) -> bytes:
            """
            Return inverse of scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_invert,
                bytes(s)
            )

        @staticmethod
        def smu(s: bytes, t: bytes) -> bytes:
            """
            Return scalar multiplied by another scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_mul,
                bytes(s), bytes(t)
            )

        @staticmethod
        def pnt(h: bytes = None) -> bytes:
            """Return point from 64-byte hash."""
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_bytes(),
                sodium._lib.crypto_core_ristretto255_from_hash,
                bytes(
                    hashlib.sha512(sodium.rnd()).digest() if h is None else h
                )
            )

        @staticmethod
        def bas(s: bytes) -> bytes:
            """Return base point multiplied by supplied scalar."""
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_scalarmult_ristretto255_base,
                bytes(s)
            )

        @staticmethod
        def mul(s: bytes, p: bytes) -> bytes:
            """Return point multiplied by supplied scalar."""
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_scalarmult_ristretto255,
                bytes(s), bytes(p)
            )

        @staticmethod
        def add(x: bytes, y: bytes) -> bytes:
            """Return sum of the supplied points."""
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_add,
                bytes(x), bytes(y)
            )

        @staticmethod
        def sub(x: bytes, y: bytes) -> bytes:
            """Return result of subtracting second point from first point."""
            return sodium._call(
                _sodium.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_sub,
                bytes(x), bytes(y)
            )

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
    # Dedicated point and scalar data structures derived from `bytes`.
    #

    class point(bytes):
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """

        @classmethod
        def random(cls) -> point:
            """Return random point object."""
            return bytes.__new__(cls, sodium.pnt())

        @classmethod
        def bytes(cls, bs: bytes) -> point:
            """Return point object obtained by transforming supplied bytes-like object."""
            return bytes.__new__(cls, sodium.pnt(bs))

        @classmethod
        def hash(cls, bs: bytes) -> point:
            """Return point object by hashing supplied bytes-like object."""
            return bytes.__new__(cls, sodium.pnt(hashlib.sha512(bs).digest()))

        @classmethod
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.
            """
            p = sodium.bas(s)
            return None if _zero(p) else bytes.__new__(cls, p)

        @classmethod
        def from_base64(cls, s: str) -> point:
            """Convert Base64 UTF-8 string representation of a point to a point instance."""
            return bytes.__new__(cls, base64.standard_b64decode(s))

        def __new__(cls, bs: bytes = None) -> point:
            """
            Return point object corresponding to supplied bytes-like object.
            No checking is performed to confirm that the bytes-like object
            is a valid point.
            """
            return bytes.__new__(cls, bs) if bs is not None else cls.random()

        def __mul__(self: point, other):
            """A point cannot be a left-hand argument."""
            raise TypeError('point must be on right-hand side of multiplication operator')

        def __rmul__(self: point, other: scalar) -> Optional[point]:
            """Return point multiplied by supplied scalar."""
            p = sodium.mul(other, self)
            return None if _zero(p) else sodium.point(p)

        def __add__(self: point, other: point) -> Optional[point]:
            """Return sum of the supplied points."""
            p = sodium.add(self, other)
            return None if _zero(p) else sodium.point(p)

        def __sub__(self: point, other: point) -> Optional[point]:
            """Return result of subtracting second point from first point."""
            p = sodium.sub(self, other)
            return None if _zero(p) else sodium.point(p)

        def to_base64(self: point) -> str:
            """Convert to equivalent Base64 UTF-8 string representation."""
            return base64.standard_b64encode(self).decode('utf-8')

    class scalar(bytes):
        """
        Wrapper class for a bytes-like object that corresponds
        to a scalar.
        """

        @classmethod
        def random(cls) -> scalar:
            """Return random non-zero scalar object."""
            return bytes.__new__(cls, sodium.rnd())

        @classmethod
        def bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return scalar object obtained by transforming supplied bytes-like
            object if it is possible to do; otherwise, return `None`.
            """
            s = sodium.scl(bs)
            return bytes.__new__(cls, s) if s is not None else None

        @classmethod
        def hash(cls, bs: bytes) -> scalar:
            """Return scalar object by hashing supplied bytes-like object."""
            h = hashlib.sha256(bs).digest()
            s = sodium.scl(h)
            while s is None:
                h = hashlib.sha256(h).digest()
                s = sodium.scl(h)
            return bytes.__new__(cls, s)

        @classmethod
        def from_base64(cls, s: str) -> scalar:
            """Convert Base64 UTF-8 string representation of a scalar to a scalar instance."""
            return bytes.__new__(cls, base64.standard_b64decode(s))

        def __new__(cls, bs: bytes = None) -> scalar:
            """
            Return scalar object corresponding to supplied bytes-like object.
            No checking is performed to confirm that the bytes-like object
            is a valid scalar.
            """
            return bytes.__new__(cls, bs) if bs is not None else cls.random()

        def __invert__(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            return sodium.scalar(sodium.inv(self))

        def inverse(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            2**252 + 27742317777372353535851937790883648493.
            """
            return sodium.scalar(sodium.inv(self))

        # pylint: disable=E1136
        def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point, None]:
            """Multiply supplied scalar or point by this scalar."""
            if isinstance(other, (native.scalar, sodium.scalar)):
                return sodium.scalar(sodium.smu(self, other))
            p = sodium.mul(self, other)
            return None if _zero(p) else sodium.point(p)

        # pylint: disable=E1136
        def __rmul__(self: scalar, other: Union[scalar, point]):
            """A scalar cannot be on the right-hand side of a non-scalar."""
            raise TypeError('scalar must be on left-hand side of multiplication operator')

        def to_base64(self: scalar) -> str:
            """Convert to equivalent Base64 UTF-8 string representation."""
            return base64.standard_b64encode(self).decode('utf-8')

    # Access to wrapper classes for bytes.
    sodium.point = point
    sodium.scalar = scalar

except: # pragma: no cover
    # Exported symbol.
    sodium = None # pragma: no cover

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
