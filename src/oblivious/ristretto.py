"""
.. module:: ristretto

ristretto module
================

This module exports a collection of primitive operations for working
with elliptic curve points and scalars, classes for representing points,
classes for representing scalars, and two wrapper classes/namespaces that
encapsulate pure-Python and shared/dynamic library variants of the above.

* Under all conditions, the wrapper class :obj:`~oblivious.ristretto.native`
  is defined and exports a pure-Python variant of every operation and class
  method exported by this module as a whole.

* If a shared/dynamic library instance of the
  `libsodium <https://doc.libsodium.org>`__ library is found on the
  system (and successfully loaded at the time this module is imported) or
  the optional `rbcl <https://pypi.org/project/rbcl>`__ package is
  installed, then the wrapper class :obj:`~oblivious.ristretto.sodium` is
  defined and exports a wrapper around the appropriate function in the
  dynamic/shared library for every operation and class method exported by
  this module as a whole. Otherwise, the exported variable ``sodium`` is
  assigned ``None``.

* All operations and class methods exported by this module correspond to
  the variants defined by :obj:`~oblivious.ristretto.sodium` if a
  dynamic/shared library is loaded. Otherwise, they correspond to the
  variants defined by :obj:`~oblivious.ristretto.native`.
"""
from __future__ import annotations
from typing import Any, NoReturn, Union, Optional
import doctest
import platform
import os
import hashlib
import ctypes
import ctypes.util
import secrets
import base64
import ge25519

#
# Attempt to load rbcl. If no local libsodium shared/dynamic library file
# is found, only native Python implementations of the functions and methods
# will be available.
#

try: # pragma: no cover
    import rbcl # pylint: disable=E0401

    # Add synonyms to deal with variations in capitalization of function names.
    setattr(
        rbcl,
        'crypto_core_ristretto255_scalarbytes',
        lambda: rbcl.crypto_core_ristretto255_SCALARBYTES
    )
    setattr(
        rbcl,
        'crypto_core_ristretto255_bytes',
        lambda: rbcl.crypto_core_ristretto255_BYTES
    )
except: # pylint: disable=W0702 # pragma: no cover
    rbcl = None

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
    """
    Confirm that the bytes-like object represents a canonical
    scalar.
    """
    c = 0
    n = 1
    for i in range(31, -1, -1):
        c |= ((s[i] - _sc25519_is_canonical_L[i]) >> 8) & n
        n &= ((s[i] ^ _sc25519_is_canonical_L[i]) - 1) >> 8
    return c != 0

def _sc25519_mul(a: bytes, b: bytes) -> bytes:
    """
    Multiply the two scalars represented by the bytes-like objects
    """
    (a, b) = (int.from_bytes(a, 'little'), int.from_bytes(b, 'little'))
    return (
        (a * b) % (pow(2, 252) + 27742317777372353535851937790883648493)
    ).to_bytes(32, 'little')

def _sc25519_sqmul(s: bytes, n: int, a: bytes) -> bytes:
    """
    Perform repeated squaring of a scalar for the designated number
    of iterations, then multiply the result by another scalar.
    """
    for _ in range(n):
        s = _sc25519_mul(s, s)
    return _sc25519_mul(s, a)

def _sc25519_invert(s: bytes) -> bytes:
    """
    Invert the scalar represented by the bytes-like object.
    """
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
    """
    Confirm that the bytes-like object represents a canonical
    Ristretto point.
    """
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

    This class encapsulates pure-Python variants of all
    primitive operations and classes exported by this module:
    :obj:`native.scl <scl>`, :obj:`native.rnd <rnd>`,
    :obj:`native.inv <inv>`, :obj:`native.smu <smu>`,
    :obj:`native.pnt <pnt>`, :obj:`native.bas <bas>`,
    :obj:`native.mul <mul>`, :obj:`native.add <add>`,
    :obj:`native.sub <sub>`, :obj:`native.point <point>`,
    and :obj:`native.scalar <scalar>`.
    For example, you can perform addition of points using
    the pure-Python point addition implementation.

    >>> p = native.pnt()
    >>> q = native.pnt()
    >>> native.add(p, q) == native.add(q, p)
    True

    Pure-Python variants of the :obj:`native.point <point>` and
    :obj:`native.scalar <scalar>` classes always employ pure-Python
    implementations of operations when their methods are invoked.

    >>> p = native.point()
    >>> q = native.point()
    >>> p + q == q + p
    True

    Nevertheless, all bytes-like objects, :obj:`point` objects,
    and :obj:`scalar` objects accepted and emitted by the various
    operations and class methods in :obj:`native` and compatible
    with those accepted and emitted by the operations and class
    methods in :obj:`sodium`.
    """
    @staticmethod
    def rnd() -> bytes:
        """
        Return random non-zero scalar.

        >>> len(rnd())
        32
        """
        while True:
            r = bytearray(secrets.token_bytes(32))
            r[-1] &= 0x1f
            if _sc25519_is_canonical(r) and not _zero(r):
                return r

    @classmethod
    def scl(cls, s: bytes = None) -> Optional[bytes]:
        """
        Return supplied byte vector if it is a valid scalar; otherwise, return
        ``None``. If no byte vector is supplied, return a random scalar.

        >>> s = scl()
        >>> t = scl(s)
        >>> s == t
        True
        >>> scl(bytes([255] * 32)) is None
        True
        """
        if s is None:
            return cls.rnd()

        s = bytearray(s)
        s[-1] &= 0x1f

        return bytes(s) if _sc25519_is_canonical(s) else None

    @staticmethod
    def inv(s: bytes) -> bytes:
        """
        Return inverse of scalar modulo
        ``2**252 + 27742317777372353535851937790883648493``.

        >>> s = scl()
        >>> p = pnt()
        >>> mul(inv(s), mul(s, p)) == p
        True
        """
        return _sc25519_invert(s)

    @staticmethod
    def smu(s: bytes, t: bytes) -> bytes:
        """
        Return scalar multiplied by another scalar.

        >>> s = scl()
        >>> t = scl()
        >>> smu(s, t) == smu(t, s)
        True
        """
        return _sc25519_mul(s, t)

    @staticmethod
    def pnt(h: bytes = None) -> bytes:
        """
        Return point from 64-byte vector (normally obtained via hashing).

        >>> p = pnt(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()
        '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
        """
        return ge25519.ge25519_p3.from_hash_ristretto255(
            hashlib.sha512(native.rnd()).digest() if h is None else h
        )

    @staticmethod
    def bas(s: bytes) -> bytes:
        """
        Return base point multiplied by supplied scalar.

        >>> bas(scalar.hash('123'.encode())).hex()
        '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'
        """
        t = bytearray(s)
        t[31] &= 127

        return ge25519.ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()

    @staticmethod
    def mul(s: bytes, p: bytes) -> bytes:
        """
        Multiply the point by the supplied scalar and return the result.

        >>> p = pnt(hashlib.sha512('123'.encode()).digest())
        >>> s = scl(bytes.fromhex(
        ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
        ... ))
        >>> mul(s, p).hex()
        '183a06e0fe6af5d7913afb40baefc4dd52ae718fee77a3a0af8777c89fe16210'
        """
        p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        if not _ristretto255_is_canonical(p) or p3 is None:
            return bytes(32) # pragma: no cover

        t = bytearray(s)
        t[31] &= 127

        return p3.scalar_mult(t).to_bytes_ristretto255()

    @staticmethod
    def add(p: bytes, q: bytes) -> bytes:
        """
        Return sum of the supplied points.

        >>> p = point.hash('123'.encode())
        >>> q = point.hash('456'.encode())
        >>> add(p, q).hex()
        '7076739c9df665d416e68b9512f5513bf1d0181a2aacefdeb1b7244528a4dd77'
        """
        p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
        if (
            not _ristretto255_is_canonical(p) or p_p3 is None or
            not _ristretto255_is_canonical(q) or q_p3 is None
        ):
            return bytes(32) # pragma: no cover

        q_cached = ge25519.ge25519_cached.from_p3(q_p3)
        r_p1p1 = ge25519.ge25519_p1p1.add(p_p3, q_cached)
        r_p3 = ge25519.ge25519_p3.from_p1p1(r_p1p1)
        return r_p3.to_bytes_ristretto255()

    @staticmethod
    def sub(p: bytes, q: bytes) -> bytes:
        """
        Return result of subtracting second point from first point.

        >>> p = point.hash('123'.encode())
        >>> q = point.hash('456'.encode())
        >>> sub(p, q).hex()
        '1a3199ca7debfe31a90171696d8bab91b99eb23a541b822a7061b09776e1046c'
        """
        p_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(p)
        q_p3 = ge25519.ge25519_p3.from_bytes_ristretto255(q)
        if (
            not _ristretto255_is_canonical(p) or p_p3 is None or
            not _ristretto255_is_canonical(q) or q_p3 is None
        ):
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

    def _call_variant_wrapped(_, function, x=None, y=None): # pragma: no cover
        """
        Wrapper to invoke external (wrapped) function.
        """
        if y is not None:
            return function(x, y)
        if x is not None:
            return function(x)
        return function()

    _sodium = None
    _call_variant = _call_variant_unwrapped

    # Attempt to load libsodium shared/dynamic library file.
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
                    except: # pylint: disable=W0702
                        continue

        # Default to bindings exported by the rbcl library if the above attempts
        # failed and rbcl is available.
        if _sodium is None and rbcl is not None: # pragma: no cover
            _sodium = rbcl
            _call_variant = _call_variant_wrapped

    # Add method variants that are not present in libsodium.
    if _sodium is not rbcl and _sodium is not None: # pragma: no cover

        def crypto_scalarmult_ristretto255_allow_scalar_zero(buf, s, p):
            """
            Variant of scalar-point multiplication function that permits
            a scalar corresponding to the zero residue.
            """
            r = _sodium.crypto_scalarmult_ristretto255(buf, s, p)

            if (1 - _zero(s)) * int(r == -1):
                raise RuntimeError('libsodium error (possibly due to invalid input)')

            return buf

        def crypto_scalarmult_ristretto255_base_allow_scalar_zero(buf, s):
            """
            Variant of scalar-point multiplication function that permits
            a scalar corresponding to the zero residue.
            """
            r = _sodium.crypto_scalarmult_ristretto255_base(buf, s)

            if (1 - _zero(s)) * int(r == -1):
                raise RuntimeError('libsodium error (possibly due to invalid input)')

            return buf

        setattr(
            _sodium,
            'crypto_scalarmult_ristretto255_allow_scalar_zero',
            crypto_scalarmult_ristretto255_allow_scalar_zero
        )
        setattr(
            _sodium,
            'crypto_scalarmult_ristretto255_base_allow_scalar_zero',
            crypto_scalarmult_ristretto255_base_allow_scalar_zero
        )

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
        Wrapper class for binary implementations of primitive
        operations.

        When this module is imported, it makes a number of attempts
        to locate an instance of the shared/dynamic library file of the
        `libsodium <https://doc.libsodium.org>`__ library on the host
        system. The sequence of attempts is listed below, in order.

        1. It uses ``ctypes.util.find_library`` to look for ``'sodium'``
           or ``'libsodium'``.

        2. It attempts to find a file ``libsodium.so`` or ``libsodium.dll``
           in the paths specified by the ``PATH`` and ``LD_LIBRARY_PATH``
           environment variables.

        3. If the `rbcl <https://pypi.org/project/rbcl>`__ package is
           installed, it reverts to the compiled subset of libsodium
           included in that package.

        If all of the above fail, then :obj:`sodium` is assigned
        the value ``None`` and all functions and class methods exported by
        this module default to their pure-Python variants (*i.e.*, those
        encapsulated within :obj:`native <native>`). One way to confirm
        that a dynamic/shared library *has not been found* when this module
        is imported is to evaluate `sodium is None`.

        If a shared/dynamic library file has been loaded successfully,
        this class encapsulates shared/dynamic library variants of all
        primitive operations and classes exported by this module:
        :obj:`sodium.scl <scl>`, :obj:`sodium.rnd <rnd>`,
        :obj:`sodium.inv <inv>`, :obj:`sodium.smu <smu>`,
        :obj:`sodium.pnt <pnt>`, :obj:`sodium.bas <bas>`,
        :obj:`sodium.mul <mul>`, :obj:`sodium.add <add>`,
        :obj:`sodium.sub <sub>`, :obj:`sodium.point <point>`,
        and :obj:`sodium.scalar <scalar>`.
        For example, you can perform addition of points using
        the point addition implementation found in the libsodium
        shared/dynamic library found on the host system.

        >>> p = sodium.pnt()
        >>> q = sodium.pnt()
        >>> sodium.add(p, q) == sodium.add(q, p)
        True

        Methods found in the shared/dynamic library variants of the
        :obj:`point` and :obj:`scalar` classes are wrappers for the
        shared/dynamic library implementations of the underlying
        operations.

        >>> p = sodium.point()
        >>> q = sodium.point()
        >>> p + q == q + p
        True

        Nevertheless, all bytes-like objects, :obj:`point` objects,
        and :obj:`scalar` objects accepted and emitted by the various
        operations and class methods in :obj:`sodium` and compatible
        with those accepted and emitted by the operations and class
        methods in :obj:`native`.
        """
        _lib = _sodium
        _call_unwrapped = _call_variant_unwrapped
        _call_wrapped = _call_variant_wrapped
        _call = _call_variant

        @staticmethod
        def rnd() -> bytes:
            """
            Return random non-zero scalar.

            >>> len(rnd())
            32
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_random
            )

        @classmethod
        def scl(cls, s: bytes = None) -> Optional[bytes]:
            """
            Return supplied byte vector if it is a valid scalar; otherwise, return
            ``None``. If no byte vector is supplied, return a random scalar.

            >>> s = scl()
            >>> t = scl(s)
            >>> s == t
            True
            >>> scl(bytes([255] * 32)) is None
            True
            """
            if s is None:
                return cls.rnd()

            s = bytearray(s)
            s[-1] &= 0x1f

            return bytes(s) if _sc25519_is_canonical(s) else None

        @staticmethod
        def inv(s: bytes) -> bytes:
            """
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scl()
            >>> p = pnt()
            >>> mul(inv(s), mul(s, p)) == p
            True
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_invert,
                bytes(s)
            )

        @staticmethod
        def smu(s: bytes, t: bytes) -> bytes:
            """
            Return scalar multiplied by another scalar.

            >>> s = scl()
            >>> t = scl()
            >>> smu(s, t) == smu(t, s)
            True
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_mul,
                bytes(s), bytes(t)
            )

        @staticmethod
        def pnt(h: bytes = None) -> bytes:
            """
            Return point from 64-byte vector (normally obtained via hashing).

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()
            '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_bytes(),
                sodium._lib.crypto_core_ristretto255_from_hash,
                bytes(
                    hashlib.sha512(sodium.rnd()).digest() if h is None else h
                )
            )

        @staticmethod
        def bas(s: bytes) -> bytes:
            """
            Return base point multiplied by supplied scalar.

            >>> bas(scalar.hash('123'.encode())).hex()
            '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_scalarmult_ristretto255_base_allow_scalar_zero,
                bytes(s)
            )

        @staticmethod
        def mul(s: bytes, p: bytes) -> bytes:
            """
            Multiply the point by the supplied scalar and return the result.

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> s = scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> mul(s, p).hex()
            '183a06e0fe6af5d7913afb40baefc4dd52ae718fee77a3a0af8777c89fe16210'
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_scalarmult_ristretto255_allow_scalar_zero,
                bytes(s), bytes(p)
            )

        @staticmethod
        def add(p: bytes, q: bytes) -> bytes:
            """
            Return sum of the supplied points.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> add(p, q).hex()
            '7076739c9df665d416e68b9512f5513bf1d0181a2aacefdeb1b7244528a4dd77'
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_add,
                bytes(p), bytes(q)
            )

        @staticmethod
        def sub(p: bytes, q: bytes) -> bytes:
            """
            Return result of subtracting second point from first point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sub(p, q).hex()
            '1a3199ca7debfe31a90171696d8bab91b99eb23a541b822a7061b09776e1046c'
            """
            return sodium._call(
                _sodium.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_sub,
                bytes(p), bytes(q)
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

except: # pylint: disable=W0702 # pragma: no cover
    # Exported symbol.
    sodium = None # pragma: no cover

#
# Dedicated point and scalar data structures derived from `bytes`.
#

for _implementation in [native] + ([sodium] if sodium is not None else []):
    # pylint: disable=cell-var-from-loop
    class point(bytes): # pylint: disable=E0102
        """
        Class for representing a point. Because this class is derived from
        :obj:`bytes`, it inherits methods such as :obj:`bytes.hex` and
        :obj:`bytes.fromhex`.

        >>> len(point.random())
        32
        >>> p = point.hash('123'.encode())
        >>> p.hex()
        '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
        >>> point.fromhex(p.hex()) == p
        True
        """
        _implementation = _implementation

        @classmethod
        def zero(cls) -> point:
            """
            Return the additive identity for points.

            >>> z = point.zero()
            >>> p = point()
            >>> z + p == p
            True
            """
            return bytes.__new__(cls, bytes(32))

        @classmethod
        def random(cls) -> point:
            """
            Return random point object.

            >>> len(point.random())
            32
            """
            return bytes.__new__(cls, cls._implementation.pnt())

        @classmethod
        def from_bytes(cls, bs: bytes) -> point:
            """
            Return point object obtained by transforming supplied bytes-like object.

            >>> p = point.from_bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()
            '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
            """
            return bytes.__new__(cls, cls._implementation.pnt(bs))

        @classmethod
        def hash(cls, bs: bytes) -> point:
            """
            Return point object by hashing supplied bytes-like object.

            >>> point.hash('123'.encode()).hex()
            '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
            """
            return bytes.__new__(cls, cls._implementation.pnt(hashlib.sha512(bs).digest()))

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> point.from_base64('hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik=').hex()
            '86855a2aade8225c449dd3f636abf745d6e68aee228a7644e88c28fa470a0229'
            """
            return bytes.__new__(cls, base64.standard_b64decode(s))

        @classmethod
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar if the scalar is valid;
            otherwise, return ``None``.

            >>> point.base(scalar.hash('123'.encode())).hex()
            '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'

            Use of the scalar corresponding to the zero residue is permitted.

            >>> point.base(scalar.from_int(0)) == point.zero()
            True
            """
            return bytes.__new__(cls, cls._implementation.bas(s))

        def __new__(cls, bs: bytes = None) -> point:
            """
            If a bytes-like object is supplied, return a point object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, return a random point
            object.

            >>> bs = bytes.fromhex(
            ...     '86855a2aade8225c449dd3f636abf745d6e68aee228a7644e88c28fa470a0229'
            ... )
            >>> point(bs).hex()
            '86855a2aade8225c449dd3f636abf745d6e68aee228a7644e88c28fa470a0229'
            >>> len(point())
            32
            """
            return bytes.__new__(cls, bs) if bs is not None else cls.random()

        def __mul__(self: point, other: Any) -> NoReturn:
            """
            Use of this method is not permitted. A point cannot be a left-hand argument.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError('point must be on right-hand side of multiplication operator')

        def __rmul__(self: point, other: scalar) -> Optional[point]:
            """
            Multiply this point by the supplied scalar and return the result.

            >>> p = point.hash('123'.encode())
            >>> s = scalar.hash('456'.encode())
            >>> (s * p).hex()
            'f61b377aa86050aaa88c90f4a4a0f1e36b0000cf46f6a34232c2f1da7a799f16'

            Multiplying a point by the scalar corresponding to the zero residue
            yields the additive identity point.

            >>> scalar.from_int(0) * point() == point.zero()
            True
            """
            return self._implementation.point(self._implementation.mul(other, self))

        def __add__(self: point, other: point) -> Optional[point]:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()
            '7076739c9df665d416e68b9512f5513bf1d0181a2aacefdeb1b7244528a4dd77'
            >>> p + point.zero() == p
            True
            """
            return self._implementation.point(self._implementation.add(self, other))

        def __sub__(self: point, other: point) -> Optional[point]:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).hex()
            '1a3199ca7debfe31a90171696d8bab91b99eb23a541b822a7061b09776e1046c'
            >>> p - p == point.zero()
            True
            """
            return self._implementation.point(self._implementation.sub(self, other))

        def to_bytes(self: point) -> bytes:
            """
            Return the bytes-like object that represents this instance.

            >>> p = point()
            >>> p.to_bytes() == p
            True
            """
            return bytes(self)

        def to_base64(self: point) -> str:
            """
            Return the Base64 UTF-8 string representation of this instance.

            >>> p = point.from_base64('hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik=')
            >>> p.to_base64()
            'hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik='
            """
            return base64.standard_b64encode(self).decode('utf-8')

    class scalar(bytes):
        """
        Class for representing a scalar. Because this class is derived from
        :obj:`bytes`, it inherits methods such as :obj:`bytes.hex` and
        :obj:`bytes.fromhex`.

        >>> len(scalar.random())
        32
        >>> s = scalar.hash('123'.encode())
        >>> s.hex()
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27a03'
        >>> scalar.fromhex(s.hex()) == s
        True
        """
        _implementation = _implementation

        @classmethod
        def random(cls) -> scalar:
            """
            Return random non-zero scalar object.

            >>> len(scalar.random())
            32
            """
            return bytes.__new__(cls, cls._implementation.rnd())

        @classmethod
        def from_bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return scalar object obtained by transforming supplied bytes-like
            object if it is possible to do; otherwise, return ``None``.

            >>> s = scl()
            >>> t = scalar.from_bytes(s)
            >>> s.hex() == t.hex()
            True
            """
            s = cls._implementation.scl(bs)
            return bytes.__new__(cls, s) if s is not None else None

        @classmethod
        def hash(cls, bs: bytes) -> scalar:
            """
            Return scalar object by hashing supplied bytes-like object.

            >>> scalar.hash('123'.encode()).hex()
            'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27a03'
            """
            h = hashlib.sha256(bs).digest()
            s = cls._implementation.scl(h)
            while s is None:
                h = hashlib.sha256(h).digest()
                s = cls._implementation.scl(h)
            return bytes.__new__(cls, s)

        @classmethod
        def from_int(cls, i: int) -> scalar:
            """
            Construct an instance from its integer (*i.e.*, residue) representation.

            >>> p = point()
            >>> zero = scalar.from_int(0)
            >>> zero * p == point.zero()
            True
            >>> one = scalar.from_int(1)
            >>> one * p == p
            True
            >>> two = scalar.from_int(2)
            >>> two * p == p + p
            True

            Negative integers are supported (and automatically converted into their
            corresponding least nonnegative residues).

            >>> q = point()
            >>> p - p == scalar.from_int(0) * p
            True
            >>> q - p - p == q + (scalar.from_int(-2) * p)
            True
            """
            return bytes.__new__(
                cls,
                (
                    i % (pow(2, 252) + 27742317777372353535851937790883648493)
                ).to_bytes(32, 'little')
            )

        @classmethod
        def from_base64(cls, s: str) -> scalar:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()
            '312d0c9130f69153bec9f5d0386a95135eb45eebf130af5f1fed1c6ed15f2500'
            """
            return bytes.__new__(cls, base64.standard_b64decode(s))

        def __new__(cls, bs: bytes = None) -> scalar:
            """
            If a bytes-like object is supplied, return a scalar object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            scalar). If no argument is supplied, return a random scalar
            object.

            >>> s = scl()
            >>> t = scalar(s)
            >>> s.hex() == t.hex()
            True
            >>> len(scalar())
            32
            """
            return bytes.__new__(cls, bs) if bs is not None else cls.random()

        def __invert__(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scalar()
            >>> p = point()
            >>> ((~s) * (s * p)) == p
            True

            The scalar corresponding to the zero residue cannot be inverted.

            >>> ~scalar.from_int(0)
            Traceback (most recent call last):
              ...
            ValueError: cannot invert scalar corresponding to zero
            """
            if _zero(self):
                raise ValueError('cannot invert scalar corresponding to zero')

            return self._implementation.scalar(self._implementation.inv(self))

        def inverse(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scalar()
            >>> p = point()
            >>> ((s.inverse()) * (s * p)) == p
            True

            The scalar corresponding to the zero residue cannot be inverted.

            >>> scalar.from_int(0).inverse()
            Traceback (most recent call last):
              ...
            ValueError: cannot invert scalar corresponding to zero
            """
            if _zero(self):
                raise ValueError('cannot invert scalar corresponding to zero')

            return self._implementation.scalar(self._implementation.inv(self))

        def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point, None]:
            """
            Multiply supplied scalar or point by this scalar.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> p = point.from_base64('hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik=')
            >>> (s * s).hex()
            'd4aecf034f60edc5cb32cdd5a4be6d069959aa9fd133c51c9dcfd960ee865e0f'
            >>> isinstance(s * s, scalar)
            True
            >>> (s * p).hex()
            '2208082412921a67f42ea399748190d2b889228372509f2f2d9929813d074e1b'
            >>> isinstance(s * p, point)
            True

            Multiplying any point or scalar by the scalar corresponding to the
            zero residue yields the point or scalar corresponding to zero.

            >>> scalar.from_int(0) * point() == point.zero()
            True
            >>> scalar.from_int(0) * scalar() == scalar.from_int(0)
            True
            """
            if (
                isinstance(other, native.scalar) or
                (sodium is not None and isinstance(other, sodium.scalar))
            ):
                return self._implementation.scalar(self._implementation.smu(self, other))

            return self._implementation.point(self._implementation.mul(self, other))

        def __rmul__(self: scalar, other: Union[scalar, point]):
            """
            A scalar cannot be on the right-hand side of a non-scalar.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError('scalar must be on left-hand side of multiplication operator')

        def __int__(self: scalar) ->  int:
            """
            Return the integer (*i.e.*, least nonnegative residue) representation
            of this instance.

            >>> s = scalar()
            >>> int(s * (~s))
            1
            """
            return int.from_bytes(self, 'little')

        def to_bytes(self: scalar) -> bytes:
            """
            Return the bytes-like object that represents this instance.

            >>> s = scalar()
            >>> s.to_bytes() == s
            True
            """
            return bytes(self)

        def to_base64(self: scalar) -> str:
            """
            Return the Base64 UTF-8 string representation of this instance.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> s.to_base64()
            'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
            """
            return base64.standard_b64encode(self).decode('utf-8')


    # Encapsulate classes for this implementation, regardless of which are
    # exported as the unqualified symbols.
    _implementation.point = point
    _implementation.scalar = scalar

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
