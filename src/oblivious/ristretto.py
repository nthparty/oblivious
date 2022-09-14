"""
.. module:: ristretto

ristretto module
================

This module exports the classes :obj:`~oblivious.ristretto.point` and
:obj:`~oblivious.ristretto.scalar` for representing points and scalars. It
also exports the two wrapper classes/namespaces
:obj:`~oblivious.ristretto.python` and :obj:`~oblivious.ristretto.sodium`
that encapsulate pure-Python and shared/dynamic library variants of the
above (respectively) and also include low-level operations that correspond
more directly to the functions found in the underlying libraries.

* Under all conditions, the wrapper class :obj:`~oblivious.ristretto.python`
  is defined and encapsulates a pure-Python variant of every class exported
  by this module as a whole. It also includes pure-Python variants of low-level
  operations that correspond to functions found in the underlying libraries.

* If a shared/dynamic library instance of the
  `libsodium <https://doc.libsodium.org>`__ library is found on the system
  (and successfully loaded at the time this module is imported) or the
  optional `rbcl <https://pypi.org/project/rbcl>`__ package is installed,
  then the wrapper class :obj:`~oblivious.ristretto.sodium` is defined.
  Otherwise, the exported variable ``sodium`` is assigned ``None``.

* If a dynamic/shared library instance is loaded, all classes exported by
  this module correspond to the variants defined within
  :obj:`~oblivious.ristretto.sodium`. Otherwise, they correspond to the
  variants defined within :obj:`~oblivious.ristretto.python`.

For most users, the classes :obj:`~oblivious.ristretto.point` and
:obj:`~oblivious.ristretto.scalar` should be sufficient. When using the
low-level operations that correspond to a specific implementation (*e.g.*,
:obj:`oblivious.ristretto.sodium.add`), users are responsible for ensuring
that inputs have the type and/or representation appropriate for that
operation.
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
# is found, only pure-Python implementations of the functions and methods
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
# Use pure-Python implementations of primitives by default.
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

class python:
    """
    Wrapper class for pure-Python implementations of primitive operations.

    This class encapsulates pure-Python variants of all low-level operations
    and of both classes exported by this module:
    :obj:`python.scl <scl>`, :obj:`python.rnd <rnd>`,
    :obj:`python.inv <inv>`, :obj:`python.smu <smu>`,
    :obj:`python.pnt <pnt>`, :obj:`python.bas <bas>`,
    :obj:`python.can <can>`, :obj:`python.mul <mul>`,
    :obj:`python.add <add>`, :obj:`python.sub <sub>`,
    :obj:`python.neg <neg>`,
    :obj:`python.point <oblivious.ristretto.python.point>`, and
    :obj:`python.scalar <oblivious.ristretto.python.scalar>`.
    For example, you can perform addition of points using
    the pure-Python point addition implementation.

    >>> p = python.pnt()
    >>> q = python.pnt()
    >>> python.add(p, q) == python.add(q, p)
    True

    Pure-Python variants of the :obj:`python.point <point>` and
    :obj:`python.scalar <scalar>` classes always employ pure-Python
    implementations of operations when their methods are invoked.

    >>> p = python.point()
    >>> q = python.point()
    >>> p + q == q + p
    True

    Nevertheless, all bytes-like objects, :obj:`point` objects, and
    :obj:`scalar` objects accepted and emitted by the various operations and
    class methods in :obj:`python` are compatible with those accepted and
    emitted by the operations and class methods in :obj:`sodium`.
    """
    @staticmethod
    def pnt(h: bytes = None) -> bytes:
        """
        Return point from 64-byte vector (normally obtained via hashing).

        >>> p = python.pnt(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()
        '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
        """
        return ge25519.ge25519_p3.from_hash_ristretto255(
            hashlib.sha512(python.rnd()).digest() if h is None else h
        )

    @staticmethod
    def bas(s: bytes) -> bytes:
        """
        Return base point multiplied by supplied scalar.

        >>> python.bas(scalar.hash('123'.encode())).hex()
        '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'
        """
        t = bytearray(s)
        t[31] &= 127

        return ge25519.ge25519_p3.scalar_mult_base(t).to_bytes_ristretto255()

    @staticmethod
    def can(p: bytes) -> bytes:
        """
        Normalize the representation of a point into its canonical form.

        >>> p = point.hash('123'.encode())
        >>> python.can(p) == p
        True
        """
        return p # In this module, the canonical representation is used at all times.

    @staticmethod
    def mul(s: bytes, p: bytes) -> bytes:
        """
        Multiply the point by the supplied scalar and return the result.

        >>> p = python.pnt(hashlib.sha512('123'.encode()).digest())
        >>> s = python.scl(bytes.fromhex(
        ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
        ... ))
        >>> python.mul(s, p).hex()
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
        >>> python.add(p, q).hex()
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
        >>> python.sub(p, q).hex()
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

    @staticmethod
    def neg(p: bytes) -> bytes:
        """
        Return the additive inverse of a point.

        >>> p = point.hash('123'.encode())
        >>> q = point.hash('456'.encode())
        >>> python.add(python.neg(p), python.add(p, q)) == q
        True
        """
        return python.sub(bytes(32), p)

    @staticmethod
    def rnd() -> bytes:
        """
        Return random non-zero scalar.

        >>> len(python.rnd())
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

        >>> s = python.scl()
        >>> t = python.scl(s)
        >>> s == t
        True
        >>> python.scl(bytes([255] * 32)) is None
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
        Return the inverse of a scalar (modulo
        ``2**252 + 27742317777372353535851937790883648493``).

        >>> s = python.scl()
        >>> p = python.pnt()
        >>> python.mul(python.inv(s), python.mul(s, p)) == p
        True
        """
        return _sc25519_invert(s)

    @staticmethod
    def smu(s: bytes, t: bytes) -> bytes:
        """
        Return scalar multiplied by another scalar.

        >>> s = python.scl()
        >>> t = python.scl()
        >>> python.smu(s, t) == python.smu(t, s)
        True
        """
        return _sc25519_mul(s, t)

#
# Attempt to load primitives from libsodium, if it is present;
# otherwise, use the rbcl library, if it is present. Otherwise,
# silently assign ``None`` to ``sodium``.
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

        def _crypto_scalarmult_ristretto255_allow_scalar_zero(buf, s, p):
            """
            Variant of scalar-point multiplication function that permits
            a scalar corresponding to the zero residue.
            """
            r = _sodium.crypto_scalarmult_ristretto255(buf, s, p)

            if (1 - _zero(s)) * int(r == -1):
                raise RuntimeError('libsodium error (possibly due to invalid input)')

            return buf

        def _crypto_scalarmult_ristretto255_base_allow_scalar_zero(buf, s):
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
            _crypto_scalarmult_ristretto255_allow_scalar_zero
        )
        setattr(
            _sodium,
            'crypto_scalarmult_ristretto255_base_allow_scalar_zero',
            _crypto_scalarmult_ristretto255_base_allow_scalar_zero
        )

    # Ensure the chosen version of libsodium (or its substitute) has the
    # necessary primitives.
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
        Wrapper class for binary implementations of primitive operations.

        When this module is imported, it makes a number of attempts to
        locate an instance of the shared/dynamic library file of the
        `libsodium <https://doc.libsodium.org>`__ library on the host
        system. The sequence of attempts is listed below, in order.

        1. It uses ``ctypes.util.find_library`` to look for ``'sodium'`` or
        ``'libsodium'``.

        2. It attempts to find a file ``libsodium.so`` or ``libsodium.dll`` in
           the paths specified by the ``PATH`` and ``LD_LIBRARY_PATH``
           environment variables.

        3. If the `rbcl <https://pypi.org/project/rbcl>`__ package is
           installed, it reverts to the compiled subset of libsodium included
           in that package.

        If all of the above fail, then :obj:`sodium` is assigned the value
        ``None`` and all classes exported by this module default to their
        pure-Python variants (*i.e.*, those encapsulated within :obj:`python`).
        To confirm that a dynamic/shared library *has been found* when this
        module is imported, evaluate the expression ``sodium is not None``.

        If a shared/dynamic library file has been loaded successfully, this
        class encapsulates shared/dynamic library variants of both classes
        exported by this module and of all the underlying low-level operations:
        :obj:`sodium.scl <scl>`, :obj:`sodium.rnd <rnd>`,
        :obj:`sodium.inv <inv>`, :obj:`sodium.smu <smu>`,
        :obj:`sodium.pnt <pnt>`, :obj:`sodium.bas <bas>`,
        :obj:`sodium.can <can>`, :obj:`sodium.mul <mul>`,
        :obj:`sodium.add <add>`, :obj:`sodium.sub <sub>`,
        :obj:`sodium.neg <neg>`,
        :obj:`sodium.point <oblivious.ristretto.sodium.point>`, and
        :obj:`sodium.scalar <oblivious.ristretto.sodium.scalar>`.
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

        Nevertheless, all bytes-like objects, :obj:`point` objects, and
        :obj:`scalar` objects accepted and emitted by the various operations
        and class methods in :obj:`sodium` are compatible with those accepted
        and emitted by the operations and class methods in :obj:`python`.
        """
        _lib = _sodium
        _call_unwrapped = _call_variant_unwrapped
        _call_wrapped = _call_variant_wrapped
        _call = _call_variant

        @staticmethod
        def pnt(h: bytes = None) -> bytes:
            """
            Construct a point from its 64-byte vector representation (normally
            obtained via hashing).

            >>> p = sodium.pnt(hashlib.sha512('123'.encode()).digest())
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
            Return the base point multiplied by the supplied scalar.

            >>> sodium.bas(scalar.hash('123'.encode())).hex()
            '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_scalarmult_ristretto255_base_allow_scalar_zero,
                bytes(s)
            )

        @staticmethod
        def can(p: bytes) -> bytes:
            """
            Normalize the representation of a point into its canonical form.

            >>> p = point.hash('123'.encode())
            >>> sodium.can(p) == p
            True
            """
            # In this module, the canonical representation is used at all times.
            return p

        @staticmethod
        def mul(s: bytes, p: bytes) -> bytes:
            """
            Multiply a point by a scalar and return the result.

            >>> p = sodium.pnt(hashlib.sha512('123'.encode()).digest())
            >>> s = sodium.scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> sodium.mul(s, p).hex()
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
            Return the sum of the supplied points.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sodium.add(p, q).hex()
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
            Return the result of subtracting the right-hand point from the
            left-hand point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sodium.sub(p, q).hex()
            '1a3199ca7debfe31a90171696d8bab91b99eb23a541b822a7061b09776e1046c'
            """
            return sodium._call(
                _sodium.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_sub,
                bytes(p), bytes(q)
            )

        @staticmethod
        def neg(p: bytes) -> bytes:
            """
            Return the additive inverse of a point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sodium.add(sodium.neg(p), sodium.add(p, q)) == q
            True
            """
            return sodium.sub(bytes(32), p)

        @staticmethod
        def rnd() -> bytes:
            """
            Return random non-zero scalar.

            >>> len(sodium.rnd())
            32
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_random
            )

        @classmethod
        def scl(cls, s: bytes = None) -> Optional[bytes]:
            """
            Return supplied byte vector if it is a valid scalar; otherwise,
            return ``None``. If no byte vector is supplied, return a random
            scalar.

            >>> s = sodium.scl()
            >>> t = sodium.scl(s)
            >>> s == t
            True
            >>> sodium.scl(bytes([255] * 32)) is None
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
            Return the inverse of a scalar (modulo
            ``2**252 + 27742317777372353535851937790883648493``).

            >>> s = sodium.scl()
            >>> p = sodium.pnt()
            >>> sodium.mul(sodium.inv(s), sodium.mul(s, p)) == p
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
            Return the product of two scalars.

            >>> s = sodium.scl()
            >>> t = sodium.scl()
            >>> sodium.smu(s, t) == sodium.smu(t, s)
            True
            """
            return sodium._call(
                sodium._lib.crypto_core_ristretto255_scalarbytes(),
                sodium._lib.crypto_core_ristretto255_scalar_mul,
                bytes(s), bytes(t)
            )

except: # pylint: disable=W0702 # pragma: no cover
    # Exported symbol.
    sodium = None # pragma: no cover

#
# Dedicated point and scalar data structures derived from `bytes`.
#

for _implementation in [python] + ([sodium] if sodium is not None else []):
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
        def random(cls) -> point:
            """
            Return random point object.

            >>> len(point.random())
            32
            """
            return bytes.__new__(cls, cls._implementation.pnt())

        @classmethod
        def bytes(cls, bs: bytes) -> point:
            """
            Return the point object obtained by transforming the supplied
            bytes-like object.

            >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
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
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar if the scalar is valid;
            otherwise, return ``None``.

            >>> point.base(scalar.hash('123'.encode())).hex()
            '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'

            Use of the scalar corresponding to the zero residue is permitted.

            >>> p = point()
            >>> point.base(scalar.from_int(0)) + p == p
            True
            """
            return bytes.__new__(cls, cls._implementation.bas(s))

        @classmethod
        def from_bytes(cls, bs: bytes) -> point:
            """
            Return the instance corresponding to the supplied bytes-like object.

            >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p == point.from_bytes(p.to_bytes())
            True
            """
            return bytes(bs)

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> point.from_base64('hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik=').hex()
            '86855a2aade8225c449dd3f636abf745d6e68aee228a7644e88c28fa470a0229'
            """
            return bytes.__new__(cls, base64.standard_b64decode(s))

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

        def canonical(self: point) -> point:
            """
            Normalize the representation of this instance into its canonical form.

            >>> p = point.hash('123'.encode())
            >>> p.canonical() == p
            True
            """
            # In this module, the canonical representation is used at all times.
            return self

        def __mul__(self: point, other: Any) -> NoReturn:
            """
            A point cannot be a left-hand argument for a multiplication operation.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError('point must be on right-hand side of multiplication operator')

        def __rmul__(self: point, other: Any) -> NoReturn:
            """
            This functionality is implemented exclusively in the method
            :obj:`scalar.__mul__`, as that method pre-empts this method
            when the second argument has the correct type (*i.e.*, it is
            a :obj:`scalar` instance). This method is included so that an
            exception can be raised if an incorrect argument is supplied.

            >>> p = point.hash('123'.encode())
            >>> 2 * p
            Traceback (most recent call last):
              ...
            TypeError: point can only be multiplied by a scalar
            """
            raise TypeError('point can only be multiplied by a scalar')

        def __add__(self: point, other: point) -> Optional[point]:
            """
            Return the sum of this instance and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()
            '7076739c9df665d416e68b9512f5513bf1d0181a2aacefdeb1b7244528a4dd77'
            >>> p + (q - q) == p
            True
            """
            return self._implementation.point(self._implementation.add(self, other))

        def __sub__(self: point, other: point) -> Optional[point]:
            """
            Return the result of subtracting another point from this instance.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).hex()
            '1a3199ca7debfe31a90171696d8bab91b99eb23a541b822a7061b09776e1046c'
            >>> p - p == point.base(scalar.from_int(0))
            True
            """
            return self._implementation.point(self._implementation.sub(self, other))

        def __neg__(self: point) -> point:
            """
            Return the negation of this instance.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> ((p + q) + (-q)) == p
            True
            """
            return (self - self) - self

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
        def bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return scalar object obtained by transforming supplied bytes-like
            object if it is possible to do; otherwise, return ``None``.

            >>> s = python.scl()
            >>> t = scalar.bytes(s)
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
            >>> zero * p == p - p
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
        def from_bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return the instance corresponding to the supplied bytes-like object.

            >>> s = python.scl()
            >>> t = scalar.from_bytes(s)
            >>> s.hex() == t.hex()
            True
            """
            return cls(bs)

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

            >>> s = python.scl()
            >>> t = scalar(s)
            >>> s.hex() == t.hex()
            True
            >>> len(scalar())
            32
            """
            return bytes.__new__(cls, bs) if bs is not None else cls.random()

        def __invert__(self: scalar) -> scalar:
            """
            Return the inverse of this instance (modulo
            ``2**252 + 27742317777372353535851937790883648493``).

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

        def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point]:
            """
            Multiply the supplied scalar or point by this instance.

            >>> p = point.hash('123'.encode())
            >>> s = scalar.hash('456'.encode())
            >>> (s * p).hex()
            'f61b377aa86050aaa88c90f4a4a0f1e36b0000cf46f6a34232c2f1da7a799f16'
            >>> p = point.from_base64('hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik=')
            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
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

            >>> scalar.from_int(0) * point() == p - p
            True
            >>> scalar.from_int(0) * scalar() == scalar.from_int(0)
            True

            Any attempt to multiply a value or object of an incompatible type by this
            instance raises an exception.

            >>> s * 2
            Traceback (most recent call last):
              ...
            TypeError: multiplication by a scalar is defined only for scalars and points
            """
            if (
                isinstance(other, python.scalar) or
                (sodium is not None and isinstance(other, sodium.scalar))
            ):
                return self._implementation.scalar(self._implementation.smu(self, other))

            if (
                isinstance(other, python.point) or
                (sodium is not None and isinstance(other, sodium.point))
            ):
                return self._implementation.point(self._implementation.mul(self, other))

            raise TypeError(
                'multiplication by a scalar is defined only for scalars and points'
            )

        def __rmul__(self: scalar, other: Union[scalar, point]):
            """
            A scalar cannot be on the right-hand side of a non-scalar.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError(
                'scalar must be on left-hand side of multiplication operator'
            )

        def to_bytes(self: scalar) -> bytes:
            """
            Return the bytes-like object that represents this instance.

            >>> s = scalar()
            >>> s.to_bytes() == s
            True
            """
            return bytes(self)

        def __int__(self: scalar) ->  int:
            """
            Return the integer (*i.e.*, least nonnegative residue) representation
            of this instance.

            >>> s = scalar()
            >>> int(s * (~s))
            1
            """
            return int.from_bytes(self, 'little')

        def to_int(self: scalar) ->  int:
            """
            Return the integer (*i.e.*, least nonnegative residue) representation
            of this instance.

            >>> s = scalar()
            >>> (s * (~s)).to_int()
            1
            """
            return int(self)

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

# Redefine top-level wrapper classes to ensure that they appear at the end of
# the auto-generated documentation.
python = python # pylint: disable=self-assigning-variable
sodium = sodium # pylint: disable=self-assigning-variable

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
