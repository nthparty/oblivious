"""
.. module:: bn254

This module exports a collection of primitive operations for working
with elliptic curve points and scalars, classes for representing points,
classes for representing scalars, and two wrapper classes/namespaces that
encapsulate pure Python and shared/dynamic library variants of the above.

* Under all conditions, the wrapper class :obj:`native` is defined and
  exports a pure Python variant of every operation and class method
  exported by this module as a whole.
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

from bn254.ecp2 import generator as get_base
from bn254.pair import e
# from bn254.bls import BLS_H as hash_to_point
from bn254 import big as bn
from bn254.ecp import ECp
from bn254.ecp2 import ECp2
from bn254.curve import r

#
# Use native Python implementations of primitives by default.
#

class native:
    @classmethod
    def scl(cls, s: bytes = None) -> Optional[bytes]:
        """
        Return supplied byte vector if it is a valid scalar; otherwise, return
        `None`. If no byte vector is supplied, return a random scalar.

        >>> s = scl()
        >>> t = scl(s)
        >>> s == t
        True
        >>> scl(bytes([255] * 32)) is None
        True
        """
        if s is None:
            return cls.rnd()

        s = int.from_bytes(s, byteorder='little')# % r

        if 0 < s < r:
            return int.to_bytes(s, 32, byteorder='little')

        return None

    @staticmethod
    def rnd() -> bytes:
        """
        Return random non-zero scalar.

        >>> len(rnd())
        32
        """
        return int.to_bytes(bn.rand(r), 32, byteorder='little')

    @staticmethod
    def inv(s: bytes) -> bytes:
        """
        Return inverse of scalar modulo ``l``.

        >>> s = scl()
        >>> p = pnt()
        >>> mul(inv(s), mul(s, p)) == p
        True
        """
        return int.to_bytes(
            bn.invmodp(int.from_bytes(
                s
                , byteorder='little'), r)
            , 32, byteorder='little')

    @staticmethod
    def smu(s: bytes, t: bytes) -> bytes:
        """
        Return scalar multiplied by another scalar.

        >>> s = scl()
        >>> t = scl()
        >>> smu(s, t) == smu(t, s)
        True
        """
        return int.to_bytes(
            bn.modmul(
                int.from_bytes(
                    s
                    , byteorder='little'),
                int.from_bytes(
                    t
                    , byteorder='little'), r)
            , 32, byteorder='little')

    @staticmethod
    def pnt(h: bytes = None) -> bytes:
        """
        Return point from 64-byte vector (normally obtained via hashing).

        >>> p = pnt(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()
        '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
        """
        h = hashlib.sha512(native.rnd()).digest() if h is None else h
        x = bn.from_bytes(h)
        p = ECp()
        while not p.set(x):
            x = x + 1
        return bytes(p.toBytes(1))

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
        s = int.from_bytes(s, byteorder='little')
        q = ECp()
        ECp.fromBytes(q, bytes(p))
        q = s * q
        return bytes(q.toBytes(1))

    @classmethod
    def bas(cls, s: bytes) -> bytes:
        """
        Return base point multiplied by supplied scalar.

        >>> bas(scalar.hash('123'.encode())).hex()
        '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'
        """

        return cls.mul(s, bytes(get_base().toBytes(1)))

    @staticmethod
    def par(p: bytes, q: bytes) -> bytes:
        """
        Pair a point with another point
        """
        q = (lambda x : (lambda y : (ECp.fromBytes(y, bytes(x)), y))(ECp())[1])(q)
        p = (lambda x : (lambda y : (ECp2.fromBytes(y, bytes(x)), y))(ECp2())[1])(p)
        return bytes(e(p, q).toBytes())



# Top-level best-effort synonyms.
scl = native.scl
rnd = native.rnd
inv = native.inv
smu = native.smu
pnt = native.pnt
bas = native.bas
mul = native.mul
# add = native.add
# sub = native.sub
par = native.par
_zero = lambda bs : bs == bytes([0]*32) or bs == bytes([0]*31+[1]+[0]*(384-32))

#
# Dedicated point and scalar data structures derived from `bytes`.
#

class point(bytes):
    """
    Class for a bytes-like object that corresponds to a point.
    """
    @classmethod
    def random(cls) -> point:
        """
        Return random point object.

        >>> len(point.random())
        32
        """
        return bytes.__new__(cls, native.pnt())

    @classmethod
    def bytes(cls, bs: bytes) -> point:
        """
        Return point object obtained by transforming supplied bytes-like object.

        >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()
        '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
        """
        return bytes.__new__(cls, native.pnt(bs))

    @classmethod
    def hash(cls, bs: bytes) -> point:
        """
        Return point object by hashing supplied bytes-like object.

        >>> point.hash('123'.encode()).hex()
        '047f39a6c6dd156531a25fa605f017d4bec13b0b6c42f0e9b641c8ee73359c5f'
        """
        return bytes.__new__(cls, native.pnt(hashlib.sha512(bs).digest()))

    @classmethod
    def base(cls, s: scalar) -> Optional[point]:
        """
        Return base point multiplied by supplied scalar
        if the scalar is valid; otherwise, return `None`.

        >>> point.base(scalar.hash('123'.encode())).hex()
        '4c207a5377f3badf358914f20b505cd1e2a6396720a9c240e5aff522e2446005'
        """
        p = native.bas(s)
        return None if _zero(p) else bytes.__new__(cls, p)

    @classmethod
    def from_base64(cls, s: str) -> point:
        """
        Convert Base64 UTF-8 string representation of a point to a point instance.

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

    def __mul__(self: point, other: point) -> Optional[point]:
        """
        Pair this point with a point in the complementary group and return the result.

        >>> p = point.hash('123'.encode())
        >>> s = scalar.hash('456'.encode())
        >>> (s * p).hex()
        'f61b377aa86050aaa88c90f4a4a0f1e36b0000cf46f6a34232c2f1da7a799f16'
        """
        p = native.par(other, self)
        return None if _zero(p) else native.point(p)

    def __rmul__(self: point, other: scalar) -> Optional[point]:
        """
        Multiply this point by the supplied scalar and return the result.

        >>> p = point.hash('123'.encode())
        >>> s = scalar.hash('456'.encode())
        >>> (s * p).hex()
        'f61b377aa86050aaa88c90f4a4a0f1e36b0000cf46f6a34232c2f1da7a799f16'
        """
        p = native.mul(other, self)
        return None if _zero(p) else native.point(p)

    def __add__(self: point, other: point) -> Optional[point]:
        """
        Return sum of this point and another point.

        >>> p = point.hash('123'.encode())
        >>> q = point.hash('456'.encode())
        >>> (p + q).hex()
        '7076739c9df665d416e68b9512f5513bf1d0181a2aacefdeb1b7244528a4dd77'
        """
        p = native.add(self, other)
        return None if _zero(p) else native.point(p)

    def __sub__(self: point, other: point) -> Optional[point]:
        """
        Return the result of subtracting another point from this point.

        >>> p = point.hash('123'.encode())
        >>> q = point.hash('456'.encode())
        >>> (p - q).hex()
        '1a3199ca7debfe31a90171696d8bab91b99eb23a541b822a7061b09776e1046c'
        """
        p = native.sub(self, other)
        return None if _zero(p) else native.point(p)

    def to_base64(self: point) -> str:
        """
        Convert to equivalent Base64 UTF-8 string representation.

        >>> p = point.from_base64('hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik=')
        >>> p.to_base64()
        'hoVaKq3oIlxEndP2Nqv3Rdbmiu4iinZE6Iwo+kcKAik='
        """
        return base64.standard_b64encode(self).decode('utf-8')

class scalar(bytes):
    """
    Class for a bytes-like object that corresponds to a scalar.
    """
    @classmethod
    def random(cls) -> scalar:
        """
        Return random non-zero scalar object.

        >>> len(scalar.random())
        32
        """
        return bytes.__new__(cls, native.rnd())

    @classmethod
    def bytes(cls, bs: bytes) -> Optional[scalar]:
        """
        Return scalar object obtained by transforming supplied bytes-like
        object if it is possible to do; otherwise, return `None`.

        >>> s = scl()
        >>> t = scalar.bytes(s)
        >>> s.hex() == t.hex()
        True
        """
        s = native.scl(bs)
        return bytes.__new__(cls, s) if s is not None else None

    @classmethod
    def hash(cls, bs: bytes) -> scalar:
        """
        Return scalar object by hashing supplied bytes-like object.

        >>> scalar.hash('123'.encode()).hex()
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27a03'
        """
        h = hashlib.sha256(bs).digest()
        s = native.scl(h)
        while s is None:
            h = hashlib.sha256(h).digest()
            s = native.scl(h)
        return bytes.__new__(cls, s)

    @classmethod
    def from_base64(cls, s: str) -> scalar:
        """
        Convert Base64 UTF-8 string representation of a scalar to a scalar instance.

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
        """
        return native.scalar(native.inv(self))

    def inverse(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        ``2**252 + 27742317777372353535851937790883648493``.

        >>> s = scalar()
        >>> p = point()
        >>> ((s.inverse()) * (s * p)) == p
        True
        """
        return native.scalar(native.inv(self))

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
        """
        if isinstance(other, native.scalar) or\
           (sodium is not None and isinstance(other, sodium.scalar)):
            return native.scalar(native.smu(self, other))
        p = native.mul(self, other)
        # return None if _zero(p) else native.point(p)
        return native.point(p)

    # def __rmul__(self: scalar, other: point):
    #     """
    #     Use of this method is not permitted. A point cannot be a left-hand argument.

    #     >>> point() * scalar()
    #     Traceback (most recent call last):
    #       ...
    #     TypeError: point must be on right-hand side of multiplication operator
    #     """
    #     raise TypeError('point must be on right-hand side of multiplication operator')

    def __rmul__(self: scalar, other: Union[scalar, point]):
        """
        A scalar cannot be on the right-hand side of a non-scalar.

        >>> point() * scalar()
        Traceback (most recent call last):
          ...
        TypeError: point must be on right-hand side of multiplication operator
        """
        raise TypeError('scalar must be on left-hand side of multiplication operator')

    def to_base64(self: scalar) -> str:
        """
        Convert to equivalent Base64 UTF-8 string representation.

        >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> s.to_base64()
        'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
        """
        return base64.standard_b64encode(self).decode('utf-8')

# Encapsulate classes that use pure Python implementations for methods.
native.point = point
native.scalar = scalar

sodium = None

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
