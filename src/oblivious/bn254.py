"""
.. module:: bn254

bn254 module
============

This module exports the classes :obj:`~oblivious.bn254.point`,
:obj:`~oblivious.bn254.scalar`, :obj:`~oblivious.bn254.point2`,
and :obj:`~oblivious.bn254.scalar2` for representing points and scalars. It
also exports the two wrapper classes/namespaces :obj:`~oblivious.bn254.python`
and :obj:`~oblivious.bn254.mcl` that encapsulate pure-Python and shared/dynamic
library variants of the above (respectively) and also include low-level
operations that correspond more directly to the functions found in the
underlying libraries.

* Under all conditions, the wrapper class :obj:`~oblivious.bn254.python`
  is defined and encapsulates a pure-Python variant of class exported by this
  module as a whole. It also includes pure-Python variants of low-level
  operations that correspond to functions found in the underlying libraries.

* If the `mclbn256 <https://pypi.org/project/mclbn256>`__ package is installed
  (which includes a bundled copy of the `mcl <https://github.com/herumi/mcl>`__
  dynamic/shared libray), then the wrapper class :obj:`~oblivious.bn254.mcl`
  is defined. Otherwise, the exported variable ``mcl`` is assigned ``None``.

* If the `mclbn256 <https://pypi.org/project/mclbn256>`__ package is installed,
  all classes exported by this module correspond to the variants defined in
  :obj:`~oblivious.bn254.mcl`. Otherwise, they correspond to the variants
  defined in :obj:`~oblivious.bn254.python`.

For most users, the classes :obj:`~oblivious.bn254.point`,
:obj:`~oblivious.bn254.scalar`, :obj:`~oblivious.bn254.point2`,
and :obj:`~oblivious.bn254.scalar2` should be sufficient.

When using the classes within :obj:`~oblivious.bn254.python` and/or
:obj:`~oblivious.bn254.mcl`, users should be aware that objects corresponding
to one implementation (*e.g.*, instances of :obj:`oblivious.bn254.mcl.point`)
are not compatible with instances corresponding to the other implementation
(*e.g.*, the methods of the :obj:`oblivious.bn254.python.point` class). When
using the primitive operations that correspond to a specific implementation
(*e.g.*, :obj:`oblivious.bn254.mcl.add`), users are responsible for ensuring
that inputs have the type and/or representation appropriate for that
operation's internal implementation.
"""
from __future__ import annotations
from typing import Any, NoReturn, Union, Optional
import doctest
import hashlib
import base64
import secrets
from bn254.ecp import generator as get_base
from bn254.ecp2 import generator as get_base2
from bn254 import big as bn, Fp12 as Fp12_, Fp as _Fp, Fp2 as _Fp2
from bn254.ecp import ECp as ECp_
from bn254.ecp2 import ECp2 as ECp2_
from bn254.curve import r

#
# An attempt will be made later to import mclbn256. If the mcl shared/dynamic
# library file bundled with mclbn256 does not load, only pure-Python
# implementations of the functions and methods will be available.
#

mclbn256 = None

#
# Use pure-Python implementations of primitives by default.
#

class _ECp(ECp_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    @classmethod
    def random(cls) -> _ECp:
        return cls(int(python.scalar.random()) * get_base())

    @classmethod
    def deserialize(cls, bs) -> _ECp:
        p_mod = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        d_inv = 0x1a7344bac91f117ea513ec0ed5682406b6c15140174d61b28b762ae9cf6d3b46
        decode = lambda ns: (int.from_bytes(ns, 'little') * d_inv) % p_mod
        x, y, z = decode(bs[:32]), decode(bs[32:64]), decode(bs[-32:])

        # Compute affine coordinates
        inv_z = bn.invmodp(z, p_mod)
        x = (x * inv_z) % p_mod
        y = (y * inv_z) % p_mod

        p = cls()
        assert p.setxy(x, y) or (x == 0 and y == 0)
        return p

    @classmethod
    def mapfrom(cls, bs) -> _ECp:
        # pylint: disable=unnecessary-direct-lambda-call
        p_mod = (
            (lambda x: x * (x * (x * ((36 * x) - 36) + 24) - 6) + 1)
            ((2 ** 62) + (2 ** 55) + 1)
        )
        while int.from_bytes(bs, 'little') >= p_mod:
            bs = hashlib.sha256(bs).digest()
            bs = bs[:-1] + bytes([bs[-1] & 0b00111111])

        x = int.from_bytes(bs, 'little')# % p_mod
        y = None
        while True:
            x3_2 = (pow(x, 3, p_mod) + 2) % p_mod
            if pow(x3_2, (p_mod - 1) // 2, p_mod) == 1:
                s = (p_mod-1) // 2
                n = 2
                while pow(n, (p_mod-1) // 2, p_mod) == -1 % p_mod:
                    n += 1
                y = pow(x3_2, (s + 1) // 2, p_mod)
                b = pow(x3_2, s, p_mod)
                g = pow(n, s, p_mod)
                r_ = 1
                while True:
                    t = b
                    m = 0
                    for m in range(r_):
                        if t == 1:
                            break
                        t = pow(t, 2, p_mod) # pragma: no cover
                    if m == 0:
                        break
                    gs = pow(g, 2**(r_ - m - 1), p_mod) # pragma: no cover
                    g = (gs * gs) % p_mod # pragma: no cover
                    y = (y * gs) % p_mod # pragma: no cover
                    b = (b * g) % p_mod # pragma: no cover
                    r_ = m # pragma: no cover
            if y is not None:
                # pylint: disable=invalid-unary-operand-type
                if y % 2 == 1:
                    y = -y
                break
            x += 1

        p = cls()
        assert p.setxy(x, y) or (x == 0 and y == 0)
        return p

    def __new__(cls, *args, **kwargs):
        p = ECp_.__new__(cls)
        _ECp.__init__(p, *args, **kwargs)
        return p

    def __init__(self, p=None):
        ECp_.__init__(self)
        if isinstance(p, (ECp_, _ECp)):
            self.setxy(*p.get())
        elif isinstance(p, python.point):
            self.setxy(*_ECp.deserialize(p).get()) # pragma: no cover

    def serialize(self) -> bytes:
        d = 0x212ba4f27ffffff5a2c62effffffffcdb939ffffffffff8a15ffffffffffff8e
        p = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        x, y, z = (*self.get(), 1)
        encode = lambda n: (n * d % p).to_bytes(32, 'little')
        return encode(x) + encode(y) + encode(z)

class _ECp2(ECp2_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    @classmethod
    def random(cls) -> _ECp2:
        return cls(int(python.scalar.random()) * get_base2())

    @classmethod
    def deserialize(cls, bs) -> _ECp2:
        p_mod = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        d_inv = 0x1a7344bac91f117ea513ec0ed5682406b6c15140174d61b28b762ae9cf6d3b46
        decode = lambda ns: (int.from_bytes(ns, 'little') * d_inv) % p_mod
        x1, y1, x2, y2, z1, z2 = (decode(bs[:32]), decode(bs[32:64]), decode(bs[64:64+32]),
                                  decode(bs[64+32:128]), decode(bs[128:128+32]), decode(bs[-32:]))
        z2 = z2-(z2&1)+1  # 1 if z2==0 else z2

        # Compute affine coordinates
        inv_z1, inv_z2 = bn.invmodp(z1, p_mod), bn.invmodp(z2, p_mod)
        x1, x2 = (x1 * inv_z1) % p_mod, (x2 * inv_z2) % p_mod
        y1, y2 = (y1 * inv_z1) % p_mod, (y2 * inv_z2) % p_mod

        q = cls()
        # pylint: disable=invalid-name
        assert q.set(_Fp2(_Fp(x1), _Fp(y1)), _Fp2(_Fp(x2), _Fp(y2))) \
               or (x1 == 0 and y1 == 0 and x2 == 0 and y2 == 0)
        return q

    @classmethod
    def mapfrom(cls, h) -> _ECp2:
        return cls((int.from_bytes(h, 'little') % r) * get_base2())

    def __new__(cls, *args, **kwargs):
        q = ECp2_.__new__(cls)
        _ECp2.__init__(q, *args, **kwargs)
        return q

    def __init__(self, q=None):
        ECp2_.__init__(self)
        if isinstance(q, (ECp2_, _ECp2)):
            self.set(*q.get())
        elif isinstance(q, python.point2):
            self.set(*_ECp2.deserialize(bytes(q)).get()) # pragma: no cover

    def serialize(self) -> bytes:
        d = 0x212ba4f27ffffff5a2c62effffffffcdb939ffffffffff8a15ffffffffffff8e

        # BN254 modulus of *F_p*.
        p = 0x2523648240000001ba344d80000000086121000000000013a700000000000013

        p1, p2 = (*self.get(),)
        x1, y1, z1, x2, y2, z2 = (*p1.get(), 1, *p2.get(), 0)

        encode = lambda n: (n * d % p).to_bytes(32, 'little')
        return encode(x1) + encode(y1) + encode(x2) + encode(y2) + encode(z1) + encode(z2)

class _Fp12(Fp12_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    @classmethod
    def deserialize(cls, bs) -> _Fp12:
        p_mod = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        d_inv = 0x1a7344bac91f117ea513ec0ed5682406b6c15140174d61b28b762ae9cf6d3b46
        decode = lambda ns: (int.from_bytes(ns, 'little') * d_inv) % p_mod
        s = _Fp12()
        s.a.a.a.x, s.a.a.b.x = decode(bs[32*0:(32*0)+32]), decode(bs[32*1:(32*1)+32])
        s.c.a.a.x, s.c.a.b.x = decode(bs[32*2:(32*2)+32]), decode(bs[32*3:(32*3)+32])
        s.b.b.a.x, s.b.b.b.x = decode(bs[32*4:(32*4)+32]), decode(bs[32*5:(32*5)+32])
        s.b.a.a.x, s.b.a.b.x = decode(bs[32*6:(32*6)+32]), decode(bs[32*7:(32*7)+32])
        s.a.b.a.x, s.a.b.b.x = decode(bs[32*8:(32*8)+32]), decode(bs[32*9:(32*9)+32])
        s.c.b.a.x, s.c.b.b.x = decode(bs[32*10:(32*10)+32]), decode(bs[32*11:(32*11)+32])
        return s

    def __new__(cls, *args, **kwargs):
        q = Fp12_.__new__(cls)
        _Fp12.__init__(q, *args, **kwargs)
        return q

    def __init__(self, s=None):
        Fp12_.__init__(self)
        if isinstance(s, (Fp12_, _Fp12)):
            self.set(*s.get())
        elif isinstance(s, python.scalar2):
            self.set(*_Fp12.deserialize(s).get()) # pragma: no cover

    def serialize(self) -> bytes:
        d = 0x212ba4f27ffffff5a2c62effffffffcdb939ffffffffff8a15ffffffffffff8e

        # BN254 modulus of *F_p*.
        p = 0x2523648240000001ba344d80000000086121000000000013a700000000000013

        encode = lambda n: (n * d % p).to_bytes(32, 'little')
        return bytes(
            encode(self.a.a.a.int()) + encode(self.a.a.b.int()) +
            encode(self.c.a.a.int()) + encode(self.c.a.b.int()) +
            encode(self.b.b.a.int()) + encode(self.b.b.b.int()) +
            encode(self.b.a.a.int()) + encode(self.b.a.b.int()) +
            encode(self.a.b.a.int()) + encode(self.a.b.b.int()) +
            encode(self.c.b.a.int()) + encode(self.c.b.b.int())
        )

class python:
    """
    Wrapper class for pure-Python implementations of primitive operations.

    This class encapsulates pure-Python variants of all classes exported by
    this module and of all the underlying low-level operations:
    :obj:`python.pnt <pnt>`, :obj:`python.bas <bas>`,
    :obj:`python.can <can>`, :obj:`python.ser <ser>`,
    :obj:`python.des <des>`, :obj:`python.mul <mul>`,
    :obj:`python.add <add>`, :obj:`python.sub <sub>`,
    :obj:`python.neg <neg>`, :obj:`python.par <par>`,
    :obj:`python.rnd <rnd>`, :obj:`python.scl <scl>`,
    :obj:`python.sse <sse>`, :obj:`python.sde <sde>`,
    :obj:`python.inv <inv>`, :obj:`python.smu <smu>`,
    :obj:`python.sad <sad>`, :obj:`python.ssu <ssu>`,
    :obj:`python.sne <sne>`,
    :obj:`python.pnt2 <pnt2>`, :obj:`python.bas2 <bas2>`,
    :obj:`python.can2 <can2>`, :obj:`python.ser2 <ser2>`,
    :obj:`python.des2 <des2>`, :obj:`python.mul2 <mul2>`,
    :obj:`python.add2 <add2>`, :obj:`python.sub2 <sub2>`,
    :obj:`python.neg2 <neg2>`,
    :obj:`python.rnd2 <rnd2>`, :obj:`python.scl2 <scl2>`,
    :obj:`python.sse2 <sse2>`, :obj:`python.sde2 <sde2>`,
    :obj:`python.inv2 <inv2>`, :obj:`python.smu2 <smu2>`,
    :obj:`python.sad2 <sad2>`,
    :obj:`python.point <oblivious.bn254.python.point>`,
    :obj:`python.scalar <oblivious.bn254.python.scalar>`,
    :obj:`python.point2 <oblivious.bn254.python.point2>`, and
    :obj:`python.scalar2 <oblivious.bn254.python.scalar2>`.
    For example, you can perform multiplication of scalars
    using the pure-Python scalar multiplication implementation.

    >>> s = python.scl()
    >>> t = python.scl()
    >>> python.smu(s, t) == python.smu(t, s)
    True

    Pure-Python variants of the :obj:`python.point <point>`
    and :obj:`python.scalar <scalar>` classes always employ pure
    Python implementations of operations when their methods are
    invoked.

    >>> p = python.scalar()
    >>> q = python.scalar()
    >>> p * q == q * p
    True
    """
    @staticmethod
    def pnt(h: Optional[bytes] = None) -> point:
        """
        Construct a point from its 64-byte vector representation (normally
        obtained via hashing).

        >>> p = python.pnt(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()[:64]
        '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
        """
        return bytes.__new__(
            python.point,
            (_ECp.random() if h is None else _ECp.mapfrom(h)).serialize()
        )

    @staticmethod
    def bas(s: scalar) -> point:
        """
        Return the base point multiplied by the supplied scalar.

        >>> bytes(python.bas(python.scalar.hash('123'.encode()))).hex()[:64]
        '2d66076815cda25556bab4a930244ac284412267e9345aceb98d71530308401a'
        """
        return s * python.point.from_base64(
            'hQAAAAAAAJGJAAAAAADnpzoAAACAHm4XDAAAwI+/9wO'
            'O////////FYr//////zm5zf////8uxqL1//9/8qQrIY'
            '7///////8Viv//////ObnN/////y7GovX//3/ypCsh'
        )

    @staticmethod
    def can(p: point) -> point:
        """
        Normalize the representation of a point into its canonical form
        and return the result.

        >>> a = python.point.hash('123'.encode())
        >>> p = python.add(a, a)
        >>> p_can = python.can(python.add(a, a))

        It may be the case that ``ser(p_can) != ser(p)``, depending on the
        implementation. It is the responsibility of the user to ensure
        that only canonical forms are serialized if those serialized forms
        must be compared.

        >>> mclbn256 = p.__class__ != python.point
        >>> (python.ser(p_can) != python.ser(p)) or not mclbn256
        True

        Normalization is idempotent.

        >>> python.can(p) == python.can(p_can)
        True
        """
        return p # This instance's coordinates are already in normal affine form.

    @staticmethod
    def ser(p: point) -> bytes:
        """
        Return the binary representation of a point.

        >>> q = python.point2.hash('123'.encode())
        >>> python.des(python.ser(q)) == q
        True
        """
        return bytes(b for b in p)

    @staticmethod
    def des(bs: bytes) -> point:
        """
        Construct a point corresponding to the supplied binary representation.

        >>> p = python.point.hash('123'.encode())
        >>> python.ser_p = bytes.fromhex(
        ...     '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
        ...     'b03c992ec97868be765b98048118a96f42bdc466a963c243c223b95196304209'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ... )
        >>> python.des(python.ser_p) == p
        True
        >>> python.ser(python.des(python.ser_p)) == python.ser_p
        True
        """
        # It may be useful to debug with ``_ECp.deserialize(bs).serialize()``
        # in place of just ``bs``.
        return bytes.__new__(python.point, bs)

    @staticmethod
    def mul(s: scalar, p: point) -> point:
        """
        Multiply a point by a scalar and return the result.

        >>> p = python.pnt(hashlib.sha512('123'.encode()).digest())
        >>> s = python.scl(bytes.fromhex(
        ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
        ... ))
        >>> python.mul(s, p).hex()[:64]
        '68b5dd61adaa83f1511efe7b4749481cc9f86e11bf82d82960b6c56373de0d24'
        """
        return bytes.__new__(python.point, _ECp(int(s) * _ECp.deserialize(p)).serialize())

    @staticmethod
    def add(p: point, q: point) -> point:
        """
        Return the sum of the supplied points.

        >>> p = python.point.hash('123'.encode())
        >>> q = python.point.hash('456'.encode())
        >>> python.point.to_bytes(python.add(p, q)).hex()[:64]
        '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
        >>> python.add(python.sub(p, q), q) == p
        True
        """
        return bytes.__new__(
            python.point,
            _ECp.serialize(_ECp.deserialize(p).add(_ECp.deserialize(q)))
        )

    @staticmethod
    def sub(p: point, q: point) -> point:
        """
        Return the result of subtracting the right-hand point from the
        left-hand point.

        >>> p = python.point.hash('123'.encode())
        >>> q = python.point.hash('456'.encode())
        >>> python.sub(p, q).hex()[:64]
        'a43a5ce1931b1300b62e5d7e1b0c691203bfd85fafd9585dc5e47a7e2acfea22'
        >>> python.sub(python.add(p, q), q) == p
        True
        """
        return bytes.__new__(
            python.point,
            _ECp.serialize(_ECp.deserialize(p).add(-1 * _ECp.deserialize(q)))
        )

    @staticmethod
    def neg(p: point) -> point:
        """
        Return the additive inverse of a point.

        >>> p = python.point.hash('123'.encode())
        >>> python.point.to_bytes(python.neg(p)).hex()[:64]
        '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
        """
        return bytes.__new__(python.point, _ECp.serialize(-1 * _ECp.deserialize(p)))

    @staticmethod
    def rnd() -> scalar:
        """
        Return random non-zero scalar.

        >>> isinstance(python.rnd(), python.scalar)
        True
        """
        # d = 0x212ba4f27ffffff5a2c62effffffffd00242ffffffffff9c39ffffffffffffb2
        # return int.to_bytes(((secrets.randbelow(r-1)+1) * d) % r, 32, 'little')

        return python.scalar(int.to_bytes(secrets.randbelow(r-1)+1, 32, 'little'))

    @classmethod
    def scl(cls, s: Union[bytes, bytearray, None] = None) -> Optional[scalar]:
        """
        Construct a scalar if the supplied bytes-like object represents
        a valid scalar; otherwise, return ``None``. If no byte vector is
        supplied, return a random scalar.

        >>> s = python.scl()
        >>> t = python.scl(s)
        >>> s == t
        True
        >>> python.scl(bytes([255] * 32)) is None
        True
        """
        if s is None:
            return python.rnd()

        if int.from_bytes(s, 'little') < r:
            return bytes.__new__(python.scalar, s)

        return None

    @staticmethod
    def sse(s: scalar) -> bytes:
        """
        Return the binary representation of a scalar.

        >>> s = python.scalar.hash('123'.encode())
        >>> python.sde(python.sse(s)) == s
        True
        """
        return bytes(b for b in s)

    @staticmethod
    def sde(bs: bytes) -> scalar:
        """
        Construct a scalar from its binary representation.

        >>> s = python.scalar.hash('123'.encode())
        >>> bs = bytes.fromhex(
        ...     '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
        ... )
        >>> python.sde(bs) == s
        True
        >>> python.sse(python.sde(bs)) == bs
        True
        """
        return bytes.__new__(python.scalar, bs)

    @staticmethod
    def inv(s: scalar) -> scalar:
        """
        Return the inverse of a scalar (modulo
        ``r = 16798108731015832284940804142231733909759579603404752749028378864165570215949``
        in the prime field `F*_r`).

        >>> s = python.scl()
        >>> p = python.pnt()
        >>> python.mul(python.inv(s), python.mul(s, p)) == p
        True
        """
        return python.scalar.from_int(bn.invmodp(int(s), r))

    @staticmethod
    def smu(s: scalar, t: scalar) -> scalar:
        """
        Return the product of two scalars.

        >>> s = python.scl()
        >>> t = python.scl()
        >>> python.smu(s, t) == python.smu(t, s)
        True
        """
        n = (python.scalar.__int__(s) * python.scalar.__int__(t)) % r
        return python.scalar.from_int(n)

    @staticmethod
    def sad(s: scalar, t: scalar) -> scalar:
        """
        Return the sum of two scalars.

        >>> s = python.scl()  # Could be `python.scl()`.
        >>> t = python.scl()
        >>> python.sad(s, t) == python.sad(t, s)
        True
        """
        return python.scalar.from_int((int(s) + int(t)) % r)

    @staticmethod
    def ssu(s: scalar, t: scalar) -> scalar:
        """
        Return the result of subtracting the right-hand scalar from the
        left-hand scalar.

        >>> s = python.scl()
        >>> t = python.scl()
        >>> python.ssu(s, t) == python.sad(s, python.sne(t))
        True
        >>> python.ssu(s, t) == python.sne(python.ssu(t, s))
        True
        """
        return python.scalar.from_int((int(s) - int(t)) % r)

    @staticmethod
    def sne(s: scalar) -> scalar:
        """
        Return the additive inverse of a scalar.

        >>> s = python.scl()
        >>> t = python.scl()
        >>> python.sne(python.sne(s)) == s
        True
        """
        return python.scalar.from_int(r - int(s))

    @staticmethod
    def pnt2(h: Optional[bytes] = None) -> point2:
        """
        Construct a second-level point if the supplied bytes-like object
        represents a valid second-level point; otherwise, return ``None``.
        If no byte vector is supplied, return a random second-level point.

        >>> p = python.pnt2(hashlib.sha512('123'.encode()).digest())
        >>> python.point2.to_bytes(p).hex()[:128] == (
        ...     '4c595542640a69c4a70bda55c27ef96c133cd1f4a5f83b3371e571960c018e19'
        ...     'c54aaec2069f8f10a00f12bcbb3511cdb7356201f5277ec5e47da91405be2809'
        ... )
        True
        """
        return bytes.__new__(
            python.point2,
            (_ECp2.random() if h is None else _ECp2.mapfrom(h)).serialize()
        )

    @staticmethod
    def bas2(s: scalar) -> point2:
        """
        Return the base second-level point multiplied by the supplied scalar.

        >>> bytes(python.bas2(python.scalar.hash('123'.encode()))).hex()[:64]
        'e7000fb12d206112c73fe1054e9d77b35c77881eba6598b7e035171d90b13e0c'
        """
        # return s * _ECp2.__new__(python.point2, get_base2())
        return bytes.__new__(python.point2, _ECp2(int(s) * get_base2()).serialize())

    @staticmethod
    def can2(p: point2) -> point2:
        """
        Normalize the representation of a second-level point into its canonical
        form and return the result.

        >>> p = python.bas2(scalar.from_int(1))
        >>> python.ser(python.can2(p)).hex()[:64]
        '669e6563afaa45af7cbc013d23f092bb3763d4dc41b97aef555bdf61de713f17'
        """
        return p # This instance's coordinates are already in normal affine form.

    @staticmethod
    def ser2(p: point2) -> bytes:
        """
        Return the binary representation of a second-level point.

        >>> p = python.point2.hash('123'.encode())
        >>> python.des2(python.ser2(p)) == p
        True

        It is the responsibility of the user to ensure that only canonical
        representations of points are serialized.
        """
        return bytes(b for b in p)

    @staticmethod
    def des2(bs: bytes) -> point2:
        """
        Return the second-level point corresponding to the supplied binary
        representation thereof.

        >>> p = python.point2.hash('123'.encode())
        >>> ser_p = bytes.fromhex(
        ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
        ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
        ...     '2c6a88bb448065eb748df632b1d872e02f54b6f56fdb84a7b1cb388fe551fb08'
        ...     '04464efa186bd4b1371e53d6f31f0e2f50ff553b6264a43331b42c976a0c541f'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        >>> python.des2(ser_p) == p
        True
        >>> python.ser(python.des2(ser_p)) == ser_p
        True
        """
        return bytes.__new__(python.point2, bs)
        # It may be useful to debug with _ECp2.deserialize(bs).serialize() in place of just bs.

    @staticmethod
    def mul2(s: scalar, p: point2) -> point2:
        """
        Multiply a second-level point by a scalar.

        >>> p = python.point2.hash('123'.encode())
        >>> s = python.scl(bytes.fromhex(
        ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
        ... ))
        >>> python.point2.to_bytes(python.mul2(s, p)).hex() == (
        ...     '5f6f2ace8566ca47354fbe244ae3e6a854c37011fb6d6ac56571c94169e4ab18'
        ...     '650bea4cfed5c9603e5949fe3d7509b17e20db4ff1f05129aad0d0a3bffb0008'
        ...     '3043c5a14b986882836b1c929952ea3881d04ca44d487d1ab2d4c0b171b87d14'
        ...     '5dca6dabb4f0ea7be5c95a861ed319d146b15d70542d3952af995a8bb35b8314'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(python.point2, _ECp2(int(s) * _ECp2.deserialize(p)).serialize())

    @staticmethod
    def add2(p: point2, q: point2) -> point2:
        """
        Return sum of the supplied second-level points.

        >>> p = python.point2.hash('123'.encode())
        >>> q = python.point2.hash('456'.encode())
        >>> python.point2.to_bytes(python.add2(p, q)).hex() == (
        ...     'cb0fc423c1bac2ac2df47bf5f5548a42b0d0a0da325bc77243d15dc587a7b221'
        ...     '9808a1649991ddf770f0060333aab4d499580b123f109b5cb180f1f8a75a090e'
        ...     '83dd34d9ecdd6fd639230f7f0cf44b218fae4d879111de6c6c037e6ffdcdc823'
        ...     'f5a48318143873ca90ad512a2ea1854200eea5537cd0ac93691d5b94ff36b212'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(
            python.point2,
            _ECp2(_ECp2.deserialize(p).add(_ECp2.deserialize(q))).serialize()
        )

    @staticmethod
    def sub2(p: point2, q: point2) -> point2:
        """
        Return the result of subtracting right-hand second-level point from the
        left-hand second-level point.

        >>> p = python.point2.hash('123'.encode())
        >>> q = python.point2.hash('456'.encode())
        >>> python.point2.to_bytes(python.sub2(p, q)).hex() == (
        ...     'e97a70c4e3a5369ebbb1dcf0cc1135c8c8e04a4ec7cffdf875ac429d66846d0b'
        ...     '191b090909c40a723027b07ac44435a6ade3813d04b3632a17c92c5c98718902'
        ...     '407c58ed13cc0c0aaa43d0eafd44080080c8199401fe4f8ed7dd0eb5fba86817'
        ...     '141f74341ce3c4884f86a97f51f7c0b208fe52be336b7651252fa9881c93d203'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(
            python.point2,
            _ECp2(_ECp2.deserialize(p).add(-1 * _ECp2.deserialize(q))).serialize()
        )

    @staticmethod
    def neg2(p: point2) -> point2:
        """
        Return the negation of a second-level point.

        >>> p = python.point2.hash('123'.encode())
        >>> python.point2.to_bytes(python.neg2(p)).hex() == (
        ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
        ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
        ...     'e7957744bb7f9abb9e7209cd4e27ae80d8ab490a1072af125034c7b09c12281c'
        ...     '0fbab105e7942bf5dbe1ac290ce01232b800aac41de98f86d04bd3a81758cf05'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(python.point2, _ECp2(-1 * _ECp2.deserialize(p)).serialize())

    @staticmethod
    def rnd2() -> scalar2:
        """
        Return random non-zero second-level scalar.

        >>> isinstance(python.rnd2(), python.scalar2)
        True
        """
        return python.scalar2.hash(secrets.token_bytes(384))

    @staticmethod
    def scl2(s: Union[bytes, bytearray, None] = None) -> Optional[scalar2]:
        """
        Construct a second-level scalar if the supplied bytes-like object
        represents a valid second-level scalar; otherwise, return ``None``.
        If no byte vector is supplied, return a random second-level scalar.

        >>> bs = bytes.fromhex(
        ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805'
        ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021'
        ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710'
        ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c'
        ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c'
        ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10'
        ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911'
        ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215'
        ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002'
        ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f'
        ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622'
        ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
        ... )
        >>> python.scalar2.to_bytes(python.scl2(bs)).hex()[700:]
        '36222db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
        """
        if s is None:
            return python.rnd2()

        try:
            return python.sde2(s)
        except ValueError: # pragma: no cover
            return None

    @staticmethod
    def sse2(s: scalar2) -> bytes:
        """
        Return the binary representation of a second-level scalar.

        >>> s = python.scalar2.hash('123'.encode())
        >>> python.sde2(python.sse2(s)) == s
        True
        """
        return bytes(b for b in s)

    @staticmethod
    def sde2(bs: bytes) -> scalar2:
        """
        Construct a second-level scalar from its binary representation.

        >>> s = python.scalar2.hash('123'.encode())
        >>> bs = bytes.fromhex(
        ...     '36980a8359d40e106075488e80cf1479f2e6ba95d6a99a67832d21b7b94d8c1d'
        ...     '5eb4d655f23e1d5d499d51d1c552b5e7df6943091427cd080f582e120613a021'
        ...     '85898ef7d016e47a74a8df62316cc4ad975cb64bb63867ed9b5221f77bb9a121'
        ...     '7bd89cd213eee0c3fdf2e0e13ef9e30383ea5607c8d13fc10e04448a6c964a00'
        ...     '04a098a55beab09732220966319333608b2187ee2196eb5b4253bc2b1aea5303'
        ...     '654260dd687a2eb176a494258ff7ef753f93105a6f0e9f46c926afdbe31ff124'
        ...     '6bdd87c32537abcdb46ad542792edd74a229c9ba61abcd993f074237a91f5215'
        ...     '8f6b07886895733edde15cb22129459162d89d3662826b74e4fcbe4e9e8c2420'
        ...     'bd53586a09f91ff8f67f92cba72c5b64a9c3965c01e93710200ab4e084955316'
        ...     'fb18950835b79fb4c2930efcc5fcaa9d82ee0faff036b80657daee233a445901'
        ...     '7df3e57cb535ed26162b3ee0f8961131a93fe3198dc5393d277ed8bac5532411'
        ...     '93b7ad15c52ca123fd26f592a2219b1bf118b3035893cc4abf614b422f978718'
        ... )
        >>> python.sde2(bs) == s
        True
        >>> python.sse(python.sde2(bs)) == bs
        True
        """
        return bytes.__new__(python.scalar2, bs)

    @staticmethod
    def inv2(s: scalar2) -> scalar2:
        """
        Return the inverse of a second-level scalar.

        >>> s = python.scl2()
        >>> python.smu2(s, python.smu2(s, python.inv2(s))) == s
        True
        >>> python.smu2(python.smu2(s, s), python.inv2(s)) == s
        True
        """
        return bytes.__new__(
            python.scalar2,
            _Fp12(_Fp12.deserialize(s).inverse()).serialize()
        )

    @staticmethod
    def smu2(s: scalar2, t: scalar2) -> scalar2:
        """
        Return second-level scalar multiplied by another scalar.

        >>> s = python.scalar2.random()
        >>> t = python.scalar2.random()
        >>> python.smu2(s, t) == python.smu2(t, s)
        True
        """
        return bytes.__new__(
            python.scalar2,
            _Fp12(_Fp12.deserialize(s) * _Fp12.deserialize(t)).serialize()
        )

    @staticmethod
    def sad2(s: scalar2, t: scalar2) -> scalar2:
        """
        Return scalar2 added to another scalar2.

        >>> s = python.scl2()
        >>> t = python.scl2()
        >>> python.sad2(s, t) == python.sad2(t, s)
        True
        """
        return bytes.__new__(
            python.scalar2,
            _Fp12(_Fp12.deserialize(s) + _Fp12.deserialize(t)).serialize()
        )

# Indicate that data structures based on the dynamic/shared library
# in mclbn256 have not (yet, at least) been defined.
mclbn256 = False

#
# Attempt to load primitives from mclbn256, if it is present;
# otherwise, use the mclbn256 library.
#

try:
    # Attempt to load mclbn256 with its (bundled) shared/dynamic library file.
    from mclbn256 import Fr, G1, G2, GT # pylint: disable=import-error

    # pylint: disable=C2801,W0621
    class mcl:
        """
        Wrapper class for binary implementations of primitive
        operations.

        When this module is imported, it makes a number of attempts
        to locate an instance of the shared/dynamic library file of the
        `mclbn256 <https://doc.mclbn256.org>`__ library on the host
        system. The sequence of attempts is listed below, in order.

        1. It uses ``ctypes.util.find_library`` to look for ``'mcl'``
           or ``'mclbn256'``.

        2. It attempts to find a file ``mclbn256.so`` or ``mclbn256.dll``
           in the paths specified by the ``PATH`` and ``LD_LIBRARY_PATH``
           environment variables.

        3. If the `mclbn256 <https://pypi.org/project/mclbn256>`__ package is
           installed, it reverts to the compiled subset of mclbn256
           included in that package.

        If all of the above fail, then :obj:`mcl` is assigned
        the value ``None`` and all classes exported by this module default
        to their pure-Python variants (*i.e.*, those encapsulated within
        :obj:`~oblivious.bn254.python`). One way to confirm that a
        dynamic/shared library *has been found* when this module
        is imported is to evaluate the expression ``mcl is not None``.

        If a shared/dynamic library file has been loaded successfully,
        this class encapsulates shared/dynamic library variants of all classes
        exported by this module and of all the underlying low-level operations:
        :obj:`mcl.pnt <pnt>`, :obj:`mcl.bas <bas>`,
        :obj:`mcl.can <can>`, :obj:`mcl.ser <ser>`,
        :obj:`mcl.des <des>`, :obj:`mcl.mul <mul>`,
        :obj:`mcl.add <add>`, :obj:`mcl.sub <sub>`,
        :obj:`mcl.neg <neg>`, :obj:`mcl.par <par>`,
        :obj:`mcl.rnd <rnd>`, :obj:`mcl.scl <scl>`,
        :obj:`mcl.sse <sse>`, :obj:`mcl.sde <sde>`,
        :obj:`mcl.inv <inv>`, :obj:`mcl.smu <smu>`,
        :obj:`mcl.sad <sad>`, :obj:`mcl.ssu <ssu>`,
        :obj:`mcl.sne <sne>`,
        :obj:`mcl.pnt2 <pnt2>`, :obj:`mcl.bas2 <bas2>`,
        :obj:`mcl.can2 <can2>`, :obj:`mcl.ser2 <ser2>`,
        :obj:`mcl.des2 <des2>`, :obj:`mcl.mul2 <mul2>`,
        :obj:`mcl.add2 <add2>`, :obj:`mcl.sub2 <sub2>`,
        :obj:`mcl.neg2 <neg2>`,
        :obj:`mcl.rnd2 <rnd2>`, :obj:`mcl.scl2 <scl2>`,
        :obj:`mcl.sse2 <sse2>`, :obj:`mcl.sde2 <sde2>`,
        :obj:`mcl.inv2 <inv2>`, :obj:`mcl.smu2 <smu2>`,
        :obj:`mcl.sad2 <sad2>`,
        :obj:`mcl.point <oblivious.bn254.mcl.point>`,
        :obj:`mcl.scalar <oblivious.bn254.mcl.scalar>`,
        :obj:`mcl.point2 <oblivious.bn254.mcl.point2>`, and
        :obj:`mcl.scalar2 <oblivious.bn254.mcl.scalar2>`.
        For example, you can perform addition of points using the point
        addition implementation found in the shared/dynamic library
        bundled with the instance of the package
        `mclbn256 <https://pypi.org/project/mclbn256>`__ that is found
        on the host system.

        >>> p = mcl.pnt()
        >>> q = mcl.pnt()
        >>> mcl.add(p, q) == mcl.add(q, p)
        True

        Methods found in the shared/dynamic library variants of the
        :obj:`point`, :obj:`scalar`, :obj:`point2`, and :obj:`scalar2`
        classes are wrappers for the shared/dynamic library
        implementations of the underlying operations.

        >>> p = mcl.point()
        >>> q = mcl.point()
        >>> p + q == q + p
        True
        """
        # pylint: disable=too-many-public-methods

        @staticmethod
        def pnt(h: Union[bytes, bytearray, None] = None) -> G1:
            """
            Construct a point if the supplied bytes-like object represents
            a valid point; otherwise, return ``None``. If no byte vector is
            supplied, return a random point.

            >>> p = mcl.pnt(hashlib.sha512('123'.encode()).digest())
            >>> p.__class__ = point
            >>> mcl.point.to_bytes(p).hex()[:64]
            '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
            """
            return G1.random() if h is None else G1.mapfrom(h)

        @staticmethod
        def bas(s: Fr) -> G1:
            """
            Return the base point multiplied by the supplied scalar.

            >>> p = mcl.bas(mcl.scalar.hash('123'.encode())).normalize().normalize()
            >>> p.__class__ = point
            >>> mcl.point.to_bytes(p).hex()[:64]
            '2d66076815cda25556bab4a930244ac284412267e9345aceb98d71530308401a'
            """
            return G1.base_point() * s

        @staticmethod
        def can(p: G1) -> G1:
            """
            Normalize the representation of a point into its canonical form and
            return the result.

            >>> a = mcl.point.hash('123'.encode())
            >>> p = mcl.add(a, a)
            >>> p_can = mcl.can(mcl.add(a, a))

            We may have ``ser(p_can) != ser(p)`` here, depending on the backend
            implementation.  Either normalization matters, or MCl is not the backend.

            >>> (mcl.ser(p_can) != mcl.ser(p)) or not mclbn256
            True

            Normalization is idempotent.

            >>> mcl.can(p) == mcl.can(p_can)
            True
            """
            return p.normalize() # Sets ``(x, y, z)`` to unique vector ``(x/z, y/z, 1)``.

        @staticmethod
        def ser(p: G1) -> bytes:
            """
            Return the binary representation of a point.

            >>> p = mcl.point.hash('123'.encode())
            >>> mcl.des(mcl.ser(p)) == p
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64 # Constants from mcl library. # pylint: disable=C0103
            return p.tostr(IoEcProj|IoArrayRaw)[1:]

        @staticmethod
        def des(bs: bytes) -> G1:
            """
            Construct a point corresponding to the supplied binary representation.

            >>> p = mcl.point.hash('123'.encode())
            >>> ser_p = bytes.fromhex(
            ...     '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            ...     'b03c992ec97868be765b98048118a96f42bdc466a963c243c223b95196304209'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ... )
            >>> mcl.des(ser_p) == p
            True
            >>> mcl.ser(mcl.des(ser_p)) == ser_p
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return G1.new_fromstr(b"4"+bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def mul(s: Fr, p: G1) -> G1:
            """
            Multiply a point by a scalar and return the result.

            >>> p = mcl.pnt(hashlib.sha512('123'.encode()).digest())
            >>> s = mcl.scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> q = mcl.mul(s, p).normalize().normalize()
            >>> q.__class__ = point
            >>> mcl.point.to_bytes(q).hex()[:64]
            '68b5dd61adaa83f1511efe7b4749481cc9f86e11bf82d82960b6c56373de0d24'
            """
            return G1.__mul__(p, s)

        @staticmethod
        def add(p: G1, q: G1) -> G1:
            """
            Return the sum of the supplied points.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.point.hash('456'.encode())
            >>> r = mcl.add(p, q).normalize().normalize()
            >>> r.__class__ = point
            >>> mcl.point.to_bytes(r).hex()[:64]
            '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
            """
            return G1.__add__(p, q)

        @staticmethod
        def sub(p: G1, q: G1) -> G1:
            """
            Return the result of subtracting the right-hand point from the
            left-hand point.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.point.hash('456'.encode())
            >>> r = mcl.sub(p, q).normalize().normalize()
            >>> r.__class__ = point
            >>> mcl.point.to_bytes(r).hex()[:64]
            'a43a5ce1931b1300b62e5d7e1b0c691203bfd85fafd9585dc5e47a7e2acfea22'
            """
            return G1.__sub__(p, q)

        @staticmethod
        def neg(p: G1) -> G1:
            """
            Return the additive inverse of a point.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.neg(p)
            >>> q.__class__ = point
            >>> mcl.point.to_bytes(q).hex()[:64]
            '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            """
            return G1.__neg__(p)

        @staticmethod
        def par(p: Union[G1, G2], q: Union[G1, G2]) -> GT:
            """
            Compute the pairing function on two points.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.point2.base(mcl.scalar.from_int(456))
            >>> r = mcl.par(p, q)
            >>> r.__class__ = mcl.scalar2
            >>> mcl.scalar2.to_bytes(r).hex()[700:]
            'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'

            The order of the two arguments is not important (as long as exactly
            one argument is an instance of :obj:`point` and the other is an
            instance of :obj:`point2`).

            >>> r = mcl.par(q, p)
            >>> r.__class__ = mcl.scalar2
            >>> mcl.scalar2.to_bytes(r).hex()[700:]
            'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'

            The pairing function is bilinear.

            >>> p = mcl.point.random()
            >>> s = mcl.scalar.random()

            >>> t = mcl.scalar.random()
            >>> q = mcl.point2.random()
            >>> -((~s) * (s * p)) - p == mcl.scalar.from_int(-2) * p
            True
            >>> s * t * p @ q == s * p @ (t * q)
            True

            Suppose there are two points: one multiplied by the scalar ``s`` and the other
            multiplied by the scalar ``t``. Their equality can be determined by using a
            balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
            same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

            >>> x = y = p
            >>> g = mcl.point2.base(mcl.scalar.from_int(1))
            >>> b = mcl.point2.base(~s * t)
            >>> (t * x) @ g == (s * y) @ b
            True

            This operation is defined only for a point and a second-level point.
            Any attempt to invoke the operation on values or objects of other types
            raises an exception.

            >>> p @ (p + p)
            Traceback (most recent call last):
              ...
            TypeError: pairing is defined only for a point and a second-level point
            >>> g @ b
            Traceback (most recent call last):
              ...
            TypeError: pairing is defined only for a point and a second-level point

            Pairing is intended to be nonsingular.

            >>> p @ q.clear()
            Traceback (most recent call last):
              ...
            TypeError: cannot meaningfully pair the infinity point
            >>> p.clear() @ g
            Traceback (most recent call last):
              ...
            TypeError: cannot meaningfully pair the infinity point
            """
            if p.zero() or q.zero():
                raise TypeError('cannot meaningfully pair the infinity point')

            if (
                (isinstance(p, G1) and isinstance(q, G1)) or
                (isinstance(p, G2) and isinstance(q, G2))
            ):
                raise TypeError(
                    'pairing is defined only for a point and a second-level point'
                )

            if isinstance(p, G1):
                return G1.__matmul__(G1.__new__(G1, p), G2.__new__(G2, q))

            return G2.__matmul__(G2.__new__(G2, p), G1.__new__(G1, q))

        @staticmethod
        def rnd() -> Fr:
            """
            Return random non-zero scalar.

            >>> s = mcl.rnd()
            >>> isinstance(s, Fr)
            True
            >>> s.__class__ = scalar
            >>> len(mcl.scalar.to_bytes(s))
            32
            """
            return Fr().randomize()

        @classmethod
        def scl(cls, bs: Union[bytes, bytearray, None] = None) -> Optional[Fr]:
            """
            Construct a scalar if the supplied bytes-like object represents
            a valid scalar; otherwise, return ``None``. If no byte vector is
            supplied, return a random scalar.

            >>> s = mcl.scl()
            >>> s.__class__ = scalar
            >>> t = mcl.scl(mcl.scalar.to_bytes(s))
            >>> s == t
            True
            >>> mcl.scl(bytes([255] * 32)) is None
            True
            """
            if bs is None:
                return cls.rnd()

            try:
                s = cls.sde(bs)
                return s
            except ValueError: # pragma: no cover
                return None

        @staticmethod
        def sse(s: Fr) -> bytes:
            """
            Return the binary representation of a scalar.

            >>> s = mcl.scalar.hash('123'.encode())
            >>> mcl.sde(mcl.sse(s)) == s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64 # Constants from mcl library. # pylint: disable=C0103
            return s.tostr(IoEcProj|IoArrayRaw)

        @staticmethod
        def sde(bs: bytes) -> Fr:
            """
            Return a scalar from its binary representation.

            >>> s = mcl.scalar.hash('123'.encode())
            >>> bs = bytes.fromhex(
            ...     '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
            ... )
            >>> mcl.sde(bs) == s
            True
            >>> mcl.sse(mcl.sde(bs)) == bs
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return Fr.new_fromstr(bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def inv(s: Fr) -> Fr:
            r"""
            Return inverse of a scalar (modulo
            ``r = 16798108731015832284940804142231733909759579603404752749028378864165570215949``
            in the prime field *F*\_*r*).

            >>> (s, p) = (mcl.scl(), mcl.pnt())
            >>> mcl.mul(mcl.inv(s), mcl.mul(s, p)) == p
            True
            """
            return Fr.__invert__(s)

        @staticmethod
        def smu(s: Fr, t: Fr) -> Fr:
            """
            Return scalar multiplied by another scalar.

            >>> (s, t) = (mcl.scl(), mcl.scl())
            >>> mcl.smu(s, t) == mcl.smu(t, s)
            True
            """
            return Fr.__mul__(s, t)

        @staticmethod
        def sad(s: Fr, t: Fr) -> Fr:
            """
            Return scalar added to another scalar.

            >>> (s, t) = (mcl.scl(), mcl.scl())
            >>> mcl.sad(s, t) == mcl.sad(t, s)
            True
            """
            return Fr.__add__(s, t)

        @staticmethod
        def ssu(s: Fr, t: Fr) -> Fr:
            """
            Return the result of one scalar subtracted from another scalar.

            >>> (s, t) = (mcl.scl(), mcl.scl())
            >>> mcl.ssu(s, t) == mcl.sad(s, mcl.sne(t))
            True
            >>> mcl.ssu(s, t) == mcl.sne(mcl.ssu(t, s))
            True
            """
            return Fr.__sub__(s, t)

        @staticmethod
        def sne(s: Fr) -> Fr:
            """
            Return the additive inverse of a scalar.

            >>> (s, t) = (mcl.scl(), mcl.scl())
            >>> mcl.sne(mcl.sne(s)) == s
            True
            """
            return Fr.__neg__(s)

        @staticmethod
        def pnt2(h: Optional[bytes] = None) -> G2:
            """
            Construct a second-level point if the supplied bytes-like object
            represents a valid second-level point; otherwise, return ``None``.
            If no byte vector is supplied, return a random second-level point.

            >>> p = mcl.pnt2(hashlib.sha512('123'.encode()).digest())
            >>> p.__class__ = point2
            >>> mcl.point2.to_bytes(p.canonical().canonical()).hex()[:128] == (
            ...     '4c595542640a69c4a70bda55c27ef96c133cd1f4a5f83b3371e571960c018e19'
            ...     'c54aaec2069f8f10a00f12bcbb3511cdb7356201f5277ec5e47da91405be2809'
            ... )
            True
            """
            return G2.random() if h is None else G2.mapfrom(h)

        @staticmethod
        def bas2(s) -> G2:
            """
            Return the base second-level point multiplied by the supplied scalar.

            >>> r = mcl.bas2(mcl.scalar.hash('123'.encode())).normalize().normalize()
            >>> r.__class__ = point2
            >>> mcl.point2.to_bytes(r).hex()[:64]
            'e7000fb12d206112c73fe1054e9d77b35c77881eba6598b7e035171d90b13e0c'
            """
            # return s * G2.__new__(point2, G2.base_point())
            return G2.base_point() * s

        @staticmethod
        def can2(p: G2) -> G2:
            """
            Normalize the representation of a second-level point into its
            canonical form and return the result.

            >>> p = mcl.bas2(scalar.from_int(1))
            >>> mcl.ser(mcl.can2(p)).hex()[:64]
            '669e6563afaa45af7cbc013d23f092bb3763d4dc41b97aef555bdf61de713f17'
            """
            return p.normalize() # Sets ``(x, y, z)`` to unique vector ``(x/z, y/z, 1)``.

        @staticmethod
        def ser2(p: G2) -> bytes:
            """
            Return the binary representation of a second-level point.

            >>> p = mcl.point2.hash('123'.encode())
            >>> mcl.des2(mcl.ser2(p)) == p
            True

            It is the responsibility of the user to ensure that only canonical
            representations of points are serialized.
            """
            IoEcProj, IoArrayRaw = 1024, 64 # Constants from mcl library. # pylint: disable=C0103
            return p.tostr(IoEcProj|IoArrayRaw)[1:]

        @staticmethod
        def des2(bs: bytes) -> G2:
            """
            Return the second-level point corresponding to the supplied binary
            representation thereof.

            >>> p = mcl.point2.hash('123'.encode())
            >>> mcl.ser_p = bytes.fromhex(
            ...     'b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba1b'
            ...     '8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f300d'
            ...     '7e59c60a595253ebf69bf0794b7a032e59b6b5037adba410d680b53ffac08517'
            ...     'cf5bc3be9d850ec64ea6939904cf66b66b6b4b82be03ee4f10661fedaf83841f'
            ...     'ba7e678442a658340a5b3c51eb5076d738cf88387ada6cbd1fe7f8d8a2268417'
            ...     'bc8aedbc99808b0450025d0c75b5f1ccb34bc69934cc620d9ea51038a1d98721'
            ... )
            >>> mcl.des2(mcl.ser_p) == p
            True
            >>> mcl.ser(mcl.des2(mcl.ser_p)) == mcl.ser_p
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return G2.new_fromstr(b"4"+bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def mul2(s: Fr, p: G2) -> G2:
            """
            Multiply a second-level point by a scalar.

            >>> p = mcl.point2.hash('123'.encode())
            >>> s = mcl.scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> r = mcl.mul2(s, p).normalize().normalize()
            >>> r.__class__ = point2
            >>> mcl.point2.to_bytes(r).hex() == (
            ...     '5f6f2ace8566ca47354fbe244ae3e6a854c37011fb6d6ac56571c94169e4ab18'
            ...     '650bea4cfed5c9603e5949fe3d7509b17e20db4ff1f05129aad0d0a3bffb0008'
            ...     '3043c5a14b986882836b1c929952ea3881d04ca44d487d1ab2d4c0b171b87d14'
            ...     '5dca6dabb4f0ea7be5c95a861ed319d146b15d70542d3952af995a8bb35b8314'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            True
            """
            return G2.__mul__(p, s)

        @staticmethod
        def add2(p: G2, q: G2) -> G2:
            """
            Return sum of the supplied second-level points.

            >>> p = mcl.point2.hash('123'.encode())
            >>> q = mcl.point2.hash('456'.encode())
            >>> r = mcl.add2(p, q).normalize().normalize()
            >>> r.__class__ = point2
            >>> mcl.point2.to_bytes(r).hex() == (
            ...     'cb0fc423c1bac2ac2df47bf5f5548a42b0d0a0da325bc77243d15dc587a7b221'
            ...     '9808a1649991ddf770f0060333aab4d499580b123f109b5cb180f1f8a75a090e'
            ...     '83dd34d9ecdd6fd639230f7f0cf44b218fae4d879111de6c6c037e6ffdcdc823'
            ...     'f5a48318143873ca90ad512a2ea1854200eea5537cd0ac93691d5b94ff36b212'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            True
            """
            return G2.__add__(p, q)

        @staticmethod
        def sub2(p: G2, q: G2) -> G2:
            """
            Return the result of subtracting the right-hand second-level point
            from the left-hand second-level point.

            >>> p = mcl.point2.hash('123'.encode())
            >>> q = mcl.point2.hash('456'.encode())
            >>> r = mcl.sub2(p, q).normalize().normalize()
            >>> r.__class__ = point2
            >>> mcl.point2.to_bytes(r).hex() == (
            ...     'e97a70c4e3a5369ebbb1dcf0cc1135c8c8e04a4ec7cffdf875ac429d66846d0b'
            ...     '191b090909c40a723027b07ac44435a6ade3813d04b3632a17c92c5c98718902'
            ...     '407c58ed13cc0c0aaa43d0eafd44080080c8199401fe4f8ed7dd0eb5fba86817'
            ...     '141f74341ce3c4884f86a97f51f7c0b208fe52be336b7651252fa9881c93d203'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            True
            """
            return G2.__sub__(p, q)

        @staticmethod
        def neg2(p: G2) -> G2:
            """
            Return the negation of a second-level point.

            >>> p = mcl.point2.hash('123'.encode())
            >>> r = mcl.neg2(p).normalize().normalize()
            >>> r.__class__ = point2
            >>> mcl.point2.to_bytes(r).hex() == (
            ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
            ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
            ...     'e7957744bb7f9abb9e7209cd4e27ae80d8ab490a1072af125034c7b09c12281c'
            ...     '0fbab105e7942bf5dbe1ac290ce01232b800aac41de98f86d04bd3a81758cf05'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            True
            """
            return G2.__neg__(p)

        @staticmethod
        def rnd2() -> GT:
            """
            Return random non-zero second-level scalar.

            >>> isinstance(mcl.rnd2(), GT)
            True
            """
            return mcl.scalar2.hash(secrets.token_bytes(384))

        @staticmethod
        def scl2(s: Union[bytes, bytearray, None] = None) -> Optional[GT]:
            """
            Construct a second-level scalar if the supplied bytes-like object
            represents a valid second-level scalar; otherwise, return ``None``.
            If no byte vector is supplied, return a random second-level scalar.

            >>> bs = bytes.fromhex(
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805'
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021'
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710'
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c'
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c'
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10'
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911'
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215'
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002'
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f'
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622'
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... )
            >>> s = mcl.scl2(bs)
            >>> s.__class__ = mcl.scalar2
            >>> mcl.scalar2.to_bytes(s).hex()[700:]
            '36222db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            """
            if s is None:
                return mcl.rnd2()

            try:
                return mcl.sde2(s)
            except ValueError: # pragma: no cover
                return None

        @staticmethod
        def sse2(s: scalar2) -> bytes:
            """
            Return the binary representation of a second-level scalar.

            >>> s = scalar2.hash('123'.encode())
            >>> mcl.sde2(mcl.sse2(s)) == s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64 # Constants from mcl library. # pylint: disable=C0103
            return s.tostr(IoEcProj|IoArrayRaw)

        @staticmethod
        def sde2(bs: bytes) -> GT:
            """
            Return the second-level scalar corresponding to the supplied binary
            representation thereof.

            >>> s = mcl.scalar2.hash('123'.encode())
            >>> bs = bytes.fromhex(
            ...     '36980a8359d40e106075488e80cf1479f2e6ba95d6a99a67832d21b7b94d8c1d'
            ...     '5eb4d655f23e1d5d499d51d1c552b5e7df6943091427cd080f582e120613a021'
            ...     '85898ef7d016e47a74a8df62316cc4ad975cb64bb63867ed9b5221f77bb9a121'
            ...     '7bd89cd213eee0c3fdf2e0e13ef9e30383ea5607c8d13fc10e04448a6c964a00'
            ...     '04a098a55beab09732220966319333608b2187ee2196eb5b4253bc2b1aea5303'
            ...     '654260dd687a2eb176a494258ff7ef753f93105a6f0e9f46c926afdbe31ff124'
            ...     '6bdd87c32537abcdb46ad542792edd74a229c9ba61abcd993f074237a91f5215'
            ...     '8f6b07886895733edde15cb22129459162d89d3662826b74e4fcbe4e9e8c2420'
            ...     'bd53586a09f91ff8f67f92cba72c5b64a9c3965c01e93710200ab4e084955316'
            ...     'fb18950835b79fb4c2930efcc5fcaa9d82ee0faff036b80657daee233a445901'
            ...     '7df3e57cb535ed26162b3ee0f8961131a93fe3198dc5393d277ed8bac5532411'
            ...     '93b7ad15c52ca123fd26f592a2219b1bf118b3035893cc4abf614b422f978718'
            ... )
            >>> mcl.sde2(bs) == s
            True
            >>> mcl.sse(mcl.sde2(bs)) == bs
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return GT.new_fromstr(bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def inv2(s: GT) -> GT:
            """
            Return the inverse of a second-level scalar.

            >>> s = mcl.scl2()
            >>> mcl.smu2(s, mcl.smu2(s, mcl.inv2(s))) == s
            True
            >>> mcl.smu2(mcl.smu2(s, s), mcl.inv2(s)) == s
            True
            """
            return GT.__inv__(s)

        @staticmethod
        def smu2(s: GT, t: GT) -> GT:
            """
            Return the product of two second-level scalars.

            >>> p1 = mcl.point.hash('123'.encode())
            >>> p2 = mcl.point.hash('456'.encode())
            >>> q1 = mcl.point2.base(mcl.scalar.hash('123'.encode()))
            >>> q2 = mcl.point2.base(mcl.scalar.hash('456'.encode()))
            >>> s = p1 @ q1
            >>> t = p2 @ q2
            >>> mcl.smu2(s, t) == mcl.smu2(t, s)
            True
            """
            return GT.__mul__(s, t)

        @staticmethod
        def sad2(s: GT, t: GT) -> GT:
            """
            Return the sum of two second-level scalars.

            >>> s = mcl.scl2()
            >>> t = mcl.scl2()
            >>> mcl.sad2(s, t) == mcl.sad2(t, s)
            True
            """
            return GT.__add__(s, t)

    # Indicate that data structures based on the dynamic/shared library have
    # successfully been defined.
    mclbn256 = True

except: # pylint: disable=W0702 # pragma: no cover
    mcl = None # Exported symbol.

#
# Dedicated point and scalar data structures for each implementation.
#

for (_implementation, _p_base_cls, _s_base_cls, _p2_base_cls, _s2_base_cls) in (
    [(python, bytes, bytes, bytes, bytes)] +
    ([(mcl, G1, Fr, G2, GT)] if mcl is not None else [])
):
    # pylint: disable=cell-var-from-loop

    class point(_p_base_cls): # pylint: disable=W0621,E0102
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """
        _implementation = _implementation

        @classmethod
        def random(cls) -> point:
            """
            Return random point object.

            >>> len(point.random())
            96
            """
            p = cls._implementation.pnt()
            p.__class__ = cls
            return p

        @classmethod
        def bytes(cls, bs: bytes) -> point:
            """
            Return point object obtained by transforming supplied bytes-like
            object if it is possible to do so; otherwise, return ``None``.

            The bytes-like object need not be the binary representation
            of a point or its coordinate(s). For a strict deserialization
            from a bytes-like object, use :obj:`point.from_bytes`.

            >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()[:64]
            '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
            """
            p = cls._implementation.pnt(bs)
            p.__class__ = cls
            return p

        @classmethod
        def hash(cls, bs: bytes) -> point: # pylint: disable=arguments-differ
            """
            Return point object by hashing supplied bytes-like object.

            >>> point.hash('123'.encode()).hex()[:64]
            '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            """
            p = cls._implementation.pnt(hashlib.sha512(bs).digest()[:32])
            p.__class__ = cls
            return p

        @classmethod
        def base(cls, s: scalar) -> point:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid.

            >>> point.base(scalar.hash('123'.encode())).canonical().hex()[:64]
            '2d66076815cda25556bab4a930244ac284412267e9345aceb98d71530308401a'
            """
            p = cls._implementation.bas(s)
            p.__class__ = cls
            return p

        @classmethod
        def from_bytes(cls, bs: bytes) -> point:
            """
            Deserialize the supplied binary representation of an instance and
            return that instance.

            >>> p = point.hash('123'.encode())
            >>> bs = p.to_bytes()
            >>> point.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            """
            p = cls._implementation.des(bs)
            p.__class__ = cls
            return p

        @classmethod
        def fromhex(cls, s: str) -> point:
            """
            Construct an instance from its hexadecimal UTF-8 string representation.

            >>> point.fromhex(
            ...     'b89ec91191915a72d4ec4434be7b438893975880b21720995c2b2458962c4e0a'
            ...     'd0efebb5c303e4d1f8461b44ec768c587eca8b0abc01d4cb0d878b076154940d'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ... ).canonical().hex()[:64]
            'b89ec91191915a72d4ec4434be7b438893975880b21720995c2b2458962c4e0a'
            """
            return cls.from_bytes(bytes.fromhex(s))

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> point.from_base64(
            ...     'hQIYpQRHupyyfPFoEm8rfmKV6i6VUP7vmngQWpxS3AEJD29fKVMW39l2oDLB+Ece'
            ...     '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            ... ).canonical().hex()[:64]
            '850218a50447ba9cb27cf168126f2b7e6295ea2e9550feef9a78105a9c52dc01'
            """
            return cls.from_bytes(base64.standard_b64decode(s))

        def __new__( # pylint: disable=arguments-differ
                cls,
                bs: Union[bytes, bytearray, None] = None
            ) -> point:
            """
            If a bytes-like object is supplied, return a point object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, return a random point
            object.

            >>> bs = bytes.fromhex(
            ...     'a5db59a0a1450aee0e47e7226d992fded25f2eb5378493ba0eb3225fc7595809'
            ...     'c76c3dc4ba5a827be515cef65823ab1b113626348415f85aa966bad842457c03'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ... )
            >>> point(bs).canonical().hex()[:64]
            'a5db59a0a1450aee0e47e7226d992fded25f2eb5378493ba0eb3225fc7595809'
            >>> len(point())
            96
            """
            return cls.from_bytes(bs) if bs is not None else cls.random()

        def canonical(self: point) -> point:
            """
            Normalize the representation of this point into its canonical form
            and return the result. This takes the *z*-coordinate, which may not
            always be equal to 1, and multiplies all coordinates *x*, *y*,
            and *z* by *z*'s multiplicative inverse. The resulting canonical
            representation is unique (*i.e.*, two points are equal if and only
            if their canonical forms are equal) and in the form
            (*x*/*z*, *y*/*z*, 1).

            >>> a = point.hash('123'.encode())
            >>> p = a + a + a + a
            >>> p == p
            True
            >>> p.to_bytes() == p.to_bytes()
            True
            >>> p.to_bytes() == p.canonical().to_bytes() and p.__class__ != python.point
            False
            >>> p.canonical().to_bytes() == p.canonical().to_bytes()
            True
            >>> p.canonical().to_bytes() == p.canonical().canonical().to_bytes()
            True
            >>> point.from_bytes(p.to_bytes()) == p
            True
            >>> point.from_bytes(p.canonical().to_bytes()) == p
            True
            >>> point.from_bytes(p.to_bytes()) == point.from_bytes(p.canonical().to_bytes())
            True
            >>> type(p.canonical()) is point
            True
            """
            p = self._implementation.can(self)
            p.__class__ = self.__class__
            return p

        def __mul__(self: point, other: Any) -> NoReturn:
            """
            Use of this method is not permitted. A point cannot be a left-hand argument.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError(
                'point must be on right-hand side of multiplication operator'
            )

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

        def __add__(self: point, other: point) -> point:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).canonical().hex()[:64]
            '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
            """
            p = self._implementation.add(self, other)
            p.__class__ = self.__class__
            return p

        def __sub__(self: point, other: point) -> point:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).canonical().hex()[:64]
            'a43a5ce1931b1300b62e5d7e1b0c691203bfd85fafd9585dc5e47a7e2acfea22'
            """
            p = self._implementation.sub(self, other)
            p.__class__ = self.__class__
            return p

        def __neg__(self: point) -> point:
            """
            Return the negation (additive inverse) of this point

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).canonical().hex()[:64]
            '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
            """
            p = self._implementation.neg(self)
            p.__class__ = self.__class__
            return p

        def __matmul__(self: point, other: point2) -> scalar2:
            """
            Return the result of pairing another second-level point with this
            instance.

            **This method is only defined for the classes**
            :obj:`oblivious.bn254.mcl.point` **and** :obj:`oblivious.bn254.mcl.point2`
            **that are available when the**
            `mclbn256 <https://pypi.org/project/mclbn256>`__ **package is installed**.
            Otherwise, :obj:`oblivious.bn254.point` and :obj:`oblivious.bn254.point2`
            correspond to the pure-Python implementations of these classes (for which
            this method is not defined).

            >>> p = point.hash('123'.encode())
            >>> q = point2.base(scalar.from_int(456))
            >>> z = (p @ q).hex()[700:]
            >>> z == 'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'
            True

            The pairing function is bilinear.

            >>> p = point.random()
            >>> q = point2.random()
            >>> s = scalar.random()
            >>> t = scalar.random()
            >>> -((~s) * (s * p)) - p == scalar.from_int(-2) * p
            True
            >>> (s * (t * p)) @ q == (s * p) @ (t * q)
            True

            Suppose there are two points: one multiplied by the scalar ``s`` and the other
            multiplied by the scalar ``t``. Their equality can be determined by using a
            balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
            same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

            >>> x = y = p
            >>> g = point2.base(scalar.from_int(1))
            >>> b = point2.base(~s * t)
            >>> (t * x) @ g == (s * y) @ b
            True
            """
            s = self._implementation.par(self, other)
            s.__class__ = self._implementation.scalar2
            return s

        def __len__(self: point) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(point())
            96
            """
            return bytes(self).__len__()

        def __bytes__(self: point) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> p = point.hash('123'.encode())
            >>> bs = bytes(p)
            >>> point.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            >>> len(bs)
            96
            """
            return self._implementation.ser(self)

        def to_bytes(self: point) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> p = point.hash('123'.encode())
            >>> bs = p.to_bytes()
            >>> point.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            >>> len(bs)
            96
            """
            return bytes(self)

        def hex(self: point) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> p = point.hash('123'.encode())
            >>> p.hex()[:64]
            '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            """
            return bytes(self).hex()

        def to_base64(self: point) -> str:
            """
            Return the Base64 UTF-8 string representation of this instance.

            >>> p = point.from_base64(
            ...     'hQIYpQRHupyyfPFoEm8rfmKV6i6VUP7vmngQWpxS3AEJD29fKVMW39l2oDLB+Ece'
            ...     '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            ... )
            >>> p.to_base64()[-64:]
            '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            """
            return base64.standard_b64encode(bytes(self)).decode('utf-8')

    class scalar(_s_base_cls): # pylint: disable=E0102
        """
        Class for representing a scalar.
        """
        _implementation = _implementation

        @classmethod
        def random(cls) -> scalar:
            """
            Return random non-zero scalar object.

            >>> len(scalar.random())
            32
            """
            s = cls._implementation.rnd()
            s.__class__ = cls
            return s

        @classmethod
        def bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return scalar object obtained by transforming supplied bytes-like
            object if it is possible to do so; otherwise, return ``None``.

            >>> s = scalar()
            >>> t = scalar.bytes(bytes(s))
            >>> s.hex() == t.hex()
            True
            """
            s = cls._implementation.scl(bs)
            if s is not None:
                s.__class__ = cls
            return s

        @classmethod
        def hash(cls, bs: bytes) -> scalar:
            """
            Return scalar object by hashing supplied bytes-like object.

            >>> scalar.hash('123'.encode()).hex()[:64]
            '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
            """
            h = hashlib.sha256(bs).digest()
            s = cls._implementation.scl(h)
            while s is None:
                h = hashlib.sha256(h).digest()
                s = cls._implementation.scl(h)

            s.__class__ = cls
            return s

        @classmethod
        def from_int(cls, i: int) -> scalar:
            """
            Construct an instance from its corresponding integer (*i.e.*, residue)
            representation.

            The integer can be in the range from
            ``-16798108731015832284940804142231733909759579603404752749028378864165570215948``
            to ``16798108731015832284940804142231733909759579603404752749028378864165570215948``
            (or a corresponding one in the range from
            ``-8399054365507916142470402071115866954879789801702376374514189432082785107974``
            to ``8399054365507916142470402071115866954879789801702376374514189432082785107974``).
            Any values outside of this range will not be reduced, may be truncated, or may raise
            a :obj:`ValueError`.  Zero-valued scalars are technically allowed, but cannot be used
            for point-scalar multiplication.

            >>> int(scalar.from_int(
            ...    16798108731015832284940804142231733909759579603404752749028378864165570215948
            ... ))
            -1
            >>> int(scalar.from_int(
            ...    -8399054365507916142470402071115866954879789801702376374514189432082785107974
            ... ))
            -8399054365507916142470402071115866954879789801702376374514189432082785107974
            >>> int(scalar.from_int(
            ...     12345678
            ... ))
            12345678
            """
            #r= 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
            d = 0x212ba4f27ffffff5a2c62effffffffd00242ffffffffff9c39ffffffffffffb2
            return cls.bytes(int.to_bytes((i * d) % r, 32, 'little'))

        @classmethod
        def from_bytes(cls, bs: bytes) -> scalar:
            """
            Deserialize the supplied binary representation of an instance and
            return that instance.

            >>> s = scalar.hash('123'.encode())
            >>> bs = s.to_bytes()
            >>> scalar.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            """
            s = cls._implementation.sde(bs)
            s.__class__ = cls
            return s

        @classmethod
        def fromhex(cls, s: str) -> scalar:
            """
            Construct an instance from its hexadecimal UTF-8 string representation.

            >>> scalar.fromhex(
            ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            ... ).hex()[:64]
            '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            """
            return cls.from_bytes(bytes.fromhex(s))

        @classmethod
        def from_base64(cls, s: str) -> scalar:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()[:64]
            '312d0c9130f69153bec9f5d0386a95135eb45eebf130af5f1fed1c6ed15f2500'
            """
            return cls.from_bytes(base64.standard_b64decode(s))

        def __new__( # pylint: disable=arguments-differ
                cls,
                bs: Union[bytes, bytearray, None] = None
            ) -> scalar:
            """
            If a bytes-like object is supplied, return a scalar object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            scalar). If no argument is supplied, return a random scalar
            object.

            >>> s = scalar()
            >>> t = scalar(bytes(s))
            >>> s.hex() == t.hex()
            True
            >>> len(scalar())
            32
            """
            return cls.from_bytes(bs) if bs is not None else cls.random()

        def __invert__(self: scalar) -> scalar:
            """
            Return the inverse of a scalar.

            >>> s = scalar()
            >>> p = point()
            >>> ((~s) * (s * p)) == p
            True
            """
            s = self._implementation.inv(self)
            s.__class__ = self.__class__
            return s

        def __mul__(
                self: scalar,
                other: Union[scalar, point, point2]
            ) -> Optional[Union[scalar, point, point2]]:
            """
            Multiply supplied scalar, point, or second-level point by this
            instance.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (s * s).hex()[:64]
            '0497a5b6a7992e7d77b59c07d4457e8bb3cf580603cfd19e05d1f31342141b00'
            >>> isinstance(s * s, scalar)
            True
            >>> p = point.from_base64(
            ...     'hQIYpQRHupyyfPFoEm8rfmKV6i6VUP7vmngQWpxS3AEJD29fKVMW39l2oDLB+Ece'
            ...     '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            ... )
            >>> (s * p).canonical().hex()[:64]
            'eee31d1780ea41771357da19a81eaddf2e7fa560142067b433764cbf98be9002'
            >>> isinstance(s * p, point)
            True

            If the second argument is a :obj:`point2` object, this method
            pre-empts :obj:`point2.__rmul__`.

            >>> p = point2.hash('123'.encode())
            >>> (s * p).canonical().hex()[:128] == (
            ...     '451f144e06deecbfe5a1527f2b5cc6f12bbde91c1fdf0d5326ad79ffc53bb106'
            ...     '6d800275af625de83d72d815335832027cc60c34f22e8c5f89f953740a409702'
            ... )
            True

            Any attempt to multiply a value or object of an incompatible type by this
            instance raises an exception.

            >>> s * 2
            Traceback (most recent call last):
              ...
            TypeError: multiplication by a scalar is defined only for scalars and points
            """
            if isinstance(other, self._implementation.scalar):
                s = self._implementation.smu(self, other)
                s.__class__ = self.__class__
                return s

            if isinstance(other, self._implementation.point):
                p = self._implementation.mul(self, other)
                p.__class__ = other.__class__
                return p

            if isinstance(other, self._implementation.point2):
                p = self._implementation.mul2(self, other)
                p.__class__ = other.__class__
                return p

            raise TypeError(
                'multiplication by a scalar is defined only for scalars and points'
            )

        def __rmul__(self: scalar, other: Any) -> NoReturn:
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

        def __add__(self: scalar, other: scalar) -> scalar:
            """
            Add another scalar to this instance.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (s + s).hex()[:64]
            '625a182261ec23a77c93eba171d42a27bc68bdd6e3615ebf3eda39dca2bf4a00'
            >>> isinstance(s + s, scalar)
            True

            >>> z = scalar2.from_base64(
            ...     'GNDgZXmP+k7MoKfMbiuNbTJp9+tBNSXlm3MTMrAuqAVLkMic6T5EUlV/U6rl+PEy'
            ...     'IYWN3i6mpQNz8YWPEShwIQmz2veiF6IKPYcmMvjO1kPTJkmyQaZ2Ab7IVb1D8HcQ'
            ...     'iN9yK8rMj9F08WrX7xsdXmItk7fP7GOFw1PBN5Ok4Bw3HvVM2DaojhsfHhmNVm07'
            ...     'vlqiJXNDBfFMrJr5yCE1HIazZRkBBdG35xAR0TYu1q2RM6LCxCiY6evD0WBKYI8Q'
            ...     'hGHTeyRjtPiPDMtCe17qhxTuiPjDPa9+5KP0XKi8qRGHlWq7TSfeG0nl4Fn5BPu0'
            ...     'dYBHFasloXMG+g4ZbzBSFTpg36BzynjeSe3qrJxUyrPQE4dQwjwLaN55JKadG6AC'
            ...     'okrFkmIqRcWcHe1xM3lCkqCWAr1Xo2YB01Q4hG/LNw85wPp6FbNNFKtvle5b9bJr'
            ...     '1d7x5+0HNQki1EXaB9k2Ii21uqnewVLCsrz8Rs3m/SLnAnGvihZOd+WAjOYCCVof'
            ... )
            >>> (z + z).hex()[700:]
            '4a1f476a7553bd83a5dd5179f98d9acddae4c505e25e95df6734c901198d83ad9019'
            >>> isinstance(z + z, scalar2)
            True
            """
            s = self._implementation.sad(self, other)
            s.__class__ = self.__class__
            return s

        def __sub__(self: scalar, other: scalar) -> scalar:
            """
            Subtract this instance from another scalar.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (s - s).hex() == '00' * len(s)
            True
            >>> isinstance(s - s, scalar)
            True
            """
            s = self._implementation.ssu(self, other)
            s.__class__ = self.__class__
            return s

        def __neg__(self: scalar) -> scalar:
            """
            Negate this instance.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (-s).hex()
            'dcd2f36ecf096e4d52360a2fc7150aeca94ba1148e1c855ae212e3d1b004fe24'
            >>> isinstance(-s, scalar)
            True
            """
            s = self._implementation.sne(self)
            s.__class__ = self.__class__
            return s

        def __len__(self: scalar) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(scalar())
            32
            """
            return bytes(self).__len__()

        def __bytes__(self: scalar) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> s = scalar.hash('123'.encode())
            >>> bs = bytes(s)
            >>> scalar.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            """
            return self._implementation.sse(self)

        def to_bytes(self: scalar) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> s = scalar.hash('123'.encode())
            >>> bs = s.to_bytes()
            >>> scalar.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            """
            return bytes(self)

        def __int__(self: scalar) -> bytes:
            """
            Compute and return the numerical representation of this instance.

            >>> s = scalar.from_int(123)
            >>> n = int(s)
            >>> scalar.from_int(n) == s
            True
            >>> type(n) is int
            True
            """
            d_inv = 0x235f846d22752e25720e909a9e82a1b4ad47e882341d8fca46c142d23fa9bc45
            n = (int.from_bytes(self._implementation.sse(self), 'little') * d_inv) % r
            return n if (n <= r//2) else n - r

        def to_int(self: scalar) -> bytes:
            """
            Compute and return the numerical representation of this instance.

            >>> s = scalar.from_int(123)
            >>> n = s.to_int()
            >>> scalar.from_int(n) == s
            True
            >>> type(n) is int
            True
            """
            return int(self)

        def hex(self: scalar) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> s = scalar.hash('123'.encode())
            >>> s.hex()
            '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
            """
            return self.to_bytes().hex()

        def to_base64(self: scalar) -> str:
            """
            Return the Base64 UTF-8 string representation of this instance.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> s.to_base64()
            'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
            """
            return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

    class point2(_p2_base_cls): # pylint: disable=W0621,E0102
        # pylint: disable=C0301 # Accommodate large outputs in doctests.
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """
        _implementation = _implementation

        @classmethod
        def random(cls) -> point2:
            """
            Return random instance.

            >>> len(point2.random())
            192
            """
            p = cls._implementation.pnt2()
            p.__class__ = cls
            return p

        @classmethod
        def bytes(cls, bs: Union[bytes, bytearray]) -> point2:
            """
            Construct an instance that corresponds to the supplied binary
            representation.

            >>> p = point2.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.canonical().hex()[:128] == (
            ...     '4c595542640a69c4a70bda55c27ef96c133cd1f4a5f83b3371e571960c018e19'
            ...     'c54aaec2069f8f10a00f12bcbb3511cdb7356201f5277ec5e47da91405be2809'
            ... )
            True
            """
            p = cls._implementation.pnt2(bs)
            p.__class__ = cls
            return p

        @classmethod
        def hash(cls, bs: Union[bytes, bytearray]) -> point2: # pylint: disable=W0221
            """
            Construct an instance by hashing the supplied bytes-like object.

            >>> point2.hash('123'.encode()).canonical().hex()[:128] == (
            ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
            ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
            ... )
            True
            """
            p = cls._implementation.pnt2(hashlib.sha512(bs).digest()[:32])
            p.__class__ = cls
            return p

        @classmethod
        def base(cls, s: scalar) -> point2:
            """
            Return base second-level point multiplied by the supplied scalar
            if the scalar is valid; otherwise, return ``None``.

            >>> point2.base(scalar.hash('123'.encode())).canonical().hex()[:128] == (
            ...     'e7000fb12d206112c73fe1054e9d77b35c77881eba6598b7e035171d90b13e0c'
            ...     '33c8ad2c92acb446fa958f3001b6c15aaf0f00092534a9d567541f9fadc64e09'
            ... )
            True
            """
            p = cls._implementation.bas2(s)
            p.__class__ = cls
            return p

        @classmethod
        def from_bytes(cls, bs: bytes) -> point2:
            """
            Deserialize the supplied binary representation of an instance and
            return that instance.

            >>> p = point2.hash('123'.encode())
            >>> bs = p.to_bytes()
            >>> point2.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            """
            p = cls._implementation.des2(bs)
            p.__class__ = cls
            return p

        @classmethod
        def fromhex(cls, s: str) -> point2:
            """
            Construct an instance from its hexadecimal UTF-8 string representation.

            >>> p = point2.fromhex(
            ...     'ab4efa2bcdeb825a67b12a10132ae1addca840ed248f83ae7dd987370dd47a05'
            ...     '31c10b08ada0e24c0327d85b108e826a55bf3dc3286488327fac75e05e293b20'
            ...     '01cbf919b53884d02b85aab9b0091eeda114fa65ca5d75620da26c4d164aa509'
            ...     '2a2d55b6f311bfe52d24adf7b4b0b6ce12ed486a37c474d35a2b373be8a3f71c'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            >>> p.canonical().hex()[:64]
            'ab4efa2bcdeb825a67b12a10132ae1addca840ed248f83ae7dd987370dd47a05'
            """
            p = cls.from_bytes(bytes.fromhex(s))
            p.__class__ = cls
            return p

        @classmethod
        def from_base64(cls, s: str) -> point2:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> p = point2.from_base64(
            ...     'xRuTJv/OWkIPMxRoCQIqNYoSixnWfMxeYwSJnjdJwxlp9E9f6oKefvbfYlJeygmK'
            ...     'YDQniir3r/EYExFuClZ7H5X00GEqz7TcoqDl5EpwLDAvrTW3GNA2lOpHvc1F/eQc'
            ...     'obJoTn35OzzK7qd/87Y3pOKNQaNENKO19DMzw9Lt+hiO////////FYr//////zm5'
            ...     'zf////8uxqL1//9/8qQrIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ... )
            >>> p.to_base64()[-64:]
            'zf////8uxqL1//9/8qQrIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            """
            p = cls.from_bytes(base64.standard_b64decode(s))
            p.__class__ = cls
            return p

        def __new__( # pylint: disable=arguments-differ
                cls,
                bs: Union[bytes, bytearray, None] = None
            ) -> point2:
            """
            If a bytes-like object is supplied, return a second-level point
            object corresponding to the supplied bytes-like object (no check
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, a random second-level point
            is returned.

            >>> bs = bytes.fromhex(
            ...     'ab4efa2bcdeb825a67b12a10132ae1addca840ed248f83ae7dd987370dd47a05'
            ...     '31c10b08ada0e24c0327d85b108e826a55bf3dc3286488327fac75e05e293b20'
            ...     '01cbf919b53884d02b85aab9b0091eeda114fa65ca5d75620da26c4d164aa509'
            ...     '2a2d55b6f311bfe52d24adf7b4b0b6ce12ed486a37c474d35a2b373be8a3f71c'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            >>> point2.from_bytes(bs).hex() == bs.hex()
            True
            >>> point2.from_bytes(bs).to_bytes() == bs
            True
            """
            p = cls.from_bytes(bs) if bs is not None else cls.random()
            p.__class__ = cls # = point2
            return p

        def canonical(self: point2) -> point2:
            """
            Normalize the representation of this point into its canonical form
            and return the result. This takes the *z*-coordinate, which may not
            always be equal to 1, and multiplies all coordinates *x*, *y*, and
            *z* by *z*'s multiplicative inverse. The resulting canonical
            representation is unique (*i.e.*, two second-level points are equal
            if and only if their canonical forms are equal) and in the form
            (*x1*/*z1*, *y1*/*z1*, *x2*/*z2*, *y2*/*z2*, 1, 0).

            >>> a = point2.hash('123'.encode())
            >>> q = a + a + a + a
            >>> q == q
            True
            >>> q.to_bytes() == q.to_bytes()
            True
            >>> q.to_bytes() == q.canonical().to_bytes() and q.__class__ != python.point2
            False
            >>> q.canonical().to_bytes() == q.canonical().to_bytes()
            True
            >>> q.canonical().to_bytes() == q.canonical().canonical().to_bytes()
            True
            >>> point2.from_bytes(q.to_bytes()) == q
            True
            >>> point2.from_bytes(q.canonical().to_bytes()) == q
            True
            >>> point2.from_bytes(q.to_bytes()) == point2.from_bytes(bytes(q.canonical()))
            True
            >>> type(q.canonical()) is point2
            True
            """
            p = self._implementation.can(self)
            p.__class__ = self.__class__
            return p

        def __mul__(self: point2, other: Any) -> NoReturn:
            """
            Use of this method is not permitted. A point cannot be a left-hand argument.

            >>> point2() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: second-level point must be on right-hand side of multiplication operator
            """
            raise TypeError(
                'second-level point must be on right-hand side of multiplication operator'
            )

        def __rmul__(self: point2, other: Any) -> NoReturn:
            """
            This functionality is implemented exclusively in the method
            :obj:`scalar.__mul__`, as that method pre-empts this method
            when the second argument has the correct type (*i.e.*, it is
            a :obj:`scalar` instance). This method is included so that an
            exception can be raised if an incorrect argument is supplied.

            >>> p = point2.hash('123'.encode())
            >>> 2 * p
            Traceback (most recent call last):
              ...
            TypeError: second-level point can only be multiplied by a scalar
            """
            raise TypeError('second-level point can only be multiplied by a scalar')

        def __add__(self: point2, other: point2) -> Optional[point2]:
            """
            Return sum of this instance and another second-level point.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> (p + q).canonical().hex()[:128] == (
            ...     'cb0fc423c1bac2ac2df47bf5f5548a42b0d0a0da325bc77243d15dc587a7b221'
            ...     '9808a1649991ddf770f0060333aab4d499580b123f109b5cb180f1f8a75a090e'
            ... )
            True
            """
            p = self._implementation.add2(self, other)
            p.__class__ = self.__class__
            return p

        def __sub__(self: point2, other: point2) -> Optional[point2]:
            """
            Return the result of subtracting another second-level point from
            this instance.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> (p - q).canonical().hex()[:128] == (
            ...     'e97a70c4e3a5369ebbb1dcf0cc1135c8c8e04a4ec7cffdf875ac429d66846d0b'
            ...     '191b090909c40a723027b07ac44435a6ade3813d04b3632a17c92c5c98718902'
            ... )
            True
            """
            p = self._implementation.sub2(self, other)
            p.__class__ = self.__class__
            return p

        def __neg__(self: point2) -> point2:
            """
            Return the negation (additive inverse) of this instance.

            >>> p = point2.hash('123'.encode())
            >>> (-p).canonical().hex()[:128] == (
            ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
            ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
            ... )
            True
            """
            p = self._implementation.neg2(self)
            p.__class__ = self.__class__
            return p

        def __matmul__(self: point2, other: point) -> scalar2:
            """
            Return the result of pairing another point with this instance.

            Input-swapped alias of :obj:`point.__matmul__`.
            """
            return self._implementation.point.__matmul__(other, self)

        def __len__(self: point2) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(point2())
            192
            """
            return bytes(self).__len__()

        def __bytes__(self: point2) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> len(bytes(point2()))
            192
            """
            return self._implementation.ser(self)

        def to_bytes(self: point2) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> p = point2.hash('123'.encode())
            >>> bs = p.to_bytes()
            >>> point2.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            """
            return bytes(self)

        def hex(self: point2) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> p = point2.hash('123'.encode())
            >>> p.canonical().hex() == (
            ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
            ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
            ...     '2c6a88bb448065eb748df632b1d872e02f54b6f56fdb84a7b1cb388fe551fb08'
            ...     '04464efa186bd4b1371e53d6f31f0e2f50ff553b6264a43331b42c976a0c541f'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            True
            """
            return self.to_bytes().hex()

        def to_base64(self: point2) -> str:
            """
            Return the Base64 UTF-8 string representation of this instance.

            >>> p = point2.from_base64(
            ...     'zn07zy59PMhe396h9AQ+FY3LqfzmaRmbVmfwKaQqTxStH2ZPqGwBjv99STlWrenq'
            ...     'Mkfc3PCxRgM1xVaJGN+WExXhuDn4V40nkdpxtU85VFgE4aj0CMUoD99bqTEqBSYD'
            ...     '50haF1C7mDxMRxmMXZinYDEMynRY69C1vTQ5IgcCdh+O////////FYr//////zm5'
            ...     'zf////8uxqL1//9/8qQrIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            ... )
            >>> p.to_base64()[-64:]
            'zf////8uxqL1//9/8qQrIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            """
            return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

    class scalar2(_s2_base_cls): # pylint: disable=function-redefined
        """
        Class for representing second-level scalars.
        """
        _implementation = _implementation

        @classmethod
        def random(cls) -> scalar2:
            """
            Return random non-zero second-level scalar.

            >>> isinstance(scalar2.random(), scalar2)
            True
            >>> len(scalar2.random())
            384
            """
            s = cls._implementation.scl2()
            s.__class__ = cls
            return s

        @classmethod
        def bytes(cls, bs: bytes) -> Optional[scalar2]:
            """
            Return second-level scalar object obtained by transforming the
            supplied bytes-like object if it is possible to do so; otherwise,
            return ``None``.

            >>> s = scalar2()
            >>> t = scalar2.bytes(bytes(s))
            >>> s.hex() == t.hex()
            True
            """
            s = cls._implementation.scl2(bs)

            if s is not None:
                s.__class__ = cls

            return s

        @classmethod
        def hash(cls, bs: Union[bytes, bytearray]) -> scalar2:
            """
            Return an instance derived by hashing the supplied bytes-like object.

            >>> s = python.scalar2.hash(bytes([123]))
            >>> s.hex()[700:]
            'e91ed56ea67d29047d588ffaf78f9ed317ff13e7f63e53276ff32988c49184e17b22'

            >>> s0 = python.scalar2.hash(secrets.token_bytes(64))
            >>> s1 = python.scalar2.hash(secrets.token_bytes(64))
            >>> python.sse(python.smu2(python.smu2(s0, python.inv2(s0)), s1)) == python.sse(s1)
            True
            """
            def pick_exponent(bs):
                i = int.from_bytes(bs, 'little')

                # Use rejection sampling to get two valid components in F_p.
                if i >= r-1:
                    return pick_exponent(hashlib.sha512(bs).digest()[:32])

                return i+1

            bs = hashlib.sha512(bs).digest()
            exponent = pick_exponent(bs[:32])

            # Generator of paired ``scalar2`` codomain, computed from pairing
            # the base points for ``point`` and ``point2``.
            z = cls._implementation.scalar2.from_base64('X+CkvfROeA1SsbpkudwsTzqOGQC9BkDmNcYpI0GHGg'
            'TPr7fTv0yO88u5bybAlDc4QTCji5RvpdhGkWLT5oysD7UX5qE2ymq+HJXrl5MkiPp4J6kfZ6Obdjr9J/G4qs4U'
            'hNgtOCecKCgdEwI4KyCbtYu5Wv2M+IgvJbWUx4ihaB1HlDwFb6rTmaa8ckaoFtY6AoM5kbbDPgNN71441LrNC5'
            'Fp2QGPRod8+0WJ9wzl6R6cWLSV14MzoqWY6ZNDAyUPMpUaUGbIKZ3QqlpxM5EOFTTYmPQqOBY3K+tNL94yZRIM'
            'ChE3W1ph9ypDcdFNd9xloWOw/APAa4FE538HbMZFEix4XpNKKIl3WPbGhTb/iY7DuUqKXouNdw8wSvzIVEYjBY'
            '6IuE7e3fr7GMvd6K/8qO3Cep7EeuFzdMKxMO21PhuhBm2KLDPbzuzoNrMfmiMOhFJadkIa8F0NmWEEKEpyCIph'
            'CwjHidMthVF/l932N4LL6EVktec8TQrotfCCEA0O')

            def square_and_multiply_exp(s, exponent):
                if exponent == 1:
                    return s

                s = s * s

                if exponent % 2 == 1:
                    s = s * z

                return square_and_multiply_exp(s, exponent // 2)

            return square_and_multiply_exp(z, exponent)

        @classmethod
        def from_bytes(cls, bs: bytes) -> scalar2:
            """
            Deserialize the supplied binary representation of an instance and
            return that instance.

            >>> s = scalar2.hash('123'.encode())
            >>> bs = s.to_bytes()
            >>> scalar2.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            """
            s = cls._implementation.sde2(bs)
            s.__class__ = cls
            return s

        @classmethod
        def fromhex(cls, s: str) -> scalar2:
            """
            Construct an instance from its hexadecimal UTF-8 string representation.

            >>> s_hex = (
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805'
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021'
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710'
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c'
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c'
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10'
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911'
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215'
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002'
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f'
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622'
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... )
            >>> s = scalar2.fromhex(s_hex)
            >>> s.hex() == s_hex
            True
            """
            return cls.from_bytes(bytes.fromhex(s))

        @classmethod
        def from_base64(cls, s: str) -> scalar2:
            """
            Construct an instance from its Base64 UTF-8 string representation.

            >>> b64s = (
            ...     'GNDgZXmP+k7MoKfMbiuNbTJp9+tBNSXlm3MTMrAuqAVLkMic6T5EUlV/U6rl+PEy'
            ...     'IYWN3i6mpQNz8YWPEShwIQmz2veiF6IKPYcmMvjO1kPTJkmyQaZ2Ab7IVb1D8HcQ'
            ...     'iN9yK8rMj9F08WrX7xsdXmItk7fP7GOFw1PBN5Ok4Bw3HvVM2DaojhsfHhmNVm07'
            ...     'vlqiJXNDBfFMrJr5yCE1HIazZRkBBdG35xAR0TYu1q2RM6LCxCiY6evD0WBKYI8Q'
            ...     'hGHTeyRjtPiPDMtCe17qhxTuiPjDPa9+5KP0XKi8qRGHlWq7TSfeG0nl4Fn5BPu0'
            ...     'dYBHFasloXMG+g4ZbzBSFTpg36BzynjeSe3qrJxUyrPQE4dQwjwLaN55JKadG6AC'
            ...     'okrFkmIqRcWcHe1xM3lCkqCWAr1Xo2YB01Q4hG/LNw85wPp6FbNNFKtvle5b9bJr'
            ...     '1d7x5+0HNQki1EXaB9k2Ii21uqnewVLCsrz8Rs3m/SLnAnGvihZOd+WAjOYCCVof'
            ... )
            >>> s = scalar2.from_base64(b64s)
            >>> s.to_base64() == b64s
            True
            """
            return cls.from_bytes(base64.standard_b64decode(s))

        def __new__( # pylint: disable=arguments-differ
                cls,
                bs: Union[bytes, bytearray, None] = None
            ) -> scalar2:
            """
            If a bytes-like object is supplied, return an instance that corresponds
            to the supplied bytes-like object (no checking is performed to confirm
            that the bytes-like object is a valid second-level scalar). If no
            argument is supplied, return a random scalar object.
            """
            return cls.from_bytes(bs) if bs is not None else cls.random()

        def __invert__(self: scalar2) -> scalar2:
            """
            Return the inverse of this instance.

            >>> s = scalar2.hash('123'.encode())
            >>> ~(~s) == s
            True
            >>> ~s == s
            False
            >>> bytes(~s).hex()[700:] == (
            ...     'ff13804852ea3ad35e8316d90a6d5dde854517e74cfc27ba676f429eb4fd52cd9b0c'
            ... )
            True
            """
            s = self._implementation.inv2(self)
            s.__class__ = self.__class__
            return s

        def __mul__(self: scalar2, other: scalar2) -> scalar2:
            """
            Multiply this instance by another second-level scalar.

            >>> s = scalar2.from_base64(
            ...     'GNDgZXmP+k7MoKfMbiuNbTJp9+tBNSXlm3MTMrAuqAVLkMic6T5EUlV/U6rl+PEy'
            ...     'IYWN3i6mpQNz8YWPEShwIQmz2veiF6IKPYcmMvjO1kPTJkmyQaZ2Ab7IVb1D8HcQ'
            ...     'iN9yK8rMj9F08WrX7xsdXmItk7fP7GOFw1PBN5Ok4Bw3HvVM2DaojhsfHhmNVm07'
            ...     'vlqiJXNDBfFMrJr5yCE1HIazZRkBBdG35xAR0TYu1q2RM6LCxCiY6evD0WBKYI8Q'
            ...     'hGHTeyRjtPiPDMtCe17qhxTuiPjDPa9+5KP0XKi8qRGHlWq7TSfeG0nl4Fn5BPu0'
            ...     'dYBHFasloXMG+g4ZbzBSFTpg36BzynjeSe3qrJxUyrPQE4dQwjwLaN55JKadG6AC'
            ...     'okrFkmIqRcWcHe1xM3lCkqCWAr1Xo2YB01Q4hG/LNw85wPp6FbNNFKtvle5b9bJr'
            ...     '1d7x5+0HNQki1EXaB9k2Ii21uqnewVLCsrz8Rs3m/SLnAnGvihZOd+WAjOYCCVof'
            ... )
            >>> bytes(s * s).hex()[700:]
            '6f11685b89b03431dac6dc9d129c6a31cc5e3036f7f781d7460ab9f532a06845bd15'
            >>> scalar2() * point()
            Traceback (most recent call last):
              ...
            TypeError: second-level scalar can only be multiplied by another second-level scalar
            """
            if isinstance(other, self._implementation.scalar2):
                s = self._implementation.smu2(self, other)
                s.__class__ = self.__class__
                return s

            raise TypeError(
                'second-level scalar can only be multiplied by another second-level scalar'
            )

        def __rmul__(self: scalar2, other: Any) -> NoReturn:
            """
            A second-level scalar cannot be on the right-hand side of a non-scalar.

            >>> 2 * scalar2()
            Traceback (most recent call last):
              ...
            TypeError: second-level scalar must be on left-hand side of multiplication operator
            """
            raise TypeError(
                'second-level scalar must be on left-hand side of multiplication operator'
            )

        def __add__(self: scalar2, other: scalar2) -> scalar2:
            """
            Add another second-level scalar to this instance.

            >>> z = scalar2.from_base64(
            ...     'GNDgZXmP+k7MoKfMbiuNbTJp9+tBNSXlm3MTMrAuqAVLkMic6T5EUlV/U6rl+PEy'
            ...     'IYWN3i6mpQNz8YWPEShwIQmz2veiF6IKPYcmMvjO1kPTJkmyQaZ2Ab7IVb1D8HcQ'
            ...     'iN9yK8rMj9F08WrX7xsdXmItk7fP7GOFw1PBN5Ok4Bw3HvVM2DaojhsfHhmNVm07'
            ...     'vlqiJXNDBfFMrJr5yCE1HIazZRkBBdG35xAR0TYu1q2RM6LCxCiY6evD0WBKYI8Q'
            ...     'hGHTeyRjtPiPDMtCe17qhxTuiPjDPa9+5KP0XKi8qRGHlWq7TSfeG0nl4Fn5BPu0'
            ...     'dYBHFasloXMG+g4ZbzBSFTpg36BzynjeSe3qrJxUyrPQE4dQwjwLaN55JKadG6AC'
            ...     'okrFkmIqRcWcHe1xM3lCkqCWAr1Xo2YB01Q4hG/LNw85wPp6FbNNFKtvle5b9bJr'
            ...     '1d7x5+0HNQki1EXaB9k2Ii21uqnewVLCsrz8Rs3m/SLnAnGvihZOd+WAjOYCCVof'
            ... )
            >>> (z + z).hex()[700:]
            '4a1f476a7553bd83a5dd5179f98d9acddae4c505e25e95df6734c901198d83ad9019'
            >>> isinstance(z + z, scalar2)
            True
            """
            s = self._implementation.sad2(self, other)
            s.__class__ = self.__class__
            return s

        def __len__(self: scalar2) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(scalar2.random())
            384
            """
            return bytes(self).__len__()

        def __bytes__(self: scalar2) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> s = scalar2.hash('123'.encode())
            >>> bs = bytes(s)
            >>> scalar2.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            >>> len(bs)
            384
            """
            self.__class__ = self.__class__._implementation.scalar2
            return self._implementation.sse(self)

        def to_bytes(self: scalar2) -> bytes:
            """
            Serialize this instance and return its binary representation.

            >>> s = scalar2.hash('123'.encode())
            >>> bs = s.to_bytes()
            >>> scalar2.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            >>> len(bs)
            384
            """
            return bytes(self)

        def hex(self: scalar2) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> s = scalar2.from_base64(
            ...     'GNDgZXmP+k7MoKfMbiuNbTJp9+tBNSXlm3MTMrAuqAVLkMic6T5EUlV/U6rl+PEy'
            ...     'IYWN3i6mpQNz8YWPEShwIQmz2veiF6IKPYcmMvjO1kPTJkmyQaZ2Ab7IVb1D8HcQ'
            ...     'iN9yK8rMj9F08WrX7xsdXmItk7fP7GOFw1PBN5Ok4Bw3HvVM2DaojhsfHhmNVm07'
            ...     'vlqiJXNDBfFMrJr5yCE1HIazZRkBBdG35xAR0TYu1q2RM6LCxCiY6evD0WBKYI8Q'
            ...     'hGHTeyRjtPiPDMtCe17qhxTuiPjDPa9+5KP0XKi8qRGHlWq7TSfeG0nl4Fn5BPu0'
            ...     'dYBHFasloXMG+g4ZbzBSFTpg36BzynjeSe3qrJxUyrPQE4dQwjwLaN55JKadG6AC'
            ...     'okrFkmIqRcWcHe1xM3lCkqCWAr1Xo2YB01Q4hG/LNw85wPp6FbNNFKtvle5b9bJr'
            ...     '1d7x5+0HNQki1EXaB9k2Ii21uqnewVLCsrz8Rs3m/SLnAnGvihZOd+WAjOYCCVof'
            ... )
            >>> s.hex() == (
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805'
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021'
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710'
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c'
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c'
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10'
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911'
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215'
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002'
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f'
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622'
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... )
            True
            """
            return self.to_bytes().hex()

        def to_base64(self: scalar2) -> str:
            """
            Return the Base64 UTF-8 string representation of this instance.

            >>> b64s = (
            ...     'GNDgZXmP+k7MoKfMbiuNbTJp9+tBNSXlm3MTMrAuqAVLkMic6T5EUlV/U6rl+PEy'
            ...     'IYWN3i6mpQNz8YWPEShwIQmz2veiF6IKPYcmMvjO1kPTJkmyQaZ2Ab7IVb1D8HcQ'
            ...     'iN9yK8rMj9F08WrX7xsdXmItk7fP7GOFw1PBN5Ok4Bw3HvVM2DaojhsfHhmNVm07'
            ...     'vlqiJXNDBfFMrJr5yCE1HIazZRkBBdG35xAR0TYu1q2RM6LCxCiY6evD0WBKYI8Q'
            ...     'hGHTeyRjtPiPDMtCe17qhxTuiPjDPa9+5KP0XKi8qRGHlWq7TSfeG0nl4Fn5BPu0'
            ...     'dYBHFasloXMG+g4ZbzBSFTpg36BzynjeSe3qrJxUyrPQE4dQwjwLaN55JKadG6AC'
            ...     'okrFkmIqRcWcHe1xM3lCkqCWAr1Xo2YB01Q4hG/LNw85wPp6FbNNFKtvle5b9bJr'
            ...     '1d7x5+0HNQki1EXaB9k2Ii21uqnewVLCsrz8Rs3m/SLnAnGvihZOd+WAjOYCCVof'
            ... )
            >>> s = scalar2.from_base64(b64s)
            >>> s.to_base64() == b64s
            True
            """
            return base64.standard_b64encode(bytes(self)).decode('utf-8')

    # Encapsulate classes for this implementation, regardless of which are
    # exported as the unqualified symbols.
    _implementation.point = point
    _implementation.scalar = scalar
    _implementation.point2 = point2
    _implementation.scalar2 = scalar2

# Remove method for which no pure-Python implementation exists.
delattr(python.point, '__matmul__')
delattr(python.point2, '__matmul__')

# Redefine top-level wrapper classes to ensure that they appear at the end of
# the auto-generated documentation.
python = python # pylint: disable=self-assigning-variable
mcl = mcl # pylint: disable=self-assigning-variable

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
