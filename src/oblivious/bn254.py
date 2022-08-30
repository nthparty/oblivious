"""
.. module:: bn254

bn254 module
============

This module exports a collection of primitive operations for working
with elliptic curve points and scalars, classes for representing points,
classes for representing scalars, and two wrapper classes/namespaces that
encapsulate pure-Python and shared/dynamic library variants of the above.

* Under all conditions, the wrapper class :obj:`~oblivious.bn254.native`
  is defined and exports a pure-Python variant of every operation and class
  method exported by this module as a whole.

* If the optional `mclbn256 <https://pypi.org/project/mclbn256>`__ package
  is installed, then the wrapper class :obj:`mcl` is defined and exports
  a wrapper around the appropriate function in the dynamic/shared library
  for every operation and class method exported by this module as a whole.
  Otherwise, the exported variable ``mcl`` is assigned ``None``.

* All operations and class methods exported by this module correspond to
  the variants defined by :obj:`~oblivious.bn254.mcl` if a dynamic/shared
  library is loaded. Otherwise, they correspond to the variants defined by
  :obj:`~oblivious.bn254.native`.
"""
from __future__ import annotations
from typing import Union, Optional
import doctest
import hashlib
import base64
import secrets
from bn254.ecp import generator as get_base
from bn254.ecp2 import generator as get_base2
from bn254.pair import e
from bn254 import big as bn, Fp12 as Fp12_
from bn254.ecp import ECp as ECp_
from bn254.ecp2 import ECp2 as ECp2_
from bn254.curve import r#, p as p_mod

# pylint: disable=too-many-lines

class _ECp(ECp_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    def __new__(cls, *args, **kwargs):
        p = ECp_.__new__(cls)
        _ECp.__init__(p, *args, **kwargs)
        return p

    def __init__(self, p=None):
        ECp_.__init__(self) #super(ECp_, self).__init__() # pylint: disable=bad-super-call
        if isinstance(p, (ECp_, _ECp)):
            self.setxy(*p.get())
        elif isinstance(p, native.point):
            self.setxy(*_ECp.deserialize(p).get())  # -or- `self.__class__.deserialize`

    def serialize_compressed(self) -> bytes:
        # pylint: disable=unnecessary-direct-lambda-call
        return bytes(
            (lambda x, y:
                (lambda xs:
                    (lambda ret,_: ret)(xs, xs.append(xs.pop() ^ ((y % 2) << 7)))
                )(list(x.to_bytes(32, 'little')))
            )(*self.get())
        )

    @classmethod
    def deserialize_compressed(cls, bs) -> bytes:
        return _ECp(
            (1 - 2 * (bs[31] >> 7)) *
            cls.mapfrom(bs[:31] + bytes([bs[31] & 0b01111111]))
        )

    def serialize(self) -> bytes:
        d = 0x212ba4f27ffffff5a2c62effffffffcdb939ffffffffff8a15ffffffffffff8e
        p = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        x, y, z = (*self.get(), 1)
        encode = lambda n: (n * d % p).to_bytes(32, 'little')
        return encode(x) + encode(y) + encode(z)

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
    def random(cls) -> _ECp:
        return cls(int(native.scalar.random()) * get_base())

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
                        t = pow(t, 2, p_mod)
                    if m == 0:
                        break
                    gs = pow(g, 2**(r_ - m - 1), p_mod)
                    g = (gs * gs) % p_mod
                    y = (y * gs) % p_mod
                    b = (b * g) % p_mod
                    r_ = m
            if y is not None:
                # pylint: disable=invalid-unary-operand-type
                if y % 2 == 1:
                    y = -y
                break
            x += 1

        p = cls()
        assert p.setxy(x, y) or (x == 0 and y == 0)
        return p

    def hex(self):
        return self.to_bytes().hex() # pylint: disable=no-member

    def zero(self):
        return self.isinf()

    def __bytes__(self):
        return self.to_bytes() # pylint: disable=no-member

class _ECp2(ECp2_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    def __new__(cls, *args, **kwargs):
        q = ECp2_.__new__(cls)
        _ECp2.__init__(q, *args, **kwargs)
        return q

    def __init__(self, q=None):
        ECp2_.__init__(self)# super(ECp2_, self).__init__() # pylint: disable=bad-super-call
        if isinstance(q, (ECp2_, _ECp2)):
            self.set(*q.get())
        elif isinstance(q, native.point2):
            self.set(*_ECp2.deserialize(bytes(q)).get())  # -or- `self.__class__.deserialize`

    def __hex__(self):
        return self.toBytes(1).hex()

    def hex(self):
        return self.toBytes(1).hex()

    def serialize_compressed(self) -> bytes:
        # pylint: disable=unnecessary-direct-lambda-call
        return bytes(
            (lambda f, x1, y1, x2, y2: f(x1, y1) + f(x2, y2))(
                (lambda x, y:
                 (lambda xs:
                  (lambda ret, _: ret)(
                      xs, xs.append(xs.pop() ^ ((y % 2) << 7))
                  ))(
                     list(x.to_bytes(32, 'little'))
                 )
                 ),
                self.x.a.int(), self.y.a.int(),
                self.x.b.int(), self.y.b.int()
            )
        )

    def serialize(self) -> bytes:
        d = 0x212ba4f27ffffff5a2c62effffffffcdb939ffffffffff8a15ffffffffffff8e
        p = 0x2523648240000001ba344d80000000086121000000000013a700000000000013# BN254 modulus of F_p
        p1, p2 = (*self.get(),)
        x1, y1, z1, x2, y2, z2 = (*p1.get(), 1, *p2.get(), 0)
        encode = lambda n: (n * d % p).to_bytes(32, 'little')
        return encode(x1) + encode(y1) + encode(x2) + encode(y2) + encode(z1) + encode(z2)

    @classmethod
    def deserialize(cls, bs) -> _ECp2:
        p_mod = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        d_inv = 0x1a7344bac91f117ea513ec0ed5682406b6c15140174d61b28b762ae9cf6d3b46
        decode = lambda ns: (int.from_bytes(ns, 'little') * d_inv) % p_mod
        x1, y1, x2, y2, z1, z2 = (decode(bs[:32]), decode(bs[32:64]), decode(bs[64:64+32]),
                                  decode(bs[64+32:128]), decode(bs[128:128+32]), decode(bs[-32:]))
        z2 = z2-(z2&1)+1  # 1 if z2==0 else z2

        # Compute affine coordinates
        inv_z1 = bn.invmodp(z1, p_mod)
        x1 = (x1 * inv_z1) % p_mod
        y1 = (y1 * inv_z1) % p_mod
        inv_z2 = bn.invmodp(z2, p_mod)
        x2 = (x2 * inv_z2) % p_mod
        y2 = (y2 * inv_z2) % p_mod

        q = cls()
        # pylint: disable=invalid-name
        Fp = q.x.a.__class__ # Could also import from the bn254 package or copy xy's from two ECp's.
        # q.x.a .x, q.y.a .x = Fp(x1), Fp(y1)
        # q.x.b .x, q.y.b .x = Fp(x2), Fp(y2)
        Fp2 = q.get()[0].__class__
        assert q.set(Fp2(Fp(x1), Fp(y1)), Fp2(Fp(x2), Fp(y2))) \
               or (x1 == 0 and y1 == 0 and x2 == 0 and y2 == 0)
        return q

    def __bytes__(self):
        return self.to_bytes() # pylint: disable=no-member

    def zero(self):
        return self.isinf()

    @classmethod
    def random(cls) -> _ECp2:
        return cls(int(native.scalar.random()) * get_base2())

    @classmethod
    def mapfrom(cls, h) -> _ECp2:
        return cls((int.from_bytes(h, 'little') % r) * get_base2())
        #raise NotImplementedError("no native support for direct mapping into point2")


class _Fp12(Fp12_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    def __new__(cls, *args, **kwargs):
        q = Fp12_.__new__(cls)
        _Fp12.__init__(q, *args, **kwargs)
        return q

    def __init__(self, s=None):
        Fp12_.__init__(self) #super(Fp12_, self).__init__() # pylint: disable=bad-super-call
        if isinstance(s, (Fp12_, _Fp12)):
            self.set(*s.get())
        elif isinstance(s, native.scalar2):
            self.set(*_Fp12.deserialize(s).get())  # -or- `self.__class__.deserialize`

    def __hex__(self):
        return self.toBytes(1).hex() # pylint: disable=too-many-function-args

    def hex(self):
        return self.toBytes(1).hex() # pylint: disable=too-many-function-args

    def serialize(self) -> bytes:
        d = 0x212ba4f27ffffff5a2c62effffffffcdb939ffffffffff8a15ffffffffffff8e
        p = 0x2523648240000001ba344d80000000086121000000000013a700000000000013# BN254 modulus of F_p
        encode = lambda n: (n * d % p).to_bytes(32, 'little')
        return bytes(
            encode(self.a.a.a.int()) + encode(self.a.a.b.int()) +
            encode(self.a.b.a.int()) + encode(self.a.b.b.int()) +
            encode(self.b.a.a.int()) + encode(self.b.a.b.int()) +
            encode(self.b.b.a.int()) + encode(self.b.b.b.int()) +
            encode(self.c.a.a.int()) + encode(self.c.a.b.int()) +
            encode(self.c.b.a.int()) + encode(self.c.b.b.int())
        )

    @classmethod
    def deserialize(cls, bs) -> _Fp12:
        p_mod = 0x2523648240000001ba344d80000000086121000000000013a700000000000013
        d_inv = 0x1a7344bac91f117ea513ec0ed5682406b6c15140174d61b28b762ae9cf6d3b46
        decode = lambda ns: (int.from_bytes(ns, 'little') * d_inv) % p_mod
        s = _Fp12()
        # s.set(Fp2(Fp(),),)
        s.a.a.a.x, s.a.a.b.x = decode(bs[32*0:(32*0)+32]), decode(bs[32*1:(32*1)+32])
        s.a.b.a.x, s.a.b.b.x = decode(bs[32*2:(32*2)+32]), decode(bs[32*3:(32*3)+32])
        s.b.a.a.x, s.b.a.b.x = decode(bs[32*4:(32*4)+32]), decode(bs[32*5:(32*5)+32])
        s.b.b.a.x, s.b.b.b.x = decode(bs[32*6:(32*6)+32]), decode(bs[32*7:(32*7)+32])
        s.c.a.a.x, s.c.a.b.x = decode(bs[32*8:(32*8)+32]), decode(bs[32*9:(32*9)+32])
        s.c.b.a.x, s.c.b.b.x = decode(bs[32*10:(32*10)+32]), decode(bs[32*11:(32*11)+32])
        return s

    def __bytes__(self):
        return self.to_bytes() # pylint: disable=no-member

    def zero(self):
        return self.isinf() # pylint: disable=no-member

    @classmethod
    def random(cls) -> _Fp12:
        return _Fp12(int(native.scalar.random()) * get_base2())

#
# An attempt will be made later to import mclbn256. If the MCl shared/dynamic
# library file bundled with mclbn256 does not load, only native Python
# implementations of the functions and methods will be available.
#

mclbn256 = None

#
# Use native Python implementations of primitives by default.
#

# pylint: disable=C2801,W0621
class native:
    """
    Wrapper class for native Python implementations of
    primitive operations.

    This class encapsulates pure Python variants of all
    primitive operations and classes exported by this module:
    :obj:`native.scl <scl>`, :obj:`native.rnd <rnd>`,
    :obj:`native.inv <inv>`, :obj:`native.smu <smu>`,
    :obj:`native.sad <sad>`, :obj:`native.ssb <ssb>`,
    :obj:`native.sne <sne>`, :obj:`native.pnt <pnt>`,
    :obj:`native.bas <bas>`, :obj:`native.mul <mul>`,
    :obj:`native.add <add>`, :obj:`native.sub <sub>`,
    :obj:`native.neg <neg>`, :obj:`native.par <par>`,
    :obj:`native.ser <ser>`, :obj:`native.des <des>`,
    :obj:`native.sse <sse>`, :obj:`native.sde <sde>`,
    :obj:`native.rnd2 <rnd2>`, :obj:`native.scl2 <scl2>`,
    :obj:`native.inv2 <inv2>`, :obj:`native.smu2 <smu2>`,
    :obj:`native.sad2 <sad2>`, :obj:`native.pnt2 <pnt2>`,
    :obj:`native.bas2 <bas2>`, :obj:`native.mul2 <mul2>`,
    :obj:`native.add2 <add2>`, :obj:`native.sub2 <sub2>`,
    :obj:`native.neg2 <neg2>`, :obj:`native.des2 <des2>`,
    :obj:`native.sde2 <sde2>`,
    :obj:`native.point <point>`, :obj:`native.scalar <scalar>`,
    :obj:`native.point <point2>`, and :obj:`native.scalar <scalar2>`.
    For example, you can perform multiplication of scalars
    using the pure Python scalar multiplication implementation.

    >>> s = native.scl()
    >>> t = native.scl()
    >>> native.smu(s, t) == native.smu(t, s)
    True

    Pure Python variants of the :obj:`native.point <point>`
    and :obj:`native.scalar <scalar>` classes always employ pure
    Python implementations of operations when their methods are
    invoked.

    >>> p = native.scalar()
    >>> q = native.scalar()
    >>> p * q == q * p
    True
    """

    @staticmethod
    def rnd() -> scalar:
        """
        Return random non-zero scalar.

        >>> isinstance(native.rnd(), native.scalar)
        True
        """
        # d = 0x212ba4f27ffffff5a2c62effffffffd00242ffffffffff9c39ffffffffffffb2
        # return int.to_bytes(((secrets.randbelow(r-1)+1) * d) % r, 32, 'little')

        return native.scalar(int.to_bytes(secrets.randbelow(r-1)+1, 32, 'little'))

    @classmethod
    def scl(cls, s: Union[bytes, bytearray, None] = None) -> Optional[scalar]:
        """
        Construct a scalar if the supplied bytes-like object represents
        a valid scalar; otherwise, return ``None``. If no byte vector is
        supplied, return a random scalar.

        >>> s = native.scl()
        >>> t = native.scl(s)
        >>> s == t
        True
        >>> native.scl(bytes([255] * 32)) is None
        True
        """
        if s is None:
            return native.rnd()

        if int.from_bytes(s, 'little') < r:
            return bytes.__new__(native.scalar, s)

        return None

    @staticmethod
    def inv(s: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        ``r=16798108731015832284940804142231733909759579603404752749028378864165570215949``
        in the prime field `F*_r`.

        >>> s = native.scl()
        >>> p = native.pnt()
        >>> native.mul(native.inv(s), native.mul(s, p)) == p
        True
        """
        return native.scalar.from_int(bn.invmodp(int(s), r))

    @staticmethod
    def smu(s: scalar, t: scalar) -> scalar:
        """
        Return scalar multiplied by another scalar.

        >>> s = native.scl()
        >>> t = native.scl()
        >>> native.smu(s, t) == native.smu(t, s)
        True
        """
        n = (native.scalar.__int__(s) * native.scalar.__int__(t)) % r
        return native.scalar.from_int(n)

    @staticmethod
    def sad(s: scalar, t: scalar) -> scalar:
        """
        Return scalar added to another scalar.

        >>> s = native.scl()  # Could be `native.scl()`.
        >>> t = native.scl()
        >>> native.sad(s, t) == native.sad(t, s)
        True
        """
        return native.scalar.from_int((int(s) + int(t)) % r)

    @staticmethod
    def sad2(s: scalar2, t: scalar2) -> scalar2:
        """
        Return scalar2 added to another scalar2.

        >>> s = native.scl2()
        >>> t = native.scl2()
        >>> native.sad2(s, t) == native.sad2(t, s)
        True
        """
        return bytes.__new__(native.scalar2,
                             _Fp12(_Fp12.deserialize(s) + _Fp12.deserialize(t)).serialize())
        #return native.scalar2.from_int((int(s) + int(t)) % r)

    @staticmethod
    def sne(s: scalar) -> scalar:
        """
        Return the additive inverse of a scalar.

        >>> s = native.scl()
        >>> t = native.scl()
        >>> native.sne(native.sne(s)) == s
        True
        """
        return native.scalar.from_int(r-int(s)) # or (-int(s) % r)

    @staticmethod
    def ssb(s: scalar, t: scalar) -> scalar:
        """
        Return the result of one scalar subtracted from another scalar.

        >>> s = native.scl()
        >>> t = native.scl()
        >>> native.ssb(s, t) == native.sad(s, native.sne(t))
        True
        >>> native.ssb(s, t) == native.sne(native.ssb(t, s))
        True
        """
        return native.scalar.from_int((int(s) - int(t)) % r)

    @staticmethod
    def pnt(h: bytes = None) -> point:
        """
        Return point from 64-byte vector (normally obtained via hashing).

        >>> p = native.pnt(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()[:64]
        '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
        """
        return bytes.__new__(native.point,
                             (_ECp.random() if h is None else _ECp.mapfrom(h)).serialize())

    @staticmethod
    def bas(s: scalar) -> point:  # G1:
        """
        Return base point multiplied by supplied scalar.

        >>> bytes(native.bas(native.scalar.hash('123'.encode()))).hex()[:64]
        '2d66076815cda25556bab4a930244ac284412267e9345aceb98d71530308401a'
        """
        # Faster: _ECp.deserialize_compressed(bytes.fromhex(
        #   '12000000000000a7130000000000216108000000804d34ba01000040826423a5')).serialize()
        # Or: 8500000000000091890000000000e7a73a000000801e6e170c0000c08fbff7038effffffffffff
        #     158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b218effffffffffff158affffffffff
        #     39b9cdffffffff2ec6a2f5ffff7ff2a42b21
        return bytes.__new__(native.point, _ECp(int(s) * get_base()).serialize())

    @staticmethod
    def bas2(s: scalar) -> point2:  # G2:
        """
        Return base point multiplied by supplied scalar.

        >>> bytes(native.bas2(native.scalar.hash('123'.encode()))).hex()[:64]
        'e7000fb12d206112c73fe1054e9d77b35c77881eba6598b7e035171d90b13e0c'
        """
        # return s * _ECp2.__new__(native.point2, get_base2())
        return bytes.__new__(native.point2, _ECp2(int(s) * get_base2()).serialize())

    @staticmethod
    def mul2(s: scalar, p: point2) -> point2:
        """
        Multiply a second-group point by a scalar.

        >>> p = native.point2.hash('123'.encode())
        >>> s = native.scl(bytes.fromhex(
        ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
        ... ))
        >>> native.point2.to_bytes(native.mul2(s, p)).hex() == (
        ...     '5f6f2ace8566ca47354fbe244ae3e6a854c37011fb6d6ac56571c94169e4ab18'
        ...     '650bea4cfed5c9603e5949fe3d7509b17e20db4ff1f05129aad0d0a3bffb0008'
        ...     '3043c5a14b986882836b1c929952ea3881d04ca44d487d1ab2d4c0b171b87d14'
        ...     '5dca6dabb4f0ea7be5c95a861ed319d146b15d70542d3952af995a8bb35b8314'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(native.point2, _ECp2(int(s) * _ECp2.deserialize(p)).serialize())

    @staticmethod
    def add2(p: point2, q: point2) -> point2:
        """
        Return sum of the supplied second-group points.

        >>> p = native.point2.hash('123'.encode())
        >>> q = native.point2.hash('456'.encode())
        >>> native.point2.to_bytes(native.add2(p, q)).hex() == (
        ...     'cb0fc423c1bac2ac2df47bf5f5548a42b0d0a0da325bc77243d15dc587a7b221'
        ...     '9808a1649991ddf770f0060333aab4d499580b123f109b5cb180f1f8a75a090e'
        ...     '83dd34d9ecdd6fd639230f7f0cf44b218fae4d879111de6c6c037e6ffdcdc823'
        ...     'f5a48318143873ca90ad512a2ea1854200eea5537cd0ac93691d5b94ff36b212'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(native.point2,
                             _ECp2(_ECp2.deserialize(p).add(_ECp2.deserialize(q))).serialize())

    @staticmethod
    def sub2(p: point2, q: point2) -> point2:
        """
        Return result of subtracting one second-group point from another.

        >>> p = native.point2.hash('123'.encode())
        >>> q = native.point2.hash('456'.encode())
        >>> native.point2.to_bytes(native.sub2(p, q)).hex() == (
        ...     'e97a70c4e3a5369ebbb1dcf0cc1135c8c8e04a4ec7cffdf875ac429d66846d0b'
        ...     '191b090909c40a723027b07ac44435a6ade3813d04b3632a17c92c5c98718902'
        ...     '407c58ed13cc0c0aaa43d0eafd44080080c8199401fe4f8ed7dd0eb5fba86817'
        ...     '141f74341ce3c4884f86a97f51f7c0b208fe52be336b7651252fa9881c93d203'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(native.point2,
                             _ECp2(_ECp2.deserialize(p).add(-1 * _ECp2.deserialize(q))).serialize())

    @staticmethod
    def neg2(p: point2) -> point2:
        """
        Return the negation of a second-group point.

        >>> p = native.point2.hash('123'.encode())
        >>> native.point2.to_bytes(native.neg2(p)).hex() == (
        ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
        ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
        ...     'e7957744bb7f9abb9e7209cd4e27ae80d8ab490a1072af125034c7b09c12281c'
        ...     '0fbab105e7942bf5dbe1ac290ce01232b800aac41de98f86d04bd3a81758cf05'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        True
        """
        return bytes.__new__(native.point2, _ECp2(-1 * _ECp2.deserialize(p)).serialize())

    @staticmethod
    def par(p: Union[point, point2], q: Union[point, point2]) -> scalar2:
        """
        Compute the pairing function on two points.

        >>> p = native.point.hash('123'.encode())
        >>> q = native.point2.base(native.scalar.from_int(456))
        >>> z = native.par(p, q).hex()[700:]
        >>> z_mcl    = 'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'
        >>> z_native = '731ff16849a86c40280717696a8aa44fbe16f565f087d003413d141de7f5d109fc0c'
        >>> mclbn256 = p.__class__ != native.point # (In case both native and mcl are defined.)
        >>> z == z_mcl if mclbn256 else z == z_native
        True

        After the ``finalExp`` `function <gist.github.com/wyatt-howe/0ca575e99b73dada1f7fb63862a23a71>`__
        from the MCl library (not yet implemented here or in the pure-Python library), the hexadecimal
        result is: ``'3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'``.

        The pairing function is bilinear.

        >>> p = native.point.random()
        >>> s = native.scalar.random()

        >>> t = native.scalar.random()
        >>> q = native.point2.random()
        >>> -((~s) * (s * p)) - p == native.scalar.from_int(-2) * p
        True
        >>> s*t*p @ q == s*p @ (t*q)
        True

        >>> x = y = p

        Suppose there are two points: one multiplied by the scalar ``s`` and the other
        multiplied by the scalar ``t``. Their equality can be determined by using a
        balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
        same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

        >>> g = native.point2.base(native.scalar.from_int(1))
        >>> b = native.point2.base(~s * t)
        >>> (t * x) @ g == (s * y) @ b
        True
        """
        _p, _q = (p, q) if (isinstance(p, native.point) and isinstance(q, native.point2)) else (
            (q, p) if (isinstance(q, native.point) and isinstance(p, native.point2)) else (None, None)
        )
        if type(_p) is type(None): # pylint: disable=unidiomatic-typecheck
            raise TypeError(
                "can only pair points of types point/ECp/G1 and point(2)/ECp2/G2 to each other"
            )
        p_ = _ECp.__new__(ECp_, _p)
        q_ = _ECp2.__new__(ECp2_, _q)
        z_ = e(q_, p_)
        return bytes.__new__(native.scalar2, _Fp12(z_).serialize())

    @staticmethod
    def mul(s: scalar, p: point) -> point:
        """
        Multiply the point by the supplied scalar and return the result.

        >>> p = native.pnt(hashlib.sha512('123'.encode()).digest())
        >>> s = native.scl(bytes.fromhex(
        ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
        ... ))
        >>> native.mul(s, p).hex()[:64]
        '68b5dd61adaa83f1511efe7b4749481cc9f86e11bf82d82960b6c56373de0d24'
        """
        return bytes.__new__(native.point, _ECp(int(s) * _ECp.deserialize(p)).serialize())

    @staticmethod
    def add(p: point, q: point) -> point:
        """
        Return sum of the supplied points.

        >>> p = native.point.hash('123'.encode())
        >>> q = native.point.hash('456'.encode())
        >>> native.point.to_bytes(native.add(p, q)).hex()[:64]
        '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
        >>> native.add(native.sub(p, q), q) == p
        True
        """
        return bytes.__new__(native.point,
                             _ECp.serialize(_ECp.deserialize(p).add(_ECp.deserialize(q))))

    @staticmethod
    def sub(p: point, q: point) -> point:
        """
        Return result of subtracting second point from first point.

        >>> p = native.point.hash('123'.encode())
        >>> q = native.point.hash('456'.encode())
        >>> native.sub(p, q).hex()[:64]
        'a43a5ce1931b1300b62e5d7e1b0c691203bfd85fafd9585dc5e47a7e2acfea22'
        >>> native.sub(native.add(p, q), q) == p
        True
        """
        return bytes.__new__(native.point,
                             _ECp.serialize(_ECp.deserialize(p).add(-1 * _ECp.deserialize(q))))

    @staticmethod
    def nrm(p: Union[point, point2]) -> None:
        """
        Normalize a point (in place).

        >>> a = native.point.hash('123'.encode())
        >>> p = native.add(a, a)
        >>> p_nrm = native.add(a, a); native.nrm(p_nrm)

        We may have ``ser(p_nrm) != ser(p)`` here, depending on the backend
        implementation.  Either normalization matters, or MCl is not the backend.
        >>> mclbn256 = p.__class__ != native.point # Use this for now while both backends are in use
        >>> (native.ser(p_nrm) != native.ser(p)) or not mclbn256
        True

        Normalization is idempotent.
        >>> native.nrm(p); native.nrm(p_nrm)
        >>> (          p ==           p_nrm )
        True
        """
        # The point's coordinates are already in normal affine form.

    @staticmethod
    def ser(p: Union[point, point2]) -> bytes:
        """
        Return the binary representation of a point.

        >>> p = native.point.hash('123'.encode())
        >>> native.des(native.ser(p)) == p
        True

        >>> q = native.point2.hash('123'.encode())
        >>> native.des(native.ser(q)) == q
        True
        """
        return bytes(b for b in p)

    @staticmethod
    def des(bs: bytes) -> point:  # G1:
        """
        Return a point from its binary representation.

        >>> p = native.point.hash('123'.encode())
        >>> native.ser_p = bytes.fromhex(
        ...     '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
        ...     'b03c992ec97868be765b98048118a96f42bdc466a963c243c223b95196304209'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ... )
        >>> native.des(native.ser_p) == p
        True
        >>> native.ser(native.des(native.ser_p)) == native.ser_p
        True
        """
        return bytes.__new__(native.point, bs)
        # It may be useful to debug with _ECp.deserialize(bs).serialize() in place of just bs.

    @staticmethod
    def sse(s: scalar) -> bytes:
        """
        Return the binary representation of a scalar.

        >>> s = native.scalar.hash('123'.encode())
        >>> native.sde(native.sse(s)) == s
        True
        """
        return bytes(b for b in s)

    @staticmethod
    def sde(bs: bytes) -> scalar:
        """
        Return a scalar from its binary representation.

        >>> s = native.scalar.hash('123'.encode())
        >>> native.sse_s = bytes.fromhex(
        ...     '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
        ... )
        >>> native.sde(native.sse_s) == s
        True
        >>> native.sse(native.sde(native.sse_s)) == native.sse_s
        True
        """
        return bytes.__new__(native.scalar, bs)

    @staticmethod
    def des2(bs: bytes) -> point2:
        """
        Return a second-group point from its binary representation.

        >>> p = native.point2.hash('123'.encode())
        >>> ser_p = bytes.fromhex(
        ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
        ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
        ...     '2c6a88bb448065eb748df632b1d872e02f54b6f56fdb84a7b1cb388fe551fb08'
        ...     '04464efa186bd4b1371e53d6f31f0e2f50ff553b6264a43331b42c976a0c541f'
        ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
        ...     '0000000000000000000000000000000000000000000000000000000000000000'
        ... )
        >>> native.des2(ser_p) == p
        True
        >>> native.ser(native.des2(ser_p)) == ser_p
        True
        """
        return bytes.__new__(native.point2, bs)
        # It may be useful to debug with _ECp2.deserialize(bs).serialize() in place of just bs.

    @staticmethod
    def sde2(bs: bytes) -> scalar2:
        """
        Return a second-level scalar from its binary representation.

        >>> s = native.scalar2.hash('123'.encode())
        >>> sse_s = bytes.fromhex(
        ...     'dc2b36dda20a09cdeecb88d36eeb9f744010151aba82a9bdcd7abd288b3bf80c'
        ...     '2e1ff32967b9227aa50698ffa663f90dec27208f60105a42c2beb388f31e4f0d'
        ...     'a40ca168fcccd07d084877ba34577b5b88d7414f8e67fd5fb17ddfead2ab890b'
        ...     '2984a34ea7a34add3735cba3bdb37f7b6bccd60e390c932aef2a62f8ba906317'
        ...     '3a0c9da4d577c0392a82a46f1220359cc682279e900463cdf250a49da0cada0c'
        ...     '9e94bb7aef9425217ae1a148b357078984cf2c9352d4b30f9488404a17f3c209'
        ...     '78a7db8b8f82e61f280ce85c6f372beb07962d72258c2d15550ff75a9903a107'
        ...     '22fd24c8b140507c130c8ab59a6b68fbec1ef95f402fda28e1024e7b7529670c'
        ...     'a026b2e8f7d4cb637d9caec3e2660e9a59af3ffa5b0cf60550cab88b3f523a11'
        ...     '7272c7adbd9b94f25a842df398724c431df7465baa0d43709f3f106593c56116'
        ...     '5bd55031bc77b9a39cce66ab27a00c0e56df4f5825fd30f099ff9316730d6d01'
        ...     'e922ad77b7ae3e36b6adff911085bad63ca2036edcb5627fc0ca8b095c401c03'
        ... )
        >>> native.sde2(sse_s) == s
        True
        >>> native.sse(native.sde2(sse_s)) == sse_s
        True
        """
        return bytes.__new__(native.scalar2, bs)

    @staticmethod
    def rnd2() -> scalar2:
        """
        Return random non-zero second-level scalar.

        >>> isinstance(native.rnd2(), native.scalar2)
        True
        """
        p = native.point.random()
        q = native.point2.base(native.scalar.random())
        return native.par(p, q)  # cls.par

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
        >>> native.scalar2.to_bytes(native.scl2(bs)).hex()[700:]
        '36222db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
        """
        if s is None:
            return native.rnd2() # cls.rnd2

        try:
            return bytes.__new__(native.scalar2, s)

        except ValueError: # pragma: no cover
            return None

    @staticmethod
    def inv2(s: scalar2) -> scalar2:
        """
        Return the inverse of a second-level scalar.

        >>> s = native.scl2()
        >>> native.smu2(s, native.smu2(s, native.inv2(s))) == s
        True
        >>> native.smu2(native.smu2(s, s), native.inv2(s)) == s
        True
        """
        return bytes.__new__(native.scalar2, _Fp12(_Fp12.deserialize(s).inverse()).serialize())

    @staticmethod
    def smu2(s: scalar2, t: scalar2) -> scalar2:
        """
        Return second-level scalar multiplied by another scalar.

        >>> p1 = native.point.hash('123'.encode())
        >>> p2 = native.point.hash('456'.encode())
        >>> q1 = native.point2.base(native.scalar.hash('123'.encode()))
        >>> q2 = native.point2.base(native.scalar.hash('456'.encode()))
        >>> s = p1 @ q1
        >>> t = p2 @ q2
        >>> native.smu2(s, t) == native.smu2(t, s)
        True
        """
        return bytes.__new__(native.scalar2,
                             _Fp12(_Fp12.deserialize(s) * _Fp12.deserialize(t)).serialize())

    @staticmethod
    def pnt2(h: bytes = None) -> point2:  # G2:
        """
        Construct a second-group point if the supplied bytes-like object
        represents a valid second-group point; otherwise, return ``None``.
        If no byte vector is supplied, return a random second-group point.

        >>> p = native.pnt2(hashlib.sha512('123'.encode()).digest())
        >>> native.point2.to_bytes(p).hex()[:128] == (
        ...     '4c595542640a69c4a70bda55c27ef96c133cd1f4a5f83b3371e571960c018e19'
        ...     'c54aaec2069f8f10a00f12bcbb3511cdb7356201f5277ec5e47da91405be2809'
        ... )
        True
        """
        return bytes.__new__(native.point2,
                             (_ECp2.random() if h is None else _ECp2.mapfrom(h)).serialize())

    @staticmethod
    def neg(p: point) -> point:  # G1:
        """
        Return the additive inverse of a point.

        >>> p = native.point.hash('123'.encode())
        >>> native.point.to_bytes(native.neg(p)).hex()[:64]
        '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
        """
        return bytes.__new__(native.point, _ECp.serialize(-1 * _ECp.deserialize(p)))

# Encapsulate pure-Python backend functions with their top-level best-effort synonyms.
scl = native.scl
rnd = native.rnd
inv = native.inv
smu = native.smu
sad = native.sad
ssb = native.ssb
sne = native.sne
pnt = native.pnt
bas = native.bas
mul = native.mul
add = native.add
sub = native.sub
neg = native.neg
par = native.par
ser = native.ser
des = native.des
sse = native.sse
sde = native.sde
rnd2 = native.rnd2
scl2 = native.scl2
inv2 = native.inv2
smu2 = native.smu2
sad2 = native.sad2
pnt2 = native.pnt2
bas2 = native.bas2
mul2 = native.mul2
add2 = native.add2
sub2 = native.sub2
neg2 = native.neg2
des2 = native.des2
sde2 = native.sde2

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

    # Ensure the chosen version of mclbn256 (or its substitute) has the necessary primitives.
    #mclbn256.mclbn256.assert_compatible()

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
        the value ``None`` and all functions and class methods exported by
        this module default to their pure-Python variants (*i.e.*, those
        encapsulated within :obj:`native <native>`). One way to confirm
        that a dynamic/shared library *has not been found* when this module
        is imported is to evaluate `mcl is None` or `not mclbn256`.

        If a shared/dynamic library file has been loaded successfully,
        this class encapsulates shared/dynamic library variants of all
        primitive operations and classes exported by this module:
        :obj:`mcl.scl <scl>`, :obj:`mcl.rnd <rnd>`, :obj:`mcl.inv <inv>`,
        :obj:`mcl.smu <smu>`, :obj:`mcl.sad <sad>`, :obj:`mcl.ssb <ssb>`,
        :obj:`mcl.sne <sne>`, :obj:`mcl.pnt <pnt>`, :obj:`mcl.bas <bas>`,
        :obj:`mcl.mul <mul>`, :obj:`mcl.add <add>`, :obj:`mcl.sub <sub>`,
        :obj:`mcl.neg <neg>`, :obj:`mcl.par <par>`, :obj:`mcl.ser <ser>`,
        :obj:`mcl.des <des>`, :obj:`mcl.sse <sse>`, :obj:`mcl.sde <sde>`,
        :obj:`mcl.rnd2 <rnd2>`, :obj:`mcl.scl2 <scl2>`,
        :obj:`mcl.inv2 <inv2>`, :obj:`mcl.smu2 <smu2>`,
        :obj:`mcl.sad2 <sad2>`, :obj:`mcl.pnt2 <pnt2>`,
        :obj:`mcl.bas2 <bas2>`, :obj:`mcl.mul2 <mul2>`,
        :obj:`mcl.add2 <add2>`, :obj:`mcl.sub2 <sub2>`,
        :obj:`mcl.neg2 <neg2>`, :obj:`mcl.des2 <des2>`,
        :obj:`mcl.sde2 <sde2>`,
        :obj:`mcl.point <point>`, :obj:`mcl.scalar <scalar>`,
        :obj:`mcl.point <point2>`, and :obj:`mcl.scalar <scalar2>`.
        For example, you can perform addition of points using
        the point addition implementation found in the mclbn256
        shared/dynamic library found on the host system.

        >>> p = mcl.pnt()
        >>> q = mcl.pnt()
        >>> mcl.add(p, q) == mcl.add(q, p)
        True

        Methods found in the shared/dynamic library variants of the
        :obj:`point` and :obj:`scalar` classes are wrappers for the
        shared/dynamic library implementations of the underlying
        operations.

        >>> p = mcl.point()
        >>> q = mcl.point()
        >>> p + q == q + p
        True

        Nevertheless, all bytes-like objects, :obj:`point` objects,
        and :obj:`scalar` objects accepted and emitted by the various
        operations and class methods in :obj:`mcl` and compatible
        with those accepted and emitted by the operations and class
        methods in :obj:`native`.
        """
        # pylint: disable=too-many-public-methods

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
        def inv(s: Fr) -> Fr:
            r"""
            Return inverse of scalar modulo
            ``r = 16798108731015832284940804142231733909759579603404752749028378864165570215949``
            in the prime field *F*\_*r*.

            >>> s = mcl.scl()
            >>> p = mcl.pnt()
            >>> mcl.mul(mcl.inv(s), mcl.mul(s, p)) == p
            True
            """
            return Fr.__invert__(s)

        @staticmethod
        def smu(s: Fr, t: Fr) -> Fr:
            """
            Return scalar multiplied by another scalar.

            >>> s = mcl.scl()
            >>> t = mcl.scl()
            >>> mcl.smu(s, t) == mcl.smu(t, s)
            True
            """
            return Fr.__mul__(s, t)

        @staticmethod
        def sad(s: Fr, t: Fr) -> Fr:
            """
            Return scalar added to another scalar.

            >>> s = mcl.scl()
            >>> t = mcl.scl()
            >>> mcl.sad(s, t) == mcl.sad(t, s)
            True
            """
            return Fr.__add__(s, t)

        @staticmethod
        def sne(s: Fr) -> Fr:
            """
            Return the additive inverse of a scalar.

            >>> s = mcl.scl()
            >>> t = mcl.scl()
            >>> mcl.sne(mcl.sne(s)) == s
            True
            """
            return Fr.__neg__(s)

        @staticmethod
        def ssb(s: Fr, t: Fr) -> Fr:
            """
            Return the result of one scalar subtracted from another scalar.

            >>> s = mcl.scl()
            >>> t = mcl.scl()
            >>> mcl.ssb(s, t) == mcl.sad(s, mcl.sne(t))
            True
            >>> mcl.ssb(s, t) == mcl.sne(mcl.ssb(t, s))
            True
            """
            return Fr.__sub__(s, t)

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
            Return base point multiplied by supplied scalar.

            >>> p = mcl.bas(mcl.scalar.hash('123'.encode())).normalize().normalize()
            >>> p.__class__ = point
            >>> mcl.point.to_bytes(p).hex()[:64]
            '2d66076815cda25556bab4a930244ac284412267e9345aceb98d71530308401a'
            """
            return G1.base_point() * s

        @staticmethod
        def mul(s: Fr, p: G1) -> G1:
            """
            Multiply the point by the supplied scalar and return the result.

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
            Return sum of the supplied points.

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
            Return result of subtracting second point from first point.

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

            The pairing function is bilinear.

            >>> p = mcl.point.random()
            >>> s = mcl.scalar.random()

            >>> t = mcl.scalar.random()
            >>> q = mcl.point2.random()
            >>> -((~s) * (s * p)) - p == mcl.scalar.from_int(-2) * p
            True
            >>> s * t * p @ q == s * p @ (t * q)
            True

            >>> x = y = p

            Suppose there are two points: one multiplied by the scalar ``s`` and the other
            multiplied by the scalar ``t``. Their equality can be determined by using a
            balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
            same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

            >>> g = mcl.point2.base(mcl.scalar.from_int(1))
            >>> b = mcl.point2.base(~s * t)
            >>> (t * x) @ g == (s * y) @ b
            True

            Pairing is defined as ``e: (G1 x G2) -> GT``. This operation accepts a point and
            a second-group point.

            >>> p @ (p + p)
            Traceback (most recent call last):
              ...
            ValueError: arguments must be from distinct groups
            >>> g @ b
            Traceback (most recent call last):
              ...
            ValueError: arguments must be from distinct groups

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
                raise ValueError('arguments must be from distinct groups')

            if isinstance(p, G1):
                return G1.__matmul__(G1.__new__(G1, p), G2.__new__(G2, q))

            return G2.__matmul__(G2.__new__(G2, p), G1.__new__(G1, q))

        @staticmethod
        def nrm(p: Union[G1, G2]) -> None:
            """
            Normalize a point (in place).

            >>> a = mcl.point.hash('123'.encode())
            >>> p = mcl.add(a, a)
            >>> p_nrm = mcl.add(a, a); mcl.nrm(p_nrm)

            We may have ``ser(p_nrm) != ser(p)`` here, depending on the backend
            implementation.  Either normalization matters, or MCl is not the backend.
            >>> (mcl.ser(p_nrm) != mcl.ser(p)) or not mclbn256
            True

            Normalization is idempotent.
            >>> mcl.nrm(p); mcl.nrm(p_nrm)
            >>> (       p ==        p_nrm )
            True
            """
            p.normalize_in_place()  # Sets ``(x, y, z)`` to ``(x/z, y/z, 1)`` which is unique.

        @staticmethod
        def ser(p: Union[G1, G2]) -> bytes:
            """
            Return the binary representation of a point.

            >>> p = mcl.point.hash('123'.encode())
            >>> mcl.des(mcl.ser(p)) == p
            True

            >>> q = mcl.point2.hash('123'.encode())
            >>> mcl.des2(mcl.ser(q)) == q
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return p.tostr(IoEcProj|IoArrayRaw)[1:]

        @staticmethod
        def des(bs: bytes) -> G1:
            """
            Return a point from its binary representation.

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
        def sse(s: Fr) -> bytes:
            """
            Return the binary representation of a scalar.

            >>> s = mcl.scalar.hash('123'.encode())
            >>> mcl.sde(mcl.sse(s)) == s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return s.tostr(IoEcProj|IoArrayRaw)

        @staticmethod
        def sde(bs: bytes) -> Fr:
            """
            Return a scalar from its binary representation.

            >>> s = mcl.scalar.hash('123'.encode())
            >>> mcl.sse_s = bytes.fromhex(
            ...     '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
            ... )
            >>> mcl.sde(mcl.sse_s) == s
            True
            >>> mcl.sse(mcl.sde(mcl.sse_s)) == mcl.sse_s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return Fr.new_fromstr(bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def des2(bs: bytes) -> G2:
            """
            Return a second-group point from its binary representation.

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
        def sde2(bs: bytes) -> GT:
            """
            Return a second-level scalar from its binary representation.

            >>> s = mcl.scalar2.hash('123'.encode())
            >>> sse_s = bytes.fromhex(
            ...     'b7c5063f93b7da4157a7a6cbc023dd81fd0eea08340b6a8d1ab1abadde517818'
            ...     'f20e988accef435f8482ac28c43d9c32f7a2ebe8a17e625d37508ac49c25cb1c'
            ...     'a4116ea2edee37eaa94ae5d04843701da4f1e580c996c0f83b8521a206bbac18'
            ...     'ed7b09acced4660ffe3c998f22fbaac0f8e6bdac50b0c3fe01371bb3cc5b8019'
            ...     '8fceff7530bb0d47148ebc3851b4326f87f3ba7b0d6604b2132deee6b87cce1d'
            ...     '55ba56cfc158e961b99d284bab92bfa9ac31f412817ace3acbebb19b8e556705'
            ...     '578f3ba79cc95e0e463bca77df27677e7251e5b75e426e9d07421e2ef6c6eb1f'
            ...     '32a4894dc91e206736d0e3bfb23027576ce4ae40b2077802cf8bf2e4309e2b1b'
            ...     '211bfef25c103fb37c4db09ce1e162730d682a727aa799c84cc94d162bb0340c'
            ...     '6d3ae24fbec091b48871f7f0ae2ee0015d8d6e343439521d31dd4ffccb270522'
            ...     'a46c6efdc550c38c9e58383d096a8f0636e7c4bdecf461e4b79ee2e982d43410'
            ...     '66c7fd4df4415aaaba4b4f70c8e119a743074a930f558112d9c4447aaf78ac07'
            ... )
            >>> mcl.sde2(sse_s) == s
            True
            >>> mcl.sse(mcl.sde2(sse_s)) == sse_s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants  # pylint: disable=C0103
            return GT.new_fromstr(bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def rnd2() -> GT:
            """
            Return random non-zero second-level scalar.

            >>> isinstance(mcl.rnd2(), GT)
            True
            """
            p = mcl.point.random()
            q = mcl.point2.base(mcl.scalar.random())
            return mcl.par(p, q)  # cls.par

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
            '35145b2cf0fb3ca4a65aebc14a7c696e58b78fc9b7504a33bd4873f23a9ceaf75201'
            """
            if s is None:
                return mcl.rnd2() # cls.rnd2

            try:
                return GT.deserialize(s)

            except ValueError: # pragma: no cover
                return None

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
            Return second-level scalar multiplied by another scalar.

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
            Return second-level scalar added to another scalar.

            >>> s = mcl.scl2()
            >>> t = mcl.scl2()
            >>> mcl.sad2(s, t) == mcl.sad2(t, s)
            True
            """
            return GT.__add__(s, t)

        @staticmethod
        def pnt2(h: bytes = None) -> G2:
            """
            Construct a second-group point if the supplied bytes-like object
            represents a valid second-group point; otherwise, return ``None``.
            If no byte vector is supplied, return a random second-group point.

            >>> p = mcl.pnt2(hashlib.sha512('123'.encode()).digest())
            >>> p.__class__ = point2
            >>> mcl.point2.to_bytes(p.normalize().normalize()).hex()[:128] == (
            ...     '4c595542640a69c4a70bda55c27ef96c133cd1f4a5f83b3371e571960c018e19'
            ...     'c54aaec2069f8f10a00f12bcbb3511cdb7356201f5277ec5e47da91405be2809'
            ... )
            True
            """
            return G2.random() if h is None else G2.mapfrom(h)

        @staticmethod
        def bas2(s) -> G2:
            """
            Return base point multiplied by supplied scalar.

            >>> r = mcl.bas2(mcl.scalar.hash('123'.encode())).normalize().normalize()
            >>> r.__class__ = point2
            >>> mcl.point2.to_bytes(r).hex()[:64]
            'e7000fb12d206112c73fe1054e9d77b35c77881eba6598b7e035171d90b13e0c'
            """
            # return s * G2.__new__(point2, G2.base_point())
            return G2.base_point() * s

        @staticmethod
        def mul2(s: Fr, p: G2) -> G2:
            """
            Multiply a second-group point by a scalar.

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
            Return sum of the supplied second-group points.

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
            Return result of subtracting one second-group point from another.

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
            Return the negation of a second-group point.

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

    # Top-level best-effort synonyms.
    scl = mcl.scl
    rnd = mcl.rnd
    inv = mcl.inv
    smu = mcl.smu
    sad = mcl.sad
    ssb = mcl.ssb
    sne = mcl.sne
    pnt = mcl.pnt
    bas = mcl.bas
    mul = mcl.mul
    add = mcl.add
    sub = mcl.sub
    neg = mcl.neg
    par = mcl.par
    ser = mcl.ser
    des = mcl.des
    sse = mcl.sse
    sde = mcl.sde
    rnd2 = mcl.rnd2
    scl2 = mcl.scl2
    inv2 = mcl.inv2
    smu2 = mcl.smu2
    sad2 = mcl.sad2
    pnt2 = mcl.pnt2
    bas2 = mcl.bas2
    mul2 = mcl.mul2
    add2 = mcl.add2
    sub2 = mcl.sub2
    neg2 = mcl.neg2
    des2 = mcl.des2
    sde2 = mcl.sde2

    # Indicate that data structures based on the dynamic/shared library have
    # successfully been defined.
    mclbn256 = True

except:  # pylint: disable=W0702 # pragma: no cover
    mcl = None  # pragma: no cover # Exported symbol.

#
# Dedicated point and scalar data structures for each implementation.
#

for (_implementation, _p_base_cls, _s_base_cls, _p2_base_cls, _s2_base_cls) in (
    [(native, bytes, bytes, bytes, bytes)] +
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
            of a point or its coordinate(s).  For a strict deserialization
            from bytes, use :obj:`point.from_bytes`.

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

            >>> point.base(scalar.hash('123'.encode())).normalize().hex()[:64]
            '2d66076815cda25556bab4a930244ac284412267e9345aceb98d71530308401a'
            """
            p = cls._implementation.bas(s)
            p.__class__ = cls
            return p

        @classmethod
        def from_bytes(cls, bs: bytes) -> point:
            """
            Deserialize the bytes representation of a point and return the point instance.

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
        def from_hex(cls, s: str) -> point:
            """
            Convert the hexadecimal UTF-8 string representation of a point to a point instance.

            >>> point.from_hex(
            ...     'b89ec91191915a72d4ec4434be7b438893975880b21720995c2b2458962c4e0a'
            ...     'd0efebb5c303e4d1f8461b44ec768c587eca8b0abc01d4cb0d878b076154940d'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ... ).normalize().hex()[:64]
            'b89ec91191915a72d4ec4434be7b438893975880b21720995c2b2458962c4e0a'
            """
            return cls.from_bytes(bytes.fromhex(s))

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Construct an instance from its corresponding Base64 UTF-8 string representation.

            >>> point.from_base64(
            ...     'hQIYpQRHupyyfPFoEm8rfmKV6i6VUP7vmngQWpxS3AEJD29fKVMW39l2oDLB+Ece'
            ...     '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            ... ).normalize().hex()[:64]
            '850218a50447ba9cb27cf168126f2b7e6295ea2e9550feef9a78105a9c52dc01'
            """
            return cls.from_bytes(base64.standard_b64decode(s))

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> point: # pylint: disable=arguments-differ
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
            >>> point(bs).normalize().hex()[:64]
            'a5db59a0a1450aee0e47e7226d992fded25f2eb5378493ba0eb3225fc7595809'
            >>> len(point())
            96
            """
            return cls.from_bytes(bs) if bs is not None else cls.random()

        def __mul__(self: point, other):
            """
            Use of this method is not permitted. A point cannot be a left-hand argument.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError('point must be on right-hand side of multiplication operator')

        def __rmul__(self: point, other: scalar) -> point:
            """
            Multiply this point by the supplied scalar and return the result.

            >>> p = point.hash('123'.encode())
            >>> s = scalar.hash('456'.encode())
            >>> (s * p).normalize().hex()[:64]
            '6df8d29225a699b5ff3cc4b7b0a9c5003c0e1a93037cb2488b278495abfa2902'
            """
            p = self._implementation.mul(other, self)
            p.__class__ = self.__class__ # = point
            return p

        def __add__(self: point, other: point) -> point:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).normalize().hex()[:64]
            '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
            """
            p = self._implementation.add(self, other)
            p.__class__ = self.__class__ # = point
            return p

        def __sub__(self: point, other: point) -> point:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).normalize().hex()[:64]
            'a43a5ce1931b1300b62e5d7e1b0c691203bfd85fafd9585dc5e47a7e2acfea22'
            """
            p = self._implementation.sub(self, other)
            p.__class__ = self.__class__ # = point
            return p

        def __matmul__(self: point, other: point2) -> scalar2:
            """
            Return the result of pairing another point with this point.

            >>> p = point.hash('123'.encode())
            >>> q = point2.base(scalar.from_int(456))
            >>> z = (p @ q).hex()[700:]
            >>> z_mcl    = 'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'
            >>> z_native = '731ff16849a86c40280717696a8aa44fbe16f565f087d003413d141de7f5d109fc0c'
            >>> mclbn256 = p.__class__ != native.point # (In case both native and mcl are defined.)
            >>> z == z_mcl if mclbn256 else z == z_native
            True

            The pairing function is bilinear
            >>> p = point.random()
            >>> s = scalar.random()

            >>> t = scalar.random()
            >>> q = point2.random()
            >>> -((~s) * (s * p)) - p == scalar.from_int(-2) * p
            True
            >>> s*t*p @ q == s*p @ (t*q)
            True

            >>> x = y = p

            Suppose there are two points: one multiplied by the scalar ``s`` and the other
            multiplied by the scalar ``t``. Their equality can be determined by using a
            balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
            same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

            >>> g = point2.base(scalar.from_int(1))
            >>> b = point2.base(~s * t)
            >>> (t * x) @ g == (s * y) @ b
            True
            """
            s = self._implementation.par(self, other)
            s.__class__ = self._implementation.scalar2
            return s

        def __neg__(self: point) -> point:
            """
            Return the negation (additive inverse) of this point

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).normalize().hex()[:64]
            '1ea48cab238fece46bd0c9fb562c859e318e17a8fb75517a4750d30ca79b911c'
            """
            p = self._implementation.neg(self)
            p.__class__ = self.__class__ # = point
            return p

        def __len__(self: point) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(point())
            96
            """
            return bytes(self).__len__()

        def __bytes__(self: point) -> bytes:
            """
            Return the binary representation of this instance.

            >>> len(bytes(point()))
            96
            """
            return self.to_bytes()

        def to_bytes(self: point) -> bytes:
            """
            Serialize this point and return its representation as bytes.

            >>> p = point.hash('123'.encode())
            >>> bs = p.to_bytes()
            >>> point.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            """
            return self._implementation.ser(self)

        def normalize(self: point) -> point:
            """
            Normalize this point and return it mutated.  This takes the z-coordinate,
            which may not always be equal to 1, and multiplies all coordinates x, y, and z
            by z's multiplicative inverse.  The resulting normalized point is unique
            (_i.e._, two points are equal if and only if their normalized forms are equal)
            and in the form (x/z, y/z, 1).

            >>> a = point.hash('123'.encode())
            >>> p = a + a + a + a
            >>> p == p
            True
            >>> p.to_bytes() == p.to_bytes()
            True
            >>> p.to_bytes() == p.normalize().to_bytes() and p.__class__ != native.point
            False
            >>> p.normalize().to_bytes() == p.normalize().to_bytes()
            True
            >>> p.normalize().to_bytes() == p.normalize().normalize().to_bytes()
            True
            >>> point.from_bytes(p.to_bytes()) == p
            True
            >>> point.from_bytes(p.normalize().to_bytes()) == p
            True
            >>> point.from_bytes(p.to_bytes()) == point.from_bytes(p.normalize().to_bytes())
            True
            >>> type(p.normalize()) is point
            True
            """
            self._implementation.nrm(self)
            return self

        def hex(self: point) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> p = point.hash('123'.encode())
            >>> p.hex()[:64]
            '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            """
            return self.to_bytes().hex()

        def to_base64(self: point) -> str:
            """
            Return an equivalent Base64 UTF-8 string representation of this instance.

            >>> p = point.from_base64(
            ...     'hQIYpQRHupyyfPFoEm8rfmKV6i6VUP7vmngQWpxS3AEJD29fKVMW39l2oDLB+Ece'
            ...     '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            ... )
            >>> p.to_base64()[-64:]
            '5PqBuRzCyiRb8xYIelEII47///////8Viv//////ObnN/////y7GovX//3/ypCsh'
            """
            return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

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
            Deserialize the bytes representation of a scalar and return the scalar instance.

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
        def from_hex(cls, s: str) -> scalar:
            """
            Convert the hexadecimal UTF-8 string representation of a scalar to a scalar
            instance.

            >>> scalar.from_hex(
            ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            ... ).hex()[:64]
            '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            """
            return cls.from_bytes(bytes.fromhex(s))

        @classmethod
        def from_base64(cls, s: str) -> scalar:
            """
            Convert Base64 UTF-8 string representation of a scalar to a scalar instance.

            >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()[:64]
            '312d0c9130f69153bec9f5d0386a95135eb45eebf130af5f1fed1c6ed15f2500'
            """
            return cls.from_bytes(base64.standard_b64decode(s))

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> scalar: # pylint: disable=arguments-differ
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
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scalar()
            >>> p = point()
            >>> ((~s) * (s * p)) == p
            True
            """
            s = self._implementation.inv(self)
            s.__class__ = self.__class__ # = scalar
            return s

        def inverse(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scalar()
            >>> p = point()
            >>> ((s.inverse()) * (s * p)) == p
            True
            """
            return ~self

        def __mul__(
                self: scalar,
                other: Union[scalar, point, point2]
            ) -> Optional[Union[scalar, point, point2]]:
            """
            Multiply supplied scalar, point, or second-group point by this
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
            >>> (s * p).normalize().hex()[:64]
            'eee31d1780ea41771357da19a81eaddf2e7fa560142067b433764cbf98be9002'
            >>> isinstance(s * p, point)
            True

            If the second argument is a :obj:`point2` object, this method
            pre-empts :obj:`point2.__rmul__`.

            >>> p = point2.hash('123'.encode())
            >>> (s * p).normalize().hex()[:128] == (
            ...     '451f144e06deecbfe5a1527f2b5cc6f12bbde91c1fdf0d5326ad79ffc53bb106'
            ...     '6d800275af625de83d72d815335832027cc60c34f22e8c5f89f953740a409702'
            ... )
            True
            """
            if isinstance(other, self._implementation.scalar):
                s = self._implementation.smu(self, other)
                s.__class__ = self.__class__ # = scalar
                return s

            if isinstance(other, self._implementation.point):
                p = self._implementation.mul(self, other)
                p.__class__ = other.__class__ # = point
                return p

            if isinstance(other, self._implementation.point2):
                p = self._implementation.mul2(self, other)
                p.__class__ = other.__class__ # = point2
                return p

            return None

        def __rmul__(self: scalar, other: Union[scalar, point]):
            """
            A scalar cannot be on the right-hand side of a non-scalar.

            >>> point() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError('scalar must be on left-hand side of multiplication operator')

        def __add__(self: scalar, other: scalar) -> scalar:
            """
            Add this scalar with another scalar.

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
            s.__class__ = self.__class__ # = scalar
            return s

        def __sub__(self: scalar, other: scalar) -> scalar:
            """
            Subtract this scalar from another scalar.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (s - s).hex() == '00' * len(s)
            True
            >>> isinstance(s - s, scalar)
            True
            """
            s = self._implementation.ssb(self, other)
            s.__class__ = self.__class__ # = scalar
            return s

        def __neg__(self: scalar) -> scalar:
            """
            Negate this scalar.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (-s).hex()
            'dcd2f36ecf096e4d52360a2fc7150aeca94ba1148e1c855ae212e3d1b004fe24'
            >>> isinstance(-s, scalar)
            True
            """
            s = self._implementation.sne(self)
            s.__class__ = self.__class__ # = scalar
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
            Return the binary representation of this instance.

            >>> len(bytes(scalar()))
            32
            """
            return self.to_bytes()

        def to_bytes(self: scalar) -> bytes:
            """
            Serialize this scalar and return its representation as bytes.

            >>> s = scalar.hash('123'.encode())
            >>> bs = s.to_bytes()
            >>> scalar.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            """
            return self._implementation.sse(self)

        def __int__(self: scalar) -> bytes:
            """
            Compute the numerical representation of this scalar and return an int instance.

            >>> s = scalar.from_int(123)
            >>> n = int(s)
            >>> scalar.from_int(n) == s
            True
            >>> type(n) is int
            True
            """
            d_inv = 0x235f846d22752e25720e909a9e82a1b4ad47e882341d8fca46c142d23fa9bc45
            n = (int.from_bytes(self._implementation.sse(self), 'little') * d_inv) % r
            return n if (n <= r//2) else n-r

        def to_int(self: scalar) -> bytes:
            """
            Compute the numerical representation of this scalar and return an int instance.

            >>> s = scalar.from_int(123)
            >>> n = s.to_int()
            >>> scalar.from_int(n) == s
            True
            >>> type(n) is int
            True
            """
            d_inv = 0x235f846d22752e25720e909a9e82a1b4ad47e882341d8fca46c142d23fa9bc45
            return (int.from_bytes(self._implementation.sse(self), 'little') * d_inv) % r

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
            Convert to equivalent Base64 UTF-8 string representation.

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
            Return second-group point obtained by transforming supplied bytes-like
            object.

            >>> p = point2.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.normalize().hex()[:128] == (
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

            >>> point2.hash('123'.encode()).normalize().hex()[:128] == (
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
            Return base second-group point multiplied by the supplied scalar
            if the scalar is valid; otherwise, return ``None``.

            >>> point2.base(scalar.hash('123'.encode())).normalize().hex()[:128] == (
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
            Deserialize the bytes representation of a second-group point and return the instance.

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
        def from_hex(cls, s: str) -> point2:
            """
            Construct a second-group point from its hexadecimal UTF-8 string representation.

            >>> p = point2.from_hex(
            ...     'ab4efa2bcdeb825a67b12a10132ae1addca840ed248f83ae7dd987370dd47a05'
            ...     '31c10b08ada0e24c0327d85b108e826a55bf3dc3286488327fac75e05e293b20'
            ...     '01cbf919b53884d02b85aab9b0091eeda114fa65ca5d75620da26c4d164aa509'
            ...     '2a2d55b6f311bfe52d24adf7b4b0b6ce12ed486a37c474d35a2b373be8a3f71c'
            ...     '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ...     '0000000000000000000000000000000000000000000000000000000000000000'
            ... )
            >>> p.normalize().hex()[:64]
            'ab4efa2bcdeb825a67b12a10132ae1addca840ed248f83ae7dd987370dd47a05'
            """
            p = cls.from_bytes(bytes.fromhex(s))
            p.__class__ = cls
            return p

        @classmethod
        def from_base64(cls, s: str) -> point2:
            """
            Construct a second-group point from its Base64 UTF-8 string representation.

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

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> point2: # pylint: disable=arguments-differ
            """
            If a bytes-like object is supplied, return a second-group point
            object corresponding to the supplied bytes-like object (no check
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, a random second-group point
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

        def __mul__(self: point, other):
            """
            Use of this method is not permitted. A point cannot be a left-hand argument.

            >>> point2() * scalar()
            Traceback (most recent call last):
              ...
            TypeError: point must be on right-hand side of multiplication operator
            """
            raise TypeError('point must be on right-hand side of multiplication operator')

        def __rmul__(self: point2, other: scalar) -> Optional[point2]:
            """
            Multiply this instance by the supplied scalar and return the
            result.

            This functionality is implemented exclusively in the
            method :obj:`scalar.__mul__`, as that method pre-empts this
            method when the second argument has the correct type (*i.e.*,
            it is a :obj:`scalar` instance). This method is included so
            that an exception can be raised if an incorrect argument is
            supplied.

            >>> p = point2.hash('123'.encode())
            >>> 2 * p
            Traceback (most recent call last):
              ...
            TypeError: second-group point can only be multiplied by a scalar
            """
            raise TypeError(
                'second-group point can only be multiplied by a scalar'
            )

        def __add__(self: point2, other: point2) -> Optional[point2]:
            """
            Return sum of this instance and another second-group point.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> (p + q).normalize().hex()[:128] == (
            ...     'cb0fc423c1bac2ac2df47bf5f5548a42b0d0a0da325bc77243d15dc587a7b221'
            ...     '9808a1649991ddf770f0060333aab4d499580b123f109b5cb180f1f8a75a090e'
            ... )
            True
            """
            p = self._implementation.add2(self, other)
            p.__class__ = self.__class__ # = point2
            return p

        def __sub__(self: point2, other: point2) -> Optional[point2]:
            """
            Return the result of subtracting another second-group point from
            this instance.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> (p - q).normalize().hex()[:128] == (
            ...     'e97a70c4e3a5369ebbb1dcf0cc1135c8c8e04a4ec7cffdf875ac429d66846d0b'
            ...     '191b090909c40a723027b07ac44435a6ade3813d04b3632a17c92c5c98718902'
            ... )
            True
            """
            p = self._implementation.sub2(self, other)
            p.__class__ = self.__class__ # = point2
            return p

        def __neg__(self: point2) -> Optional[point2]:
            """
            Return the negation (additive inverse) of this instance.

            >>> p = point2.hash('123'.encode())
            >>> (-p).normalize().hex()[:128] == (
            ...     '30326199f303fce7a77cff6d2fb0b3de8cd409d1d562f3543f7d064cdc58d309'
            ...     '7e88038ad76e85e5df26e4a9486a657b0431c8e7e09b0a1abf90fc874c515207'
            ... )
            True
            """
            p = self._implementation.neg2(self)
            p.__class__ = self.__class__ # = point2
            return p

        def __matmul__(self: point2, other: point) -> Optional[scalar2]:
            """
            Return the result of pairing another point with this point.

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
            Return the binary representation of this instance.

            >>> len(bytes(point2()))
            192
            """
            return self.to_bytes()

        def to_bytes(self: point2) -> bytes:
            """
            Serialize this second-group point and return its representation as bytes.

            >>> p = point2.hash('123'.encode())
            >>> bs = p.to_bytes()
            >>> point2.from_bytes(bs) == p
            True
            >>> type(bs) is bytes
            True
            """
            return self._implementation.ser(self)

        def normalize(self: point2) -> point2:
            """
            Normalize this second-group point and return it mutated.  This takes the z-coordinate,
            which may not always be equal to 1, and multiplies all coordinates x, y, and z
            by z's multiplicative inverse.  The resulting normalized point is unique (_i.e._, two
            second-group points are equal if and only if their normalized forms are equal) and in
            the form (x1/z1, y1/z1, x2/z2, y2/z2, 1, 0).

            >>> a = point2.hash('123'.encode())
            >>> q = a + a + a + a
            >>> q == q
            True
            >>> q.to_bytes() == q.to_bytes()
            True
            >>> q.to_bytes() == q.normalize().to_bytes() and q.__class__ != native.point2
            False
            >>> q.normalize().to_bytes() == q.normalize().to_bytes()
            True
            >>> q.normalize().to_bytes() == q.normalize().normalize().to_bytes()
            True
            >>> point2.from_bytes(q.to_bytes()) == q
            True
            >>> point2.from_bytes(q.normalize().to_bytes()) == q
            True
            >>> point2.from_bytes(q.to_bytes()) == point2.from_bytes(bytes(q.normalize()))
            True
            >>> type(q.normalize()) is point2
            True
            """
            self._implementation.nrm(self)
            return self

        def hex(self: point2) -> str:
            """
            Generates hexadecimal representation of this instance.

            >>> p = point2.hash('123'.encode())
            >>> p.normalize().hex() == (
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
            Convert to equivalent Base64 UTF-8 string representation.

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
        def hash(cls, bs: Union[bytes, bytearray]) -> scalar2:
            """
            Return an instance derived by hashing the supplied bytes-like object.

            >>> s = native.scalar2.hash(bytes([123]))
            >>> z = s.hex()[700:]
            >>> z_mcl    = 'd210461ad2293454f3c2e9ad5fedcb671d0f13b30ec467744b9a16c881bb572bb50c'
            >>> z_native = '141886a680e6a24930f9b3a5988a9a83212c94ba3dfcd275e8627ad5f1925ddafd23'
            >>> mclbn256 = s.__class__ != native.scalar2 # (In case both native and mcl are defined.)
            >>> z == z_mcl if mclbn256 else z == z_native
            True
            """
            bs = hashlib.sha512(bs).digest()
            p = cls._implementation.point.hash(bs[:32])
            q = cls._implementation.point2.base(cls._implementation.scalar.hash(bs[32:]))
            s = cls._implementation.par(p, q)
            s.__class__ = cls
            return s

        @classmethod
        def from_bytes(cls, bs: bytes) -> scalar2:
            """
            Deserialize the bytes representation of a second-level scalar and return the instance.

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
        def from_hex(cls, s: str) -> scalar2:
            """
            Construct an instance from its hexadecimal UTF-8 string representation.

            >>> s = scalar2.from_hex(
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
            return cls.from_bytes(bytes.fromhex(s))

        @classmethod
        def from_base64(cls, s: str) -> scalar2:
            """
            Construct an instance from a Base64 UTF-8 string representation thereof.

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

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> scalar2: # pylint: disable=arguments-differ
            """
            If a bytes-like object is supplied, return an instance that
            corresponds to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            scalar). If no argument is supplied, return a random scalar
            object.
            """
            return cls.from_bytes(bs) if bs is not None else cls.random()

        def __invert__(self: scalar2) -> scalar2:
            """
            Return inverse of scalar.
            """
            s = self._implementation.inv2(self)
            s.__class__ = self.__class__ # = scalar2
            return s

        def inverse(self: scalar2) -> scalar2:
            """
            Return inverse of this scalar.

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
            >>> s_inv = bytes(s.inverse()).hex()[700:]
            >>> s_inv_mcl    = 'ec02e64a4556213eade4604303b93219233e21fd8e50f536e6421c7f73597f5bc905'
            >>> s_inv_native = 'd71413d63b9d7e08181eaecca0227b6de4dc36a8befe4e38597420345aec519c220b'
            >>> mclbn256 = s.__class__ != native.scalar2 # (In case both native and mcl are defined.)
            >>> s_inv == s_inv_mcl if mclbn256 else s_inv == s_inv_native
            True
            >>> ~~s == s
            True
            >>> ~s == s
            False
            """
            s = self._implementation.inv2(self)
            s.__class__ = self.__class__ # = scalar2
            return s

        def __mul__(self: scalar2, other: scalar2) -> scalar2:
            """
            Multiply supplied scalar by another scalar.

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
                s.__class__ = self.__class__ # = scalar2
                return s

            raise TypeError(
                'second-level scalar can only be multiplied by another second-level scalar'
            )

        def __rmul__(self: scalar2, other: Union[scalar2, point2]):
            """
            A scalar cannot be on the right-hand side of a non-scalar.

            >>> 2 * scalar2()
            Traceback (most recent call last):
              ...
            TypeError: second-level scalar can only be multiplied by another second-level scalar
            """
            raise TypeError(
                'second-level scalar can only be multiplied by another second-level scalar'
            )

        def __add__(self: scalar2, other: scalar2) -> scalar2:
            """
            Add this scalar with another scalar.

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
            s.__class__ = self.__class__ # = scalar2
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
            Return the binary representation of this instance.

            >>> len(bytes(scalar2()))
            384
            """
            return self.to_bytes()

        def to_bytes(self: scalar2) -> bytes:
            """
            Serialize this scalar and return its representation as bytes.

            >>> s = scalar2.hash('123'.encode())
            >>> bs = s.to_bytes()
            >>> scalar2.from_bytes(bs) == s
            True
            >>> type(bs) is bytes
            True
            """
            self.__class__ = type(self)._implementation.scalar2
            return self._implementation.sse(self)

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
            Convert this instance to an equivalent Base64 UTF-8 string representation.

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

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
