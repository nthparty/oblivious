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
from bn254.curve import r

class _ECp(ECp_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    def __new__(cls, *args, **kwargs):
        p = ECp_.__new__(cls)
        _ECp.__init__(p, *args, **kwargs)
        return p

    def __init__(self, p=None):
        super(ECp_, self).__init__() # pylint: disable=bad-super-call
        if isinstance(p, (ECp_, _ECp)):
            self.setxy(*p.get())

    def serialize(self) -> bytes:
        # pylint: disable=unnecessary-direct-lambda-call
        return bytes(
            (lambda x, y:
                (lambda xs:
                    (lambda ret,_: ret)(xs, xs.append(xs.pop() ^ ((y % 2) << 7)))
                )(list(x.to_bytes(32, 'little')))
            )(*self.get())
        )

    @classmethod
    def deserialize(cls, bs) -> bytes:
        return (
            (1 - 2 * (bs[31] >> 7)) *
            _ECp.mapfrom(bs[:31] + bytes([bs[31] & 0b01111111]))
        )
    @classmethod
    def random(cls) -> _ECp:
        return _ECp(int(native.scalar.random()) * get_base())

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

        p = ECp_()
        p.setxy(x, y)

        return p

    def hex(self):
        return self.serialize().hex()

    def zero(self):
        return self.isinf()

    def __bytes__(self):
        return self.serialize()

class _ECp2(ECp2_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    def __new__(cls, *args, **kwargs):
        q = ECp2_.__new__(cls)
        _ECp2.__init__(q, *args, **kwargs)
        return q

    def __init__(self, q=None):
        super(ECp2_, self).__init__() # pylint: disable=bad-super-call
        if isinstance(q, (ECp2_, _ECp2)):
            self.set(*q.get())

    def __hex__(self):
        return self.toBytes(1).hex()

    def hex(self):
        return self.toBytes(1).hex()

    def serialize(self) -> bytes:
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

    def __bytes__(self):
        return self.serialize()

    def zero(self):
        return self.isinf()

    @classmethod
    def random(cls) -> _ECp2:
        return _ECp2(int(native.scalar.random()) * get_base2())

class _Fp12(Fp12_): # pylint: disable=invalid-name
    """Internal class."""
    # pylint: disable=missing-function-docstring
    def __new__(cls, *args, **kwargs):
        q = Fp12_.__new__(cls)
        _Fp12.__init__(q, *args, **kwargs)
        return q

    def __init__(self, q=None):
        super(Fp12_, self).__init__() # pylint: disable=bad-super-call
        if isinstance(q, (Fp12_, _Fp12)):
            self.set(*q.get())

    def __hex__(self):
        return self.toBytes(1).hex() # pylint: disable=too-many-function-args

    def hex(self):
        return self.toBytes(1).hex() # pylint: disable=too-many-function-args

    def serialize(self) -> bytes:
        return bytes(
            self.a.a.a.int().to_bytes(32, 'little') + self.a.a.b.int().to_bytes(32, 'little') +
            self.a.b.a.int().to_bytes(32, 'little') + self.a.b.b.int().to_bytes(32, 'little') +
            self.b.a.a.int().to_bytes(32, 'little') + self.b.a.b.int().to_bytes(32, 'little') +
            self.b.b.a.int().to_bytes(32, 'little') + self.b.b.b.int().to_bytes(32, 'little') +
            self.c.a.a.int().to_bytes(32, 'little') + self.c.a.b.int().to_bytes(32, 'little') +
            self.c.b.a.int().to_bytes(32, 'little') + self.c.b.b.int().to_bytes(32, 'little')
        )

    def __bytes__(self):
        return self.serialize()

    def zero(self):
        return self.isinf() # pylint: disable=no-member

    @classmethod
    def random(cls) -> _Fp12:
        return _Fp12(int(native.scalar.random()) * get_base2())

#
# Attempt to load mclbn256. If no local mclbn256 shared/dynamic library file
# is found, only native Python implementations of the functions and methods
# will be available.
#

# try: # pragma: no cover
#     import mclbn256 # pylint: disable=E0401
# except: # pylint: disable=W0702 # pragma: no cover
#     mclbn256 = None
mclbn256 = None
#     print('failed to load mclbn256')
# import mclbn256

#
# Use native Python implementations of primitives by default.
#

# pylint: disable=C0103
def _make_native(G, F):
    """
    Factory to make the exported symbols.
    """
    # pylint: disable=C2801,W0621
    class native:
        """
        Wrapper class for native Python implementations of
        primitive operations.

        This class encapsulates pure Python variants of all
        primitive operations and classes exported by this module:
        :obj:`native.scl <scl>`, :obj:`native.rnd <rnd>`,
        :obj:`native.inv <inv>`, :obj:`native.smu <smu>`,
        :obj:`native.pnt <pnt>`, :obj:`native.bas <bas>`, :obj:`native.bas2 <bas2>`,
        :obj:`native.mul <mul>`, :obj:`native.add <add>`,
        :obj:`native.sub <sub>`, :obj:`native.par <par>`,
        :obj:`native.point <point>`, and :obj:`native.scalar <scalar>`.
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

            >>> isinstance(rnd(), Fr)
            True
            """
            return F.__new__(scalar, secrets.randbelow(r-1)+1)

        @classmethod
        def scl(cls, s: Union[bytes, bytearray, None] = None) -> Optional[scalar]:
            """
            Construct a scalar if the supplied bytes-like object represents
            a valid scalar; otherwise, return ``None``. If no byte vector is
            supplied, return a random scalar.

            >>> s = scl()
            >>> t = scl(s)
            >>> s == t
            True
            >>> scl(bytes([255] * 32)) is None
            True
            """
            if s is None:
                return cls.rnd()

            s = F.from_bytes(s, 'little')

            if not s == 0 and s < r:
                return F.__new__(scalar, s)

            return None

        @staticmethod
        def inv(s: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            ``r=16798108731015832284940804142231733909759579603404752749028378864165570215949``
            in the prime field `F*_r`.

            >>> s = scl()
            >>> p = pnt()
            >>> mul(inv(s), mul(s, p)) == p
            True
            """
            return F.__new__(s.__class__, bn.invmodp(s, r))

        @staticmethod
        def smu(s: scalar, t: scalar) -> scalar:
            """
            Return scalar multiplied by another scalar.

            >>> s = scl()
            >>> t = scl()
            >>> smu(s, t) == smu(t, s)
            True
            """
            return F.__new__(s.__class__, F.__mul__(s, t) % r)

        @staticmethod
        def sad(s: scalar, t: scalar) -> scalar:
            """
            Return scalar added to another scalar.

            >>> s = scl()  # Could be `native.scl()`.
            >>> t = scl()
            >>> sad(s, t) == sad(t, s)
            True
            """
            #return F.__new__(s.__class__, F.__add__(int(s), int(t)) % r)
            return F.__new__(native.scalar, F.__add__(int(s), int(t)) % r)

        @staticmethod
        def sad2(s: scalar2, t: scalar2) -> scalar2:
            """
            Return scalar2 added to another scalar2.

            >>> s = scl2()  # Should eventually be changed to `native.scl2()` or the like.
            >>> t = scl2()
            >>> sad2(s, t) == sad2(t, s)
            True
            """
            return None#F.__new__(s.__class__, F.__add__(s, t) % r)
            #return F.__new__(native.scalar2, F.__add__(int(s), int(t)) % r)

        @staticmethod
        def pnt(h: bytes = None) -> point:
            """
            Return point from 64-byte vector (normally obtained via hashing).

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()[:64]
            '346d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf'
            """
            return G.__new__(point, G.random() if h is None else G.mapfrom(h))

        @staticmethod
        def bas(s: scalar) -> point:  # G1:
            """
            Return base point multiplied by supplied scalar.

            >>> bytes(bas(scalar.hash('123'.encode()))).hex()
            'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
            """
            return s * _ECp.__new__(point, get_base())
            # return s * get_base()

        @staticmethod
        def bs2(s: scalar) -> point2:  # G2:
            """
            Return base point multiplied by supplied scalar.

            >>> bytes(bs2(scalar.hash('123'.encode()))).hex()[50:]
            'd1b99a7ca5660d124528b442d33e15eca23a202df3222c542e7bd71955c7623669554af518de01'
            """
            # return s * _ECp2.__new__(point2, get_base2())
            return _ECp2(int(s) * get_base2())

        @staticmethod
        def par(p: Union[point, point2], q: Union[point, point2]) -> scalar2:
            """
            Compute the pairing function on two points.

            >>> p = point.hash('123'.encode())
            >>> q = point2.base(scalar.from_int(456))
            >>> z = par(p, q).tostr(1088).hex()[700:]
            >>> z_mcl    = 'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'
            >>> z_native = '150f663b60a9bd1c7263a988765827328bee5c78602648cb82600a4730f4fc183301'
            >>> z == z_mcl if mclbn256 else z == z_native
            True

            After the ``finalExp`` `function <gist.github.com/wyatt-howe/0ca575e99b73dada1f7fb63862a23a71>`__
            from the MCl library (not yet implemented here or in the pure-Python library), the hexadecimal
            result is: ``'3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'``.

            The pairing function is bilinear.

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
            _p, _q = (p, q) if (p.G == _ECp and q.G == _ECp2) else (
                (q, p) if (q.G == _ECp and p.G == _ECp2) else (None, None)
            )
            if type(_p) is type(None): # pylint: disable=unidiomatic-typecheck
                raise TypeError(
                    "can only pair points of types point/ECp/G1 and point(2)/ECp2/G2 to each other"
                )
            p_ = _ECp.__new__(_ECp, _p)
            q_ = _ECp2.__new__(_ECp2, _q)
            z = e(q_, p_)
            return _Fp12.__new__(scalar2, z)

        @staticmethod
        def mul(s: scalar, p: point) -> point:
            """
            Multiply the point by the supplied scalar and return the result.

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> s = scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> mul(s, p).tostr(1088).hex()[:64]
            '34aa7645c6b3d473b7c6805cc3967ecdff6eb44cfea0a665861043e992c3fc1e'
            """
            s = s % r #assert int(s) < r
            return p.G.__new__(p.__class__, p.G.__rmul__(p.G(p), int(s)))

        @staticmethod
        def add(p: point, q: point) -> point:
            """
            Return sum of the supplied points.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> add(p, q).tostr(1088).hex()[:64]
            '34448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f7'
            """
            return p.G.__new__(p.__class__, p.G.add(p.copy(), q))

        @staticmethod
        def sub(p: point, q: point) -> point:
            """
            Return result of subtracting second point from first point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sub(p, q).tostr(1088).hex()[:64]
            '34bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb'
            """
            return p.G.__new__(p.__class__, p.G.add(-1 * q, p))

    _G = G

    #
    # Dedicated point and scalar data structures derived from `bytes`.
    #
    class point(G): # pylint: disable=W0621,E0102
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """
        _native = native
        G = _G

        @classmethod
        def random(cls) -> point:
            """
            Return random point object.

            >>> len(point.random())
            32
            """
            return cls._native.pnt()

        @classmethod
        def bytes(cls, bs: bytes) -> point:
            """
            Return point object obtained by transforming supplied bytes-like object.

            >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()[:64]
            '346d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf'
            """
            return cls._native.pnt(bs)

        @classmethod
        def hash(cls, bs: bytes) -> point:
            """
            Return point object by hashing supplied bytes-like object.

            >>> point.hash('123'.encode()).hex()[:64]
            '34825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb48'
            """
            return cls._native.pnt(hashlib.sha512(bs).digest()[:32])  # really only need ≥254-bits

        @classmethod
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()[:64]
            '34dfeb7d0cc60851a112fbbda37d09bf067c5eae37439c19210ff649341337e7'
            """
            p = G.__new__(cls, (cls._native.bas if cls.G == _ECp else cls._native.bs2)(s))
            return None if p.zero() else p

        @classmethod
        def base2(cls, s: scalar) -> Optional[point2]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()[:64]
            '34dfeb7d0cc60851a112fbbda37d09bf067c5eae37439c19210ff649341337e7'
            """
            return point2.base(s)

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Convert the Base64 UTF-8 string representation of a point to a point instance.

            >>> point.from_base64(
            ...     'NEpv+1fjZiqHt34jbtWI99kmecwtkDy//Kmsfj9XpeQRgEwOVD/rd4YH4gXUqEDm6C' +
            ...     'Q2exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            ... ).hex()[:64]
            '344a6ffb57e3662a87b77e236ed588f7d92679cc2d903cbffca9ac7e3f57a5e4'
            """
            return G.__new__(cls, G.deserialize(base64.standard_b64decode(s)))

        @classmethod
        def from_hex(cls, s: str) -> point:
            """
            Convert the hexadecimal UTF-8 string representation of a point to a point instance.

            >>> point.from_hex(
            ...     '346f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d2' +
            ...     '1e597c27f58b7cf87029fcdd03edc697d6c107bd5a7284d08c4116d1b72ea89a' +
            ...     '1ec25ecce13dd95858edfc48e8f2a6c405d83e25f08e1fa9bf4962fa73a0d54817'
            ... ).hex()[:64]
            '346f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d2'
            """
            return G.__new__(cls, G.deserialize(bytes.fromhex(s)))

        def hex(self) -> str:
            """
            Generates hexadecimal representation of the point instance.
            """
            return self.serialize().hex()[:64] # `hex(self)` fails, even though there is `G.__hex__`

        def __repr__(self) -> str:
            """
            Return string representation of this instance.
            """
            print(self.serialize(), end='', flush=True)
            return ''

        def __new__(cls, bs: Optional[bytes] = None) -> point:
            """
            If a bytes-like object is supplied, return a point object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, return a random point
            object.

            >>> bs = bytes.fromhex(
            ...     '34bb20e8dbca1c76266cb9a51a655c08f93247ad17c632e8d74dca168bdfddb0' +
            ...     '1d3be9e63a9f2c0b689b38ae9475e728dcb836466553fd04c1a51a90a7645c61' +
            ...     '0d46bad2e723a3511417c20956e8448131f04c7959ae8c606b2e7aca477c92170b'
            ... )
            >>> point(bs).hex()[:64]
            '34bb20e8dbca1c76266cb9a51a655c08f93247ad17c632e8d74dca168bdfddb0'
            >>> len(point())
            32
            """
            return G.__new__(cls, G.deserialize(bs)) if bs is not None else cls.random()

        def __mul__(self: point, other):
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
            >>> (s * p).hex()[:64]
            '34b60472878ad6b5ca553ae1416aae57571f0e843b092610b92f5599c5d1c1ab'
            """
            p = self.__class__._native.mul(other, self)
            return None if p.zero() else p

        def __add__(self: point, other: point) -> Optional[point]:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()[:64]
            '34448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f7'
            """
            p = self.__class__._native.add(self, other)
            return None if p.zero() else p

        def __sub__(self: point, other: point) -> Optional[point]:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).hex()[:64]
            '34bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb'
            """
            p = self.__class__._native.sub(self, other)
            return None if p.zero() else p

        def __matmul__(self: point, other: point2) -> Optional[scalar2]:
            """
            Return the result of pairing another point with this point.

            >>> p = point.hash('123'.encode())
            >>> q = point2.base(scalar.from_int(456))
            >>> z = (p @ q).hex()[700:]
            >>> z_mcl    = '3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'
            >>> z_native = '150f663b60a9bd1c7263a988765827328bee5c78602648cb82600a4730f4fc183301'
            >>> z == z_mcl if mclbn256 else z == z_native
            True

            After the finalexp function: gist.github.com/wyatt-howe/0ca575e99b73dada1f7fb63862a23a71
            from MCl (not implemented in the pure-Python library, or here, yet), the result hex. is:
            '3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'

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
            s = self.__class__._native.par(self, other)
            return s

        def __neg__(self: point) -> Optional[point]:
            """
            Return the negation (additive inverse) of this point

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()[:64]
            '34448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f7'
            """
            p = G.__new__(self.__class__, G.__neg__(self))
            return None if p.zero() else p

        def __len__(self) -> int:
            """Return length (in bytes) of the binary representation of this instance."""
            return bytes(self).__len__()

        def to_base64(self: point) -> str:
            """
            Convert to equivalent Base64 UTF-8 string representation.

            >>> p = point.from_base64(
            ...     'NEpv+1fjZiqHt34jbtWI99kmecwtkDy//Kmsfj9XpeQRgEwOVD/rd4YH4gXUqEDm6C' +
            ...     'Q2exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            ... )
            >>> p.to_base64()[-64:]
            'exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            """
            return base64.standard_b64encode(bytes(self)).decode('utf-8')

    _F = F

    class scalar(F): # pylint: disable=E0102
        """
        Wrapper class for a bytes-like object that corresponds
        to a scalar.
        """
        _native = native
        F = _F

        @classmethod
        def random(cls) -> scalar:
            """
            Return random non-zero scalar object.

            >>> len(scalar.random())
            32
            """
            return F.__new__(cls, cls._native.rnd())

        @classmethod
        def bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return scalar object obtained by transforming supplied bytes-like
            object if it is possible to do so; otherwise, return ``None``.

            >>> s = scalar()
            >>> t = scalar.bytes(bytes(s))
            >>> s.hex() == t.hex()[:64]
            True
            """
            s = cls._native.scl(bs)
            return F.__new__(cls, s) if s is not None else None

        @classmethod
        def hash(cls, bs: bytes) -> scalar:
            """
            Return scalar object by hashing supplied bytes-like object.

            >>> scalar.hash('123'.encode()).hex()[:64]
            '482d79cb1b8da4c68d16e9dffb6882716e11480e376ab51c6daf7fe88677c709'
            """
            h = hashlib.sha256(bs).digest()
            s = cls._native.scl(h)
            while s is None:
                h = hashlib.sha256(h).digest()
                s = cls._native.scl(h)
            return s

        @classmethod
        def from_base64(cls, s: str) -> scalar:
            """
            Convert Base64 UTF-8 string representation of a scalar to a scalar instance.

            >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()[:64]
            'b9cb30a0187fe56bd9784315638fb203b61007dae22d73581563968e92e6f415'
            """
            return F.__new__(cls, int.from_bytes(base64.standard_b64decode(s), 'little'))

        @classmethod
        def from_hex(cls, s: str) -> scalar:
            """
            Convert the hexadecimal UTF-8 string representation of a scalar to a scalar
            instance.

            >>> scalar.from_hex(
            ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            ... ).hex()[:64]
            'c423b05250408af6199ea09ff8c235d9ba4fd5ec58b2dda9125868bbc276ef1d'
            """
            return F.__new__(cls, F.from_bytes(bytes.fromhex(s), 'little'))

        @classmethod
        def from_int(cls, i: int) -> scalar:
            """
            Convert an integer/residue representation of a scalar to a scalar instance.

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
            return F.__new__(cls, i)

        def hex(self):
            """
            Generates hexadecimal representation of the point instance.
            """
            return bytes(self).hex()

        def __int__(self) -> int:
            """
            Generates an integer representation of the point instance.
            """
            n = self % r  # assert self < r  # assert int.__new__(int, self) < r
            return n if n < r / 2 else n - r

        def __repr__(self) -> str:
            """
            Return (debug) string representation of this instance.
            """
            print(bytes(self), end='', flush=True)
            return ''

        def __str__(self) -> str:
            """
            Return string representation of this instance.
            """
            print(int(self), end='', flush=True)
            return ''

        def __new__(cls, bs: bytes = None) -> scalar:
            """
            If a bytes-like object is supplied, return a scalar object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            scalar). If no argument is supplied, return a random scalar
            object.

            >>> s = scalar()
            >>> t = scalar(s)
            >>> s.hex() == t.hex()[:64]
            True
            >>> len(scalar())
            32
            """
            s = cls._native.scl(bs)
            return F.__new__(cls, s) if s is not None else cls.random()

        def __invert__(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scalar()
            >>> p = point()
            >>> ((~s) * (s * p)) == p
            True
            """
            return self.__class__._native.inv(self)

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

        def __mul__(self: scalar, other: Union[scalar, point]) -> Union[scalar, point, None]:
            """
            Multiply supplied scalar or point by this scalar.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> p = point.from_base64(
            ...     'NEpv+1fjZiqHt34jbtWI99kmecwtkDy//Kmsfj9XpeQRgEwOVD/rd4YH4gXUqEDm6C' +
            ...     'Q2exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            ... )
            >>> (s * s).hex()[:64]
            'c4948d8f468d2613e429370afdc7ab7105a3e86bbc43cac0a223d95e700a9707'
            >>> isinstance(s * s, scalar)
            True
            >>> (s * p).hex()[:64]
            '34e4487e7a431b32ff61d7671f5e682cabecd12a1404748f2da935cbfd7626a2'
            >>> isinstance(s * p, point)
            True
            """
            if isinstance(other, (self.__class__._native.scalar)):
                # if isinstance(other, (native.scalar, self.__class__._native.scalar)):#
                return self.__class__._native.smu(self, other)
            p = self.__class__._native.mul(self, other)  # other.__mul__(self)
            return None if p.zero() else p

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
            '6597614031feca36a2f1862ac69ec50764210eb4450eb2f628c62cdda268c606'
            >>> isinstance(s + s, scalar)
            True

            >>> z = point.base(s) @ point2.base(s)
            >>> zz = (z + z).hex()[700:]
            >>> zz_mcl    = '0318fa6a428def47eb38709deaa8f843c3916e30e932bb5ce0f70c8ca3a1112f9305'
            >>> zz_native = 'a40983c35f6010ec8ba4dc4fd20116064b176728e9f71543990f4e0baf2652abcc00'
            >>> zz == zz_mcl if mclbn256 else zz == zz_native
            True
            >>> isinstance(z + z, scalar2)
            True
            """
            return F.__new__(self.__class__, F.__add__(self, other))

        def __bytes__(self) -> bytes:
            """Return binary representation of this instance."""
            return self.serialize() if self.__class__.F == _Fp12 else int.to_bytes(self % r, 32, 'little')

        def __len__(self) -> int:
            """Return length (in bytes) of the binary representation of this instance."""
            return 32 if self < pow(2, 32*8) else 384
            # return bytes(self).__len__()

        def to_base64(self: scalar) -> str:
            """
            Convert to equivalent Base64 UTF-8 string representation.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> s.to_base64()
            'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
            """
            return base64.standard_b64encode(bytes(self)).decode('utf-8')

    # Encapsulate classes that use wrappers for shared/dynamic library bindings for methods.
    native.point = point
    native.scalar = scalar
    return native, point, scalar

_, point2, scalar2 = _make_native(_ECp2, _Fp12)
native, point, scalar = _make_native(_ECp, int)

# Encapsulate pure-Python functions.
scl = native.scl
rnd = native.rnd
inv = native.inv
smu = native.smu
pnt = native.pnt
bas = native.bas
bs2 = native.bs2
par = native.par
mul = native.mul
add = native.add
sad = native.sad
sad2 = native.sad2
sub = native.sub

# Indicate that data structures based on the dynamic/shared library have
# not been defined.
mclbn256 = False

# Encapsulate classes that use pure-Python implementations for methods.
native.point = point
native.scalar = scalar

#
# Attempt to load primitives from mclbn256, if it is present;
# otherwise, use the mclbn256 library.
#

try:
    # Attempt to load mclbn256 with its (bundled) shared/dynamic library file.
    from mclbn256 import Fr, G1, G2, GT

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
        is imported is to evaluate `mcl is None`.

        If a shared/dynamic library file has been loaded successfully,
        this class encapsulates shared/dynamic library variants of all
        primitive operations and classes exported by this module:
        :obj:`mcl.scl <scl>`, :obj:`mcl.rnd <rnd>`,
        :obj:`mcl.inv <inv>`, :obj:`mcl.smu <smu>`,
        :obj:`mcl.pnt <pnt>`, :obj:`mcl.bas <bas>`, :obj:`mcl.bs2 <bs2>`,
        :obj:`mcl.mul <mul>`, :obj:`mcl.add <add>`,
        :obj:`mcl.sad <sad>`, :obj:`mcl.sad2 <sad2>`,
        :obj:`mcl.sub <sub>`, :obj:`mcl.par <par>`,
        :obj:`mcl.point <point>`, and :obj:`mcl.scalar <scalar>`.
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

            >>> isinstance(rnd(), Fr)
            True
            """
            return Fr().randomize()

        @classmethod
        def scl(cls, s: Union[bytes, bytearray, None] = None) -> Optional[Fr]:
            """
            Construct a scalar if the supplied bytes-like object represents
            a valid scalar; otherwise, return ``None``. If no byte vector is
            supplied, return a random scalar.

            >>> s = scl()
            >>> t = scl(s)
            >>> s == t
            True
            >>> scl(bytes([255] * 32)) is None
            True
            """
            if s is None:
                return cls.rnd()

            try:
                s = Fr(s)
                if not s.is_zero():
                    return s
            except ValueError:
                return None

            # Addresses Pylint warning: ``inconsistent-return-statements``.
            return None # pragma: no cover

        @staticmethod
        def inv(s: Fr) -> Fr:
            r"""
            Return inverse of scalar modulo
            ``r = 16798108731015832284940804142231733909759579603404752749028378864165570215949``
            in the prime field *F*\_*r*.

            >>> s = scl()
            >>> p = pnt()
            >>> mul(inv(s), mul(s, p)) == p
            True
            """
            return Fr.__invert__(s)

        @staticmethod
        def smu(s: Fr, t: Fr) -> Fr:
            """
            Return scalar multiplied by another scalar.

            >>> s = scl()
            >>> t = scl()
            >>> smu(s, t) == smu(t, s)
            True
            """
            return Fr.__mul__(s, t)

        @staticmethod
        def sad(s: Fr, t: Fr) -> Fr:
            """
            Return scalar added to another scalar.

            >>> s = scl()
            >>> t = scl()
            >>> sad(s, t) == sad(t, s)
            True
            """
            return Fr.__add__(s, t)

        @staticmethod
        def pnt(h: Union[bytes, bytearray, None] = None) -> G1:
            """
            Construct a point if the supplied bytes-like object represents
            a valid point; otherwise, return ``None``. If no byte vector is
            supplied, return a random point.

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> p.tostr(1088).hex()[:64]
            '346d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf'
            """
            return G1.__new__(point, G1.random() if h is None else G1.mapfrom(h))

        @staticmethod
        def bas(s: Fr) -> G1:
            """
            Return base point multiplied by supplied scalar.

            >>> bytes(bas(scalar.hash('123'.encode()))).hex()[:64]
            'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
            """
            return G1.base_point() * s

        @staticmethod
        def mul(s: G1, p: G1) -> G1:
            """
            Multiply the point by the supplied scalar and return the result.

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> s = scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> mul(s, p).tostr(1088).hex()[:64]
            '34aa7645c6b3d473b7c6805cc3967ecdff6eb44cfea0a665861043e992c3fc1e'
            """
            return G1.__mul__(p, s)

        @staticmethod
        def add(p: G1, q: G1) -> G1:
            """
            Return sum of the supplied points.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> add(p, q).tostr(1088).hex()[:64]
            '34448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f7'
            """
            return G1.__add__(p, q)

        @staticmethod
        def sub(p: G1, q: G1) -> G1:
            """
            Return result of subtracting second point from first point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sub(p, q).tostr(1088).hex()[:64]
            '34bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb'
            """
            return G1.__sub__(p, q)

        @staticmethod
        def par(p: Union[G1, G2], q: Union[G1, G2]) -> GT:
            """
            Compute the pairing function on two points.

            >>> p = point.hash('123'.encode())
            >>> q = point2.base(scalar.from_int(456))
            >>> par(p, q).tostr(1088).hex()[700:]
            'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'

            The pairing function is bilinear.

            >>> p = point.random()
            >>> s = scalar.random()

            >>> t = scalar.random()
            >>> q = point2.random()
            >>> -((~s) * (s * p)) - p == scalar.from_int(-2) * p
            True
            >>> s * t * p @ q == s * p @ (t * q)
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

            Pairing is defined as ``e: (G1 x G2) -> GT``. This operation accepts a point and
            a second-level point.

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
        def rnd2() -> GT:
            """
            Return random non-zero second-level scalar.

            >>> isinstance(mcl.rnd2(), GT)
            True
            """
            p = point.random()
            q = point2.base(scalar.random())
            return mcl.par(p, q)

        @staticmethod
        def scl2(s: Union[bytes, bytearray, None] = None) -> Optional[GT]:
            """
            Construct a second-level scalar if the supplied bytes-like object
            represents a valid second-level scalar; otherwise, return ``None``.
            If no byte vector is supplied, return a random second-level scalar.

            >>> bs = bytes(scalar2.from_hex(
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805' +
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021' +
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710' +
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c' +
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c' +
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10' +
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911' +
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215' +
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002' +
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f' +
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622' +
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... ))
            >>> mcl.scl2(bs).tostr(1088).hex()[700:]
            '35145b2cf0fb3ca4a65aebc14a7c696e58b78fc9b7504a33bd4873f23a9ceaf75201'
            """
            if s is None:
                return mcl.rnd2()

            try:
                return GT.deserialize(s)
            except ValueError: # pragma: no cover
                return None

            return None

        @staticmethod
        def inv2(s: GT) -> GT:
            """
            Return the inverse of a second-level scalar.
            """
            return GT.__inv__(s)


        @staticmethod
        def smu2(s: GT, t: GT) -> GT:
            """
            Return scalar multiplied by another scalar.

            >>> p1 = point.hash('123'.encode())
            >>> p2 = point.hash('456'.encode())
            >>> q1 = point2.base(scalar.hash('123'.encode()))
            >>> q2 = point2.base(scalar.hash('456'.encode()))
            >>> s = p1 @ q1
            >>> t = p2 @ q2
            >>> mcl.smu2(s, t) == mcl.smu2(t, s)
            True
            """
            return GT.__mul__(s, t)

        @staticmethod
        def sad2(s: GT, t: GT) -> GT:
            """
            Return scalar added to another scalar.

            >>> s = scl2()
            >>> t = scl2()
            >>> sad2(s, t) == sad2(t, s)
            True
            """
            return GT.__add__(s, t)

        @staticmethod
        def pnt2(h: bytes = None) -> G2:
            """
            Construct a second-level point if the supplied bytes-like object
            represents a valid second-level point; otherwise, return ``None``.
            If no byte vector is supplied, return a random second-level point.

            >>> p = mcl.pnt2(hashlib.sha512('123'.encode()).digest())
            >>> p.tostr(1088).hex()[:128] == (
            ...     '342f742f356b0621f1c61891c7cc8fb988dc79b3be6f164fd4b0f9f833ade6aa' +
            ...     '1cb5b80e05db5afd589ccf2a6ddadee8ba108d9c25313d52ede65c058ab659fb'
            ... )
            True
            """
            return G2.random() if h is None else G2.mapfrom(h)

        @staticmethod
        def bas2(s) -> G2:
            """
            Return base point multiplied by supplied scalar.

            >>> bytes(bs2(scalar.hash('123'.encode()))).hex()[50:]
            'd1b99a7ca5660d124528b442d33e15eca23a202df3222c542e7bd71955c7623669554af518de01'
            """
            # return s * G2.__new__(point2, G2.base_point())
            return G2.base_point() * s

        @staticmethod
        def mul2(s: Fr, p: G2) -> G2:
            """
            Multiply a second-level point by a scalar.

            >>> p = point2.hash('123'.encode())
            >>> s = scl(bytes.fromhex(
            ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
            ... ))
            >>> mul2(s, p).tostr(1088).hex() == (
            ...     '3400b4ab995841dc4a07d967f729cf060ccc523e2488d7f43a1502b3fcbede10' +
            ...     '2492e908b39cfa5cb6cf54788eaa051f3d5547eb4eaedac85f246ee65e196eab' +
            ...     '212069764e60decd750f4e9af0466e9c09166d38acd68483101543fb2982168d' +
            ...     '0227245bf2ab45188b832031263a03135b6aae374f6906448650858a0e6e42d9' +
            ...     '1e0065b7cc518b81da1b65f813b695aea5a76dc476f8a82780d7550e93478fad1' +
            ...     '3689798227e5572ad2461e3972b98dd52dae5917db3f88005b2e61d50a1464013'
            ... )
            True
            """
            return G2.__mul__(p, s)

        @staticmethod
        def add2(p: G2, q: G2) -> G2:
            """
            Return sum of the supplied second-level points.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> add2(p, q).tostr(1088).hex() == (
            ...     '34f4fd8a265221c37e279252f3b45a66e901d87aed9873178cfabd60e52958d2' +
            ...     '24a66fe2a31cc05e6d5e75d9522ea1aacd54c72560cbd43735eb89b0798c2f50' +
            ...     '061da782a97e17b18d53d86a95b8ba115711f054660a17fd195a2fc5fe6412c8' +
            ...     '02d8776e0ff5ece51e407d96caeba3e4d100b8f59aa300038e458832f2eec183' +
            ...     '1c4d7c682d012e9049fe66102bad19796849d6f254099d7b12b733fb860d73471' +
            ...     'ea1d7afed4721cf2367cdf29ede71917a7a437f8c483a5d5aba3281c2c06b2915'
            ... )
            True
            """
            return G2.__add__(p, q)

        @staticmethod
        def sub2(p: G2, q: G2) -> G2:
            """
            Return result of subtracting one second-level point from another.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> sub2(p, q).tostr(1088).hex() == (
            ...     '34d7953fc7aca8b323666fd6fe8bf001ac06223d149e33a09eddd1a04958b12e' +
            ...     '222859a4f008c76531c7208aa6a08f2c5128b2d1f34d24c381e30ae6e9cc4e84' +
            ...     '182b8e5d456d3e6895e1b043fa1f1b525c78dafff8d51e42b932ab0b637a0b8d' +
            ...     '2128a6126ad40d68337c2087d8efb5eb3c922ce06b427cf56c7e947e12c63009' +
            ...     '214d7c682d012e9049fe66102bad19796849d6f254099d7b12b733fb860d73471' +
            ...     'ea1d7afed4721cf2367cdf29ede71917a7a437f8c483a5d5aba3281c2c06b2915'
            ... )
            True
            """
            return G2.__sub__(p, q)

    #
    # Dedicated point and scalar data structures.
    #

    class point(G1): # pylint: disable=W0621,E0102
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """
        @classmethod
        def random(cls) -> point:
            """
            Return random point object.

            >>> len(point.random())
            32
            """
            p = mcl.pnt()
            p.__class__ = point
            return p

        @classmethod
        def bytes(cls, bs: bytes) -> point:
            """
            Return point object obtained by transforming supplied bytes-like
            object if it is possible to do so; otherwise, return ``None``.

            >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()[:64]
            '346d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf'
            """
            p = mcl.pnt(bs)
            p.__class__ = point
            return p

        @classmethod
        def hash(cls, bs: bytes) -> point: # pylint: disable=arguments-differ
            """
            Return point object by hashing supplied bytes-like object.

            >>> point.hash('123'.encode()).hex()[:64]
            '34825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb48'
            """
            p = mcl.pnt(hashlib.sha512(bs).digest()[:32])
            p.__class__ = point
            return p

        @classmethod
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()[:64]
            '34dfeb7d0cc60851a112fbbda37d09bf067c5eae37439c19210ff649341337e7'
            """
            p = G1.__new__(cls, mcl.bas(s))
            p.__class__ = point
            return None if p.zero() else p

        @classmethod
        def from_hex(cls, s: str) -> point:
            """
            Convert the hexadecimal UTF-8 string representation of a point to a point instance.

            >>> point.from_hex(
            ...     '346f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d2' +
            ...     '1e597c27f58b7cf87029fcdd03edc697d6c107bd5a7284d08c4116d1b72ea89a' +
            ...     '1ec25ecce13dd95858edfc48e8f2a6c405d83e25f08e1fa9bf4962fa73a0d54817'
            ... ).hex()[:64]
            '346f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d2'
            """
            return G1.__new__(cls, G1().fromstr(bytes.fromhex(s), 1088))

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Construct an instance from its corresponding Base64 UTF-8 string representation.

            >>> point.from_base64(
            ...     'NEpv+1fjZiqHt34jbtWI99kmecwtkDy//Kmsfj9XpeQRgEwOVD/rd4YH4gXUqEDm6C' +
            ...     'Q2exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            ... ).hex()[:64]
            '344a6ffb57e3662a87b77e236ed588f7d92679cc2d903cbffca9ac7e3f57a5e4'
            """
            return G1.__new__(cls, G1().fromstr(base64.standard_b64decode(s), 1088))

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> point: # pylint: disable=arguments-differ
            """
            If a bytes-like object is supplied, return a point object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, return a random point
            object.

            >>> bs = bytes.fromhex(
            ...     '346f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d2' +
            ...     '1e597c27f58b7cf87029fcdd03edc697d6c107bd5a7284d08c4116d1b72ea89a' +
            ...     '1ec25ecce13dd95858edfc48e8f2a6c405d83e25f08e1fa9bf4962fa73a0d54817'
            ... )
            >>> point(bs).hex()[:64]
            '346f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d2'
            >>> len(point())
            32
            """
            return G1.__new__(cls, G1().fromstr(bs, 1088)) if bs is not None else cls.random()

        def __mul__(self: point, other):
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
            >>> (s * p).hex()[:64]
            '34b60472878ad6b5ca553ae1416aae57571f0e843b092610b92f5599c5d1c1ab'
            """
            p = mcl.mul(other, self)
            p.__class__ = point
            return None if p.zero() else p

        def __add__(self: point, other: point) -> Optional[point]:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()[:64]
            '34448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f7'
            """
            p = mcl.add(self, other)
            p.__class__ = point
            return None if p.zero() else p

        def __sub__(self: point, other: point) -> Optional[point]:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).hex()[:64]
            '34bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb'
            """
            p = mcl.sub(self, other)
            p.__class__ = point
            return None if p.zero() else p

        def __matmul__(self: point, other: point2) -> Optional[scalar2]:
            """
            Return the result of pairing another point with this point.

            >>> p = point.hash('123'.encode())
            >>> q = point2.base(scalar.from_int(456))
            >>> (p @ q).hex()[700:]
            '3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'

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
            s = mcl.par(self, other)
            s.__class__ = scalar2
            # Could be ``None if s.zero() or s.one() else s``, but no way to get identities.
            return s

        def __neg__(self: point) -> Optional[point]:
            """
            Return the negation (additive inverse) of this point

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()[:64]
            '34448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f7'
            """
            p = G1.__new__(self.__class__, G1.__neg__(self))
            p.__class__ = point
            return None if p.zero() else p

        def __len__(self: point) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(point())
            32
            """
            return bytes(self).__len__()

        def hex(self: point) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> p = point.hash('123'.encode())
            >>> p.hex()[-64:]
            '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            """
            # Note that ``hex(self)`` fails, even though ``G1.__hex__`` exists.
            return self.tostr(1088).hex()  # IoEcProj|IoArrayRaw == 1024|64 == 1088

        def to_base64(self: point) -> str:
            """
            Return an equivalent Base64 UTF-8 string representation of this instance.

            >>> p = point.from_base64(
            ...     'NEpv+1fjZiqHt34jbtWI99kmecwtkDy//Kmsfj9XpeQRgEwOVD/rd4YH4gXUqEDm6C' +
            ...     'Q2exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            ... )
            >>> p.to_base64()[-64:]
            'exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            """
            return base64.standard_b64encode(self.tostr(1088)).decode('utf-8')

    class scalar(Fr): # pylint: disable=E0102
        """
        Class for representing a scalar.
        """
        @classmethod
        def random(cls) -> scalar:
            """
            Return random non-zero scalar object.

            >>> len(scalar.random())
            32
            """
            return Fr.__new__(cls, mcl.rnd())

        @classmethod
        def bytes(cls, bs: bytes) -> Optional[scalar]:
            """
            Return scalar object obtained by transforming supplied bytes-like
            object if it is possible to do so; otherwise, return ``None``.

            >>> s = scalar()
            >>> t = scalar.bytes(bytes(s))
            >>> s.hex() == t.hex()[:64]
            True
            """
            s = mcl.scl(bs)
            s = Fr.__new__(cls, s) if s is not None else None
            return s

        @classmethod
        def hash(cls, bs: bytes) -> scalar:
            """
            Return scalar object by hashing supplied bytes-like object.

            >>> scalar.hash('123'.encode()).hex()[:64]
            '482d79cb1b8da4c68d16e9dffb6882716e11480e376ab51c6daf7fe88677c709'
            """
            h = hashlib.sha256(bs).digest()
            s = mcl.scl(h)
            while s is None:
                h = hashlib.sha256(h).digest()
                s = mcl.scl(h)

            s.__class__ = scalar
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
            return Fr.__new__(cls, i)

        @classmethod
        def from_hex(cls, s: str) -> scalar:
            """
            Convert the hexadecimal UTF-8 string representation of a scalar to a scalar
            instance.

            >>> scalar.from_hex(
            ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            ... ).hex()[:64]
            'c423b05250408af6199ea09ff8c235d9ba4fd5ec58b2dda9125868bbc276ef1d'
            """
            return Fr.__new__(cls, Fr.deserialize(bytes.fromhex(s)))

        @classmethod
        def from_base64(cls, s: str) -> scalar:
            """
            Convert Base64 UTF-8 string representation of a scalar to a scalar instance.

            >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()[:64]
            'b9cb30a0187fe56bd9784315638fb203b61007dae22d73581563968e92e6f415'
            """
            return Fr.__new__(cls, Fr.deserialize(base64.standard_b64decode(s)))

        def __new__(cls, s: Union[bytes, bytearray, None] = None) -> scalar: # pylint: disable=arguments-differ
            """
            If a bytes-like object is supplied, return a scalar object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            scalar). If no argument is supplied, return a random scalar
            object.

            >>> s = scalar()
            >>> t = scalar(s)
            >>> s.hex() == t.hex()[:64]
            True
            >>> len(scalar())
            32
            """
            return Fr.__new__(cls, s) if s is not None else cls.random()

        def __invert__(self: scalar) -> scalar:
            """
            Return inverse of scalar modulo
            ``2**252 + 27742317777372353535851937790883648493``.

            >>> s = scalar()
            >>> p = point()
            >>> ((~s) * (s * p)) == p
            True
            """
            s = mcl.inv(self)
            s.__class__ = scalar
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
            ) -> Union[scalar, point, point2, None]:
            """
            Multiply supplied scalar, point, or second-level point by this
            instance.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> (s * s).hex()[:64]
            'c4948d8f468d2613e429370afdc7ab7105a3e86bbc43cac0a223d95e700a9707'
            >>> isinstance(s * s, scalar)
            True
            >>> p = point.from_base64(
            ...     'NEpv+1fjZiqHt34jbtWI99kmecwtkDy//Kmsfj9XpeQRgEwOVD/rd4YH4gXUqEDm6C' +
            ...     'Q2exlXqxReLuZBGRb8hQsYFhqZua0pEoguRVDDd2My3uf/pRv6HfJctcjwkGfwIw=='
            ... )
            >>> (s * p).hex()[:64]
            '34e4487e7a431b32ff61d7671f5e682cabecd12a1404748f2da935cbfd7626a2'
            >>> isinstance(s * p, point)
            True

            If the second argument is a :obj:`point2` object, this method
            pre-empts :obj:`point2.__rmul__`.

            >>> p = point2.hash('123'.encode())
            >>> (s * p).hex()[:128] == (
            ...     '34e8bd0a0a52edcf9a9ae0e98c29e2ab4ff2260e3c2e4e7ffebd26c2788c4038' +
            ...     '032af0d8ada206fb669f62965e1ea5ec4d10368426d13cdfc3c70c93b34e647e'
            ... )
            True
            """
            if isinstance(other, scalar):
                s = mcl.smu(self, other)
                s.__class__ = scalar
                return s

            if isinstance(other, point):
                p = mcl.mul(self, other)
                p.__class__ = point
                return p

            if isinstance(other, point2):
                p = mcl.mul2(self, other)
                p.__class__ = point2
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
            '6597614031feca36a2f1862ac69ec50764210eb4450eb2f628c62cdda268c606'
            >>> isinstance(s + s, scalar)
            True

            >>> z = point.base(s) @ point2.base(s)
            >>> (z + z).hex()[700:]
            '0318fa6a428def47eb38709deaa8f843c3916e30e932bb5ce0f70c8ca3a1112f9305'
            >>> isinstance(z + z, scalar2)
            True
            """
            return Fr.__new__(self.__class__, Fr.__add__(self, other))

        def __len__(self: scalar) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(scalar())
            32
            """
            return bytes(self).__len__()

        def hex(self: scalar) -> str:
            """
            Return a hexadecimal representation of this instance.

            >>> s = scalar.hash('123'.encode())
            >>> s.hex()
            '482d79cb1b8da4c68d16e9dffb6882716e11480e376ab51c6daf7fe88677c709'
            """
            # Note that ``hex(self)`` fails, even though ``Fr.__hex__`` exists.
            return self.tostr(1088).hex()

        def to_base64(self: scalar) -> str:
            """
            Convert to equivalent Base64 UTF-8 string representation.

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> s.to_base64()
            'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
            """
            return base64.standard_b64encode(bytes(self)).decode('utf-8')

    class point2(G2): # pylint: disable=W0621,E0102
        # pylint: disable=C0301 # Accommodate large outputs in doctests.
        """
        Wrapper class for a bytes-like object that corresponds
        to a point.
        """
        @classmethod
        def random(cls) -> point2:
            """
            Return random instance.

            >>> len(point2.random())
            64
            """
            p = mcl.pnt2()
            p.__class__ = point2
            return p

        @classmethod
        def bytes(cls, bs: Union[bytes, bytearray]) -> point2:
            """
            Return second-level point obtained by transforming supplied bytes-like
            object.

            >>> p = point2.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()[:128] == (
            ...     '342f742f356b0621f1c61891c7cc8fb988dc79b3be6f164fd4b0f9f833ade6aa' +
            ...     '1cb5b80e05db5afd589ccf2a6ddadee8ba108d9c25313d52ede65c058ab659fb'
            ... )
            True
            """
            p = mcl.pnt2(bs)
            p.__class__ = point2
            return p

        @classmethod
        def hash(cls, bs: Union[bytes, bytearray]) -> point2: # pylint: disable=W0221
            """
            Construct an instance by hashing the supplied bytes-like object.

            >>> point2.hash('123'.encode()).hex()[:128] == (
            ...     '34b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba' +
            ...     '1b8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f30'
            ... )
            True
            """
            p = mcl.pnt2(hashlib.sha512(bs).digest()[:32])
            p.__class__ = point2
            return p

        @classmethod
        def base(cls, s: scalar) -> Optional[point2]:
            """
            Return base second-level point multiplied by the supplied scalar
            if the scalar is valid; otherwise, return ``None``.

            >>> point2.base(scalar.hash('123'.encode())).hex()[:128] == (
            ...     '3444c4594a118b339c699c1072debc2d3e58de5ee3cf7ec7a018982ed7744899' +
            ...     '0451b7ba30e34e05b0768f78c7f477f9b1c16053e10219748e6061ed60ad2821'
            ... )
            True
            """
            p = mcl.bas2(s)
            p.__class__ = point2
            return None if p.zero() else p

        @classmethod
        def from_hex(cls, s: str) -> point2:
            """
            Construct a second-level point from its hexadecimal UTF-8 string representation.

            >>> p = point2.from_hex(
            ...     '349781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d' +
            ...     '09baf46f54c19d1619095bfac06138925169628606bd83bc05050f49da501beb' +
            ...     '05bec8487cbb19df94a60bae19eeb29f073d5e94d68bfb3cf8c8f03204ae26f9' +
            ...     '0b214ca049febe607fcf00019aaeb704fc52fe00439c5f2d1d5b506f02ccb330' +
            ...     '05d5308fc98c4786d993a3e2e06daf5b51d2ef81a53063faf5da6c1cb57753bd' +
            ...     '1241d01fcd4aea1268d8b36ea3917ee728672b33cefe13fe705b2f863a26679811'
            ... )
            >>> p.hex()[:64]
            '349781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d'
            """
            p = G2.__new__(cls, G2().fromstr(bytes.fromhex(s), 1088))
            p.__class__ = point2
            return p

        @classmethod
        def from_base64(cls, s: str) -> point2:
            """
            Construct a second-level point from its Base64 UTF-8 string representation.

            >>> p = point2.from_base64(
            ...     'NJeB1+JFzMjcU993iGTwvyeBKOuhYUua34jgo6f0rI0J' +
            ...     'uvRvVMGdFhkJW/rAYTiSUWlihga9g7wFBQ9J2lAb6wW+' +
            ...     'yEh8uxnflKYLrhnusp8HPV6U1ov7PPjI8DIErib5CyFM' +
            ...     'oEn+vmB/zwABmq63BPxS/gBDnF8tHVtQbwLMszAF1TCP' +
            ...     'yYxHhtmTo+Lgba9bUdLvgaUwY/r12mwctXdTvRJB0B/N' +
            ...     'SuoSaNizbqORfucoZyszzv4T/nBbL4Y6JmeYEQ=='
            ... )
            >>> p.to_base64()[-64:]
            'gaUwY/r12mwctXdTvRJB0B/NSuoSaNizbqORfucoZyszzv4T/nBbL4Y6JmeYEQ=='
            """
            p = G2.__new__(cls, G2().fromstr(base64.standard_b64decode(s), 1088))
            p.__class__ = point2
            return p

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> point2: # pylint: disable=arguments-differ
            """
            If a bytes-like object is supplied, return a second-level point
            object corresponding to the supplied bytes-like object (no check
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, a random second-level point
            is returned.

            >>> bs = bytes.fromhex(
            ...     '349781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d' +
            ...     '09baf46f54c19d1619095bfac06138925169628606bd83bc05050f49da501beb' +
            ...     '05bec8487cbb19df94a60bae19eeb29f073d5e94d68bfb3cf8c8f03204ae26f9' +
            ...     '0b214ca049febe607fcf00019aaeb704fc52fe00439c5f2d1d5b506f02ccb330' +
            ...     '05d5308fc98c4786d993a3e2e06daf5b51d2ef81a53063faf5da6c1cb57753bd' +
            ...     '1241d01fcd4aea1268d8b36ea3917ee728672b33cefe13fe705b2f863a26679811'
            ... )
            >>> point2(bs).hex() == (
            ...     '349781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d' +
            ...     '09baf46f54c19d1619095bfac06138925169628606bd83bc05050f49da501beb' +
            ...     '05bec8487cbb19df94a60bae19eeb29f073d5e94d68bfb3cf8c8f03204ae26f9' +
            ...     '0b214ca049febe607fcf00019aaeb704fc52fe00439c5f2d1d5b506f02ccb330' +
            ...     '05d5308fc98c4786d993a3e2e06daf5b51d2ef81a53063faf5da6c1cb57753bd' +
            ...     '1241d01fcd4aea1268d8b36ea3917ee728672b33cefe13fe705b2f863a26679811'
            ... )
            True
            """
            p = G2.__new__(cls, G2().fromstr(bs, 1088)) if bs is not None else cls.random()
            p.__class__ = point2
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
            TypeError: second-level point can only be multiplied by a scalar
            """
            raise TypeError(
                'second-level point can only be multiplied by a scalar'
            )

        def __add__(self: point2, other: point2) -> Optional[point2]:
            """
            Return sum of this instance and another second-level point.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> (p + q).hex()[:128] == (
            ...     '34f4fd8a265221c37e279252f3b45a66e901d87aed9873178cfabd60e52958d2' +
            ...     '24a66fe2a31cc05e6d5e75d9522ea1aacd54c72560cbd43735eb89b0798c2f50'
            ... )
            True
            """
            p = G2.__add__(self, other)
            p.__class__ = point2
            return None if p.zero() else p

        def __sub__(self: point2, other: point2) -> Optional[point2]:
            """
            Return the result of subtracting another second-level point from
            this instance.

            >>> p = point2.hash('123'.encode())
            >>> q = point2.hash('456'.encode())
            >>> (p - q).hex()[:128] == (
            ...     '34d7953fc7aca8b323666fd6fe8bf001ac06223d149e33a09eddd1a04958b12e' +
            ...     '222859a4f008c76531c7208aa6a08f2c5128b2d1f34d24c381e30ae6e9cc4e84'
            ... )
            True
            """
            p = G2.__sub__(self, other)
            p.__class__ = point2
            return None if p.zero() else p

        def __neg__(self: point2) -> Optional[point2]:
            """
            Return the negation (additive inverse) of this instance.

            >>> p = point2.hash('123'.encode())
            >>> (-p).hex()[:128] == (
            ...     '34b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba' +
            ...     '1b8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f30'
            ... )
            True
            """
            p = G2.__neg__(self)
            p.__class__ = point2
            return None if p.zero() else p

        def __matmul__(self: point2, other: point) -> Optional[scalar2]:
            """
            Return the result of pairing another point with this point.

            Input-swapped alias of :obj:`point.__matmul__`.
            """
            return point.__matmul__(other, self)

        def __len__(self: point2) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(point2())
            64
            """
            return bytes(self).__len__()

        def hex(self: point2) -> str:
            """
            Generates hexadecimal representation of this instance.

            >>> p = point2.hash('123'.encode())
            >>> p.hex() == (
            ...     '34b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba' +
            ...     '1b8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f30' +
            ...     '0d7e59c60a595253ebf69bf0794b7a032e59b6b5037adba410d680b53ffac085' +
            ...     '17cf5bc3be9d850ec64ea6939904cf66b66b6b4b82be03ee4f10661fedaf8384' +
            ...     '1fba7e678442a658340a5b3c51eb5076d738cf88387ada6cbd1fe7f8d8a226841' +
            ...     '7bc8aedbc99808b0450025d0c75b5f1ccb34bc69934cc620d9ea51038a1d98721'
            ... )
            True
            """
            # Note that ``hex(self)`` fails, even though ``G2.__hex__`` exists.
            return self.tostr(1088).hex()

        def to_base64(self: point2) -> str:
            """
            Convert to equivalent Base64 UTF-8 string representation.

            >>> p = point2.from_base64(
            ...     'NJeB1+JFzMjcU993iGTwvyeBKOuhYUua34jgo6f0rI0J' +
            ...     'uvRvVMGdFhkJW/rAYTiSUWlihga9g7wFBQ9J2lAb6wW+' +
            ...     'yEh8uxnflKYLrhnusp8HPV6U1ov7PPjI8DIErib5CyFM' +
            ...     'oEn+vmB/zwABmq63BPxS/gBDnF8tHVtQbwLMszAF1TCP' +
            ...     'yYxHhtmTo+Lgba9bUdLvgaUwY/r12mwctXdTvRJB0B/N' +
            ...     'SuoSaNizbqORfucoZyszzv4T/nBbL4Y6JmeYEQ=='
            ... )
            >>> p.to_base64()[-64:]
            'gaUwY/r12mwctXdTvRJB0B/NSuoSaNizbqORfucoZyszzv4T/nBbL4Y6JmeYEQ=='
            """
            return base64.standard_b64encode(self.tostr(1088)).decode('utf-8')

    class scalar2(GT): # pylint: disable=function-redefined
        """
        Class for representing second-level scalars.
        """
        @classmethod
        def random(cls) -> scalar2:
            """
            Return random non-zero second-level scalar.

            >>> isinstance(scalar2.random(), scalar2)
            True
            >>> len(scalar2.random())
            384
            """
            s = GT.__new__(cls, mcl.scl2())
            s.__class__ = scalar2
            return s

        @classmethod
        def hash(cls, bs: Union[bytes, bytearray]) -> scalar2:
            """
            Return an instance derived by hashing the supplied bytes-like object.

            >>> scalar2.hash(bytes([123])).hex()[700:]
            '711c01cf0b95f190d86fc304e57f4757f285b068a0a5584218c73a8664066391b21a'
            """
            bs = hashlib.sha512(bs).digest()
            p = point.hash(bs[:32])
            q = point2.base(scalar.hash(bs[32:]))
            s = mcl.par(p, q)
            s.__class__ = scalar2
            return s

        @classmethod
        def from_hex(cls, s: str) -> scalar2:
            """
            Construct an instance from its hexadecimal UTF-8 string representation.

            >>> s = scalar2.from_hex(
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805' +
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021' +
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710' +
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c' +
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c' +
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10' +
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911' +
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215' +
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002' +
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f' +
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622' +
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... )
            >>> s.hex() == (
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805' +
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021' +
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710' +
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c' +
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c' +
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10' +
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911' +
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215' +
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002' +
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f' +
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622' +
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... )
            True
            """
            return GT.__new__(cls, GT.deserialize(bytes.fromhex(s)))

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
            return GT.__new__(cls, GT.deserialize(base64.standard_b64decode(s)))

        def __new__(cls, bs: Union[bytes, bytearray, None] = None) -> scalar2: # pylint: disable=arguments-differ
            """
            If a bytes-like object is supplied, return an instance that
            corresponds to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            scalar). If no argument is supplied, return a random scalar
            object.
            """
            return GT.__new__(cls, bs) if bs is not None else cls.random()

        def __invert__(self: scalar2) -> scalar2:
            """
            Return inverse of scalar.
            """
            return mcl.inv2(self)

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
            >>> bytes(s.inverse()).hex()[700:]
            'ec02e64a4556213eade4604303b93219233e21fd8e50f536e6421c7f73597f5bc905'
            >>> ~~s == s
            True
            >>> ~s == s
            False
            """
            return mcl.inv2(self)

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
            'be074ceff84460009cfd5cf5d7f985bb2e49b9687328b38f2bef0a025c081384150e'
            >>> scalar2() * point()
            Traceback (most recent call last):
              ...
            TypeError: second-level scalar can only be multiplied by another second-level scalar
            """
            if isinstance(other, scalar2):
                return mcl.smu2(self, other)

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

            >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
            >>> z = point.base(s) @ point2.base(s)
            >>> (z + z).hex()[700:]
            '0318fa6a428def47eb38709deaa8f843c3916e30e932bb5ce0f70c8ca3a1112f9305'
            >>> isinstance(z + z, scalar2)
            True
            """
            return GT.__new__(self.__class__, GT.__add__(self, other))

        def __len__(self: scalar2) -> int:
            """
            Return length (in bytes) of the binary representation of this instance.

            >>> len(scalar2.random())
            384
            """
            return bytes(self).__len__()

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
            ...     '18d0e065798ffa4ecca0a7cc6e2b8d6d3269f7eb413525e59b731332b02ea805' +
            ...     '4b90c89ce93e4452557f53aae5f8f13221858dde2ea6a50373f1858f11287021' +
            ...     '09b3daf7a217a20a3d872632f8ced643d32649b241a67601bec855bd43f07710' +
            ...     '88df722bcacc8fd174f16ad7ef1b1d5e622d93b7cfec6385c353c13793a4e01c' +
            ...     '371ef54cd836a88e1b1f1e198d566d3bbe5aa225734305f14cac9af9c821351c' +
            ...     '86b365190105d1b7e71011d1362ed6ad9133a2c2c42898e9ebc3d1604a608f10' +
            ...     '8461d37b2463b4f88f0ccb427b5eea8714ee88f8c33daf7ee4a3f45ca8bca911' +
            ...     '87956abb4d27de1b49e5e059f904fbb475804715ab25a17306fa0e196f305215' +
            ...     '3a60dfa073ca78de49edeaac9c54cab3d0138750c23c0b68de7924a69d1ba002' +
            ...     'a24ac592622a45c59c1ded7133794292a09602bd57a36601d35438846fcb370f' +
            ...     '39c0fa7a15b34d14ab6f95ee5bf5b26bd5def1e7ed07350922d445da07d93622' +
            ...     '2db5baa9dec152c2b2bcfc46cde6fd22e70271af8a164e77e5808ce602095a1f'
            ... )
            True
            """
            # Note that ``hex(self)`` fails, even though ``GT.__hex__`` exists.
            return self.serialize().hex()

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

    # Top-level best-effort synonyms.
    scl = mcl.scl
    rnd = mcl.rnd
    inv = mcl.inv
    smu = mcl.smu
    sad = mcl.sad
    pnt = mcl.pnt
    bas = mcl.bas
    mul = mcl.mul
    add = mcl.add
    sub = mcl.sub
    par = mcl.par
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

    # Gather classes that use wrappers for shared/dynamic library bindings for methods.
    mcl.point = point
    mcl.scalar = scalar
    mcl.point2 = point2
    mcl.scalar2 = scalar2

    # Indicate that data structures based on the dynamic/shared library have
    # successfully been defined.
    mclbn256 = True

except: # pylint: disable=W0702 # pragma: no cover
    mcl = None # pragma: no cover # Exported symbol.

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
