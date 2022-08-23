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
if __name__ == "__main__":
    from _bn254.ecp import generator as get_base
    from _bn254.ecp2 import generator as get_base2
    from _bn254.pair import e
    from _bn254 import big as bn, Fp12 as Fp12_
    from _bn254.ecp import ECp as ECp_
    from _bn254.ecp2 import ECp2 as ECp2_
    from _bn254.curve import r
else:
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
        return self.to_bytes().hex()

    def zero(self):
        return self.isinf()

    def __bytes__(self):
        return self.to_bytes()

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
        return self.to_bytes()

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
        return self.to_bytes()

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
            '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
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
            >>> z = par(p, q).hex()[700:]
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
            >>> mul(s, p).hex()[:64]
            'aa7645c6b3d473b7c6805cc3967ecdff6eb44cfea0a665861043e992c3fc1e'
            """
            s = s % r #assert int(s) < r
            return p.G.__new__(p.__class__, p.G.__rmul__(p.G(p), int(s)))

        @staticmethod
        def add(p: point, q: point) -> point:
            """
            Return sum of the supplied points.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> add(p, q).hex()[:64]
            '448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f719'
            """
            return p.G.__new__(p.__class__, p.G.add(p.copy(), q))

        @staticmethod
        def sub(p: point, q: point) -> point:
            """
            Return result of subtracting second point from first point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sub(p, q).hex()[:64]
            'bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb'
            """
            return p.G.__new__(p.__class__, p.G.add(-1 * q, p))

'''
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
            96
            """
            return cls._native.pnt()

        @classmethod
        def bytes(cls, bs: bytes) -> point:
            """
            Return point object obtained by transforming supplied bytes-like object.

            >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()[:64]
            '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf'
            """
            return cls._native.pnt(bs)

        @classmethod
        def hash(cls, bs: bytes) -> point:
            """
            Return point object by hashing supplied bytes-like object.

            >>> point.hash('123'.encode()).hex()[:64]
            '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            """
            return cls._native.pnt(hashlib.sha512(bs).digest()[:32])  # really only need ≥254-bits

        @classmethod
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()[:64]
            'dfeb7d0cc60851a112fbbda37d09bf067c5eae37439c19210ff649341337e7'
            """
            p = G.__new__(cls, (cls._native.bas if cls.G == _ECp else cls._native.bs2)(s))
            return None if p.zero() else p

        @classmethod
        def base2(cls, s: scalar) -> Optional[point2]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()[:64]
            'dfeb7d0cc60851a112fbbda37d09bf067c5eae37439c19210ff649341337e7'
            """
            return point2.base(s)

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Convert the Base64 UTF-8 string representation of a point to a point instance.

            >>> point.from_base64(
            ...     'Sm/7V+NmKoe3fiNu1Yj32SZ5zC2QPL/8qax+P1el5BGATA5UP+t3hgfiBdSoQObo'
            ...     'JDZ7GVerFF4u5kEZFvyFCxgWGpm5rSkSiC5FUMN3YzLe5/+lG/od8ly1yPCQZ/Aj'
            ... ).hex()[:64]
            '4a6ffb57e3662a87b77e236ed588f7d92679cc2d903cbffca9ac7e3f57a5e4'
            """
            return G.__new__(cls, G.deserialize(base64.standard_b64decode(s)))

        @classmethod
        def from_hex(cls, s: str) -> point:
            """
            Convert the hexadecimal UTF-8 string representation of a point to a point instance.

            >>> point.from_hex(
            ...     '6f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d21e' +
            ...     '597c27f58b7cf87029fcdd03edc697d6c107bd5a7284d08c4116d1b72ea89a1e' +
            ...     'c25ecce13dd95858edfc48e8f2a6c405d83e25f08e1fa9bf4962fa73a0d54817'
            ... ).hex()[:64]
            '6f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d21e'
            """
            return G.__new__(cls, G.deserialize(bytes.fromhex(s)))

        def hex(self) -> str:
            """
            Generates hexadecimal representation of the point instance.
            """
            return self.to_bytes().hex() # `hex(self)` fails, even though there is `G.__hex__`

        def __repr__(self) -> str:
            """
            Return string representation of this instance.
            """
            print(self.to_bytes(), end='', flush=True)
            return ''

        def __new__(cls, bs: Optional[bytes] = None) -> point:
            """
            If a bytes-like object is supplied, return a point object
            corresponding to the supplied bytes-like object (no checking
            is performed to confirm that the bytes-like object is a valid
            point). If no argument is supplied, return a random point
            object.

            >>> bs = bytes.fromhex(
            ...     'bb20e8dbca1c76266cb9a51a655c08f93247ad17c632e8d74dca168bdfddb01d' +
            ...     '3be9e63a9f2c0b689b38ae9475e728dcb836466553fd04c1a51a90a7645c610d' +
            ...     '46bad2e723a3511417c20956e8448131f04c7959ae8c606b2e7aca477c92170b'
            ... )
            >>> point(bs).hex()[:64]
            'b60472878ad6b5ca553ae1416aae57571f0e843b092610b92f5599c5d1c1ab0c'
            >>> len(point())
            96
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
            'b60472878ad6b5ca553ae1416aae57571f0e843b092610b92f5599c5d1c1ab'
            """
            p = self.__class__._native.mul(other, self)
            return None if p.zero() else p

        def __add__(self: point, other: point) -> Optional[point]:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()[:64]
            '448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f719'
            """
            p = self.__class__._native.add(self, other)
            return None if p.zero() else p

        def __sub__(self: point, other: point) -> Optional[point]:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).hex()[:64]
            'bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb07'
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
            '448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f719'
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
            'e4487e7a431b32ff61d7671f5e682cabecd12a1404748f2da935cbfd7626a2'
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
            return self.to_bytes() if self.__class__.F == _Fp12 else int.to_bytes(self % r, 32, 'little')

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
'''

# _, point2, scalar2 = _make_native(_ECp2, _Fp12)
# native, point, scalar = _make_native(_ECp, int)
#
# # Encapsulate pure-Python functions.
# scl = native.scl
# rnd = native.rnd
# inv = native.inv
# smu = native.smu
# pnt = native.pnt
# bas = native.bas
# bs2 = native.bs2
# par = native.par
# mul = native.mul
# add = native.add
# sad = native.sad
# sad2 = native.sad2
# sub = native.sub
#
# # Indicate that data structures based on the dynamic/shared library have
# # not been defined.
# mclbn256 = False
#
# # Encapsulate classes that use pure-Python implementations for methods.
# native.point = point
# native.scalar = scalar

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

            >>> s = mcl.rnd()
            >>> isinstance(s, Fr)
            True
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
            >>> t = mcl.scl(mcl.scalar.to_bytes(s))
            >>> s == t
            True
            >>> mcl.scl(bytes([255] * 32)) is None
            True
            """
            if bs is None:
                return cls.rnd()

            try:
                s = sde(bs)
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
            >>> mcl.point.to_bytes(p).hex()[:64]
            '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
            """
            return G1.random() if h is None else G1.mapfrom(h)

        @staticmethod
        def bas(s: Fr) -> G1:
            """
            Return base point multiplied by supplied scalar.

            >>> mcl.point.to_bytes(mcl.bas(mcl.scalar.hash('123'.encode()))).hex()[:64]
            'a67f57d9a09ce5cf7ae7de06e79b691e0ddbcb16e46df1deb8d70a8b109be30e'
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
            >>> mcl.point.to_bytes(mcl.mul(s, p)).hex()[:64]
            '3433f81d39af903c7a791daefcde5bcbba3ef4c6c7aaba1650028971ecd7941c'
            """
            return G1.__mul__(p, s)

        @staticmethod
        def add(p: G1, q: G1) -> G1:
            """
            Return sum of the supplied points.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.point.hash('456'.encode())
            >>> mcl.point.to_bytes(mcl.add(p, q)).hex()[:64]
            '448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f719'
            """
            return G1.__add__(p, q)

        @staticmethod
        def sub(p: G1, q: G1) -> G1:
            """
            Return result of subtracting second point from first point.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.point.hash('456'.encode())
            >>> mcl.point.to_bytes(mcl.sub(p, q)).hex()[:64]
            'bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb07'
            """
            return G1.__sub__(p, q)

        @staticmethod
        def neg(p: G1) -> G1:
            """
            Return the additive inverse of a point.

            >>> p = mcl.point.hash('123'.encode())
            >>> mcl.point.to_bytes(mcl.neg(p)).hex()[:64]
            '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            """
            return G1.__neg__(p)

        @staticmethod
        def par(p: Union[G1, G2], q: Union[G1, G2]) -> GT:
            """
            Compute the pairing function on two points.

            >>> p = mcl.point.hash('123'.encode())
            >>> q = mcl.point2.base(mcl.scalar.from_int(456))
            >>> mcl.scalar2.to_bytes(mcl.par(p, q)).hex()[700:]
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
        def ser(p: G1) -> bytes:
            """
            Return the binary representation of a point.

            >>> p = mcl.point.hash('123'.encode())
            >>> mcl.des(mcl.ser(p)) == p
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants
            return p.tostr(IoEcProj|IoArrayRaw)[1:]

        @staticmethod
        def des(bs: bytes) -> G1:
            """
            Return a point from its binary representation.

            >>> p = mcl.point.hash('123'.encode())
            >>> ser_p = bytes.fromhex(
            ...   '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
            ...   'b03c992ec97868be765b98048118a96f42bdc466a963c243c223b95196304209'
            ...   '8effffffffffff158affffffffff39b9cdffffffff2ec6a2f5ffff7ff2a42b21'
            ... )
            >>> mcl.des(ser_p) == p
            True
            >>> mcl.ser(mcl.des(ser_p)) == ser_p
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants
            return G1.new_fromstr(b"4"+bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def sse(s: Fr) -> bytes:
            """mcl.
            Return the binary representation of a scalar.

            >>> s = mcl.scalar.hash('123'.encode())
            >>> mcl.sde(mcl.sse(s)) == s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants
            return s.tostr(IoEcProj|IoArrayRaw)

        @staticmethod
        def sde(bs: bytes) -> Fr:
            """
            Return a scalar from its binary representation.

            >>> s = mcl.scalar.hash('123'.encode())
            >>> sse_s = bytes.fromhex(
            ...   '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
            ... )
            >>> mcl.sde(sse_s) == s
            True
            >>> mcl.sse(mcl.sde(sse_s)) == sse_s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants
            return Fr.new_fromstr(bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def des2(bs: bytes) -> G2:
            """
            Return a second-group point from its binary representation.

            >>> p = mcl.point2.hash('123'.encode())
            >>> ser_p = bytes.fromhex(
            ...   'b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba1b'
            ...   '8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f300d'
            ...   '7e59c60a595253ebf69bf0794b7a032e59b6b5037adba410d680b53ffac08517'
            ...   'cf5bc3be9d850ec64ea6939904cf66b66b6b4b82be03ee4f10661fedaf83841f'
            ...   'ba7e678442a658340a5b3c51eb5076d738cf88387ada6cbd1fe7f8d8a2268417'
            ...   'bc8aedbc99808b0450025d0c75b5f1ccb34bc69934cc620d9ea51038a1d98721'
            ... )
            >>> mcl.des2(ser_p) == p
            True
            >>> mcl.ser(mcl.des2(ser_p)) == ser_p
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants
            return G2.new_fromstr(b"4"+bs, IoEcProj|IoArrayRaw)

        @staticmethod
        def sde2(bs: bytes) -> GT:
            """
            Return a second-level scalar from its binary representation.

            >>> s = mcl.scalar2.hash('123'.encode())
            >>> sse_s = bytes.fromhex(
            ...   'b7c5063f93b7da4157a7a6cbc023dd81fd0eea08340b6a8d1ab1abadde517818'
            ...   'f20e988accef435f8482ac28c43d9c32f7a2ebe8a17e625d37508ac49c25cb1c'
            ...   'a4116ea2edee37eaa94ae5d04843701da4f1e580c996c0f83b8521a206bbac18'
            ...   'ed7b09acced4660ffe3c998f22fbaac0f8e6bdac50b0c3fe01371bb3cc5b8019'
            ...   '8fceff7530bb0d47148ebc3851b4326f87f3ba7b0d6604b2132deee6b87cce1d'
            ...   '55ba56cfc158e961b99d284bab92bfa9ac31f412817ace3acbebb19b8e556705'
            ...   '578f3ba79cc95e0e463bca77df27677e7251e5b75e426e9d07421e2ef6c6eb1f'
            ...   '32a4894dc91e206736d0e3bfb23027576ce4ae40b2077802cf8bf2e4309e2b1b'
            ...   '211bfef25c103fb37c4db09ce1e162730d682a727aa799c84cc94d162bb0340c'
            ...   '6d3ae24fbec091b48871f7f0ae2ee0015d8d6e343439521d31dd4ffccb270522'
            ...   'a46c6efdc550c38c9e58383d096a8f0636e7c4bdecf461e4b79ee2e982d43410'
            ...   '66c7fd4df4415aaaba4b4f70c8e119a743074a930f558112d9c4447aaf78ac07'
            ... )
            >>> mcl.sde2(sse_s) == s
            True
            >>> mcl.sse(mcl.sde2(sse_s)) == sse_s
            True
            """
            IoEcProj, IoArrayRaw = 1024, 64  # MCl constants
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
            return mcl.par(p, q)

        @staticmethod
        def scl2(s: Union[bytes, bytearray, None] = None) -> Optional[GT]:
            """
            Construct a second-level scalar if the supplied bytes-like object
            represents a valid second-level scalar; otherwise, return ``None``.
            If no byte vector is supplied, return a random second-level scalar.

            >>> bs = bytes.fromhex(
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
            >>> mcl.scalar2.to_bytes(mcl.scl2(bs)).hex()[700:]
            '35145b2cf0fb3ca4a65aebc14a7c696e58b78fc9b7504a33bd4873f23a9ceaf75201'
            """
            if s is None:
                return mcl.rnd2()

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
            >>> mcl.point2.to_bytes(p).hex()[:128] == (
            ...     '2f742f356b0621f1c61891c7cc8fb988dc79b3be6f164fd4b0f9f833ade6aa1c' +
            ...     'b5b80e05db5afd589ccf2a6ddadee8ba108d9c25313d52ede65c058ab659fb01'
            ... )
            True
            """
            return G2.random() if h is None else G2.mapfrom(h)

        @staticmethod
        def bas2(s) -> G2:
            """
            Return base point multiplied by supplied scalar.

            >>> mcl.point2.to_bytes(mcl.bas2(mcl.scalar.hash('123'.encode()))).hex()[-64:]
            'c7ebe37352d6335bbd0726b461d52e9e0e82dd4f97b0587c652ff0607769d922'
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
            >>> mcl.point2.to_bytes(mcl.mul2(s, p)).hex() == (
            ...     '857e3001cdf579a7b9965d670b4f5ca64fe538d1ddc13251401ec2a221973e11'
            ...     'e578f35c903ffb3afd9d4092267508c10c3e41881fe4fe9a124ed936c623d515'
            ...     'c5e9c6e8d0664e1a26a62635a9b852a765fad113393826cb7d5067fa55bb2a15'
            ...     '5a6be5a856451ac349e8ed9694ed8d017b6eba74ce830389efb9e0b1b0b7160b'
            ...     '4e72f7d27266af39c8c971ffb2a9e36a1bf338ce0817ba9e084fe174d7e66a1b'
            ...     'a56b5b75d31dc7ae88815ca8d8965c5516b7a21f7edd98c521449fcc3e55e00b'
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
            >>> mcl.point2.to_bytes(mcl.add2(p, q)).hex() == (
            ...     'f4fd8a265221c37e279252f3b45a66e901d87aed9873178cfabd60e52958d224' +
            ...     'a66fe2a31cc05e6d5e75d9522ea1aacd54c72560cbd43735eb89b0798c2f5006' +
            ...     '1da782a97e17b18d53d86a95b8ba115711f054660a17fd195a2fc5fe6412c802' +
            ...     'd8776e0ff5ece51e407d96caeba3e4d100b8f59aa300038e458832f2eec1831c' +
            ...     '4d7c682d012e9049fe66102bad19796849d6f254099d7b12b733fb860d73471e' +
            ...     'a1d7afed4721cf2367cdf29ede71917a7a437f8c483a5d5aba3281c2c06b2915'
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
            >>> mcl.point2.to_bytes(mcl.sub2(p, q)).hex() == (
            ...     'd7953fc7aca8b323666fd6fe8bf001ac06223d149e33a09eddd1a04958b12e22' +
            ...     '2859a4f008c76531c7208aa6a08f2c5128b2d1f34d24c381e30ae6e9cc4e8418' +
            ...     '2b8e5d456d3e6895e1b043fa1f1b525c78dafff8d51e42b932ab0b637a0b8d21' +
            ...     '28a6126ad40d68337c2087d8efb5eb3c922ce06b427cf56c7e947e12c6300921' +
            ...     '4d7c682d012e9049fe66102bad19796849d6f254099d7b12b733fb860d73471e' +
            ...     'a1d7afed4721cf2367cdf29ede71917a7a437f8c483a5d5aba3281c2c06b2915'
            ... )
            True
            """
            return G2.__sub__(p, q)

        @staticmethod
        def neg2(p: G2) -> G2:
            """
            Return the negation of a second-group point.

            >>> p = mcl.point2.hash('123'.encode())
            >>> mcl.point2.to_bytes(mcl.neg2(p)).hex() == (
            ...     'b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba1b'
            ...     '8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f300d'
            ...     '95a639f5a6adacbb1c640f86b4851d33af494afc05728fa92b7f4a0088a39d0d'
            ...     '44a43c41627af1e0c4596c66fb30baaa9c94b47dc149466af199e052d2e09e05'
            ...     'ba7e678442a658340a5b3c51eb5076d738cf88387ada6cbd1fe7f8d8a2268417'
            ...     'bc8aedbc99808b0450025d0c75b5f1ccb34bc69934cc620d9ea51038a1d98721'
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
    raise ModuleNotFoundError("mcl failed")
    mcl = None  # pragma: no cover # Exported symbol.

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

        >>> len(mcl.point.random())
        96
        """
        p = pnt()
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

        >>> p = mcl.point.bytes(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()[:64]
        '6d68495eb4d539db4df70fd24d54fae37c9adf7dfd8dc705ccb8de8630e7cf22'
        """
        p = pnt(bs)
        p.__class__ = cls
        return p

    @classmethod
    def hash(cls, bs: bytes) -> point: # pylint: disable=arguments-differ
        """
        Return point object by hashing supplied bytes-like object.

        >>> mcl.point.hash('123'.encode()).hex()[:64]
        '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
        """
        p = pnt(hashlib.sha512(bs).digest()[:32])
        p.__class__ = cls
        return p

    @classmethod
    def base(cls, s: scalar) -> point:
        """
        Return base point multiplied by supplied scalar
        if the scalar is valid.

        >>> mcl.point.base(mcl.scalar.hash('123'.encode())).hex()[:64]
        'a67f57d9a09ce5cf7ae7de06e79b691e0ddbcb16e46df1deb8d70a8b109be30e'
        """
        p = bas(s)
        p.__class__ = cls
        return p

    @classmethod
    def from_bytes(cls, bs: bytes) -> point:
        """
        Deserialize the bytes representation of a point and return the point instance.

        >>> p = mcl.point.hash('123'.encode())
        >>> bs = p.to_bytes()
        >>> mcl.point.from_bytes(bs) == p
        True
        >>> type(bs) is bytes
        True
        """
        p = des(bs)
        p.__class__ = cls
        return p

    @classmethod
    def from_hex(cls, s: str) -> point:
        """
        Convert the hexadecimal UTF-8 string representation of a point to a point instance.

        >>> mcl.point.from_hex(
        ...     '6f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d21e' +
        ...     '597c27f58b7cf87029fcdd03edc697d6c107bd5a7284d08c4116d1b72ea89a1e' +
        ...     'c25ecce13dd95858edfc48e8f2a6c405d83e25f08e1fa9bf4962fa73a0d54817'
        ... ).hex()[:64]
        '6f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d21e'
        """
        return cls.from_bytes(bytes.fromhex(s))

    @classmethod
    def from_base64(cls, s: str) -> point:
        """
        Construct an instance from its corresponding Base64 UTF-8 string representation.

        >>> mcl.point.from_base64(
        ...     'Sm/7V+NmKoe3fiNu1Yj32SZ5zC2QPL/8qax+P1el5BGATA5UP+t3hgfiBdSoQObo'
        ...     'JDZ7GVerFF4u5kEZFvyFCxgWGpm5rSkSiC5FUMN3YzLe5/+lG/od8ly1yPCQZ/Aj'
        ... ).hex()[:64]
        '4a6ffb57e3662a87b77e236ed588f7d92679cc2d903cbffca9ac7e3f57a5e411'
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
        ...     '6f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d21e' +
        ...     '597c27f58b7cf87029fcdd03edc697d6c107bd5a7284d08c4116d1b72ea89a1e' +
        ...     'c25ecce13dd95858edfc48e8f2a6c405d83e25f08e1fa9bf4962fa73a0d54817'
        ... )
        >>> mcl.point(bs).hex()[:64]
        '6f6257f18b206fcc2e159cb945600be3dadc3e5d24ecc25d850f62cb2d95d21e'
        >>> len(mcl.point())
        96
        """
        return cls.from_bytes(bs) if bs is not None else cls.random()

    def __mul__(self: point, other):
        """
        Use of this method is not permitted. A point cannot be a left-hand argument.

        >>> mcl.point() * mcl.scalar()
        Traceback (most recent call last):
          ...
        TypeError: point must be on right-hand side of multiplication operator
        """
        raise TypeError('point must be on right-hand side of multiplication operator')

    def __rmul__(self: point, other: scalar) -> point:
        """
        Multiply this point by the supplied scalar and return the result.

        >>> p = mcl.point.hash('123'.encode())
        >>> s = mcl.scalar.hash('456'.encode())
        >>> (s * p).hex()[:64]
        '438fd27cd2537530eff87e827b2fe844cae1fd5cf17fcc5165cb2f4e22b8c90d'
        """
        p = mul(other, self)
        p.__class__ = self.__class__ # = point
        return p

    def __add__(self: point, other: point) -> point:
        """
        Return sum of this point and another point.

        >>> p = mcl.point.hash('123'.encode())
        >>> q = mcl.point.hash('456'.encode())
        >>> (p + q).hex()[:64]
        '448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f719'
        """
        p = mcl.add(self, other)
        p.__class__ = self.__class__ # = point
        return p

    def __sub__(self: point, other: point) -> point:
        """
        Return the result of subtracting another point from this point.

        >>> p = mcl.point.hash('123'.encode())
        >>> q = mcl.point.hash('456'.encode())
        >>> (p - q).hex()[:64]
        'bf1212d1028ba42f9f47065c17afc8d07299afe483e3e7e3e39fa3f763bceb07'
        """
        p = sub(self, other)
        p.__class__ = self.__class__ # = point
        return p

    def __matmul__(self: point, other: point2) -> scalar2:
        """
        Return the result of pairing another point with this point.

        >>> p = mcl.point.hash('123'.encode())
        >>> q = mcl.point2.base(mcl.scalar.from_int(456))
        >>> (p @ q).hex()[700:]
        'd01f7e038b05acc5519eeda026c4aa111eb12f3483f274c60e34e6ec7571435df707'

        The pairing function is bilinear
        >>> p = mcl.point.random()
        >>> s = mcl.scalar.random()

        >>> t = mcl.scalar.random()
        >>> q = mcl.point2.random()
        >>> -((~s) * (s * p)) - p == mcl.scalar.from_int(-2) * p
        True
        >>> s*t*p @ q == s*p @ (t*q)
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
        """
        s = par(self, other)
        s.__class__ = mcl.scalar2
        return s

    def __neg__(self: point) -> point:
        """
        Return the negation (additive inverse) of this point

        >>> p = mcl.point.hash('123'.encode())
        >>> q = mcl.point.hash('456'.encode())
        >>> (p + q).hex()[:64]
        '448e4ef105c30224fd1dabc80e86370a6cfe20acfedf44624be9a9693dc6f719'
        """
        p = neg(self)
        p.__class__ = self.__class__ # = point
        return p

    def __len__(self: point) -> int:
        """
        Return length (in bytes) of the binary representation of this instance.

        >>> len(mcl.point())
        96
        """
        return bytes(self).__len__()

    def __bytes__(self: point) -> bytes:
        """
        Return the binary representation of this instance.

        >>> len(bytes(mcl.point()))
        96
        """
        return self.to_bytes()

    def to_bytes(self: point) -> bytes:
        """
        Serialize this point and return its representation as bytes.

        >>> p = mcl.point.hash('123'.encode())
        >>> bs = p.to_bytes()
        >>> mcl.point.from_bytes(bs) == p
        True
        >>> type(bs) is bytes
        True
        """
        return ser(self)

    def hex(self: point) -> str:
        """
        Return a hexadecimal representation of this instance.

        >>> p = mcl.point.hash('123'.encode())
        >>> p.hex()[:64]
        '825aa78af4c88d6de4abaebabf1a96f668956b92876cfb5d3a44829899cb480f'
        """
        return self.to_bytes().hex()

    def to_base64(self: point) -> str:
        """
        Return an equivalent Base64 UTF-8 string representation of this instance.

        >>> p = mcl.point.from_base64(
        ...     'Sm/7V+NmKoe3fiNu1Yj32SZ5zC2QPL/8qax+P1el5BGATA5UP+t3hgfiBdSoQObo'
        ...     'JDZ7GVerFF4u5kEZFvyFCxgWGpm5rSkSiC5FUMN3YzLe5/+lG/od8ly1yPCQZ/Aj'
        ... )
        >>> p.to_base64()[-64:]
        'JDZ7GVerFF4u5kEZFvyFCxgWGpm5rSkSiC5FUMN3YzLe5/+lG/od8ly1yPCQZ/Aj'
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

class scalar(Fr): # pylint: disable=E0102
    """
    Class for representing a scalar.
    """
    @classmethod
    def random(cls) -> scalar:
        """
        Return random non-zero scalar object.

        >>> len(mcl.scalar.random())
        32
        """
        s = rnd()
        s.__class__ = cls
        return s

    @classmethod
    def bytes(cls, bs: bytes) -> Optional[scalar]:
        """
        Return scalar object obtained by transforming supplied bytes-like
        object if it is possible to do so; otherwise, return ``None``.

        >>> s = mcl.scalar()
        >>> t = mcl.scalar.bytes(bytes(s))
        >>> s.hex() == t.hex()
        True
        """
        s = scl(bs)
        if s is not None:
            s.__class__ = cls
        return s

    @classmethod
    def hash(cls, bs: bytes) -> scalar:
        """
        Return scalar object by hashing supplied bytes-like object.

        >>> mcl.scalar.hash('123'.encode()).hex()[:64]
        '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
        """
        h = hashlib.sha256(bs).digest()
        s = scl(h)
        while s is None:
            h = hashlib.sha256(h).digest()
            s = scl(h)

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

        >>> int(mcl.scalar.from_int(
        ...    16798108731015832284940804142231733909759579603404752749028378864165570215948
        ... ))
        -1
        >>> int(mcl.scalar.from_int(
        ...    -8399054365507916142470402071115866954879789801702376374514189432082785107974
        ... ))
        -8399054365507916142470402071115866954879789801702376374514189432082785107974
        >>> int(mcl.scalar.from_int(
        ...     12345678
        ... ))
        12345678
        """
        r = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
        d = 0x212ba4f27ffffff5a2c62effffffffd00242ffffffffff9c39ffffffffffffb2
        return cls.bytes(int.to_bytes((i * d) % r, 32, 'little'))

    @classmethod
    def from_bytes(cls, bs: bytes) -> scalar:
        """
        Deserialize the bytes representation of a scalar and return the scalar instance.

        >>> s = mcl.scalar.hash('123'.encode())
        >>> bs = s.to_bytes()
        >>> mcl.scalar.from_bytes(bs) == s
        True
        >>> type(bs) is bytes
        True
        """
        s = sde(bs)
        s.__class__ = cls
        return s

    @classmethod
    def from_hex(cls, s: str) -> scalar:
        """
        Convert the hexadecimal UTF-8 string representation of a scalar to a scalar
        instance.

        >>> mcl.scalar.from_hex(
        ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
        ... ).hex()[:64]
        '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
        """
        return cls.from_bytes(bytes.fromhex(s))

    @classmethod
    def from_base64(cls, s: str) -> scalar:
        """
        Convert Base64 UTF-8 string representation of a scalar to a scalar instance.

        >>> mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()[:64]
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

        >>> s = mcl.scalar()
        >>> t = mcl.scalar(bytes(s))
        >>> s.hex() == t.hex()
        True
        >>> len(mcl.scalar())
        32
        """
        return cls.from_bytes(bs) if bs is not None else cls.random()

    def __invert__(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        ``2**252 + 27742317777372353535851937790883648493``.

        >>> s = mcl.scalar()
        >>> p = mcl.point()
        >>> ((~s) * (s * p)) == p
        True
        """
        s = inv(self)
        s.__class__ = self.__class__ # = scalar
        return s

    def inverse(self: scalar) -> scalar:
        """
        Return inverse of scalar modulo
        ``2**252 + 27742317777372353535851937790883648493``.

        >>> s = mcl.scalar()
        >>> p = mcl.point()
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

        >>> s = mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> (s * s).hex()[:64]
        '0497a5b6a7992e7d77b59c07d4457e8bb3cf580603cfd19e05d1f31342141b00'
        >>> isinstance(s * s, mcl.scalar)
        True
        >>> p = mcl.point.from_base64(
        ...     'Sm/7V+NmKoe3fiNu1Yj32SZ5zC2QPL/8qax+P1el5BGATA5UP+t3hgfiBdSoQObo'
        ...     'JDZ7GVerFF4u5kEZFvyFCxgWGpm5rSkSiC5FUMN3YzLe5/+lG/od8ly1yPCQZ/Aj'
        ... )
        >>> (s * p).hex()[:64]
        '92e0736c20a98d5ee1a87a5581ec39d15dadfe78f764de8b10816badb3a0f11b'
        >>> isinstance(s * p, mcl.point)
        True

        If the second argument is a :obj:`point2` object, this method
        pre-empts :obj:`point2.__rmul__`.

        >>> p = mcl.point2.hash('123'.encode())
        >>> (s * p).hex()[:128] == (
        ...     'bc463967d25116ddaa02730506135251f991d65bb879dbc1af3d8eba3a193410' +
        ...     '9da6b99ab6280c77b30047d639a4a9273f7a3ddba13279f12952ead4cdbb191a'
        ... )
        True
        """
        if isinstance(other, mcl.scalar):
            s = smu(self, other)
            s.__class__ = self.__class__ # = scalar
            return s

        if isinstance(other, mcl.point):
            p = mul(self, other)
            p.__class__ = other.__class__ # = point
            return p

        if isinstance(other, mcl.point2):
            p = mul2(self, other)
            p.__class__ = other.__class__ # = point2
            return p

        return None

    def __rmul__(self: scalar, other: Union[scalar, point]):
        """
        A scalar cannot be on the right-hand side of a non-scalar.

        >>> mcl.point() * mcl.scalar()
        Traceback (most recent call last):
          ...
        TypeError: point must be on right-hand side of multiplication operator
        """
        raise TypeError('scalar must be on left-hand side of multiplication operator')

    def __add__(self: scalar, other: scalar) -> scalar:
        """
        Add this scalar with another scalar.

        >>> s = mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> (s + s).hex()[:64]
        '625a182261ec23a77c93eba171d42a27bc68bdd6e3615ebf3eda39dca2bf4a00'
        >>> isinstance(s + s, mcl.scalar)
        True

        >>> z = mcl.point.base(s) @ mcl.point2.base(s)
        >>> (z + z).hex()[700:]
        '1c0daff47053fbcec33770d7c21b4c610d3a4c9c625cbec0c84493ea27a58f9aa722'
        >>> isinstance(z + z, mcl.scalar2)
        True
        """
        s = sad(self, other)
        s.__class__ = self.__class__ # = scalar
        return s

    def __sub__(self: scalar, other: scalar) -> scalar:
        """
        Subtract this scalar from another scalar.

        >>> s = mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> (s - s).hex() == '00' * len(s)
        True
        >>> isinstance(s - s, mcl.scalar)
        True
        """
        s = ssb(self, other)
        s.__class__ = self.__class__ # = scalar
        return s

    def __neg__(self: scalar) -> scalar:
        """
        Negate this scalar.

        >>> s = mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> (-s).hex()
        'dcd2f36ecf096e4d52360a2fc7150aeca94ba1148e1c855ae212e3d1b004fe24'
        >>> isinstance(-s, mcl.scalar)
        True
        """
        s = sne(self)
        s.__class__ = self.__class__ # = scalar
        return s

    def __len__(self: scalar) -> int:
        """
        Return length (in bytes) of the binary representation of this instance.

        >>> len(mcl.scalar())
        32
        """
        return bytes(self).__len__()

    def __bytes__(self: scalar) -> bytes:
        """
        Return the binary representation of this instance.

        >>> len(bytes(mcl.scalar()))
        32
        """
        return self.to_bytes()

    def to_bytes(self: scalar) -> bytes:
        """
        Serialize this scalar and return its representation as bytes.

        >>> s = mcl.scalar.hash('123'.encode())
        >>> bs = s.to_bytes()
        >>> mcl.scalar.from_bytes(bs) == s
        True
        >>> type(bs) is bytes
        True
        """
        return sse(self)

    def hex(self: scalar) -> str:
        """
        Return a hexadecimal representation of this instance.

        >>> s = mcl.scalar.hash('123'.encode())
        >>> s.hex()
        '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
        """
        return self.to_bytes().hex()

    def to_base64(self: scalar) -> str:
        """
        Convert to equivalent Base64 UTF-8 string representation.

        >>> s = mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> s.to_base64()
        'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

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

        >>> len(mcl.point2.random())
        192
        """
        p = pnt2()
        p.__class__ = cls
        return p

    @classmethod
    def bytes(cls, bs: Union[bytes, bytearray]) -> point2:
        """
        Return second-group point obtained by transforming supplied bytes-like
        object.

        >>> p = mcl.point2.bytes(hashlib.sha512('123'.encode()).digest())
        >>> p.hex()[:128] == (
        ...     '2f742f356b0621f1c61891c7cc8fb988dc79b3be6f164fd4b0f9f833ade6aa1c' +
        ...     'b5b80e05db5afd589ccf2a6ddadee8ba108d9c25313d52ede65c058ab659fb01'
        ... )
        True
        """
        p = pnt2(bs)
        p.__class__ = cls
        return p

    @classmethod
    def hash(cls, bs: Union[bytes, bytearray]) -> point2: # pylint: disable=W0221
        """
        Construct an instance by hashing the supplied bytes-like object.

        >>> mcl.point2.hash('123'.encode()).hex()[:128] == (
        ...     'b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba1b' +
        ...     '8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f300d'
        ... )
        True
        """
        p = pnt2(hashlib.sha512(bs).digest()[:32])
        p.__class__ = cls
        return p

    @classmethod
    def base(cls, s: scalar) -> point2:
        """
        Return base second-group point multiplied by the supplied scalar
        if the scalar is valid; otherwise, return ``None``.

        >>> mcl.point2.base(mcl.scalar.hash('123'.encode())).hex()[:128] == (
        ...     'e5625a9b4515490c87158df594e7f8bcfef1c4b59c242ceb17b29dabfd6b1614' +
        ...     '492de719a86d02f81486be7cf7c765b93b28ef3ba3c1ab8e686eb91879e3ce16'
        ... )
        True
        """
        p = bas2(s)
        p.__class__ = cls
        return p

    @classmethod
    def from_bytes(cls, bs: bytes) -> point2:
        """
        Deserialize the bytes representation of a second-group point and return the instance.

        >>> p = mcl.point2.hash('123'.encode())
        >>> bs = p.to_bytes()
        >>> mcl.point2.from_bytes(bs) == p
        True
        >>> type(bs) is bytes
        True
        """
        p = des2(bs)
        p.__class__ = cls
        return p

    @classmethod
    def from_hex(cls, s: str) -> point2:
        """
        Construct a second-group point from its hexadecimal UTF-8 string representation.

        >>> p = mcl.point2.from_hex(
        ...     '9781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d09' +
        ...     'baf46f54c19d1619095bfac06138925169628606bd83bc05050f49da501beb05' +
        ...     'bec8487cbb19df94a60bae19eeb29f073d5e94d68bfb3cf8c8f03204ae26f90b' +
        ...     '214ca049febe607fcf00019aaeb704fc52fe00439c5f2d1d5b506f02ccb33005' +
        ...     'd5308fc98c4786d993a3e2e06daf5b51d2ef81a53063faf5da6c1cb57753bd12' +
        ...     '41d01fcd4aea1268d8b36ea3917ee728672b33cefe13fe705b2f863a26679811'
        ... )
        >>> p.hex()[:64]
        '9781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d09'
        """
        p = cls.from_bytes(bytes.fromhex(s))
        p.__class__ = cls
        return p

    @classmethod
    def from_base64(cls, s: str) -> point2:
        """
        Construct a second-group point from its Base64 UTF-8 string representation.

        >>> p = mcl.point2.from_base64(
        ...     '1e8RZms9smwYT3/m6wNFXUuZsf/1PrQsFvt1dBpD8x8TtwQKwEcqW'
        ...     '444Ac3cMDBucX0/+rq68Mb/FWVBVXkdAT4kRkPKJJu3TlvKj77P8i'
        ...     'vMHG1ByJne8ekzkxwfqY4gIEOARXRgzA+YtIpSXaCq5f0wXf6k2rd'
        ...     'bfCnq/k8fYCB7VCKG2FhKDtwjloplhDP+XHEcBJYGNjQ2te8BGQ0W'
        ...     'C9zbUt6iYW+mahIKALBa95uh2VeTU/yKskgEqPHbPY4U'
        ... )
        >>> p.to_base64()[-64:]
        'XHEcBJYGNjQ2te8BGQ0WC9zbUt6iYW+mahIKALBa95uh2VeTU/yKskgEqPHbPY4U'
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
        ...     '9781d7e245ccc8dc53df778864f0bf278128eba1614b9adf88e0a3a7f4ac8d09' +
        ...     'baf46f54c19d1619095bfac06138925169628606bd83bc05050f49da501beb05' +
        ...     'bec8487cbb19df94a60bae19eeb29f073d5e94d68bfb3cf8c8f03204ae26f90b' +
        ...     '214ca049febe607fcf00019aaeb704fc52fe00439c5f2d1d5b506f02ccb33005' +
        ...     'd5308fc98c4786d993a3e2e06daf5b51d2ef81a53063faf5da6c1cb57753bd12' +
        ...     '41d01fcd4aea1268d8b36ea3917ee728672b33cefe13fe705b2f863a26679811'
        ... )
        >>> mcl.point2.from_bytes(bs).hex() == bs.hex()
        True
        >>> mcl.point2.from_bytes(bs).to_bytes() == bs
        True
        """
        p = cls.from_bytes(bs) if bs is not None else cls.random()
        p.__class__ = cls # = point2
        return p

    def __mul__(self: point, other):
        """
        Use of this method is not permitted. A point cannot be a left-hand argument.

        >>> mcl.point2() * mcl.scalar()
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

        >>> p = mcl.point2.hash('123'.encode())
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

        >>> p = mcl.point2.hash('123'.encode())
        >>> q = mcl.point2.hash('456'.encode())
        >>> (p + q).hex()[:128] == (
        ...     'f4fd8a265221c37e279252f3b45a66e901d87aed9873178cfabd60e52958d224' +
        ...     'a66fe2a31cc05e6d5e75d9522ea1aacd54c72560cbd43735eb89b0798c2f5006'
        ... )
        True
        """
        p = add2(self, other)
        p.__class__ = self.__class__ # = point2
        return p

    def __sub__(self: point2, other: point2) -> Optional[point2]:
        """
        Return the result of subtracting another second-group point from
        this instance.

        >>> p = mcl.point2.hash('123'.encode())
        >>> q = mcl.point2.hash('456'.encode())
        >>> (p - q).hex()[:128] == (
        ...     'd7953fc7aca8b323666fd6fe8bf001ac06223d149e33a09eddd1a04958b12e22' +
        ...     '2859a4f008c76531c7208aa6a08f2c5128b2d1f34d24c381e30ae6e9cc4e8418'
        ... )
        True
        """
        p = sub2(self, other)
        p.__class__ = self.__class__ # = point2
        return p

    def __neg__(self: point2) -> Optional[point2]:
        """
        Return the negation (additive inverse) of this instance.

        >>> p = mcl.point2.hash('123'.encode())
        >>> (-p).hex()[:128] == (
        ...     'b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba1b'
        ...     '8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f300d'
        ... )
        True
        """
        p = neg2(self)
        p.__class__ = self.__class__ # = point2
        return p

    def __matmul__(self: point2, other: point) -> Optional[scalar2]:
        """
        Return the result of pairing another point with this point.

        Input-swapped alias of :obj:`point.__matmul__`.
        """
        return mcl.point.__matmul__(other, self)

    def __len__(self: point2) -> int:
        """
        Return length (in bytes) of the binary representation of this instance.

        >>> len(mcl.point2())
        192
        """
        return bytes(self).__len__()

    def __bytes__(self: point2) -> bytes:
        """
        Return the binary representation of this instance.

        >>> len(bytes(mcl.point2()))
        192
        """
        return self.to_bytes()

    def to_bytes(self: point2) -> bytes:
        """
        Serialize this second-group point and return its representation as bytes.

        >>> p = mcl.point2.hash('123'.encode())
        >>> bs = p.to_bytes()
        >>> mcl.point2.from_bytes(bs) == p
        True
        >>> type(bs) is bytes
        True
        """
        return ser(self)

    def hex(self: point2) -> str:
        """
        Generates hexadecimal representation of this instance.

        >>> p = mcl.point2.hash('123'.encode())
        >>> p.hex() == (
        ...     'b5b0a52e43ba71ae03317333da4ba9452dbdbbec353ade0c732348e0bea4ba1b' +
        ...     '8860718e5ba784d55799ab292459a638f6399738a6de348742e6a789674f300d' +
        ...     '7e59c60a595253ebf69bf0794b7a032e59b6b5037adba410d680b53ffac08517' +
        ...     'cf5bc3be9d850ec64ea6939904cf66b66b6b4b82be03ee4f10661fedaf83841f' +
        ...     'ba7e678442a658340a5b3c51eb5076d738cf88387ada6cbd1fe7f8d8a2268417' +
        ...     'bc8aedbc99808b0450025d0c75b5f1ccb34bc69934cc620d9ea51038a1d98721'
        ... )
        True
        """
        return self.to_bytes().hex()

    def to_base64(self: point2) -> str:
        """
        Convert to equivalent Base64 UTF-8 string representation.

        >>> p = mcl.point2.from_base64(
        ...     'jlFzA78Vio9xgpo7'
        ...     'qRM1/El9zyBR/NDDLdBDQCBnDRPrUv7i+55gzKmlYJEK'
        ...     'y9dlL/4jTKF9V/2tQCavplpiGnqBS0cykf2tK1LwTAOq'
        ...     'oBJusHKjvdRHgWpZuDZfe5UMfEBSjp0KAA+H81FHKAIM'
        ...     'HdGYIHF39qvU1TAPjfKYSwATrfEHBKFj6MZrdw5eoWYt'
        ...     'Jt3zOQjvYuf7Mkyhbo/iEUql7r8s5S4Scfxxu13bTpDr8UsIC5ZsJr3Vx0eB4AQA'
        ... )
        >>> p.to_base64()[-64:]
        'Jt3zOQjvYuf7Mkyhbo/iEUql7r8s5S4Scfxxu13bTpDr8UsIC5ZsJr3Vx0eB4AQA'
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

class scalar2(GT): # pylint: disable=function-redefined
    """
    Class for representing second-level scalars.
    """
    @classmethod
    def random(cls) -> scalar2:
        """
        Return random non-zero second-level scalar.

        >>> isinstance(mcl.scalar2.random(), mcl.scalar2)
        True
        >>> len(mcl.scalar2.random())
        384
        """
        s = mcl.scl2()
        s.__class__ = cls
        return s

    @classmethod
    def hash(cls, bs: Union[bytes, bytearray]) -> scalar2:
        """
        Return an instance derived by hashing the supplied bytes-like object.

        >>> mcl.scalar2.hash(bytes([123])).hex()[700:]
        'd210461ad2293454f3c2e9ad5fedcb671d0f13b30ec467744b9a16c881bb572bb50c'
        """
        bs = hashlib.sha512(bs).digest()
        p = mcl.point.hash(bs[:32])
        q = mcl.point2.base(mcl.scalar.hash(bs[32:]))
        s = par(p, q)
        s.__class__ = cls
        return s

    @classmethod
    def from_bytes(cls, bs: bytes) -> scalar2:
        """
        Deserialize the bytes representation of a second-level scalar and return the instance.

        >>> s = mcl.scalar2.hash('123'.encode())
        >>> bs = s.to_bytes()
        >>> mcl.scalar2.from_bytes(bs) == s
        True
        >>> type(bs) is bytes
        True
        """
        s = sde2(bs)
        s.__class__ = cls
        return s

    @classmethod
    def from_hex(cls, s: str) -> scalar2:
        """
        Construct an instance from its hexadecimal UTF-8 string representation.

        >>> s = mcl.scalar2.from_hex(
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
        >>> s = mcl.scalar2.from_base64(b64s)
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
        s = inv2(self)
        s.__class__ = self.__class__ # = scalar2
        return s

    def inverse(self: scalar2) -> scalar2:
        """
        Return inverse of this scalar.

        >>> s = mcl.scalar2.from_base64(
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
        s = inv2(self)
        s.__class__ = self.__class__ # = scalar2
        return s

    def __mul__(self: scalar2, other: scalar2) -> scalar2:
        """
        Multiply supplied scalar by another scalar.

        >>> s = mcl.scalar2.from_base64(
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
        >>> mcl.scalar2() * mcl.point()
        Traceback (most recent call last):
          ...
        TypeError: second-level scalar can only be multiplied by another second-level scalar
        """
        if isinstance(other, mcl.scalar2):
            s = smu2(self, other)
            s.__class__ = self.__class__ # = scalar2
            return s

        raise TypeError(
            'second-level scalar can only be multiplied by another second-level scalar'
        )

    def __rmul__(self: scalar2, other: Union[scalar2, point2]):
        """
        A scalar cannot be on the right-hand side of a non-scalar.

        >>> 2 * mcl.scalar2()
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

        >>> s = mcl.scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
        >>> z = mcl.point.base(s) @ mcl.point2.base(s)
        >>> (z + z).hex()[700:]
        '1c0daff47053fbcec33770d7c21b4c610d3a4c9c625cbec0c84493ea27a58f9aa722'
        >>> isinstance(z + z, mcl.scalar2)
        True
        """
        s = sad2(self, other)
        s.__class__ = self.__class__ # = scalar2
        return s

    def __len__(self: scalar2) -> int:
        """
        Return length (in bytes) of the binary representation of this instance.

        >>> len(mcl.scalar2.random())
        384
        """
        return bytes(self).__len__()

    def __bytes__(self: scalar2) -> bytes:
        """
        Return the binary representation of this instance.

        >>> len(bytes(mcl.scalar2()))
        384
        """
        return self.to_bytes()

    def to_bytes(self: scalar2) -> bytes:
        """
        Serialize this scalar and return its representation as bytes.

        >>> s = mcl.scalar2.hash('123'.encode())
        >>> bs = s.to_bytes()
        >>> mcl.scalar2.from_bytes(bs) == s
        True
        >>> type(bs) is bytes
        True
        """
        return sse(self)

    def hex(self: scalar2) -> str:
        """
        Return a hexadecimal representation of this instance.

        >>> s = mcl.scalar2.from_base64(
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
        >>> s = mcl.scalar2.from_base64(b64s)
        >>> s.to_base64() == b64s
        True
        """
        return base64.standard_b64encode(bytes(self)).decode('utf-8')



# Gather classes that use wrappers for shared/dynamic library bindings for methods.
mcl.point = point
mcl.scalar = scalar
mcl.point2 = point2
mcl.scalar2 = scalar2



if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
