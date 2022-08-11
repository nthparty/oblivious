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
def _make_native(G, F, global_scope=True):
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
        :obj:`native.pnt <pnt>`, :obj:`native.bas <bas>`, :obj:`native.bas <bs2>`,
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

            >>> len(rnd())
            32
            """
            return F.__new__(scalar, secrets.randbelow(r-1)+1)

        @classmethod
        def scl(cls, s: bytes = None) -> Optional[scalar]:
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

        # @staticmethod
        # def sad(s: scalar, t: scalar) -> scalar:
        #     """
        #     Return scalar added to another scalar.
        #
        #     >>> s = scl()
        #     >>> t = scl()
        #     >>> sad(s, t) == sad(t, s)
        #     True
        #     """
        #     return F.__new__(s.__class__, F.__sad__(s, t) % r)

        @staticmethod
        def pnt(h: bytes = None) -> point:
            """
            Return point from 64-byte vector (normally obtained via hashing).

            >>> p = pnt(hashlib.sha512('123'.encode()).digest())
            >>> p.hex()
            '9c6f2b3917ac249b3a43b3df3399ff54cd185be714a24541782b142a7ccb3423'
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
            >>> q = point.base2(scalar.from_int(456))
            >>> z = par(p, q).hex()[700:]
            >>> z_mcl    = '3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'
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
            >>> q = point2.random()  # -or- point.base2(scalar.random())
            >>> -((~s) * (s * p)) - p == scalar.from_int(-2) * p
            True
            >>> s*t*p @ q == s*p @ (t*q)
            True

            >>> x = y = p

            Suppose there are two points: one multiplied by the scalar ``s`` and the other
            multiplied by the scalar ``t``. Their equality can be determined by using a
            balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
            same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

            >>> g = point.base2(scalar.from_int(1))
            >>> b = point.base2(~s * t)
            >>> (t * x) @ g == (s * y) @ b
            True
            """
            # p = point.random()
            # s = scalar.random()
            # t = scalar.random()
            # q = point2.random()
            # stp = s * t * p
            # tq = (t * q)
            # b = stp @ q == s * p @ tq

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
            >>> mul(s, p).hex()
            'a7f9b967b2d85e2b18e93717d1aac438ce660017023a1207a080f45b42c6b19f'
            """
            s = s % r #assert int(s) < r
            return p.G.__new__(p.__class__, p.G.__rmul__(p.G(p), int(s)))

        @staticmethod
        def add(p: point, q: point) -> point:
            """
            Return sum of the supplied points.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> add(p, q).hex()
            '1a78bb2f044b38e84a82b6eb7bbc2d339132481a98d635aca3b78c899095b68b'
            """
            return p.G.__new__(p.__class__, p.G.add(p.copy(), q))

        @staticmethod
        def sub(p: point, q: point) -> point:
            """
            Return result of subtracting second point from first point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> sub(p, q).hex()
            '7dad51d4465bcd77bebf243c466726192a411d527dbd5ab8124a98ab0ccc8922'
            """
            return p.G.__new__(p.__class__, p.G.add(-1 * q, p))

    if global_scope:
        # Top-level best-effort synonyms.
        global scl, rnd, inv, smu, pnt, bas, bs2, par, mul, add, sub # pylint: disable=W0601
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
        sub = native.sub

        global mclbn256 # pylint: disable=W0603
        mclbn256 = False

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
            >>> p.hex()
            '9c6f2b3917ac249b3a43b3df3399ff54cd185be714a24541782b142a7ccb3423'
            """
            return cls._native.pnt(bs)

        @classmethod
        def hash(cls, bs: bytes) -> point:
            """
            Return point object by hashing supplied bytes-like object.

            >>> point.hash('123'.encode()).hex()
            'a8884a30f29ca2163f5719b5c4d9707bb94ae44bd54811d44b2c8b78af64c711'
            """
            return cls._native.pnt(hashlib.sha512(bs).digest()[:32])  # really only need ≥254-bits

        @classmethod
        def base(cls, s: scalar) -> Optional[point]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()
            'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
            """
            p = G.__new__(cls, (cls._native.bas if cls.G == _ECp else cls._native.bs2)(s))
            return None if p.zero() else p

        @classmethod
        def base2(cls, s: scalar) -> Optional[point2]:
            """
            Return base point multiplied by supplied scalar
            if the scalar is valid; otherwise, return `None`.

            >>> point.base(scalar.hash('123'.encode())).hex()
            'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
            """
            return point2.base(s)

        @classmethod
        def from_base64(cls, s: str) -> point:
            """
            Convert the Base64 UTF-8 string representation of a point to a point instance.

            >>> point.from_base64('hoVmn8Pi6U9Gx8L/cJxHHYTjwrl0bKMNNPMjoxXqGJI=').hex()
            '8685669fc3e2e94f46c7c2ff709c471d84e3c2b9746ca30d34f323a315ea1892'
            """
            return G.__new__(cls, G.deserialize(base64.standard_b64decode(s)))

        @classmethod
        def from_hex(cls, s: str) -> point:
            """
            Convert the hexadecimal UTF-8 string representation of a point to a point instance.

            >>> point.from_hex(
            ...     'afa9a593ff45b66b3545fe6e56fa56da0d966fd7a61dec45bf99a45a45ab4d0c'
            ... ).hex()
            'afa9a593ff45b66b3545fe6e56fa56da0d966fd7a61dec45bf99a45a45ab4d0c'
            """
            return G.__new__(cls, G.deserialize(bytes.fromhex(s)))

        def hex(self) -> str:
            """
            Generates hexadecimal representation of the point instance.
            """
            return self.serialize().hex()  # `hex(self)` fails, even though there is `G.__hex__`

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
            ...     '80e437b94b704007e4f2fcfabae00df29853a8e027cc85e6328b870b4fd1be8a'
            ... )
            >>> point(bs).hex()
            '80e437b94b704007e4f2fcfabae00df29853a8e027cc85e6328b870b4fd1be8a'
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
            >>> (s * p).hex()
            '3914c4cf63ce5a5a3dab97e837038959403999221186f5f923328abedd0f151d'
            """
            p = self.__class__._native.mul(other, self)
            return None if p.zero() else p

        def __add__(self: point, other: point) -> Optional[point]:
            """
            Return sum of this point and another point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p + q).hex()
            '1a78bb2f044b38e84a82b6eb7bbc2d339132481a98d635aca3b78c899095b68b'
            """
            p = self.__class__._native.add(self, other)
            return None if p.zero() else p

        def __sub__(self: point, other: point) -> Optional[point]:
            """
            Return the result of subtracting another point from this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.hash('456'.encode())
            >>> (p - q).hex()
            '7dad51d4465bcd77bebf243c466726192a411d527dbd5ab8124a98ab0ccc8922'
            """
            p = self.__class__._native.sub(self, other)
            return None if p.zero() else p

        def __matmul__(self: point, other: point2) -> Optional[scalar2]:
            """
            Return the result of pairing another point with this point.

            >>> p = point.hash('123'.encode())
            >>> q = point.base2(scalar.from_int(456))
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

            >>> g = point.base2(scalar.from_int(1))
            >>> b = point.base2(~s * t)
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
            >>> (p + q).hex()
            '1a78bb2f044b38e84a82b6eb7bbc2d339132481a98d635aca3b78c899095b68b'
            """
            p = G.__new__(self.__class__, G.__neg__(self))
            return None if p.zero() else p

        def __len__(self) -> int:
            """Return length (in bytes) of the binary representation of this instance."""
            return bytes(self).__len__()

        def to_base64(self: point) -> str:
            """
            Convert to equivalent Base64 UTF-8 string representation.

            >>> p = point.from_base64('5fLTU+9atKP+91ZEZWc1qX6mzsmI39kFKqSlRiYiZxo=')
            >>> p.to_base64()
            '5fLTU+9atKP+91ZEZWc1qX6mzsmI39kFKqSlRiYiZxo='
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
            object if it is possible to do; otherwise, return `None`.

            >>> s = scl()
            >>> t = scalar.bytes(bytes(s))
            >>> s.hex() == t.hex()
            True
            """
            s = cls._native.scl(bs)
            return F.__new__(cls, s) if s is not None else None

        @classmethod
        def hash(cls, bs: bytes) -> scalar:
            """
            Return scalar object by hashing supplied bytes-like object.

            >>> scalar.hash('123'.encode()).hex()
            '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
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

            >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()
            '312d0c9130f69153bec9f5d0386a95135eb45eebf130af5f1fed1c6ed15f2500'
            """
            return F.__new__(cls, int.from_bytes(base64.standard_b64decode(s), 'little'))

        @classmethod
        def from_hex(cls, s: str) -> scalar:
            """
            Convert the hexadecimal UTF-8 string representation of a scalar to a scalar
            instance.

            >>> scalar.from_hex(
            ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
            ... ).hex()
            '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
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

            >>> s = scl()
            >>> t = scalar(s)
            >>> s.hex() == t.hex()
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
            >>> p = point.from_base64('hoVmn8Pi6U9Gx8L/cJxHHYTjwrl0bKMNNPMjoxXqGJI=')
            >>> (s * s).hex()
            '5435c4667d60491122e1e47044890e8fa8aaa2e40b0e1380b6e918af25fcc21a'
            >>> isinstance(s * s, scalar)
            True
            >>> (s * p).hex()
            '34624e581a5f8e76dd10badc62c587d4aae20b8cef45975677e1ebdba52b2e99'
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
            >>> (s + s).hex()
            '625a182261ec23a77c93eba171d42a27bc68bdd6e3615ebf3eda39dca2bf4a00'
            >>> isinstance(s + s, scalar)
            True

            >>> z = point.base(s) @ point.base2(s)
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

_, point2, scalar2 = _make_native(_ECp2, _Fp12, global_scope=False)
native, point, scalar = _make_native(_ECp, int)

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

    # pylint: disable=C0103
    def _make_mcl(G, F, global_scope=True):
        """
        Factory to make the exported symbols.
        """
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
            @staticmethod
            def rnd() -> scalar:
                """
                Return random non-zero scalar.

                >>> len(rnd())
                32
                """
                return F.__new__(scalar, Fr().randomize())
                # Locked to Fr for the field.    self.__class__ === scalar

            @classmethod
            def scl(cls, s: bytes = None) -> Optional[scalar]:
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

                try:
                    s = Fr(s)
                except ValueError:
                    return None

                if not s.is_zero():
                    return F.__new__(scalar, s)
                    # Locked to Fr for the field.    self.__class__ === scalar

                return None

            @staticmethod
            def inv(s: scalar) -> scalar:
                r"""
                Return inverse of scalar modulo
                ``r=16798108731015832284940804142231733909759579603404752749028378864165570215949``
                in the prime field *F\*_r*.

                >>> s = scl()
                >>> p = pnt()
                >>> mul(inv(s), mul(s, p)) == p
                True
                """
                return F.__new__(s.__class__, F.__invert__(s))#slower: F.__new__(s.__class__, ~F(s))

            @staticmethod
            def smu(s: scalar, t: scalar) -> scalar:
                """
                Return scalar multiplied by another scalar.

                >>> s = scl()
                >>> t = scl()
                >>> smu(s, t) == smu(t, s)
                True
                """
                return F.__new__(s.__class__, F.__mul__(s, t))

            # @staticmethod
            # def sad(s: scalar, t: scalar) -> scalar:
            #     """
            #     Return scalar added to another scalar.
            #
            #     >>> s = scl()
            #     >>> t = scl()
            #     >>> sad(s, t) == sad(t, s)
            #     True
            #     """
            #     # return s + t
            #     # return F.__sad__(s, t)
            #     return F.__new__(s.__class__, F.__sad__(s, t))

            @staticmethod
            def pnt(h: bytes = None) -> point:
                """
                Return point from 64-byte vector (normally obtained via hashing).

                >>> p = pnt(hashlib.sha512('123'.encode()).digest())
                >>> p.hex()
                '9c6f2b3917ac249b3a43b3df3399ff54cd185be714a24541782b142a7ccb3423'
                """
                return G.__new__(point, G.random() if h is None else G.mapfrom(h))

            @staticmethod
            def bas(s: scalar) -> point:#G1:
                """
                Return base point multiplied by supplied scalar.

                >>> bytes(bas(scalar.hash('123'.encode()))).hex()
                'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
                """
                return s * G1.__new__(point, G1.base_point())
                # return G1.base_point() * s

            @staticmethod
            def bs2(s: scalar) -> point2:#G2:
                """
                Return base point multiplied by supplied scalar.

                >>> bytes(bs2(scalar.hash('123'.encode()))).hex()[50:]
                'd1b99a7ca5660d124528b442d33e15eca23a202df3222c542e7bd71955c7623669554af518de01'
                """
                # return s * G2.__new__(point2, G2.base_point())
                return G2.base_point() * s

            @staticmethod
            def par(p: Union[point, point2], q: Union[point, point2]) -> scalar2:
                """
                Compute the pairing function on two points.

                >>> p = point.hash('123'.encode())
                >>> q = point.base2(scalar.from_int(456))
                >>> par(p, q).hex()[700:]
                '3619f8827c626c4bfd265424f25ce5f8449d6f4cd29575284c50b203ef57d9e1c408'

                The pairing function is bilinear.

                >>> p = point.random()
                >>> s = scalar.random()

                >>> t = scalar.random()
                >>> q = point2.random() # Or ``point.base2(scalar.random())``.
                >>> -((~s) * (s * p)) - p == scalar.from_int(-2) * p
                True
                >>> s * t * p @ q == s * p @ (t * q)
                True

                >>> x = y = p

                Suppose there are two points: one multiplied by the scalar ``s`` and the other
                multiplied by the scalar ``t``. Their equality can be determined by using a
                balancing point: ``g**(~s * t)``.  If the pairing of ``t * x`` with ``g`` is the
                same as the pairing with ``s * y`` and ``g**(~s * t)``, then ``x`` equals ``y``.

                >>> g = point.base2(scalar.from_int(1))
                >>> b = point.base2(~s * t)
                >>> (t * x) @ g == (s * y) @ b
                True
                """
                return GT.__new__(scalar2, p.G.__matmul__(p, q))

            @staticmethod
            def mul(s: scalar, p: point) -> point:
                """
                Multiply the point by the supplied scalar and return the result.

                >>> p = pnt(hashlib.sha512('123'.encode()).digest())
                >>> s = scl(bytes.fromhex(
                ...     '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
                ... ))
                >>> mul(s, p).hex()
                'a7f9b967b2d85e2b18e93717d1aac438ce660017023a1207a080f45b42c6b19f'
                """
                return p.G.__new__(p.__class__, p.G.__mul__(p, s))

            @staticmethod
            def add(p: point, q: point) -> point:
                """
                Return sum of the supplied points.

                >>> p = point.hash('123'.encode())
                >>> q = point.hash('456'.encode())
                >>> add(p, q).hex()
                '1a78bb2f044b38e84a82b6eb7bbc2d339132481a98d635aca3b78c899095b68b'
                """
                return p.G.__new__(p.__class__, p.G.__add__(p, q))

            @staticmethod
            def sub(p: point, q: point) -> point:
                """
                Return result of subtracting second point from first point.

                >>> p = point.hash('123'.encode())
                >>> q = point.hash('456'.encode())
                >>> sub(p, q).hex()
                '7dad51d4465bcd77bebf243c466726192a411d527dbd5ab8124a98ab0ccc8922'
                """
                return p.G.__new__(p.__class__, p.G.__sub__(p, q))

        if global_scope:
            # Top-level best-effort synonyms.
            global scl, rnd, inv, smu, pnt, bas, bs2, par, mul, add, sub # pylint: disable=W0601
            scl = mcl.scl
            rnd = mcl.rnd
            inv = mcl.inv
            smu = mcl.smu
            pnt = mcl.pnt
            bas = mcl.bas
            bs2 = mcl.bs2
            par = mcl.par
            mul = mcl.mul
            add = mcl.add
            sub = mcl.sub

            global mclbn256 # pylint: disable=W0603
            mclbn256 = True

        _G = G
        #
        # Dedicated point and scalar data structures derived from `bytes`.
        #
        class point(G): # pylint: disable=W0621,E0102
            """
            Wrapper class for a bytes-like object that corresponds
            to a point.
            """
            _mcl = mcl
            G = _G

            @classmethod
            def random(cls) -> point:
                """
                Return random point object.

                >>> len(point.random())
                32
                """
                return cls._mcl.pnt()

            @classmethod
            def bytes(cls, bs: bytes) -> point:
                """
                Return point object obtained by transforming supplied bytes-like object.

                >>> p = point.bytes(hashlib.sha512('123'.encode()).digest())
                >>> p.hex()
                '9c6f2b3917ac249b3a43b3df3399ff54cd185be714a24541782b142a7ccb3423'
                """
                return cls._mcl.pnt(bs)

            @classmethod
            def hash(cls, bs: bytes) -> point:
                """
                Return point object by hashing supplied bytes-like object.

                >>> point.hash('123'.encode()).hex()
                'a8884a30f29ca2163f5719b5c4d9707bb94ae44bd54811d44b2c8b78af64c711'
                """
                return cls._mcl.pnt(hashlib.sha512(bs).digest()[:32])  # really only need ≥254-bits

            @classmethod
            def base(cls, s: scalar) -> Optional[point]:
                """
                Return base point multiplied by supplied scalar
                if the scalar is valid; otherwise, return `None`.

                >>> point.base(scalar.hash('123'.encode())).hex()
                'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
                """
                p = G.__new__(cls, (cls._mcl.bas if cls.G == G1 else cls._mcl.bs2)(s))
                return None if p.zero() else p

            @classmethod
            def base2(cls, s: scalar) -> Optional[point2]:
                """
                Return base point multiplied by supplied scalar
                if the scalar is valid; otherwise, return `None`.

                >>> point.base(scalar.hash('123'.encode())).hex()
                'de3f74aad3b970f759d2e07d657cc1a97828c3c0c1280fed45fba4db88c92587'
                """
                return point2.base(s)

            @classmethod
            def from_base64(cls, s: str) -> point:
                """
                Convert the Base64 UTF-8 string representation of a point to a point instance.

                >>> point.from_base64('hoVmn8Pi6U9Gx8L/cJxHHYTjwrl0bKMNNPMjoxXqGJI=').hex()
                '8685669fc3e2e94f46c7c2ff709c471d84e3c2b9746ca30d34f323a315ea1892'
                """
                return G.__new__(cls, G.deserialize(base64.standard_b64decode(s)))

            @classmethod
            def from_hex(cls, s: str) -> point:
                """
                Convert the hexadecimal UTF-8 string representation of a point to a point instance.

                >>> point.from_hex(
                ...     'afa9a593ff45b66b3545fe6e56fa56da0d966fd7a61dec45bf99a45a45ab4d0c'
                ... ).hex()
                'afa9a593ff45b66b3545fe6e56fa56da0d966fd7a61dec45bf99a45a45ab4d0c'
                """
                return G.__new__(cls, G.deserialize(bytes.fromhex(s)))

            def hex(self) -> str:
                """
                Generates hexadecimal representation of this instance.
                """
                # Note that ``hex(self)`` fails, even though there is ``G.__hex__``.
                return self.serialize().hex()

            def __repr__(self) -> str:
                """
                Return string representation of this instance.
                """
                print(bytes(self), end='', flush=True)
                return ''

            def __new__(cls, bs: bytes = None) -> point:
                """
                If a bytes-like object is supplied, return a point object
                corresponding to the supplied bytes-like object (no checking
                is performed to confirm that the bytes-like object is a valid
                point). If no argument is supplied, return a random point
                object.

                >>> bs = bytes.fromhex(
                ...     '8031b72abe00d4c04ab3b920aab8995bc5e87026f152ea1e3a87e1647c44dd19'
                ... )
                >>> point(bs).hex()
                '8031b72abe00d4c04ab3b920aab8995bc5e87026f152ea1e3a87e1647c44dd19'
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
                >>> (s * p).hex()
                '3914c4cf63ce5a5a3dab97e837038959403999221186f5f923328abedd0f151d'
                """
                p = self.__class__._mcl.mul(other, self)
                return None if p.zero() else p

            def __add__(self: point, other: point) -> Optional[point]:
                """
                Return sum of this point and another point.

                >>> p = point.hash('123'.encode())
                >>> q = point.hash('456'.encode())
                >>> (p + q).hex()
                '1a78bb2f044b38e84a82b6eb7bbc2d339132481a98d635aca3b78c899095b68b'
                """
                p = self.__class__._mcl.add(self, other)
                return None if p.zero() else p

            def __sub__(self: point, other: point) -> Optional[point]:
                """
                Return the result of subtracting another point from this point.

                >>> p = point.hash('123'.encode())
                >>> q = point.hash('456'.encode())
                >>> (p - q).hex()
                '7dad51d4465bcd77bebf243c466726192a411d527dbd5ab8124a98ab0ccc8922'
                """
                p = self.__class__._mcl.sub(self, other)
                return None if p.zero() else p

            def __matmul__(self: point, other: point2) -> Optional[scalar2]:
                """
                Return the result of pairing another point with this point.

                >>> p = point.hash('123'.encode())
                >>> q = point.base2(scalar.from_int(456))
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

                >>> g = point.base2(scalar.from_int(1))
                >>> b = point.base2(~s * t)
                >>> (t * x) @ g == (s * y) @ b
                True
                """
                s = self.__class__._mcl.par(self, other)
                return s

            def __neg__(self: point) -> Optional[point]:
                """
                Return the negation (additive inverse) of this point

                >>> p = point.hash('123'.encode())
                >>> q = point.hash('456'.encode())
                >>> (p + q).hex()
                '1a78bb2f044b38e84a82b6eb7bbc2d339132481a98d635aca3b78c899095b68b'
                """
                p = G.__new__(self.__class__, G.__neg__(self))
                return None if p.zero() else p

            def __len__(self) -> int:
                """Return length (in bytes) of the binary representation of this instance."""
                return bytes(self).__len__()

            def to_base64(self: point) -> str:
                """
                Convert to equivalent Base64 UTF-8 string representation.

                >>> p = point.from_base64('5fLTU+9atKP+91ZEZWc1qX6mzsmI39kFKqSlRiYiZxo=')
                >>> p.to_base64()
                '5fLTU+9atKP+91ZEZWc1qX6mzsmI39kFKqSlRiYiZxo='
                """
                return base64.standard_b64encode(bytes(self)).decode('utf-8')

        _F = F
        class scalar(F): # pylint: disable=E0102
            """
            Wrapper class for a bytes-like object that corresponds
            to a scalar.
            """
            _mcl = mcl
            F = _F

            @classmethod
            def random(cls) -> scalar:
                """
                Return random non-zero scalar object.

                >>> len(scalar.random())
                32
                """
                return F.__new__(cls, cls._mcl.rnd())

            @classmethod
            def bytes(cls, bs: bytes) -> Optional[scalar]:
                """
                Return scalar object obtained by transforming supplied bytes-like
                object if it is possible to do; otherwise, return `None`.

                >>> s = scl()
                >>> t = scalar.bytes(bytes(s))
                >>> s.hex() == t.hex()
                True
                """
                s = cls._mcl.scl(bs)
                return F.__new__(cls, s) if s is not None else None

            @classmethod
            def hash(cls, bs: bytes) -> scalar:
                """
                Return scalar object by hashing supplied bytes-like object.

                >>> scalar.hash('123'.encode()).hex()
                '93d829354cb3592743174133104b5405ba6992b67bb219fbde3e394d70505913'
                """
                h = hashlib.sha256(bs).digest()
                s = cls._mcl.scl(h)
                while s is None:
                    h = hashlib.sha256(h).digest()
                    s = cls._mcl.scl(h)
                return s

            @classmethod
            def from_base64(cls, s: str) -> scalar:
                """
                Convert Base64 UTF-8 string representation of a scalar to a scalar instance.

                >>> scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=').hex()
                '312d0c9130f69153bec9f5d0386a95135eb45eebf130af5f1fed1c6ed15f2500'
                """
                return F.__new__(cls, F.deserialize(base64.standard_b64decode(s)))

            @classmethod
            def from_hex(cls, s: str) -> scalar:
                """
                Convert the hexadecimal UTF-8 string representation of a scalar to a scalar
                instance.

                >>> scalar.from_hex(
                ...     '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
                ... ).hex()
                '3ab45f5b1c9339f1d25b878cce1c053b5492b4dc1affe689cbe141769f655e1e'
                """
                return F.__new__(cls, F.deserialize(bytes.fromhex(s)))

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

            def hex(self) -> str:
                """
                Generates hexadecimal representation of the point instance.
                """
                return self.serialize().hex()  # `hex(self)` fails, even though there is `F.__hex__`

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

                >>> s = scl()
                >>> t = scalar(s)
                >>> s.hex() == t.hex()
                True
                >>> len(scalar())
                32
                """
                s = bs # or `cls._mcl.scl(bs)`, but ``mclbn256`` handles this already
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
                return self.__class__._mcl.inv(self)

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
                >>> p = point.from_base64('hoVmn8Pi6U9Gx8L/cJxHHYTjwrl0bKMNNPMjoxXqGJI=')
                >>> (s * s).hex()
                '5435c4667d60491122e1e47044890e8fa8aaa2e40b0e1380b6e918af25fcc21a'
                >>> isinstance(s * s, scalar)
                True
                >>> (s * p).hex()
                '34624e581a5f8e76dd10badc62c587d4aae20b8cef45975677e1ebdba52b2e99'
                >>> isinstance(s * p, point)
                True
                """
                if isinstance(other, (self.__class__._mcl.scalar)):
                # if isinstance(other, (native.scalar, self.__class__._mcl.scalar)):#
                    return self.__class__._mcl.smu(self, other)
                p = self.__class__._mcl.mul(self, other)#other.__mul__(self)
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
                >>> (s + s).hex()
                '625a182261ec23a77c93eba171d42a27bc68bdd6e3615ebf3eda39dca2bf4a00'
                >>> isinstance(s + s, scalar)
                True

                >>> z = point.base(s) @ point.base2(s)
                >>> (z + z).hex()[700:]
                '0318fa6a428def47eb38709deaa8f843c3916e30e932bb5ce0f70c8ca3a1112f9305'
                >>> isinstance(z + z, scalar2)
                True
                """
                return F.__new__(self.__class__, F.__add__(self, other))

            def __len__(self) -> int:
                """Return length (in bytes) of the binary representation of this instance."""
                return bytes(self).__len__()

            def to_base64(self: scalar) -> str:
                """
                Convert to equivalent Base64 UTF-8 string representation.

                >>> s = scalar.from_base64('MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA=')
                >>> s.to_base64()
                'MS0MkTD2kVO+yfXQOGqVE160XuvxMK9fH+0cbtFfJQA='
                """
                return base64.standard_b64encode(bytes(self)).decode('utf-8')

        # Encapsulate classes that use wrappers for shared/dynamic library bindings for methods.
        mcl.point = point
        mcl.scalar = scalar

        return mcl, point, scalar

    _, point2, scalar2 = _make_mcl(G2, GT, global_scope=False)
    mcl, point, scalar = _make_mcl(G1, Fr)

except: # pylint: disable=W0702 # pragma: no cover
    # Exported symbol.
    mcl = None # pragma: no cover

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
