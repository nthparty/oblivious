"""
Test suite containing functional unit tests for the exported primitives and
classes in the :obj:`oblivious.bn254` module, as well as unit tests
confirming algebraic relationships among primitives.
"""
# pylint: disable=C0103,C0116
from unittest import TestCase
import importlib
import base64
from bitlist import bitlist
from fountains import fountains

try:
    from oblivious import bn254 #pylint: disable=E0401# allows PyLint to fail the try block's import
except: # pylint: disable=W0702
    # To support generation of reference specifications for unit tests.
    spec = importlib.util.spec_from_file_location("bn254", "src/oblivious/bn254.py")
    bn254 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bn254)

# Constants for the number of input-output pairs to include in each test and for
# representation sizes of data structures (in their binary form).
TRIALS_PER_TEST = 16
POINT_HASH_LEN = 64 # Size of raw hash digest required to construct a point.
POINT_LEN = 32*3 # Three 32-byte coordinate values (x, y, and z, in projective coordinates).
SCALAR_LEN = 32 # Really ≤32, but the ``scalar.bytes(bs)`` function will never do modulo reductions.

# To simulate an environment in which mcl is absent, some tests set
# `bn254.mcl` to `None`;
# the references below are used for restoration.
#mcl_lib_restore = bn254.mcl._lib # pylint: disable=W0212
mcl_restore = bn254.mcl

def api_methods():
    """
    API symbols that should be available to users upon module import.
    """
    return {
        'point', 'scalar',
        'scl', 'rnd', 'inv', 'smu',
        'pnt', 'bas', 'mul', 'add', 'sub'
    }

class Test_namespace(TestCase):
    """
    Check that namespaces provide access to the expected
    classes and functions.
    """
    def test_init(self):
        init = importlib.import_module('oblivious.__init__')
        self.assertTrue('bn254' in init.__dict__)

    def test_modules(self):
        module = importlib.import_module('oblivious.bn254')
        self.assertTrue('native' in module.__dict__)
        self.assertTrue('mcl' in module.__dict__)
        self.assertTrue(api_methods().issubset(module.__dict__.keys()))

    def test_native(self):
        self.assertTrue(api_methods().issubset(set(dir(bn254.native))))

    def test_mcl(self):
        if bn254.mcl is not None:
            self.assertTrue(api_methods().issubset(set(dir(bn254.mcl))))

def check_or_generate_operation(test, fun, lengths, bits): # pylint: disable=R1710
    """
    This function does either of two things depending on `bits`:
    * checks that test inputs drawn from the fountains input bit stream
      produce the bits provided in the reference output bit vector, or
    * generates a reference output bit vector by applying the function
      to the fountains input bit stream.
    """
    def get_bytes(o):
        if type(o) in (bytes, bitlist, bytearray):  # `isinstance` will be wrong for `native` types.
            return o
        cls = bn254.native if isinstance(o, bytes) else bn254.mcl
        try:
            cls.can(o)
        except AttributeError:
            pass
        return cls.ser(o) if ('point' in str(o.__class__) or 'G'in str(o.__class__)) else cls.sse(o)

    fs = fountains( # Generate the input bit stream.
        sum(lengths),
        seed=bytes(0), # This is also the default; explicit for clarity.
        limit=min(TRIALS_PER_TEST, (len(bits) * 4) if bits is not None else 256),
        bits=bits[:(TRIALS_PER_TEST // 4)] if bits is not None else None,
        function=lambda *args, **kwargs: get_bytes(fun(*args, **kwargs))
    )

    if bits is None: # There is no output reference bit vector, so test is not possible.
        return bitlist(list(fs)).hex() # Return reference output bits for test.

    test.assertTrue(all(fs)) # Check that all outputs match.

def mcl_hidden_and_fallback(hidden=False, fallback=False):
    """
    Return binary wrapper class definition that conforms to the
    scenario being tested.
    """
    # pylint: disable=W0212
    if hidden:
        bn254.mcl = None
    elif fallback:
        bn254.mcl = mcl_restore
        #bn254.mcl._lib = bn254.mclbn256
        #bn254.mcl._call = bn254.mcl._call_wrapped
    else:
        bn254.mcl = mcl_restore
        #bn254.mcl._lib = mcl_lib_restore
        #bn254.mcl._call = bn254.mcl._call_unwrapped

def define_classes(cls, hidden=False, fallback=False): # pylint: disable=R0915
    """
    Define and return four classes of unit tests given a wrapper
    class (`native` or `mcl`) for primitive operations.
    """
    class Test_primitives(TestCase):
        """
        Direct tests of primitive operators that operate on bytes-like objects.
        """
        def test_rnd(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.rnd()
                self.assertTrue(cls.scl(bytes(s)))

        def test_scl_none(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                bs = bytes([255] * 32)  # bytes of a number above r, the maximum scalar value
                s = cls.scl(bs)
                self.assertTrue(s is None)

        def test_scl(
                self,
                bits='ffff'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            # pylint: disable=C3001
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                # Using `b00011111` would guarantee a valid scalar, as r is between 2^253 and 2^254.
                bs = bytes(bs)
                r = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
                return bitlist([1 if (
                                          bool(cls.scl(bs)) == (int.from_bytes(bs, 'little') < r)
                                     ) is not None else 0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_inv(
                self,
                bits='0aea'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs = bytes(bs)
                s = cls.scl(bs)
                return cls.inv(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_smu(
                self,
                bits='dfad'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chance of testing with a valid (*i.e.*, ``s < r``) scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s1, s2) = (cls.scl(bs[:SCALAR_LEN]), cls.scl(bs[SCALAR_LEN:]))
                return cls.smu(s1, s2) if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_pnt_none(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.ser(cls.pnt())) == POINT_LEN)

        def test_pnt(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.pnt, [POINT_HASH_LEN], bits)

        def test_bas(
                self,
                bits='82d6'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs = bytes(bs)
                s = cls.scl(bs)
                return cls.bas(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_mul(
                self,
                bits='b9e1'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s, p) = (cls.scl(bs[:SCALAR_LEN]), cls.pnt(bs[SCALAR_LEN:]))
                return cls.mul(s, p) if (s is not None and p is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_add(
                self,
                bits='40d9'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                return cls.add(p1, p2) if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_sub(
                self,
                bits='71df'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                return cls.sub(p1, p2) if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

    class Test_classes(TestCase):
        """
        Tests of point and scalar wrapper classes and their methods.
        """
        def test_point_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point.random()) == POINT_LEN)

        def test_point_bytes(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point.bytes, [POINT_HASH_LEN], bits)

        def test_point_hash(
                self,
                bits='c8ea'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point.hash, [POINT_HASH_LEN], bits)

        def test_point_base(
                self,
                bits='ebed'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs = bytes(bs)
                s = cls.scalar.bytes(bs)
                return cls.point.base(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_point_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point()
                p_b64 = base64.standard_b64encode(bytes(p)).decode('utf-8')
                self.assertEqual(p.to_base64(), p_b64)
                self.assertEqual(cls.point.from_base64(p_b64), p)

        def test_point(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point()) == POINT_LEN)

        def test_point_rmul(
                self,
                bits='b9e1'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s, p) = (cls.scalar.bytes(bs[:SCALAR_LEN]), cls.point.bytes(bs[SCALAR_LEN:]))
                # pylint: disable=C2801 # Overriding overloaded method for :obj:`scalar`.
                return p.__rmul__(s) if (s is not None and p is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_point_scalar_mul_op(
                self,
                bits='b9e1'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s, p) = (cls.scalar.bytes(bs[:SCALAR_LEN]), cls.point.bytes(bs[SCALAR_LEN:]))
                # Below, ``*`` invokes :obj:`scalar.__mul__`, which delegates to :obj:`mul`
                # due to the type of the second argument.
                return s * p if (s is not None and p is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_point_add(
                self,
                bits='40d9'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (
                    cls.point.bytes(bs[:POINT_HASH_LEN]),
                    cls.point.bytes(bs[POINT_HASH_LEN:])
                )
                return p1 + p2 if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_point_sub(
                self,
                bits='71df'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (
                    cls.point.bytes(bs[:POINT_HASH_LEN]),
                    cls.point.bytes(bs[POINT_HASH_LEN:])
                )
                return p1 - p2 if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_scalar_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar.random()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scalar.bytes(bytes(s)) is not None)
                self.assertTrue(len(bytes(s)) == SCALAR_LEN and len(s.to_bytes()) == SCALAR_LEN)

        def test_scalar_bytes(
                self,
                bits='ffff'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            # pylint: disable=C3001
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs = bytes(bs)
                return bitlist([1 if cls.scalar.bytes(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_hash(
                self,
                bits='1c21'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.scalar.hash, [SCALAR_LEN], bits)

        def test_scalar_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                s_b64 = base64.standard_b64encode(bytes(s)).decode('utf-8')
                self.assertEqual(s.to_base64(), s_b64)
                self.assertEqual(cls.scalar.from_base64(s_b64), s)

        def test_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scalar.bytes(bytes(s)) is not None)
                self.assertTrue(len(bytes(s)) == SCALAR_LEN and len(s.to_bytes()) == SCALAR_LEN)

        def test_scalar_inverse(
                self,
                bits='c4e3'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs)
                return s.inverse() if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_invert_op(
                self,
                bits='c4e3'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs)
                return ~s if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_mul(
                self,
                bits='93d3'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.scalar.hash(bs[SCALAR_LEN:]))
                return s1 * s2 if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

    class Test_types(TestCase):
        """
        Tests verifying that methods return objects of the appropriate type.
        """
        def test_types_point_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            p = cls.point.random()
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point.bytes(bs)
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_hash(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point.hash(bs)
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_base(self):
            mcl_hidden_and_fallback(hidden, fallback)
            p = cls.point.base(cls.scalar.random())
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_mul(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR_LEN + POINT_HASH_LEN, limit=1)
            (s, p) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.point.hash(bs[SCALAR_LEN:]))
            self.assertTrue(isinstance(s * p, cls.point))

        def test_types_point_add(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point.hash(bs[:POINT_HASH_LEN]), cls.point.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 + p1, cls.point))

        def test_types_point_sub(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point.hash(bs[:POINT_HASH_LEN]), cls.point.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 - p1, cls.point))

        def test_types_scalar_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar.random(), cls.scalar))

        def test_types_scalar_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = bytes(cls.scalar.random())
            self.assertTrue(isinstance(cls.scalar.bytes(bs), cls.scalar))

        def test_types_scalar_hash(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR_LEN, limit=1)
            self.assertTrue(isinstance(cls.scalar.hash(bs), cls.scalar))

        def test_types_scalar_invert(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(~cls.scalar.random(), cls.scalar))

        def test_types_scalar_inverse(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar.random().inverse(), cls.scalar))

        def test_types_scalar_mul_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar.random(), cls.scalar.random())
            self.assertTrue(isinstance(s0 * s1, cls.scalar))

        def test_types_scalar_mul_point(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar() * cls.point(), cls.point))

    class Test_algebra(TestCase):
        """
        Tests of algebraic properties of primitive operations and class methods.
        """
        def test_algebra_scalar_inverse_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN, limit=TRIALS_PER_TEST):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs = bytes(bs)
                s = cls.scl(bs)
                if s is not None:
                    self.assertEqual(cls.inv(cls.inv(s)), s)

        def test_algebra_scalar_inverse_mul_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid (_i.e._ `s<r`) scalar.
                bs[SCALAR_LEN - 1] &= 0b00111111
                bs = bytes(bs)
                (s, p) = (cls.scl(bs[:SCALAR_LEN]), cls.pnt(bs[SCALAR_LEN:]))
                if s is not None:
                    self.assertEqual(cls.mul(cls.inv(s), cls.mul(s, p)), p)

        def test_algebra_scalar_mul_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains((2 * SCALAR_LEN) + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                bs = bytearray(bs)
                bs[SCALAR_LEN - 1] &= 0b00111111 # Improve chance of testing with a valid scalar.
                bs[SCALAR_LEN + SCALAR_LEN - 1] &= 0b00111111
                bs = bytes(bs)
                (s0, s1, p0) = (
                    cls.scl(bs[:SCALAR_LEN]),
                    cls.scl(bs[SCALAR_LEN: SCALAR_LEN + SCALAR_LEN]),
                    cls.pnt(bs[SCALAR_LEN + SCALAR_LEN:])
                )
                if s0 is not None and s1 is not None:
                    self.assertEqual(
                        cls.mul(s0, cls.mul(s1, p0)),
                        cls.mul(s1, cls.mul(s0, p0))
                    )

        def test_algebra_point_add_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                self.assertEqual(cls.add(p0, p1), cls.add(p1, p0))

        def test_algebra_point_add_sub_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                self.assertEqual(cls.add(cls.sub(p0, p1), p1), p0)

        def test_algebra_scalar_mul_point_mul_associate(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                bs = bytearray(bs)
                bs[SCALAR_LEN - 1] &= 0b00111111 # Improve chance of testing with a valid scalar.
                bs[SCALAR_LEN + SCALAR_LEN - 1] &= 0b00111111
                bs = bytes(bs)
                (s0, s1, p0) = (
                    cls.scl(bs[:SCALAR_LEN]),
                    cls.scl(bs[SCALAR_LEN: SCALAR_LEN + SCALAR_LEN]),
                    cls.pnt(bs[SCALAR_LEN + SCALAR_LEN:])
                )
                if s0 is not None and s1 is not None:
                    self.assertEqual(
                        cls.mul(s0, cls.mul(s1, p0)),
                        cls.mul(cls.smu(s0, s1), p0)
                    )

        def test_algebra_scalar_mul_point_add_distribute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + (2 * POINT_HASH_LEN), limit=TRIALS_PER_TEST):
                bs = bytearray(bs)
                bs[SCALAR_LEN - 1] &= 0b00111111  # Improve chance of testing with a valid scalar.
                bs = bytes(bs)
                (s0, p0, p1) = (
                    cls.scl(bs[:SCALAR_LEN]),
                    cls.pnt(bs[SCALAR_LEN: SCALAR_LEN + POINT_HASH_LEN]),
                    cls.pnt(bs[SCALAR_LEN + POINT_HASH_LEN:])
                )
                if s0 is not None:
                    self.assertEqual(
                        cls.add(cls.mul(s0, p0), cls.mul(s0, p1)),
                        cls.mul(s0, cls.add(p0, p1))
                    )

        def test_algebra_scalar_mul_scalar_on_right_hand_side_of_non_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random()
            self.assertRaises(TypeError, lambda: bytes([0]) * s)

        def test_algebra_scalar_mul_point_on_left_hand_side(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random()
            p = cls.point.hash(bytes(POINT_LEN))
            self.assertRaises(TypeError, lambda: p * s)

    return (
        Test_primitives,
        Test_classes,
        Test_types,
        Test_algebra
    )

# The instantiated test classes below are discovered by the testing framework and
# executed in alphabetical order.
(
    Test_primitives_native_no_mcl,
    Test_classes_native_no_mcl,
    Test_types_native_no_mcl,
    Test_algebra_native_no_mcl
) = define_classes(bn254.native, hidden=True)

if bn254.mcl is not None and bn254.mclbn256 is True:
    (
        Test_primitives_mcl_mclbn256_no_mcl,
        Test_classes_mcl_mclbn256_no_mcl,
        Test_types_mcl_mclbn256_no_mcl,
        Test_algebra_mcl_mclbn256_no_mcl
    ) = define_classes(bn254.mcl, fallback=True)

(Test_primitives_native, Test_classes_native, Test_types_native, Test_algebra_native) = \
    define_classes(bn254.native)

if bn254.mcl is not None:
    (Test_primitives_mcl, Test_classes_mcl, Test_types_mcl, Test_algebra_mcl) = \
        define_classes(bn254.mcl)

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    for tests in [Test_primitives_native(), Test_classes_native()]:
        print(
            '\nUnit test reference bit vectors for ' +
            tests.__class__.__name__ + ' methods...'
        )
        for m in [m for m in dir(tests) if m.startswith('test_')]:
            method = getattr(tests, m)
            if 'bits' in method.__code__.co_varnames:
                print('* ' + m + ": '" + method(bits=None) + "'")
