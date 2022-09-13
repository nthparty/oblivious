"""
Test suite containing functional unit tests for the exported primitives and
classes in the :obj:`oblivious.bn254` module, as well as unit tests
confirming algebraic relationships among primitives.
"""
# pylint: disable=missing-function-docstring
from unittest import TestCase
import importlib
import base64
from bitlist import bitlist
from fountains import fountains

try:
    from oblivious import bn254 # pylint: disable=import-error
except: # pylint: disable=bare-except
    # To support generation of reference specifications for unit tests.
    spec = importlib.util.spec_from_file_location("bn254", "src/oblivious/bn254.py")
    bn254 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bn254)

# Constants for the number of input-output pairs to include in each test and for
# representation sizes of data structures (in their binary form).
TRIALS_PER_TEST = 16
POINT_HASH_LEN = 64 # Size of raw hash digest required to construct a point.
POINT_LEN = 32 * 3 # Three 32-byte coordinate values (*x*, *y*, and *z* in projective coordinates).
POINT2_LEN = 192
SCALAR_LEN = 32
SCALAR2_LEN = 384

# To simulate an environment in which the mcl library is absent, some tests set
# ``bn254.mcl`` to ``None``; the references below are used for restoration.
mcl_restore = bn254.mcl

def api_functions():
    """
    Low-level functions that should be available to users within each of the two
    namespaces.
    """
    return {
        'rnd', 'scl', 'sse', 'sde', 'inv', 'smu', 'sad', 'ssu', 'sne',
        'pnt', 'bas', 'can', 'ser', 'des', 'mul', 'add', 'sub', 'neg', 'par',
        'rnd2', 'scl2', 'sse2', 'sde2', 'inv2', 'smu2', 'sad2', 'pnt2', 'bas2',
        'can2', 'ser2', 'des2', 'mul2', 'add2', 'sub2', 'neg2'
    }

def api_classes():
    """
    Classes that should be available to users upon module import.
    """
    return {'point', 'scalar', 'point2', 'scalar2'}

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
        self.assertTrue('python' in module.__dict__)
        self.assertTrue('mcl' in module.__dict__)
        self.assertTrue(api_classes().issubset(module.__dict__.keys()))

    def test_python(self):
        self.assertTrue(api_functions().issubset(set(dir(bn254.python))))
        self.assertTrue(api_classes().issubset(set(dir(bn254.python))))

    def test_mcl(self):
        if bn254.mcl is not None:
            self.assertTrue(api_functions().issubset(set(dir(bn254.mcl))))
            self.assertTrue(api_classes().issubset(set(dir(bn254.mcl))))

def check_or_generate_operation(test, fun, lengths, bits):
    """
    This function does either of two things depending on the parameter ``bits``:
    * checks that test inputs drawn from the :obj:`fountains` input bit stream
      produce the bits provided in the reference output bit vector, or
    * generates a reference output bit vector by applying the function
      to the :obj:`fountains` input bit stream.
    """
    def get_bytes(o):
        if type(o) in (bytes, bytearray, bitlist):
            return o

        cls = bn254.python if isinstance(o, bytes) else bn254.mcl

        # Transform points to canonical form.
        cls_str = str(o.__class__)
        if 'point2' in cls_str or 'G2' in cls_str:
            o = cls.can2(o)
        elif 'point' in cls_str or 'G1' in cls_str:
            o = cls.can(o)

        return (
            cls.ser(o)
            if ('point' in str(o.__class__) or 'G' in str(o.__class__)) else
            cls.sse(o)
        )

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
    if hidden:
        bn254.mcl = None
    elif fallback:
        bn254.mcl = mcl_restore
    else:
        bn254.mcl = mcl_restore

def define_classes(cls, hidden=False, fallback=False): # pylint: disable=too-many-statements
    """
    Define and return four classes of unit tests given a wrapper
    class (``python`` or ``mcl``) for primitive operations.
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
                bs = bytes([255] * 32) # Representation value above the maximum scalar value.
                s = cls.scl(bs)
                self.assertTrue(s is None)

        def test_scl(
                self,
                bits='ffff'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chances of testing with a valid scalar.
                bs = bytes(bs)
                r = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
                return bitlist([
                    1
                    if (bool(cls.scl(bs)) == (int.from_bytes(bs, 'little') < r)) is not None else
                    0
                ])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_sse(
                self,
                bits='ab29'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                s = cls.scl(bytes(bs))
                return cls.sse(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_sde(
                self,
                bits='ab29'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                s = cls.scl(bytes(bs))
                return cls.sde(cls.sse(s)) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_inv(
                self,
                bits='0aea'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
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
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s1, s2) = (cls.scl(bs[:SCALAR_LEN]), cls.scl(bs[SCALAR_LEN:]))
                return cls.smu(s1, s2) if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_sad(
                self,
                bits='6c5b'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s1, s2) = (cls.scl(bs[:SCALAR_LEN]), cls.scl(bs[SCALAR_LEN:]))
                return cls.sad(s1, s2) if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_ssu(
                self,
                bits='dc34'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                bs[SCALAR_LEN - 1] &= 0b00011111
                bs = bytes(bs)
                (s1, s2) = (cls.scl(bs[:SCALAR_LEN]), cls.scl(bs[SCALAR_LEN:]))
                return cls.ssu(s1, s2) if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_sne(
                self,
                bits='66d6'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                bs = bytes(bs)
                s = cls.scl(bs)
                return cls.sne(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

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
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid scalar.
                bs = bytes(bs)
                s = cls.scl(bs)
                return cls.bas(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_can(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.can(cls.pnt(bs))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_ser(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.ser(cls.pnt(bs))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_des(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.des(cls.ser(cls.pnt(bs)))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_mul(
                self,
                bits='b9e1'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid scalar.
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

        def test_neg(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.neg(cls.pnt(bs))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_par(
                self,
                bits='0000'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.point.hash(bs), cls.point2.hash(bs))
                # Outputs for ``python`` and ``mcl`` differ, as expected.
                return bytes([0 if len(cls.sse2(cls.par(p1, p2))) == 384 else 1])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_rnd2(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.rnd2()
                self.assertTrue(cls.scl2(bytes(s)) is not None)

        def test_scl2(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.sse2(cls.scl2(cls.scalar2.hash(bs).to_bytes()))
            return check_or_generate_operation(self, fun, [SCALAR2_LEN], bits)

        def test_sse2(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.sse2(cls.scalar2.hash(bs))
            return check_or_generate_operation(self, fun, [SCALAR2_LEN], bits)

        def test_sde2(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.sse2(cls.sde2(cls.sse2(cls.scalar2.hash(bs))))
            return check_or_generate_operation(self, fun, [SCALAR2_LEN], bits)

        def test_inv2(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.sse2(cls.inv2(cls.scalar2.hash(bs)))
            return check_or_generate_operation(self, fun, [SCALAR2_LEN], bits)

        def test_smu2(
                self,
                bits='ed98'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar2.hash(bs[:SCALAR2_LEN]), cls.scalar2.hash(bs[SCALAR2_LEN:]))
                return cls.sse2(cls.smu2(s1, s2))
            return check_or_generate_operation(self, fun, [SCALAR2_LEN, SCALAR2_LEN], bits)

        def test_sad2(
                self,
                bits='1d51'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar2.hash(bs[:SCALAR2_LEN]), cls.scalar2.hash(bs[SCALAR2_LEN:]))
                return cls.sse2(cls.sad2(s1, s2))
            return check_or_generate_operation(self, fun, [SCALAR2_LEN, SCALAR2_LEN], bits)

        def test_pnt2(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.pnt2, [POINT_HASH_LEN], bits)

        def test_bas2(
                self,
                bits='1ed0'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.bas2(cls.scalar.hash(bs))
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_can2(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.ser2(cls.can2(cls.pnt2(bs)))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_ser2(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.ser2(cls.can2(cls.pnt2(bs)))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_des2(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.des2(cls.ser2(cls.can2(cls.pnt2(bs))))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_mul2(
                self,
                bits='1e5c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s, p) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.pnt2(bs[SCALAR_LEN:]))
                return cls.mul2(s, p)
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_add2(
                self,
                bits='424e'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.pnt2(bs[:POINT_HASH_LEN]), cls.pnt2(bs[POINT_HASH_LEN:]))
                return cls.add2(p1, p2)
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_sub2(
                self,
                bits='15c9'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.pnt2(bs[:POINT_HASH_LEN]), cls.pnt2(bs[POINT_HASH_LEN:]))
                return cls.sub2(p1, p2)
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_neg2(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.neg2(cls.pnt2(bs))
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

    class Test_classes(TestCase): # pylint: disable=too-many-public-methods
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
                bs[-1] &= 0b00011111 # Improve chance of testing with a valid scalar.
                s = cls.scalar.bytes(bytes(bs))
                return cls.point.base(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_point_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point()
                self.assertEqual(cls.point.from_bytes(p.to_bytes()), p)

        def test_point_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point()
                self.assertEqual(cls.point.fromhex(p.hex()), p)

        def test_point_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point()
                p_b64 = base64.standard_b64encode(p.to_bytes()).decode('utf-8')
                self.assertEqual(p.to_base64(), p_b64)
                self.assertEqual(cls.point.from_base64(p.to_base64()), p)
                self.assertEqual(cls.point.from_base64(p_b64), p)

        def test_point(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point()) == POINT_LEN)

        def test_point_canonical(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.point.bytes(bs).canonical()
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_point_scalar_mul(
                self,
                bits='b9e1'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00111111 # Improve chance of testing with a valid scalar.
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

        def test_point_neg(
                self,
                bits='bc3d'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                p = cls.point.bytes(bs)
                return -p if p is not None else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_point_pair(
                self,
                bits='0000'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (
                    cls.point.hash(bs[:POINT_HASH_LEN]),
                    cls.point2.hash(bs[POINT_HASH_LEN:])
                )
                # Output differs between ``python`` and ``mcl`` implementations (as expected).
                return bytes([0]) if isinstance(p1 @ p2, cls.scalar2) else bytes([1])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_scalar_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar.random()
                self.assertTrue(cls.scalar.bytes(bytes(s)) is not None)
                self.assertTrue(len(s) == SCALAR_LEN and len(s.to_bytes()) == SCALAR_LEN)

        def test_scalar_bytes(
                self,
                bits='ab29'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = bytearray(bs)
                bs[-1] &= 0b00011111 # Improve chances of testing with a valid scalar.
                s = cls.scalar.bytes(bytes(bs))
                return s.to_bytes() if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_hash(
                self,
                bits='1c21'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.scalar.hash, [SCALAR_LEN], bits)

        def test_scalar_to_int(
                self,
                bits='6969'
            ):
            def fun(bs):
                s = cls.scalar.hash(bs)
                return abs(s.to_int()).to_bytes(32, 'little')
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_from_int(
                self,
                bits='d27b'
            ):
            def fun(bs):
                s = cls.scalar.from_int(int.from_bytes(bs, 'little'))
                return s if (s is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                self.assertEqual(cls.scalar.from_bytes(s.to_bytes()), s)

        def test_scalar_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                self.assertEqual(cls.scalar.fromhex(s.hex()), s)

        def test_scalar_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                s_b64 = base64.standard_b64encode(s.to_bytes()).decode('utf-8')
                self.assertEqual(s.to_base64(), s_b64)
                self.assertEqual(cls.scalar.from_base64(s_b64), s)
                self.assertEqual(cls.scalar.from_base64(s.to_base64()), s)

        def test_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scalar.bytes(bytes(s)) is not None)
                self.assertTrue(len(bytes(s)) == SCALAR_LEN and len(s.to_bytes()) == SCALAR_LEN)

        def test_scalar_invert(
                self,
                bits='c4e3'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs)
                return ~s
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

        def test_scalar_add(
                self,
                bits='debe'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs[SCALAR_LEN:])
                t = cls.scalar.hash(bs[:SCALAR_LEN])
                return s + t
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_scalar_sub(
                self,
                bits='7fc9'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs[SCALAR_LEN:])
                t = cls.scalar.hash(bs[:SCALAR_LEN])
                return s - t
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_scalar_neg(
                self,
                bits='a1de'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs)
                return -s
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_point2_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point2.random()) == POINT2_LEN)

        def test_point2_bytes(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point2.bytes, [POINT_HASH_LEN], bits)

        def test_point2_hash(
                self,
                bits='d51b'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point2.hash, [POINT_HASH_LEN], bits)

        def test_point2_base(
                self,
                bits='1ed0'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.point2.base(cls.scalar.hash(bs))
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_point2_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point2()
                self.assertEqual(cls.point2.from_bytes(p.to_bytes()), p)

        def test_point2_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point2()
                self.assertEqual(cls.point2.fromhex(p.hex()), p)

        def test_point2_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point2()
                p_b64 = base64.standard_b64encode(p.to_bytes()).decode('utf-8')
                self.assertEqual(p.to_base64(), p_b64)
                self.assertEqual(cls.point2.from_base64(p.to_base64()), p)
                self.assertEqual(cls.point2.from_base64(p_b64), p)

        def test_point2(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point2()) == POINT2_LEN)

        def test_point2_canonical(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return cls.point2.bytes(bs).canonical()
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_point2_scalar_mul(
                self,
                bits='1e5c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s, p) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.point2.bytes(bs[SCALAR_LEN:]))
                # Below, ``*`` invokes :obj:`scalar.__mul__`, which delegates to :obj:`mul`
                # due to the type of the second argument.
                return s * p
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_point2_add(
                self,
                bits='424e'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.point2.bytes(bs[:POINT_HASH_LEN]), cls.point2.bytes(bs[POINT_HASH_LEN:]))
                return p1 + p2
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_point2_sub(
                self,
                bits='15c9'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.point2.bytes(bs[:POINT_HASH_LEN]), cls.point2.bytes(bs[POINT_HASH_LEN:]))
                return p1 - p2
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_point2_neg(
                self,
                bits='d28c'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                return -cls.point2.bytes(bs)
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN], bits)

        def test_scalar2_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar2.random()
                self.assertTrue(cls.scalar2.bytes(s.to_bytes()) is not None)
                self.assertTrue(len(s) == SCALAR2_LEN and len(s.to_bytes()) == SCALAR2_LEN)

        def test_scalar2_bytes(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                bs = cls.scalar2.hash(bs).to_bytes()
                s = cls.scalar2.bytes(bs)
                return s.to_bytes()
            return check_or_generate_operation(self, fun, [SCALAR2_LEN], bits)

        def test_scalar2_hash(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.scalar2.hash, [SCALAR2_LEN], bits)

        def test_scalar2_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar2()
                self.assertEqual(cls.scalar2.from_bytes(s.to_bytes()), s)

        def test_scalar2_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar2()
                self.assertEqual(cls.scalar2.fromhex(s.hex()), s)

        def test_scalar2_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar2()
                s_b64 = base64.standard_b64encode(s.to_bytes()).decode('utf-8')
                self.assertEqual(s.to_base64(), s_b64)
                self.assertEqual(cls.scalar2.from_base64(s_b64), s)
                self.assertEqual(cls.scalar2.from_base64(s.to_base64()), s)

        def test_scalar2(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar2()
                self.assertTrue(cls.scalar2(s.to_bytes()) is not None)
                self.assertTrue(len(s) == SCALAR2_LEN and len(s.to_bytes()) == SCALAR2_LEN)

        def test_scalar2_invert(
                self,
                bits='a567'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar2.hash(bs)
                return ~s
            return check_or_generate_operation(self, fun, [SCALAR2_LEN], bits)

        def test_scalar2_mul(
                self,
                bits='b0f7'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar2.hash(bs[:SCALAR_LEN]), cls.scalar2.hash(bs[SCALAR_LEN:]))
                return s1 * s2
            return check_or_generate_operation(self, fun, [SCALAR2_LEN, SCALAR2_LEN], bits)

        def test_scalar2_add(
                self,
                bits='015e'
            ):
            mcl_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar2.hash(bs[:SCALAR_LEN]), cls.scalar2.hash(bs[SCALAR_LEN:]))
                return s1 + s2
            return check_or_generate_operation(self, fun, [SCALAR2_LEN, SCALAR2_LEN], bits)

    class Test_types(TestCase): # pylint: disable=too-many-public-methods
        """
        Tests verifying that methods that should return point and scalar classes
        do indeed return point and scalar objects of the expected types.
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

        def test_types_point_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = cls.point.random().to_bytes()
            self.assertTrue(isinstance(cls.point.from_bytes(bs), cls.point))

        def test_types_point_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.point.random().hex()
            self.assertTrue(isinstance(cls.point.fromhex(s), cls.point))

        def test_types_point_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.point.random().to_base64()
            self.assertTrue(isinstance(cls.point.from_base64(s), cls.point))

        def test_types_point_canonical(self):
            mcl_hidden_and_fallback(hidden, fallback)
            p = cls.point.base(cls.scalar.random())
            self.assertTrue(isinstance(p.canonical(), cls.point))

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

        def test_types_point_neg(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point.hash(bs)
            self.assertTrue(isinstance(-p, cls.point))

        def test_types_point_point2_matmul(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point.hash(bs[:POINT_HASH_LEN]), cls.point2.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 @ p1, cls.scalar2))

        def test_types_scalar_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar.random(), cls.scalar))

        def test_types_scalar_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = cls.scalar.random().to_bytes()
            self.assertTrue(isinstance(cls.scalar.bytes(bs), cls.scalar))

        def test_types_scalar_hash(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR_LEN, limit=1)
            self.assertTrue(isinstance(cls.scalar.hash(bs), cls.scalar))

        def test_types_scalar_to_int_from_int(self):
            mcl_hidden_and_fallback(hidden, fallback)
            n = cls.scalar.random().to_int()
            self.assertTrue(isinstance(cls.scalar.from_int(n), cls.scalar))

        def test_types_scalar_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = cls.scalar.random().to_bytes()
            self.assertTrue(isinstance(cls.scalar.from_bytes(bs), cls.scalar))

        def test_types_scalar_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random().hex()
            self.assertTrue(isinstance(cls.scalar.fromhex(s), cls.scalar))

        def test_types_scalar_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random().to_base64()
            self.assertTrue(isinstance(cls.scalar.from_base64(s), cls.scalar))

        def test_types_scalar_invert(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(~cls.scalar.random(), cls.scalar))

        def test_types_scalar_mul_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar.random(), cls.scalar.random())
            self.assertTrue(isinstance(s0 * s1, cls.scalar))

        def test_types_scalar_add_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar.random(), cls.scalar.random())
            self.assertTrue(isinstance(s0 + s1, cls.scalar))

        def test_types_scalar_sub_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar.random(), cls.scalar.random())
            self.assertTrue(isinstance(s0 - s1, cls.scalar))

        def test_types_scalar_neg(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random()
            self.assertTrue(isinstance(-s, cls.scalar))

        def test_types_scalar_mul_point(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar() * cls.point(), cls.point))

        def test_types_point2_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            p = cls.point2.random()
            self.assertTrue(isinstance(p, cls.point2))

        def test_types_point2_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point2.bytes(bs)
            self.assertTrue(isinstance(p, cls.point2))

        def test_types_point2_hash(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point2.hash(bs)
            self.assertTrue(isinstance(p, cls.point2))

        def test_types_point2_base(self):
            mcl_hidden_and_fallback(hidden, fallback)
            p = cls.point2.base(cls.scalar.random())
            self.assertTrue(isinstance(p, cls.point2))

        def test_types_point2_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = cls.point2.random().to_bytes()
            self.assertTrue(isinstance(cls.point2.from_bytes(bs), cls.point2))

        def test_types_point2_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.point2.random().hex()
            self.assertTrue(isinstance(cls.point2.fromhex(s), cls.point2))

        def test_types_point2_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.point2.random().to_base64()
            self.assertTrue(isinstance(cls.point2.from_base64(s), cls.point2))

        def test_types_point2_canonical(self):
            mcl_hidden_and_fallback(hidden, fallback)
            p = cls.point2.base(cls.scalar.random())
            self.assertTrue(isinstance(p.canonical(), cls.point2))

        def test_types_point2_mul(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR_LEN + POINT_HASH_LEN, limit=1)
            (s, p) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.point2.hash(bs[SCALAR_LEN:]))
            self.assertTrue(isinstance(s * p, cls.point2))

        def test_types_point2_add(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point2.hash(bs[:POINT_HASH_LEN]), cls.point2.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 + p1, cls.point2))

        def test_types_point2_sub(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point2.hash(bs[:POINT_HASH_LEN]), cls.point2.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 - p1, cls.point2))

        def test_types_point2_neg(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            self.assertTrue(isinstance(-cls.point2.hash(bs), cls.point2))

        def test_types_scalar2_random(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar2.random(), cls.scalar2))

        def test_types_scalar2_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = cls.scalar2.random().to_bytes()
            self.assertTrue(isinstance(cls.scalar2.bytes(bs), cls.scalar2))

        def test_types_scalar2_hash(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR2_LEN, limit=1)
            self.assertTrue(isinstance(cls.scalar2.hash(bs), cls.scalar2))

        def test_types_scalar2_to_bytes_from_bytes(self):
            mcl_hidden_and_fallback(hidden, fallback)
            bs = cls.scalar2.random().to_bytes()
            self.assertTrue(isinstance(cls.scalar2.from_bytes(bs), cls.scalar2))

        def test_types_scalar2_hex_fromhex(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar2.random().hex()
            self.assertTrue(isinstance(cls.scalar2.fromhex(s), cls.scalar2))

        def test_types_scalar2_to_base64_from_base64(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar2.random().to_base64()
            self.assertTrue(isinstance(cls.scalar2.from_base64(s), cls.scalar2))

        def test_types_scalar2_invert(self):
            mcl_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(~cls.scalar2.random(), cls.scalar2))

        def test_types_scalar2_mul_scalar2(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar2.random(), cls.scalar2.random())
            self.assertTrue(isinstance(s0 * s1, cls.scalar2))

        def test_types_scalar2_add_scalar2(self):
            mcl_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar2.random(), cls.scalar2.random())
            self.assertTrue(isinstance(s0 + s1, cls.scalar2))

    class Test_algebra(TestCase):
        """
        Tests of common algebraic properties of low-level operations (for all classes).
        """
        def test_algebra_point_add_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(2 * POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point.hash(bs[:POINT_HASH_LEN]),
                    cls.point.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add(p0, p1), cls.add(p1, p0))

        def test_algebra_point_add_sub_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(2 * POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point.hash(bs[:POINT_HASH_LEN]),
                    cls.point.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add(cls.sub(p0, p1), p1), p0)

        def test_algebra_point_add_neg_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(2 * POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point.hash(bs[:POINT_HASH_LEN]),
                    cls.point.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add(cls.neg(p0), cls.add(p0, p1)), p1)

        def test_algebra_point_neg_neg_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                p = cls.point.hash(bs[:POINT_HASH_LEN])
                self.assertEqual(cls.neg(cls.neg(p)), p)

        def test_algebra_point_add_neg_sub_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(2 * POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point.hash(bs[:POINT_HASH_LEN]),
                    cls.point.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add(p0, cls.neg(p1)), cls.sub(p0, p1))

        def test_algebra_point_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                z = cls.point.base(cls.scalar.from_int(0))
                p = cls.point.hash(bs)
                self.assertEqual(cls.add(z, p), p)
                self.assertEqual(cls.add(p, z), p)

        def test_algebra_scalar_inverse_inverse_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN, limit=TRIALS_PER_TEST):
                s = cls.scalar.hash(bs)
                self.assertEqual(cls.inv(cls.inv(s)), s)

        def test_algebra_scalar_inverse_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN, limit=TRIALS_PER_TEST):
                s = cls.scalar.hash(bs)
                self.assertEqual(cls.inv(cls.inv(s)), s)

        def test_algebra_scalar_inverse_mul_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (s, p) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.point.hash(bs[SCALAR_LEN:])
                )
                self.assertEqual(cls.mul(cls.inv(s), cls.mul(s, p)), p)

        def test_algebra_scalar_mul_point_scalar_zero(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                z = cls.point.base(cls.scalar.from_int(0))
                p = cls.point.hash(bs)
                self.assertEqual(cls.mul(cls.scalar.from_int(0), p), z)

        def test_algebra_scalar_mul_point_scalar_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                p = cls.point.hash(bs)
                self.assertEqual(cls.mul(cls.scalar.from_int(1), p), p)

        def test_algebra_scalar_mul_point_mul_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains((2 * SCALAR_LEN) + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (s0, s1, p0) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.scalar.hash(bs[SCALAR_LEN: SCALAR_LEN + SCALAR_LEN]),
                    cls.point.hash(bs[SCALAR_LEN + SCALAR_LEN:])
                )
                self.assertEqual(
                    cls.mul(s0, cls.mul(s1, p0)),
                    cls.mul(s1, cls.mul(s0, p0))
                )

        def test_algebra_scalar_add_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + SCALAR_LEN, limit=TRIALS_PER_TEST):
                (s0, s1) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.scalar.hash(bs[SCALAR_LEN:])
                )
                self.assertEqual(cls.sad(s0, s1), cls.sad(s1, s0))

        def test_algebra_scalar_add_neg_add_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + SCALAR_LEN, limit=TRIALS_PER_TEST):
                (s0, s1) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.scalar.hash(bs[SCALAR_LEN:])
                )
                self.assertEqual(cls.sad(cls.sad(s0, cls.sne(s0)), s1), s1)

        def test_algebra_scalar_mul_point_mul_associate(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (s0, s1, p0) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.scalar.hash(bs[SCALAR_LEN: SCALAR_LEN + SCALAR_LEN]),
                    cls.point.hash(bs[SCALAR_LEN + SCALAR_LEN:])
                )
                self.assertEqual(
                    cls.mul(s0, cls.mul(s1, p0)),
                    cls.mul(cls.smu(s0, s1), p0)
                )

        def test_algebra_scalar_mul_point_add_distribute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + (2 * POINT_HASH_LEN), limit=TRIALS_PER_TEST):
                (s0, p0, p1) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.point.hash(bs[SCALAR_LEN: SCALAR_LEN + POINT_HASH_LEN]),
                    cls.point.hash(bs[SCALAR_LEN + POINT_HASH_LEN:])
                )
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

        def test_algebra_point2_add_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point2.hash(bs[:POINT_HASH_LEN]),
                    cls.point2.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.can2(cls.add2(p0, p1)), cls.can2(cls.add2(p1, p0)))

        def test_algebra_point2_add_sub_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point2.hash(bs[:POINT_HASH_LEN]),
                    cls.point2.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add2(cls.sub2(p0, p1), p1), p0)

        def test_algebra_point2_add_neg_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(2 * POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point2.hash(bs[:POINT_HASH_LEN]),
                    cls.point2.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add2(cls.neg2(p0), cls.add2(p0, p1)), p1)

        def test_algebra_point2_neg_neg_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                p = cls.point2.hash(bs[:POINT_HASH_LEN])
                self.assertEqual(cls.neg2(cls.neg2(p)), p)

        def test_algebra_point2_add_neg_sub_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(2 * POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (
                    cls.point2.hash(bs[:POINT_HASH_LEN]),
                    cls.point2.hash(bs[POINT_HASH_LEN:])
                )
                self.assertEqual(cls.add2(p0, cls.neg2(p1)), cls.sub2(p0, p1))

        def test_algebra_point2_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                z = cls.point2.base(cls.scalar.from_int(0))
                p = cls.point2.hash(bs)
                self.assertEqual(cls.add2(z, p), p)
                self.assertEqual(cls.add2(p, z), p)

        def test_algebra_scalar_mul_point2_mul_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains((2 * SCALAR_LEN) + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (s0, s1, p0) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.scalar.hash(bs[SCALAR_LEN: SCALAR_LEN + SCALAR_LEN]),
                    cls.point2.hash(bs[SCALAR_LEN + SCALAR_LEN:])
                )
                self.assertEqual(
                    cls.mul(s0, cls.mul2(s1, p0)),
                    cls.mul(s1, cls.mul2(s0, p0))
                )

        def test_algebra_scalar_mul_point2_mul_associate(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (s0, s1, p0) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.scalar.hash(bs[SCALAR_LEN: SCALAR_LEN + SCALAR_LEN]),
                    cls.point2.hash(bs[SCALAR_LEN + SCALAR_LEN:])
                )
                self.assertEqual(
                    cls.mul2(s0, cls.mul2(s1, p0)),
                    cls.mul2(cls.smu(s0, s1), p0)
                )

        def test_algebra_scalar_mul_point2_add_distribute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + (2 * POINT_HASH_LEN), limit=TRIALS_PER_TEST):
                (s0, p0, p1) = (
                    cls.scalar.hash(bs[:SCALAR_LEN]),
                    cls.point2.hash(bs[SCALAR_LEN: SCALAR_LEN + POINT_HASH_LEN]),
                    cls.point2.hash(bs[SCALAR_LEN + POINT_HASH_LEN:])
                )
                self.assertEqual(
                    cls.add2(cls.mul2(s0, p0), cls.mul2(s0, p1)),
                    cls.mul2(s0, cls.add2(p0, p1))
                )

        def test_algebra_scalar_mul_point2_on_left_hand_side(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random()
            p = cls.point2.hash(bytes(POINT2_LEN))
            self.assertRaises(TypeError, lambda: p * s)

        def test_algebra_scalar2_inverse_inverse_cancel(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR2_LEN, limit=TRIALS_PER_TEST):
                s = cls.scalar2.hash(bs)
                self.assertEqual(cls.inv2(cls.inv2(s)), s)

        def test_algebra_scalar2_inverse_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN, limit=TRIALS_PER_TEST):
                s = cls.scalar2.hash(bs)
                self.assertEqual(cls.inv2(cls.inv2(s)), s)

        def test_algebra_scalar2_mul_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR2_LEN + SCALAR2_LEN, limit=TRIALS_PER_TEST):
                (s0, s1) = (
                    cls.scalar2.hash(bs[:SCALAR2_LEN]),
                    cls.scalar2.hash(bs[SCALAR2_LEN:])
                )
                self.assertEqual(cls.smu2(s0, s1), cls.smu2(s1, s0))

        def test_algebra_scalar2_mul_inverse_mul_identity(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR2_LEN + SCALAR2_LEN, limit=TRIALS_PER_TEST):
                (s0, s1) = (
                    cls.scalar2.hash(bs[:SCALAR2_LEN]),
                    cls.scalar2.hash(bs[SCALAR2_LEN:])
                )
                self.assertEqual(cls.smu2(cls.smu2(s0, cls.inv2(s0)), s1), s1)

        def test_algebra_scalar2_add_commute(self):
            mcl_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR2_LEN + SCALAR2_LEN, limit=TRIALS_PER_TEST):
                (s0, s1) = (
                    cls.scalar2.hash(bs[:SCALAR2_LEN]),
                    cls.scalar2.hash(bs[SCALAR2_LEN:])
                )
                self.assertEqual(cls.sad2(s0, s1), cls.sad2(s1, s0))

        def test_algebra_scalar2_mul_scalar_on_right_hand_side_of_non_scalar(self):
            mcl_hidden_and_fallback(hidden, fallback)
            s = cls.scalar2.random()
            self.assertRaises(TypeError, lambda: bytes([0]) * s)

    return (
        Test_primitives,
        Test_classes,
        Test_types,
        Test_algebra
    )

# The instantiated test classes below are discovered by the testing framework and
# executed in alphabetical order.
(
    Test_primitives_python_no_mcl,
    Test_classes_python_no_mcl,
    Test_types_python_no_mcl,
    Test_algebra_python_no_mcl
) = define_classes(bn254.python, hidden=True)

if bn254.mcl is not None and bn254.mclbn256 is True:
    (
        Test_primitives_mcl_mclbn256_no_mcl,
        Test_classes_mcl_mclbn256_no_mcl,
        Test_types_mcl_mclbn256_no_mcl,
        Test_algebra_mcl_mclbn256_no_mcl
    ) = define_classes(bn254.mcl, fallback=True)

(Test_primitives_python, Test_classes_python, Test_types_python, Test_algebra_python) = \
    define_classes(bn254.python)

if bn254.mcl is not None:
    (Test_primitives_mcl, Test_classes_mcl, Test_types_mcl, Test_algebra_mcl) = \
        define_classes(bn254.mcl)

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    for tests in [Test_primitives_python(), Test_classes_python()]:
        print(
            '\nUnit test reference bit vectors for ' +
            tests.__class__.__name__ + ' methods...'
        )
        for m in [m for m in dir(tests) if m.startswith('test_')]:
            method = getattr(tests, m)
            if 'bits' in method.__code__.co_varnames:
                print('* ' + m + ": '" + method(bits=None) + "'")
