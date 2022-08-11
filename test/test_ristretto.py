"""
Test suite containing functional unit tests for the exported primitives and
classes in the :obj:`oblivious.ristretto` module, as well as unit tests
confirming algebraic relationships among primitives.
"""
# pylint: disable=C0103,C0116
from unittest import TestCase
import importlib
import base64
from bitlist import bitlist
from fountains import fountains

try:
    from oblivious import ristretto
except: # pylint: disable=W0702
    # To support generation of reference specifications for unit tests.
    spec = importlib.util.spec_from_file_location("ristretto", "src/oblivious/ristretto.py")
    ristretto = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ristretto)

# Constants for the number of input-output pairs to include in each test and for
# representation sizes of data structures (in their binary form).
TRIALS_PER_TEST = 16
POINT_HASH_LEN = 64 # Size of raw hash digest required to construct a point.
POINT_LEN = 32
SCALAR_LEN = 32

# To simulate an environment in which sodium is absent, some tests set
# `ristretto.sodium` to `None` or modify `ristretto.sodium._sodium`;
# the references below are used for restoration.
sodium_lib_restore = ristretto.sodium._lib # pylint: disable=W0212
sodium_restore = ristretto.sodium

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
        self.assertTrue('ristretto' in init.__dict__)

    def test_modules(self):
        module = importlib.import_module('oblivious.ristretto')
        self.assertTrue('native' in module.__dict__)
        self.assertTrue('sodium' in module.__dict__)
        self.assertTrue(api_methods().issubset(module.__dict__.keys()))

    def test_native(self):
        self.assertTrue(api_methods().issubset(set(dir(ristretto.native))))

    def test_sodium(self):
        if ristretto.sodium is not None:
            self.assertTrue(api_methods().issubset(set(dir(ristretto.sodium))))

def check_or_generate_operation(test, fun, lengths, bits): # pylint: disable=R1710
    """
    This function does either of two things depending on `bits`:
    * checks that test inputs drawn from the fountains input bit stream
      produce the bits provided in the reference output bit vector, or
    * generates a reference output bit vector by applying the function
      to the fountains input bit stream.
    """
    fs = fountains( # Generate the input bit stream.
        sum(lengths),
        seed=bytes(0), # This is also the default; explicit for clarity.
        limit=min(TRIALS_PER_TEST, (len(bits) * 4) if bits is not None else 256),
        bits=bits[:(TRIALS_PER_TEST // 4)] if bits is not None else None,
        function=fun
    )

    if bits is None: # There is no output reference bit vector, so test is not possible.
        return bitlist(list(fs)).hex() # Return reference output bits for test.

    test.assertTrue(all(fs)) # Check that all outputs match.

def sodium_hidden_and_fallback(hidden=False, fallback=False):
    """
    Return binary wrapper class definition that conforms to the
    scenario being tested.
    """
    # pylint: disable=W0212
    if hidden:
        ristretto.sodium = None
    elif fallback:
        ristretto.sodium = sodium_restore
        ristretto.sodium._lib = ristretto.rbcl
        ristretto.sodium._call = ristretto.sodium._call_wrapped
    else:
        ristretto.sodium = sodium_restore
        ristretto.sodium._lib = sodium_lib_restore
        ristretto.sodium._call = ristretto.sodium._call_unwrapped

def define_classes(cls, hidden=False, fallback=False): # pylint: disable=R0915
    """
    Define and return four classes of unit tests given a wrapper
    class (`native` or `sodium`) for primitive operations.
    """
    class Test_primitives(TestCase):
        """
        Direct tests of primitive operators that operate on bytes-like objects.
        """
        def test_rnd(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.rnd()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scl(s))

        def test_scl_none(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scl()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scl(s))

        def test_scl(
                self,
                bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            # pylint: disable=C3001
            fun = lambda bs: bitlist([1 if cls.scl(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_inv(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scl(bs)
                return cls.inv(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_smu(
                self,
                bits='2ca120487000010295804000850254008018000000008000080100008400000c'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scl(bs[:SCALAR_LEN]), cls.scl(bs[SCALAR_LEN:]))
                return cls.smu(s1, s2) if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

        def test_pnt_none(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.pnt()) == POINT_LEN)

        def test_pnt(
                self,
                bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.pnt, [POINT_HASH_LEN], bits)

        def test_bas(
                self,
                bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scl(bs)
                return cls.bas(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_mul(
                self,
                bits='0240281c2c0429000440190404c00003082024e160cca1002800a00108100002'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s, p) = (cls.scl(bs[:SCALAR_LEN]), cls.pnt(bs[SCALAR_LEN:]))
                return cls.mul(s, p) if (s is not None and p is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_add(
                self,
                bits='0ce3cd934a855c343cb16371dc8dffe999168117d8952b53ad3b5ed8af59a01f'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                return cls.add(p1, p2) if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_sub(
                self,
                bits='64edf78ce6a904bfbb4184005b76b8f9614ea0aefb0f7ef00c882b155acbb968'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                return cls.sub(p1, p2) if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

    class Test_classes(TestCase):
        """
        Tests of point and scalar wrapper classes and their methods.
        """
        def test_point_random(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point.random()) == POINT_LEN)

        def test_point_bytes(
                self,
                bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point.bytes, [POINT_HASH_LEN], bits)

        def test_point_hash(
                self,
                bits='10cb044c737b034d5755f8ba0e29432745ed4fb1a78ea22a15b2d1113492841b'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point.hash, [POINT_HASH_LEN], bits)

        def test_point_base(
                self,
                bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return cls.point.base(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_point_base64(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                p = cls.point()
                p_b64 = base64.standard_b64encode(p).decode('utf-8')
                self.assertEqual(p.to_base64(), p_b64)
                self.assertEqual(cls.point.from_base64(p_b64), p)

        def test_point(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point()) == POINT_LEN)

        def test_point_rmul(
                self,
                bits='0240281c2c0429000440190404c00003082024e160cca1002800a00108100002'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s, p) = (cls.scalar.bytes(bs[:SCALAR_LEN]), cls.point.bytes(bs[SCALAR_LEN:]))
                # pylint: disable=C2801 # Overriding overloaded method for :obj:`scalar`.
                return p.__rmul__(s) if (s is not None and p is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_point_scalar_mul_op(
                self,
                bits='0240281c2c0429000440190404c00003082024e160cca1002800a00108100002'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s, p) = (cls.scalar.bytes(bs[:SCALAR_LEN]), cls.point.bytes(bs[SCALAR_LEN:]))
                # Below, ``*`` invokes :obj:`scalar.__mul__`, which delegates to :obj:`mul`
                # due to the type of the second argument.
                return s * p if (s is not None and p is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, POINT_HASH_LEN], bits)

        def test_point_add(
                self,
                bits='0ce3cd934a855c343cb16371dc8dffe999168117d8952b53ad3b5ed8af59a01f'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (
                    cls.point.bytes(bs[:POINT_HASH_LEN]),
                    cls.point.bytes(bs[POINT_HASH_LEN:])
                )
                return p1 + p2 if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_point_sub(
                self,
                bits='64edf78ce6a904bfbb4184005b76b8f9614ea0aefb0f7ef00c882b155acbb968'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (p1, p2) = (
                    cls.point.bytes(bs[:POINT_HASH_LEN]),
                    cls.point.bytes(bs[POINT_HASH_LEN:])
                )
                return p1 - p2 if (p1 is not None and p2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [POINT_HASH_LEN, POINT_HASH_LEN], bits)

        def test_scalar_random(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar.random()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scalar.bytes(s) is not None)

        def test_scalar_bytes(
                self,
                bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            # pylint: disable=C3001
            fun = lambda bs: bitlist([1 if cls.scalar.bytes(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_hash(
                self,
                bits='09991cc13ab3799d9c05e0c75968859298977fb7b78efa2dcb6e1689e927ac0e'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.scalar.hash, [SCALAR_LEN], bits)

        def test_scalar_base64(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                s_b64 = base64.standard_b64encode(s).decode('utf-8')
                self.assertEqual(s.to_base64(), s_b64)
                self.assertEqual(cls.scalar.from_base64(s_b64), s)

        def test_scalar(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar()
                self.assertTrue(len(s) == SCALAR_LEN and cls.scalar.bytes(s) is not None)

        def test_scalar_inverse(
                self,
                bits='5dc66e5b233363b178154a0aebee957038ef1dbbad4455f332c2b7bc50886008'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs)
                return s.inverse() if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_invert_op(
                self,
                bits='5dc66e5b233363b178154a0aebee957038ef1dbbad4455f332c2b7bc50886008'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.hash(bs)
                return ~s if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN], bits)

        def test_scalar_mul(
                self,
                bits='e54eda3b0689089cc453b8cb6c90621ebca97462a0865811bc86087f6810da06'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.scalar.hash(bs[SCALAR_LEN:]))
                return s1 * s2 if (s1 is not None and s2 is not None) else bytes([0])
            return check_or_generate_operation(self, fun, [SCALAR_LEN, SCALAR_LEN], bits)

    class Test_types(TestCase):
        """
        Tests verifying that methods return objects of the appropriate type.
        """
        def test_types_point_random(self):
            sodium_hidden_and_fallback(hidden, fallback)
            p = cls.point.random()
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_bytes(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point.bytes(bs)
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_hash(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN, limit=1)
            p = cls.point.hash(bs)
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_base(self):
            sodium_hidden_and_fallback(hidden, fallback)
            p = cls.point.base(cls.scalar.random())
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_mul(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR_LEN + POINT_HASH_LEN, limit=1)
            (s, p) = (cls.scalar.hash(bs[:SCALAR_LEN]), cls.point.hash(bs[SCALAR_LEN:]))
            self.assertTrue(isinstance(s * p, cls.point))

        def test_types_point_add(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point.hash(bs[:POINT_HASH_LEN]), cls.point.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 + p1, cls.point))

        def test_types_point_sub(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=1)
            (p0, p1) = (cls.point.hash(bs[:POINT_HASH_LEN]), cls.point.hash(bs[POINT_HASH_LEN:]))
            self.assertTrue(isinstance(p0 - p1, cls.point))

        def test_types_scalar_random(self):
            sodium_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar.random(), cls.scalar))

        def test_types_scalar_bytes(self):
            sodium_hidden_and_fallback(hidden, fallback)
            bs = bytes(cls.scalar.random())
            self.assertTrue(isinstance(cls.scalar.bytes(bs), cls.scalar))

        def test_types_scalar_hash(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(SCALAR_LEN, limit=1)
            self.assertTrue(isinstance(cls.scalar.hash(bs), cls.scalar))

        def test_types_scalar_invert(self):
            sodium_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(~cls.scalar.random(), cls.scalar))

        def test_types_scalar_inverse(self):
            sodium_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar.random().inverse(), cls.scalar))

        def test_types_scalar_mul_scalar(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (s0, s1) = (cls.scalar.random(), cls.scalar.random())
            self.assertTrue(isinstance(s0 * s1, cls.scalar))

        def test_types_scalar_mul_point(self):
            sodium_hidden_and_fallback(hidden, fallback)
            self.assertTrue(isinstance(cls.scalar() * cls.point(), cls.point))

    class Test_algebra(TestCase):
        """
        Tests of algebraic properties of primitive operations and class methods.
        """
        def test_algebra_scalar_inverse_identity(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN, limit=TRIALS_PER_TEST):
                s = cls.scl(bs)
                if s is not None:
                    self.assertEqual(cls.inv(cls.inv(s)), s)

        def test_algebra_scalar_inverse_mul_cancel(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (s, p) = (cls.scl(bs[:SCALAR_LEN]), cls.pnt(bs[SCALAR_LEN:]))
                if s is not None:
                    self.assertEqual(cls.mul(cls.inv(s), cls.mul(s, p)), p)

        def test_algebra_scalar_mul_commute(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains((2 * SCALAR_LEN) + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
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
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                self.assertEqual(cls.add(p0, p1), cls.add(p1, p0))

        def test_algebra_point_add_sub_cancel(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(POINT_HASH_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
                (p0, p1) = (cls.pnt(bs[:POINT_HASH_LEN]), cls.pnt(bs[POINT_HASH_LEN:]))
                self.assertEqual(cls.add(cls.sub(p0, p1), p1), p0)

        def test_algebra_scalar_mul_point_mul_associate(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + SCALAR_LEN + POINT_HASH_LEN, limit=TRIALS_PER_TEST):
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
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(SCALAR_LEN + (2 * POINT_HASH_LEN), limit=TRIALS_PER_TEST):
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
            sodium_hidden_and_fallback(hidden, fallback)
            s = cls.scalar.random()
            self.assertRaises(TypeError, lambda: bytes([0]) * s)

        def test_algebra_scalar_mul_point_on_left_hand_side(self):
            sodium_hidden_and_fallback(hidden, fallback)
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
    Test_primitives_native_no_sodium,
    Test_classes_native_no_sodium,
    Test_types_native_no_sodium,
    Test_algebra_native_no_sodium
) = define_classes(ristretto.native, hidden=True)

if ristretto.rbcl is not None:
    (
        Test_primitives_sodium_rbcl_no_sodium,
        Test_classes_sodium_rbcl_no_sodium,
        Test_types_sodium_rbcl_no_sodium,
        Test_algebra_sodium_rbcl_no_sodium
    ) = define_classes(ristretto.sodium, fallback=True)

(Test_primitives_native, Test_classes_native, Test_types_native, Test_algebra_native) = \
    define_classes(ristretto.native)

(Test_primitives_sodium, Test_classes_sodium, Test_types_sodium, Test_algebra_sodium) = \
    define_classes(ristretto.sodium)

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
                print('* ' + m + ': ' + method(bits=None))
