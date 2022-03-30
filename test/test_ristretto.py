"""
Test suite containing functional unit tests for the exported primitives and
classes, as well as unit tests confirming algebraic relationships among
primitives.
"""
# pylint: disable=C0103,C0116

from importlib import import_module
import base64
from bitlist import bitlist
from fountains import fountains
from unittest import TestCase # pylint: disable=C0411

try:
    from oblivious import ristretto
except: # To support generation of reference specifications for unit tests.
    import sys
    sys.path.append('./oblivious')
    import ristretto

# Constant for the number of input-output pairs to include in each test.
TRIALS_PER_TEST = 16

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
        init = import_module('oblivious.__init__')
        self.assertTrue('ristretto' in init.__dict__)

    def test_modules(self):
        module = import_module('oblivious.ristretto')
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
                self.assertTrue(len(s) == 32 and cls.scl(s))

        def test_scl_none(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scl()
                self.assertTrue(len(s) == 32 and cls.scl(s))

        def test_scl(
                self,
                bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            fun = lambda bs: bitlist([1 if cls.scl(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_inv(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scl(bs)
                return cls.inv(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_smu(
                self,
                bits='2ca120487000010295804000850254008018000000008000080100008400000c'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
                return\
                    cls.smu(s1, s2)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_pnt_none(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.pnt()) == 32)

        def test_pnt(
                self,
                bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.pnt, [64], bits)

        def test_bas(
                self,
                bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scl(bs)
                return cls.bas(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_mul(
                self,
                bits='2c040004500080008180400080000008a1180020001080080211004000080040'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
                return\
                    cls.mul(s2, cls.bas(s1))\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_add(
                self,
                bits='28400040500000008480000020024c00211800080000800002110040ac001044'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
                return\
                    cls.add(cls.bas(s1), cls.bas(s2))\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_sub(
                self,
                bits='24210008500080028000000025020c08000001200000800002008002ac081040'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
                return\
                    cls.sub(cls.bas(s1), cls.bas(s2))\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

    class Test_classes(TestCase):
        """
        Tests of point and scalar wrapper classes and their methods.
        """

        def test_point_random(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                self.assertTrue(len(cls.point.random()) == 32)

        def test_point_bytes(
                self,
                bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point.bytes, [64], bits)

        def test_point_hash(
                self,
                bits='10cb044c737b034d5755f8ba0e29432745ed4fb1a78ea22a15b2d1113492841b'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.point.hash, [64], bits)

        def test_point_base(
                self,
                bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return cls.point.base(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

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
                self.assertTrue(len(cls.point()) == 32)

        def test_point_rmul(
                self,
                bits='2c040004500080008180400080000008a1180020001080080211004000080040'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                return\
                    cls.point.base(s2).__rmul__(s1)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_point_scalar_mul_op(
                self,
                bits='2c040004500080008180400080000008a1180020001080080211004000080040'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                # Below, `*` invokes `scalar.__mul__`, which delegates to `mul`
                # due to the type of the second argument.
                return\
                    s1 * cls.point.base(s2)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_point_add(
                self,
                bits='28400040500000008480000020024c00211800080000800002110040ac001044'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                return\
                    cls.point.base(s1) + cls.point.base(s2)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_point_sub(
                self,
                bits='24210008500080028000000025020c08000001200000800002008002ac081040'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                return\
                    cls.point.base(s1) - cls.point.base(s2)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_scalar_random(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for _ in range(TRIALS_PER_TEST):
                s = cls.scalar.random()
                self.assertTrue(len(s) == 32 and cls.scalar.bytes(s) is not None)

        def test_scalar_bytes(
                self,
                bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            fun = lambda bs: bitlist([1 if cls.scalar.bytes(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_hash(
                self,
                bits='09991cc13ab3799d9c05e0c75968859298977fb7b78efa2dcb6e1689e927ac0e'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            return check_or_generate_operation(self, cls.scalar.hash, [32], bits)

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
                self.assertTrue(len(s) == 32 and cls.scalar.bytes(s) is not None)

        def test_scalar_inverse(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return s.inverse() if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_invert_op(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return ~s if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_mul(
                self,
                bits='2ca120487000010295804000850254008018000000008000080100008400000c'
            ):
            sodium_hidden_and_fallback(hidden, fallback)
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                return\
                    s1 * s2\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

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
            (bs,) = fountains(64, limit=1)
            p = cls.point.bytes(bs)
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_hash(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(64, limit=1)
            p = cls.point.hash(bs)
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_base(self):
            sodium_hidden_and_fallback(hidden, fallback)
            p = cls.point.base(cls.scalar.random())
            self.assertTrue(isinstance(p, cls.point))

        def test_types_point_mul(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(32 + 64, limit=1)
            (s, p) = (cls.scalar.hash(bs[:32]), cls.point.hash(bs[64:]))
            self.assertTrue(isinstance(s * p, cls.point))

        def test_types_point_add(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(64 + 64, limit=1)
            (p0, p1) = (cls.point.hash(bs[:64]), cls.point.hash(bs[64:]))
            self.assertTrue(isinstance(p0 + p1, cls.point))

        def test_types_point_sub(self):
            sodium_hidden_and_fallback(hidden, fallback)
            (bs,) = fountains(64 + 64, limit=1)
            (p0, p1) = (cls.point.hash(bs[:64]), cls.point.hash(bs[64:]))
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
            (bs,) = fountains(32, limit=1)
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
            (bs,) = fountains(32 + 64, limit=1)
            (s, p) = (cls.scalar.hash(bs[:32]), cls.point.hash(bs[64:]))
            self.assertTrue(isinstance(s * p, cls.point))

    class Test_algebra(TestCase):
        """
        Tests of algebraic properties of primitive operators.
        """

        def test_algebra_scalar_inverse_identity(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(32, limit=TRIALS_PER_TEST):
                s = cls.scl(bs)
                if s is not None:
                    self.assertEqual(cls.inv(cls.inv(s)), s)

        def test_algebra_scalar_inverse_mul_cancel(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(32 + 64, limit=TRIALS_PER_TEST):
                (s0, p0) = (cls.scl(bs[:32]), cls.pnt(bs[32:]))
                if s0 is not None:
                    self.assertEqual(cls.mul(cls.inv(s0), cls.mul(s0, p0)), p0)

        def test_algebra_scalar_mul_commute(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(32 + 32 + 64, limit=TRIALS_PER_TEST):
                (s0, s1, p0) = (cls.scl(bs[:32]), cls.scl(bs[32:64]), cls.pnt(bs[64:]))
                if s0 is not None and s1 is not None:
                    self.assertEqual(
                        cls.mul(s0, cls.mul(s1, p0)),
                        cls.mul(s1, cls.mul(s0, p0))
                    )

        def test_algebra_point_add_commute(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(64 + 64, limit=TRIALS_PER_TEST):
                (p0, p1) = (cls.pnt(bs[:64]), cls.pnt(bs[64:]))
                self.assertEqual(cls.add(p0, p1), cls.add(p1, p0))

        def test_algebra_point_add_sub_cancel(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(64 + 64, limit=TRIALS_PER_TEST):
                (p0, p1) = (cls.pnt(bs[:64]), cls.pnt(bs[64:]))
                self.assertEqual(cls.add(cls.sub(p0, p1), p1), p0)

        def test_algebra_scalar_mul_point_mul_associate(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(32 + 32 + 64, limit=TRIALS_PER_TEST):
                (s0, s1, p0) = (cls.scl(bs[:32]), cls.scl(bs[32:64]), cls.pnt(bs[64:]))
                if s0 is not None and s1 is not None:
                    self.assertEqual(
                        cls.mul(s0, cls.mul(s1, p0)),
                        cls.mul(cls.smu(s0, s1), p0)
                    )

        def test_algebra_scalar_mul_point_add_distribute(self):
            sodium_hidden_and_fallback(hidden, fallback)
            for bs in fountains(32 + 64 + 64, limit=TRIALS_PER_TEST):
                (s0, p0, p1) = (cls.scl(bs[:32]), cls.pnt(bs[32:96]), cls.pnt(bs[96:]))
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
            p = cls.point.hash(bytes([0]*32))
            self.assertRaises(TypeError, lambda: p * s)

    return (
        Test_primitives,
        Test_classes,
        Test_types,
        Test_algebra
    )

# The instantiated test classes below are discovered by nose and
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

(Test_primitives_native, Test_classes_native, Test_types_native, Test_algebra_native) =\
    define_classes(ristretto.native)

(Test_primitives_sodium, Test_classes_sodium, Test_types_sodium, Test_algebra_sodium) =\
    define_classes(ristretto.sodium)

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    for tests in [Test_primitives_native(), Test_classes_sodium()]:
        print('\nUnit test reference bit vectors for ' + tests.__class__.__name__ + ' methods...')
        for m in [m for m in dir(tests) if m.startswith('test_')]:
            method = getattr(tests, m)
            if 'bits' in method.__code__.co_varnames:
                print('* ' + m + ': ' + method(bits=None))
