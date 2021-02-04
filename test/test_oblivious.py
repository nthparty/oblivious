"""Functional and algebraic unit tests for primitives and classes.

Test suite containing functional unit tests for the exported primitives and
classes, as well as unit tests confirming algebraic relationships among
primitives.
"""
# pylint: disable=C0103,C0116

from importlib import import_module
from itertools import islice
from bitlist import bitlist
from fountains import fountains
from unittest import TestCase # pylint: disable=C0411

from oblivious.oblivious import * # pylint: disable=W0401,W0614

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
        self.assertTrue('native' in init.__dict__)
        self.assertTrue('sodium' in init.__dict__)
        self.assertTrue(api_methods().issubset(init.__dict__.keys()))

    def test_module(self):
        module = import_module('oblivious.oblivious')
        self.assertTrue('native' in module.__dict__)
        self.assertTrue('sodium' in module.__dict__)
        self.assertTrue(api_methods().issubset(module.__dict__.keys()))

    def test_native(self):
        self.assertTrue(api_methods().issubset(set(dir(native))))

    def test_sodium(self):
        self.assertTrue(api_methods().issubset(set(dir(sodium))))

def check_or_generate_operation(self, fun, lengths, bits): # pylint: disable=R1710
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
        limit=256,
        bits=bits, # Reference output bit vector.
        function=fun
    )

    if bits is None: # There is no output reference bit vector, so test is not possible.
        return bitlist(list(fs)).hex() # Return reference output bits for test.

    self.assertTrue(all(fs)) # Check that all outputs match.

def define_classes(cls):
    """
    Define and return three classes of unit tests given a wrapper
    class of primitive operations.
    """

    class Test_primitives(TestCase):
        """
        Direct tests of primitive operators that operate on bytes-like objects.
        """

        def test_rnd(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                s = cls.rnd()
                return bitlist([1 if len(s) == 32 and cls.scl(s) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scl_none(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                s = cls.scl()
                return bitlist([1 if len(s) == 32 and cls.scl(s) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scl(
                self,
                bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
            ):
            fun = lambda bs: bitlist([1 if cls.scl(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_inv(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            def fun(bs):
                s = cls.scl(bs)
                return cls.inv(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_smu(
                self,
                bits='2ca120487000010295804000850254008018000000008000080100008400000c'
            ):
            def fun(bs):
                (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
                return\
                    cls.smu(s1, s2)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_pnt_none(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                p = cls.pnt()
                return bitlist([1 if len(p) == 32 else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_pnt(
                self,
                bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
            ):
            return check_or_generate_operation(self, cls.pnt, [64], bits)

        def test_bas(
                self,
                bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
            ):
            def fun(bs):
                s = cls.scl(bs)
                return cls.bas(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_mul(
                self,
                bits='2c040004500080008180400080000008a1180020001080080211004000080040'
            ):
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

        def test_point_random(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                p = cls.point.random()
                return bitlist([1 if len(p) == 32 else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_point_bytes(
                self,
                bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
            ):
            return check_or_generate_operation(self, cls.point.bytes, [64], bits)

        def test_point_hash(
                self,
                bits='10cb044c737b034d5755f8ba0e29432745ed4fb1a78ea22a15b2d1113492841b'
            ):
            return check_or_generate_operation(self, cls.point.hash, [64], bits)

        def test_point_base(
                self,
                bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
            ):
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return cls.point.base(s) if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_point(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                p = cls.point()
                return bitlist([1 if len(p) == 32 else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_point_rmul(
                self,
                bits='2c040004500080008180400080000008a1180020001080080211004000080040'
            ):
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
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                return\
                    cls.point.base(s1) - cls.point.base(s2)\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

        def test_scalar_random(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                s = cls.scalar.random()
                return bitlist([1 if len(s) == 32 and cls.scalar.bytes(s) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_bytes(
                self,
                bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
            ):
            fun = lambda bs: bitlist([1 if cls.scalar.bytes(bs) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_hash(
                self,
                bits='09991cc13ab3799d9c05e0c75968859298977fb7b78efa2dcb6e1689e927ac0e'
            ):
            return check_or_generate_operation(self, cls.scalar.hash, [32], bits)

        def test_scalar(
                self,
                bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
            ):
            def fun(bs): # pylint: disable=W0613
                s = cls.scalar()
                return bitlist([1 if len(s) == 32 and cls.scalar.bytes(s) is not None else 0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_inverse(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return s.inverse() if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_invert_op(
                self,
                bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
            ):
            def fun(bs):
                s = cls.scalar.bytes(bs)
                return ~s if s is not None else bytes([0])
            return check_or_generate_operation(self, fun, [32], bits)

        def test_scalar_mul(
                self,
                bits='2ca120487000010295804000850254008018000000008000080100008400000c'
            ):
            def fun(bs):
                (s1, s2) = (cls.scalar.bytes(bs[:32]), cls.scalar.bytes(bs[32:]))
                return\
                    s1 * s2\
                    if s1 is not None and s2 is not None else\
                    bytes([0])
            return check_or_generate_operation(self, fun, [32, 32], bits)

    class Test_algebra(TestCase):
        """
        Tests of algebraic properties of primitive operators.
        """

        def test_algebra_scalar_inverse_identity(self):
            for bs in list(islice(fountains(32), 0, 256)):
                s = cls.scl(bs)
                if s is not None:
                    self.assertEqual(inv(inv(s)), s)

        def test_algebra_scalar_inverse_mul_cancel(self):
            for bs in list(islice(fountains(32 + 64), 0, 256)):
                (s0, p0) = (cls.scl(bs[:32]), cls.pnt(bs[32:]))
                if s0 is not None:
                    self.assertEqual(cls.mul(inv(s0), cls.mul(s0, p0)), p0)

        def test_algebra_scalar_mul_commute(self):
            for bs in list(islice(fountains(32 + 32 + 64), 0, 256)):
                (s0, s1, p0) = (cls.scl(bs[:32]), cls.scl(bs[32:64]), cls.pnt(bs[64:]))
                if s0 is not None and s1 is not None:
                    self.assertEqual(
                        cls.mul(s0, cls.mul(s1, p0)),
                        cls.mul(s1, cls.mul(s0, p0))
                    )

        def test_algebra_point_add_commute(self):
            for bs in list(islice(fountains(64 + 64), 0, 256)):
                (p0, p1) = (cls.pnt(bs[:64]), cls.pnt(bs[64:]))
                self.assertEqual(cls.add(p0, p1), cls.add(p1, p0))

        def test_algebra_point_add_sub_cancel(self):
            for bs in list(islice(fountains(64 + 64), 0, 256)):
                (p0, p1) = (cls.pnt(bs[:64]), cls.pnt(bs[64:]))
                self.assertEqual(cls.add(cls.sub(p0, p1), p1), p0)

        def test_algebra_scalar_mul_point_mul_associate(self):
            for bs in list(islice(fountains(32 + 32 + 64), 0, 256)):
                (s0, s1, p0) = (cls.scl(bs[:32]), cls.scl(bs[32:64]), cls.pnt(bs[64:]))
                if s0 is not None and s1 is not None:
                    self.assertEqual(
                        cls.mul(s0, cls.mul(s1, p0)),
                        cls.mul(cls.smu(s0, s1), p0)
                    )

        def test_algebra_scalar_mul_point_add_distribute(self):
            for bs in list(islice(fountains(32 + 64 + 64), 0, 256)):
                (s0, p0, p1) = (cls.scl(bs[:32]), cls.pnt(bs[32:96]), cls.pnt(bs[96:]))
                if s0 is not None:
                    self.assertEqual(
                        cls.add(cls.mul(s0, p0), cls.mul(s0, p1)),
                        cls.mul(s0, cls.add(p0, p1))
                    )

        def test_algebra_scalar_mul_scalar_on_right_hand_side_of_non_scalar(self):
            s = cls.scalar.random()
            self.assertRaises(TypeError, lambda: bytes([0]) * s)

        def test_algebra_scalar_mul_point_on_left_hand_side(self):
            s = cls.scalar.random()
            p = cls.point.bytes([0]*32)
            self.assertRaises(TypeError, lambda: p * s)

    return (
        Test_primitives,
        Test_classes,
        Test_algebra
    )

# The instantiated test classes below are discovered and executed
# (e.g., using nosetests).
(Test_primitives_native, Test_classes_native, Test_algebra_native) =\
    define_classes(native)
(Test_primitives_sodium, Test_classes_sodium, Test_algebra_sodium) =\
    define_classes(sodium)

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    for tests in [Test_primitives_native(), Test_classes_sodium()]:
        print('\nUnit test reference bit vectors for ' + tests.__class__.__name__ + ' methods...')
        for m in [m for m in dir(tests) if m.startswith('test_')]:
            print('* ' + m + ': ' + getattr(tests, m)(bits=None))
