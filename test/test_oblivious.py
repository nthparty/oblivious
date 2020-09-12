from importlib import import_module
from parts import parts
from bitlist import bitlist
from fountains import fountains
from unittest import TestCase

from oblivious import *

def api_methods():
    """API symbols that should be available to users upon module import."""
    return {
        'point', 'scalar',
        'scl', 'rnd', 'inv',
        'pnt', 'bas', 'mul', 'add', 'sub'
    }

def none_to_list(x):
    """Used for turning a `None` parameter into the absence of a parameter."""
    return [] if x is None else [x]

def check_or_generate(self, fs, bits):
    if bits is not None:
        self.assertTrue(all(fs)) # Check that all tests succeeded.
    else:
        return bitlist(list(fs)).hex() # Return target bits for this test.

def check_or_generate_operation(self, fun, lengths, bits):
    fs = fountains(
        sum(lengths),
        seed=bytes(0), # This is also the default; explicit for clarity.
        limit=256,
        bits=bits,
        function=fun
    )
    return check_or_generate(self, fs, bits)

def check_rnd(
        self, cls,
        bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    ):
    fun = lambda bs: bitlist([1 if len(cls.rnd()) == 32 else 0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_scl(
        self, cls,
        bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
    ):
    fun = lambda bs: bitlist([1 if cls.scl(bs) is not None else 0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_inv(
        self, cls,
        bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
    ):
    def fun(bs):
        s = cls.scl(bs)
        return cls.inv(s) if s is not None else bytes([0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_pnt(
        self, cls,
        bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
    ):
    fun = lambda bs: cls.pnt(bs)
    return check_or_generate_operation(self, fun, [64], bits)

def check_bas(
        self, cls,
        bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
    ):
    def fun(bs):
        s = cls.scl(bs)
        return cls.bas(s) if s is not None else bytes([0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_mul(
        self, cls,
        bits='2c040004500080008180400080000008a1180020001080080211004000080040'
    ):
    def fun(bs):
        (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
        return\
            cls.mul(s2, cls.bas(s1))\
            if s1 is not None and s2 is not None else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_add(
        self, cls,
        bits='28400040500000008480000020024c00211800080000800002110040ac001044'
    ):
    def fun(bs):
        (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
        return\
            cls.add(cls.bas(s1), cls.bas(s2))\
            if s1 is not None and s2 is not None else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_sub(
        self, cls,
        bits='24210008500080028000000025020c08000001200000800002008002ac081040'
    ):
    def fun(bs):
        (s1, s2) = (cls.scl(bs[:32]), cls.scl(bs[32:]))
        return\
            cls.sub(cls.bas(s1), cls.bas(s2))\
            if s1 is not None and s2 is not None else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_point(
        self, cls,
        bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
    ):
    fun = lambda bs: cls.point(bs)
    return check_or_generate_operation(self, fun, [64], bits)

def check_point_base(
        self, cls,
        bits='00386671840148d05620421002a2110aa800e289010040404cb2101c20e165a0'
    ):
    def fun(bs):
        s = cls.scalar(bs)
        return cls.point.base(s) if s is not None else bytes([0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_point_rmul(
        self, cls,
        bits='2c040004500080008180400080000008a1180020001080080211004000080040'
    ):
    def fun(bs):
        (s1, s2) = (cls.scalar(bs[:32]), cls.scalar(bs[32:]))
        return\
            s1 * cls.point.base(s2)\
            if s1 is not None and s2 is not None else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_point_add(
        self, cls,
        bits='28400040500000008480000020024c00211800080000800002110040ac001044'
    ):
    def fun(bs):
        (s1, s2) = (cls.scalar(bs[:32]), cls.scalar(bs[32:]))
        return\
            cls.point.base(s1) + cls.point.base(s2)\
            if s1 is not None and s2 is not None else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_point_sub(
        self, cls,
        bits='24210008500080028000000025020c08000001200000800002008002ac081040'
    ):
    def fun(bs):
        (s1, s2) = (cls.scalar(bs[:32]), cls.scalar(bs[32:]))
        return\
            cls.point.base(s1) - cls.point.base(s2)\
            if s1 is not None and s2 is not None else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_scalar(
        self, cls,
        bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'
    ):
    fun = lambda bs: bitlist([1 if cls.scalar(bs) is not None else 0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_scalar_rnd(
        self, cls,
        bits='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    ):
    fun = lambda bs: bitlist([1 if len(cls.scalar.random()) == 32 else 0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_scalar_inverse(
        self, cls,
        bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
    ):
    def fun(bs):
        s = cls.scalar(bs)
        return s.inverse() if s is not None else bytes([0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_scalar_inv_op(
        self, cls,
        bits='41c07230000960b274044a0080a8018aa0114380150000028c2700006081e1e1'
    ):
    def fun(bs):
        s = cls.scalar(bs)
        return ~s if s is not None else bytes([0])
    return check_or_generate_operation(self, fun, [32], bits)

class Test_native(TestCase):
    def test_rnd(self, bits=None):
        return check_rnd(self, native, *none_to_list(bits))

    def test_scl(self, bits=None):
        return check_scl(self, native, *none_to_list(bits))

    def test_inv(self, bits=None):
        return check_inv(self, native, *none_to_list(bits))

    def test_pnt(self, bits=None):
        return check_pnt(self, native, *none_to_list(bits))

    def test_bas(self, bits=None):
        return check_bas(self, native, *none_to_list(bits))

    def test_mul(self, bits=None):
        return check_mul(self, native, *none_to_list(bits))

    def test_add(self, bits=None):
        return check_add(self, native, *none_to_list(bits))

    def test_sub(self, bits=None):
        return check_sub(self, native, *none_to_list(bits))

class Test_native_classes(TestCase):
    def test_point(self, bits=None):
        return check_point(self, native, *none_to_list(bits))

    def test_point_base(self, bits=None):
        return check_point_base(self, native, *none_to_list(bits))

    def test_point_rmul(self, bits=None):
        return check_point_rmul(self, native, *none_to_list(bits))

    def test_point_add(self, bits=None):
        return check_point_add(self, native, *none_to_list(bits))

    def test_point_sub(self, bits=None):
        return check_point_sub(self, native, *none_to_list(bits))

    def test_scalar(self, bits=None):
        return check_scalar(self, native, *none_to_list(bits))

    def test_scalar_rnd(self, bits=None):
        return check_scalar_rnd(self, native, *none_to_list(bits))

    def test_scalar_inv(self, bits=None):
        return check_scalar_inverse(self, native, *none_to_list(bits))

    def test_scalar_inv_op(self, bits=None):
        return check_scalar_inv_op(self, native, *none_to_list(bits))

class Test_sodium(TestCase):
    def test_rnd(self, bits=None):
        return check_rnd(self, sodium, *none_to_list(bits))

    def test_scl(self, bits=None):
        return check_scl(self, sodium, *none_to_list(bits))

    def test_inv(self, bits=None):
        return check_inv(self, sodium, *none_to_list(bits))

    def test_pnt(self, bits=None):
        return check_pnt(self, sodium, *none_to_list(bits))

    def test_bas(self, bits=None):
        return check_bas(self, sodium, *none_to_list(bits))

    def test_mul(self, bits=None):
        return check_mul(self, sodium, *none_to_list(bits))

    def test_add(self, bits=None):
        return check_add(self, sodium, *none_to_list(bits))

    def test_sub(self, bits=None):
        return check_sub(self, sodium, *none_to_list(bits))

class Test_sodium_classes(TestCase):
    def test_point(self, bits=None):
        return check_point(self, sodium, *none_to_list(bits))

    def test_point_base(self, bits=None):
        return check_point_base(self, sodium, *none_to_list(bits))

    def test_point_rmul(self, bits=None):
        return check_point_rmul(self, sodium, *none_to_list(bits))

    def test_point_add(self, bits=None):
        return check_point_add(self, sodium, *none_to_list(bits))

    def test_point_sub(self, bits=None):
        return check_point_sub(self, sodium, *none_to_list(bits))

    def test_scalar(self, bits=None):
        return check_scalar(self, sodium, *none_to_list(bits))

    def test_scalar_rnd(self, bits=None):
        return check_scalar_rnd(self, sodium, *none_to_list(bits))

    def test_scalar_inv(self, bits=None):
        return check_scalar_inverse(self, sodium, *none_to_list(bits))

    def test_scalar_inv_op(self, bits=None):
        return check_scalar_inv_op(self, sodium, *none_to_list(bits)) 

class Test_namespace(TestCase):
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

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    test_oblivious = Test_native()
    for m in [m for m in dir(test_oblivious) if m.startswith('test_')]:
        print(m + ': ' + getattr(test_oblivious, m)(bits=None))
