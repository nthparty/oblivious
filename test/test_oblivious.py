from importlib import import_module
from parts import parts
from bitlist import bitlist
from fountains import fountains
from unittest import TestCase

from oblivious import *

def api_methods():
    """API symbols that should be available to users upon module import."""
    return {
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
    fun = lambda bs: bitlist([1 if cls.scl(bs) else 0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_inv(
        self, cls,
        bits='74b7b5f914b56330255405678cad0c89aba783133e447b58b227c0e741bb0905'
    ):
    fun = lambda bs: cls.inv(bs)
    return check_or_generate_operation(self, fun, [32], bits)

def check_pnt(
        self, cls,
        bits='baf12de24e54deae0aa116816bf5eee23b1168c78e892372e08a9884de9d4c1b'
    ):
    fun = lambda bs: cls.pnt(bs)
    return check_or_generate_operation(self, fun, [64], bits)

def check_bas(
        self, cls,
        bits='080874618c0878927620101043a31002e840818101204000401210101261c120'
    ):
    fun = lambda bs: cls.bas(bs) if cls.scl(bs) else bytes([0])
    return check_or_generate_operation(self, fun, [32], bits)

def check_mul(
        self, cls,
        bits='28c5004000000100850000002102088891100000000081080810004280080004'
    ):
    def fun(bs):
        (bs1, bs2) = parts(bs, length=32)
        return\
            cls.mul(bs1, cls.bas(bs2))\
            if cls.scl(bs1) and cls.scl(bs2) else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_add(
        self, cls,
        bits='0844000040000002818040008400000031080028000081080801000204081800'
    ):
    def fun(bs):
        (bs1, bs2) = parts(bs, length=32)
        return\
            cls.add(cls.bas(bs1), cls.bas(bs2))\
            if cls.scl(bs1) and cls.scl(bs2) else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

def check_sub(
        self, cls,
        bits='002400041000800280800000a5024408111000800000810000008040a0081040'
    ):
    def fun(bs):
        (bs1, bs2) = parts(bs, length=32)
        return\
            cls.sub(cls.bas(bs1), cls.bas(bs2))\
            if cls.scl(bs1) and cls.scl(bs2) else\
            bytes([0])
    return check_or_generate_operation(self, fun, [32, 32], bits)

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
