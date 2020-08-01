from parts import parts
from bitlist import bitlist
from fountains import fountains
from unittest import TestCase

from oblivious import *

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

class Test_oblivious(TestCase):
    def test_scalar(self, bits='4df8fe738c097afa7f255b10c3ab118eeb73e38935605042ccb7581c73f1e5e9'):
        def fun(bs):
            return bitlist([1 if scalar(bs) else 0])
        return check_or_generate_operation(self, fun, [32], bits)

    def test_base(self, bits='080874618c0878927620101043a31002e840818101204000401210101261c120'):
        def fun(bs):
            return base(bs) if scalar(bs) else bytes([0])
        return check_or_generate_operation(self, fun, [32], bits)

    def test_mul(self, bits='28c5004000000100850000002102088891100000000081080810004280080004'):
        def fun(bs):
            (bs1, bs2) = parts(bs, length=32)
            return mul(bs1, base(bs2)) if scalar(bs1) and scalar(bs2) else bytes([0])
        return check_or_generate_operation(self, fun, [32, 32], bits)

    def test_add(self, bits='0844000040000002818040008400000031080028000081080801000204081800'):
        def fun(bs):
            (bs1, bs2) = parts(bs, length=32)
            return add(base(bs1), base(bs2)) if scalar(bs1) and scalar(bs2) else bytes([0])
        return check_or_generate_operation(self, fun, [32, 32], bits)

    def test_sub(self, bits='002400041000800280800000a5024408111000800000810000008040a0081040'):
        def fun(bs):
            (bs1, bs2) = parts(bs, length=32)
            return sub(base(bs1), base(bs2)) if scalar(bs1) and scalar(bs2) else bytes([0])
        return check_or_generate_operation(self, fun, [32, 32], bits)

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    test_oblivious = Test_oblivious()
    for m in [m for m in dir(test_oblivious) if m.startswith('test_')]:
        print(m + ': ' + getattr(test_oblivious, m)(bits=None))
