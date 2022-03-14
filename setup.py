"""
Setup, package, and build file for the oblivious cryptography library.
"""
from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read().replace(".. include:: toc.rst\n\n", "")

# The lines below are parsed by `docs/conf.py`.
name = "oblivious"
version = "5.0.0"

setup(
    name=name,
    version=version,
    packages=[name,],
    install_requires=[
        "parts~=1.3",
        "bitlist~=0.7",
        "fountains~=1.3",
        "fe25519~=1.2",
        "ge25519~=1.2",
        "six~=1.16",
        "cffi~=1.15",
        "rbcl~=0.2"
    ],
    license="MIT",
    url="https://github.com/nthparty/oblivious",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Python library that serves as an API for common "+\
                "cryptographic primitives used to implement OPRF, OT, "+\
                "and PSI protocols.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
)
