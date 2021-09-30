from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read().replace(".. include:: toc.rst\n\n", "")

# The lines below are parsed by `docs/conf.py`.
name = "oblivious"
version = "4.0.1"

setup(
    name=name,
    version=version,
    packages=[name,],
    install_requires=[
        "parts~=1.1.2",
        "bitlist~=0.5.1",
        "fountains~=1.1.1",
        "fe25519~=1.0.0",
        "ge25519~=1.0.0",
        "six~=1.16.0",
        "cffi~=1.14.6",
        "rbcl~=0.1.3"
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
    test_suite="nose.collector",
    tests_require=["nose"],
)
