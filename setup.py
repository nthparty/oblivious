from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

# The lines below are parsed by `docs/conf.py`.
name = "oblivious"
version = "4.0.0"

setup(
    name=name,
    version=version,
    packages=[name,],
    install_requires=[
        "fe25519~=0.2.0",
        "ge25519~=0.2.0",
        "parts~=1.0.3",
        "bitlist~=0.4.0",
        "fountains~=0.2.1",
        "cffi~=1.14.6",
        "six~=1.16.0",
        "rbcl~=0.1.3",
    ],
    license="MIT",
    url="https://github.com/nthparty/oblivious",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Python library that serves as an API for common "+\
                "primitives used to implement OPRF, OT, and PSI protocols.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)
