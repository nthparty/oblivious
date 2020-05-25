from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="oblivious",
    version="0.0.1.0",
    packages=["oblivious",],
    install_requires=["fe25519","ge25519",],
    license="MIT",
    url="https://github.com/nthparty/oblivious",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Python library that serves as an API for common "+\
                "primitives used to implement OPRF and OT protocols.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)
