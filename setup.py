import sys
from setuptools import setup

requirements = {
    'install': [
        'parts~=1.3',
        'bitlist~=0.7',
        'fe25519~=1.2',
        'ge25519~=1.2',
        'bn254~=0.1'
    ],
    'docs': [
        'sphinx~=4.2.0',
        'sphinx-rtd-theme~=1.0.0'
    ],
    'test': [
        'fountains~=1.3',
        'pytest~=7.0',
        'pytest-cov~=3.0'
    ],
    'lint': [
        'pylint~=2.14.0'
    ],
    'coveralls': [
        'coveralls~=3.3.1'
    ],
    'publish': [
        'setuptools~=62.0',
        'wheel~=0.37',
        'twine~=4.0'
    ]
}

# Emit a ``requirements.txt`` file based on the supplied options.
if len(sys.argv) > 1 and 'requirements' in sys.argv:
    with open('requirements.txt', 'w') as file:
        file.write('\n'.join([
            requirement
            for option in sys.argv[sys.argv.index('requirements') + 1:]
            for requirement in requirements.get(option, [])
        ]) + '\n')
    exit()

with open("README.rst", "r") as fh:
    long_description = fh.read().replace(".. include:: toc.rst\n\n", "")

# The lines below are parsed by `docs/conf.py`.
name = "oblivious"
version = "6.0.0"

setup(
    name=name,
    version=version,
    packages=[name,],
    install_requires=requirements['install'],
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
