from setuptools import setup

with open('README.rst', 'r') as fh:
    long_description = fh.read().replace('.. include:: toc.rst\n\n', '')

# The lines below are parsed by `docs/conf.py`.
name = 'oblivious'
version = '6.0.0'

setup(
    name=name,
    version=version,
    packages=[name,],
    install_requires=[
        'parts~=1.3',
        'bitlist~=0.7',
        'fe25519~=1.2',
        'ge25519~=1.2',
        'bn254~=0.1'
    ],
    extras_require={
        'rbcl': [
            'six~=1.16',
            'cffi~=1.15',
            'rbcl~=0.2'
        ],
        'mcl': [
            # Look Dad, no CFFI!
            'mclbn256~=0.7'
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
    },
    license='MIT',
    url='https://github.com/nthparty/oblivious',
    author='Andrei Lapets',
    author_email='a@lapets.io',
    description='Python library that serves as an API for common ' + \
                'cryptographic primitives used to implement OPRF, OT, ' + \
                'and PSI protocols.',
    long_description=long_description,
    long_description_content_type='text/x-rst',
)
