=========
oblivious
=========

Python library that serves as an API for common primitives used to implement OPRF, OT, and PSI protocols.

|pypi| |readthedocs| |travis| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/oblivious.svg
   :target: https://badge.fury.io/py/oblivious
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/oblivious/badge/?version=latest
   :target: https://oblivious.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |travis| image:: https://app.travis-ci.com/nthparty/oblivious.svg?branch=main
   :target: https://app.travis-ci.com/nthparty/oblivious
   :alt: Travis CI build status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/oblivious/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/oblivious?branch=main
   :alt: Coveralls test coverage summary.

Purpose
-------
This library provides native Python implementations, Python `libsodium <https://github.com/jedisct1/libsodium>`_ wrappers, and additional utility methods for cryptographic primitives that are often used to implement `oblivious pseudorandom function (OPRF) <https://en.wikipedia.org/wiki/Pseudorandom_function_family>`_, `oblivious transfer (OT) <https://en.wikipedia.org/wiki/Oblivious_transfer>`_, and `private set intersection (PSI) <https://en.wikipedia.org/wiki/Private_set_intersection>`_ protocols.

For more information and background about the underlying mathematical structures and primitives, consult materials about `Curve25519 <https://cr.yp.to/ecdh.html>`_, the `Ristretto <https://ristretto.group/>`_ group, and the related `Ed25519 <https://ed25519.cr.yp.to/>`_ system.

Package Installation and Usage
------------------------------
The package is available on `PyPI <https://pypi.org/project/oblivious/>`_::

    python -m pip install oblivious

The library can be imported in the usual ways::

    import oblivious
    from oblivious import *

Examples
^^^^^^^^
This library supports concise construction of elliptic curve points and scalars::

    >>> from oblivious import point, scalar
    >>> p = point.hash('abc'.encode()) # Point derived from a hash of a string.
    >>> s = scalar() # Random scalar.

Built-in Python operators are overloaded to support point operations (addition, subtraction, negation, and equality) and scalar operations (multiplication by a scalar and inversion of scalars)::

    >>> q = s * p
    >>> p == (~s) * q
    True
    >>> p == (((~s) * s)) * p
    True
    >>> p + q == q + p
    True

Because the classes ``point`` and ``scalar`` are derived from ``bytes``, `all methods and other operators <https://docs.python.org/3/library/stdtypes.html#bytes>`_ supported by ``bytes`` objects are supported by ``point`` and ``scalar`` objects:

    >>> hex = '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
    >>> s = scalar.fromhex(hex)
    >>> s.hex()
    '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'

In addition, Base64 conversion methods are included to support concise encoding and decoding of ``point`` and ``scalar`` objects.

    >>> s.to_base64()
    'NcFB8cLENUPenRiIBaIQq8o805oemGMEmRzt7UKxFwk='
    >>> s == scalar.from_base64('NcFB8cLENUPenRiIBaIQq8o805oemGMEmRzt7UKxFwk=')
    True

Using Native Python or Shared/Dynamic Library
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In addition to the operations and classes exported by this library, two wrapper classes/namespaces are also exported: ``native`` and ``sodium``. These encapsulate pure Python implementations and shared/dynamic library (*i.e.*, libsodium) wrappers, respectively, of all operations and classes available in the ``oblivious`` module. This makes it possible to explicitly choose whether an operation requires only Python or also requires the presence of a compiled copy of libsodium on the host system.

The example below uses native Python implementations of the scalar multiplication operation (relying on the `ge25519 <https://pypi.org/project/ge25519>`_ library)::

    >>> from oblivious import native
    >>> p = native.point.hash('abc'.encode())
    >>> s = native.scalar.hash('123'.encode())
    >>> (s * p).to_base64()
    'SrC7vA9sSR5f4E27ALxk14MPotTYR6B33B4ZN+mQXFA='

To check whether an instance of the libsodium shared/dynamic library has been loaded successfully, the check below can be performed::

    >>> from oblivious import sodium
    >>> sodium is not None # Was the dynamic/shared library loaded?
    True

In the example below, the scalar multiplication operation invokes a binding for the ``crypto_scalarmult_ristretto255`` function `exported by libsodium <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto>`_::

    >>> p = sodium.point.hash('abc'.encode())
    >>> s = sodium.scalar.hash('123'.encode())
    >>> (s * p).to_base64()
    'SrC7vA9sSR5f4E27ALxk14MPotTYR6B33B4ZN+mQXFA='

The operations and class methods exported by the ``oblivious`` module directly (*e.g.*, the method ``__add__`` within the class ``point`` that is imported via the statement ``from oblivious import point``) correspond either (A) to libsodium wrappers if an instance of libsodium is found and loaded or (B) to pure Python implementations if all attempts to load a working instances of libsodium fail. The ordered list below summarizes what definitions are exported under various conditions and the ordered sequence of attempts to locate and load an instance of libsodium.

1. Under all conditions, the wrapper class ``native`` is defined and encapsulates a pure Python variant of every operation and class method available in the ``oblivious`` module. **As a starting default**, all operations and classes exported directly by the ``oblivious`` module correspond to the pure Python implementations.

2. If a shared/dynamic library instance of  libsodium is found on the system and successfully loaded during one of the attempts below, then the wrapper class ``sodium`` is defined:
  
  a. the built-in ``ctypes.util.find_library`` function is able to locate ``'sodium'`` or ``'libsodium'`` and it is loaded successfully;
  b. a file ``libsodium.so`` or ``libsodium.dll`` in the paths specified by the ``PATH`` and ``LD_LIBRARY_PATH`` environment variables is found and loaded successfully; or
  c. the compiled subset of libsodium included in the `rbcl <https://pypi.org/project/rbcl/>`_ package is loaded successfully.

3. If ``sodium`` is **not** ``None``, then the ``sodium`` class encapsulates libsodium wrappers for every operation and class supported by the ``oblivious`` module. Furthermore, **those operations and classes exported directly by the library are redefined** to use the bindings available in the loaded instance of libsodium. The ``native`` class is still exported, as well, and all operations and class methods encapsulated within ``native`` remain as-is (*i.e.*, pure Python implementations).

Documentation
-------------
.. include:: toc.rst

The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    cd docs
    python -m pip install -r requirements.txt
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../setup.py && make html

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configuration details)::

    python -m pip install nose coverage
    nosetests

Concise unit tests are implemented with the help of `fountains <https://pypi.org/project/fountains/>`_; new reference specifications for these tests can be generated by running the testing module directly::

    python test/test_oblivious.py

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    python -m pip install pylint
    pylint oblivious test/test_oblivious

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/oblivious>`_ for this library.

Versioning
----------
Beginning with version 0.1.0, the version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.
