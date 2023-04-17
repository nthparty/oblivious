=========
oblivious
=========

Python library that serves as an API for common cryptographic primitives used to implement OPRF, OT, and PSI protocols.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/oblivious.svg
   :target: https://badge.fury.io/py/oblivious
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/oblivious/badge/?version=latest
   :target: https://oblivious.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nthparty/oblivious/workflows/lint-test-cover-docs/badge.svg
   :target: https://github.com/nthparty/oblivious/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/oblivious/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/oblivious?branch=main
   :alt: Coveralls test coverage summary.

Purpose
-------
This library provides pure-Python implementations, Python wrappers for `libsodium <https://github.com/jedisct1/libsodium>`__ and `mcl <https://github.com/herumi/mcl>`__, and additional utility methods for cryptographic primitives that are often used to implement `oblivious pseudorandom function (OPRF) <https://en.wikipedia.org/wiki/Pseudorandom_function_family>`__, `oblivious transfer (OT) <https://en.wikipedia.org/wiki/Oblivious_transfer>`__, and `private set intersection (PSI) <https://en.wikipedia.org/wiki/Private_set_intersection>`__ protocols.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/oblivious>`__::

    python -m pip install oblivious

It is possible to install the library together with packages that bundle dynamic/shared libraries, such as `rbcl <https://pypi.org/project/rbcl>`__ and/or `mclbn256 <https://pypi.org/project/mclbn256>`__ (note that in some environments, the brackets and/or commas may need to be escaped)::

    python -m pip install oblivious[rbcl]
    python -m pip install oblivious[mclbn256]
    python -m pip install oblivious[rbcl,mclbn256]

The library can be imported in the usual ways::

    import oblivious
    from oblivious import ristretto
    from oblivious import bn254

Examples
^^^^^^^^

.. |ristretto| replace:: ``ristretto``
.. _ristretto: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.ristretto.html

This library supports concise construction of elliptic curve points and scalars. The examples below use the |ristretto|_ module that provides data structures for working with the `Ristretto <https://ristretto.group>`__ group::

    >>> from oblivious.ristretto import point, scalar
    >>> p = point.hash('abc'.encode()) # Point derived from a hash of a string.
    >>> s = scalar() # Random scalar.
    >>> t = scalar.from_int(0) # Scalar corresponding to the zero residue.

Built-in Python operators are overloaded to support point operations (such as addition, subtraction, negation, and equality) and scalar operations (such as multiplication by a scalar and inversion of scalars)::

    >>> q = s * p
    >>> p == (~s) * q
    True
    >>> p == ((~s) * s) * p
    True
    >>> p + q == q + p
    True
    >>> t * p == p - p
    True

.. |point| replace:: ``point``
.. _point: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.ristretto.html#oblivious.ristretto.point

.. |scalar| replace:: ``scalar``
.. _scalar: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.ristretto.html#oblivious.ristretto.scalar

.. |bytes| replace:: ``bytes``
.. _bytes: https://docs.python.org/3/library/stdtypes.html#bytes

The |point|_ and |scalar|_ classes have common conversion methods that correspond to those supported by |bytes|_ objects (and in some cases, these classes are themselves derived from |bytes|_)::

    >>> hex = '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'
    >>> s = scalar.from_hex(hex)
    >>> s.hex()
    '35c141f1c2c43543de9d188805a210abca3cd39a1e986304991ceded42b11709'

In addition, Base64 conversion methods are included to support concise encoding and decoding of |point|_ and |scalar|_ objects::

    >>> s.to_base64()
    'NcFB8cLENUPenRiIBaIQq8o805oemGMEmRzt7UKxFwk='
    >>> s == scalar.from_base64('NcFB8cLENUPenRiIBaIQq8o805oemGMEmRzt7UKxFwk=')
    True

For more information and background about the underlying mathematical structures and primitives found in the |ristretto|_ module, consult materials about `Curve25519 <https://cr.yp.to/ecdh.html>`__, the `Ristretto <https://ristretto.group>`__ group, and the related `Ed25519 <https://ed25519.cr.yp.to>`__ system.

Using Pure Python or a Shared/Dynamic Library
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. |python| replace:: ``python``
.. _python: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.ristretto.html#oblivious.ristretto.python

.. |sodium| replace:: ``sodium``
.. _sodium: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.ristretto.html#oblivious.ristretto.sodium

Each module within this library can export two variants of its primitives and data structures: one corresponding to pure-Python implementations and another corresponding to shared/dynamic library wrappers.

For example, the |ristretto|_ module exports two container classes/namespaces: |python|_ and |sodium|_. These encapsulate pure-Python implementations and shared/dynamic library (*i.e.*, libsodium) wrappers, respectively, of all operations and classes available in the |ristretto|_ module. This makes it possible to explicitly choose whether an operation requires only Python or also requires the presence of a compiled copy of libsodium on the host system.

The example below uses pure-Python implementations of the scalar multiplication operation (relying on the `ge25519 <https://pypi.org/project/ge25519>`__ library)::

    >>> from oblivious.ristretto import python
    >>> p = python.point.hash('abc'.encode())
    >>> s = python.scalar.hash('123'.encode())
    >>> (s * p).to_base64()
    'SrC7vA9sSR5f4E27ALxk14MPotTYR6B33B4ZN+mQXFA='

To check whether an instance of the libsodium shared/dynamic library has been loaded successfully, the check below can be performed::

    >>> from oblivious.ristretto import sodium
    >>> sodium is not None # Was the dynamic/shared library loaded?
    True

In the example below, the scalar multiplication operation invokes a binding for the ``crypto_scalarmult_ristretto255`` function `exported by libsodium <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto>`__::

    >>> p = sodium.point.hash('abc'.encode())
    >>> s = sodium.scalar.hash('123'.encode())
    >>> (s * p).to_base64()
    'SrC7vA9sSR5f4E27ALxk14MPotTYR6B33B4ZN+mQXFA='

.. |add| replace:: ``__add__``
.. _add: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.ristretto.html#oblivious.ristretto.point.__add__

The class methods exported by the |ristretto|_ module directly (*e.g.*, the method |add|_ within the class |point|_ that is imported via the statement ``from oblivious.ristretto import point``) correspond either (A) to libsodium wrappers if an instance of libsodium is found and loaded or (B) to pure-Python implementations if all attempts to load a working instances of libsodium fail. The ordered list below summarizes what definitions are exported under various conditions and the ordered sequence of attempts to locate and load an instance of libsodium.

1. Under all conditions, the wrapper class |python|_ is defined and encapsulates a pure-Python variant of every low-level operation and class available in the |ristretto|_ module. **As a starting default**, all classes exported directly by the |ristretto|_ module correspond to the pure-Python implementations.

2. If a shared/dynamic library instance of libsodium is found on the system and successfully loaded during one of the attempts below, then the wrapper class |sodium|_ is defined:

   a. the built-in ``ctypes.util.find_library`` function is able to locate ``'sodium'`` or ``'libsodium'`` and it is loaded successfully;
   b. a file ``libsodium.so`` or ``libsodium.dll`` under the paths specified by the ``PATH`` and ``LD_LIBRARY_PATH`` environment variables is found and loaded successfully; or
   c. the optional `rbcl <https://pypi.org/project/rbcl>`__ package is installed and the compiled subset of libsodium included in that package is loaded successfully.

3. If ``sodium`` is **not** ``None``, then the |sodium|_ class encapsulates libsodium wrappers for low-level operations and for every class exported by the |ristretto|_ module. Furthermore, **those classes exported directly by the library are redefined** to use the bindings available in the loaded instance of libsodium. The |python|_ class is still exported, as well, and all operations and class methods encapsulated within |python|_ remain as-is (*i.e.*, pure-Python implementations).

.. |bn254| replace:: ``bn254``
.. _bn254: https://oblivious.readthedocs.io/en/7.0.0/_source/oblivious.bn254.html

The classes within the |bn254|_ module (both those that are pure-Python implementations and those that are wrappers for functions in the `mcl <https://github.com/herumi/mcl>`__ library) are organized in a similar manner. More information is available in the documentation for the |bn254|_ module.

Development
-----------
All installation and development dependencies are fully specified in ``pyproject.toml``. The ``project.optional-dependencies`` object is used to `specify optional requirements <https://peps.python.org/pep-0621>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__::

    python -m pip install .[docs,lint]

Documentation
^^^^^^^^^^^^^
The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__::

    python -m pip install .[docs]
    cd docs
    sphinx-apidoc -f -e -E --templatedir=_templates -o _source .. && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see the ``pyproject.toml`` file for configuration details, and note that unit tests that require `rbcl <https://pypi.org/project/rbcl>`__ and/or `mclbn256 <https://pypi.org/project/mclbn256>`__ are skipped if the corresponding optional package is not installed)::

    python -m pip install .[test]
    python -m pytest

Concise unit tests are implemented with the help of `fountains <https://pypi.org/project/fountains>`__; new reference specifications for the tests in a given testing module can be generated by running that testing module directly::

    python test/test_ristretto.py
    python test/test_bn254.py

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__::

    python -m pip install .[lint]
    python -m pylint src/oblivious test/test_ristretto.py test/test_bn254.py

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/oblivious>`__ for this library.

Versioning
^^^^^^^^^^
Beginning with version 0.1.0, the version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/oblivious>`__ by a package maintainer. First, install the dependencies required for packaging and publishing::

    python -m pip install .[publish]

Ensure that the correct version number appears in ``pyproject.toml``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions. Create and push a tag for this version (replacing ``?.?.?`` with the version number)::

    git tag ?.?.?
    git push origin ?.?.?

Remove any old build/distribution files. Then, package the source into a distribution archive::

    rm -rf build dist src/*.egg-info
    python -m build --sdist --wheel .

Finally, upload the package distribution archive to `PyPI <https://pypi.org>`__::

    python -m twine upload dist/*
