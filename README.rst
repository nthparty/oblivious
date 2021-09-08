=========
oblivious
=========

Python library that serves as an API for common primitives used to implement OPRF, OT, and PSI protocols.

|pypi| |travis| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/oblivious.svg
   :target: https://badge.fury.io/py/oblivious
   :alt: PyPI version and link.

.. |travis| image:: https://travis-ci.com/nthparty/oblivious.svg?branch=main
   :target: https://travis-ci.com/nthparty/oblivious

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/oblivious/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/oblivious?branch=main

Purpose
-------
This library provides native Python implementations, Python `libsodium <https://github.com/jedisct1/libsodium>`_ wrappers, and additional utility methods for cryptographic primitives that are often used to implement `oblivious pseudorandom function (OPRF) <https://en.wikipedia.org/wiki/Pseudorandom_function_family>`_, `oblivious transfer (OT) <https://en.wikipedia.org/wiki/Oblivious_transfer>`_, and `private set intersection (PSI) <https://en.wikipedia.org/wiki/Private_set_intersection>`_ protocols.

For more information and background about the underlying mathematical structures and primitives, consult materials about `Curve25519 <https://cr.yp.to/ecdh.html>, the `Ristretto <https://ristretto.group/>`_ group, and the related `Ed25519 <https://ed25519.cr.yp.to/>`_ system.

Package Installation and Usage
------------------------------
The package is available on PyPI::

    python -m pip install oblivious

The library can be imported in the usual ways::

    import oblivious
    from oblivious import *

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configuration details)::

    nosetests

Concise unit tests are implemented with the help of `fountains <https://pypi.org/project/fountains/>`_ and new reference bit lists for these tests can be generated in the following way::

    python test/test_oblivious.py

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    pylint oblivious test/test_oblivious

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the GitHub page for this library.

Versioning
----------
Beginning with version 0.1.0, the version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.
