=========
oblivious
=========

Python library that serves as an API for common primitives used to implement OPRF and OT protocols.

.. image:: https://badge.fury.io/py/oblivious.svg
   :target: https://badge.fury.io/py/oblivious
   :alt: PyPI version and link.

Purpose
-------
This library provides native Python definitions and Python `libsodium <https://github.com/jedisct1/libsodium>`_ wrappers for cryptographic primitives that are often used to implement `oblivious pseudorandom function (OPRF) <https://en.wikipedia.org/wiki/Pseudorandom_function_family>`_ and `oblivious transfer (OT) <https://en.wikipedia.org/wiki/Oblivious_transfer>`_ protocols.

For more information on the underlying mathematical structures and primitives, consult materials about the `Ed25519 <https://ed25519.cr.yp.to/>`_ system and the `Ristretto <https://ristretto.group/>`_ group.

Package Installation and Usage
------------------------------
The package is available on PyPI::

    python -m pip install oblivious

The library can be imported in the usual ways::

    import oblivious
    from oblivious import *

Conventions
-----------
Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    pylint oblivious
