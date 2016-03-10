Settings
========

CRYPTOGRAPHY_BACKEND
--------------------

Default: :py:func:`cryptography.hazmat.backends.default_backend`

CRYPTOGRAPHY_DIGEST
-------------------

Default: :py:class:`cryptography.hazmat.primitives.hashes.SHA256`

The digest algorithm to use for signing and key generation.

CRYPTOGRAPHY_KEY
----------------

Default: :py:obj:`None`

When value is :py:obj:`None` a key will be derived from
``SECRET_KEY``. Otherwise the value will be used for the key.

CRYPTOGRAPHY_SALT
-----------------

Default: ``'django-cryptography'``
