Django Cryptography
===================

A Django wrapper for the Python Cryptography_ library. Providing a
drop in replacement for Django's own cryptographic primitives.

More information available in the documentation_.

Requirements
------------

* Python_ (2.7, 3.2, 3.3, 3.4, or 3.5)
* Cryptography_
* Django_ (1.8, 1.9)

Installation
------------

Add ``'django_cryptography'`` to your ``INSTALLED_APPS``.

.. code-block:: python

   INSTALLED_APPS = [
       ...
       'django_cryptography',
   ]

.. _Cryptography: https://cryptography.io/
.. _Django: https://www.djangoproject.com/
.. _Python: https://www.python.org/
.. _documentation: https://django-cryptography.readthedocs.org/en/latest/
