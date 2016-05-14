Django Cryptography
===================

A set of primitives for easily encrypting data in Django, wrapping
the Python Cryptography_ library. Also provided is a drop in
replacement for Django's own cryptographic primitives, using
Cryptography_ as the backend provider.

Do not forget to read the documentation_.

.. image:: https://img.shields.io/travis/georgemarshall/django-cryptography.svg
   :target: https://travis-ci.org/georgemarshall/django-cryptography
.. image:: https://img.shields.io/codecov/c/github/georgemarshall/django-cryptography.svg
   :target: https://codecov.io/github/georgemarshall/django-cryptography
.. image:: https://www.quantifiedcode.com/api/v1/project/ceb16c3d35264fd0a1be165af1456d4e/badge.svg
   :target: https://www.quantifiedcode.com/app/project/ceb16c3d35264fd0a1be165af1456d4e
   :alt: Code issues

Cryptography by example
-----------------------

Using symmetrical encryption to store sensitive data in the database.
Wrap the desired model field with ``EncryptedField`` to easily
protect its contents.

.. code-block:: python

   from django.db import models

   from django_cryptography.fields import EncryptedField


   class MyModel(models.Model):
       name = models.CharField(max_length=50)
       sensitive_data = EncryptedField(models.CharField(max_length=50))

The data will now be automatically encrypted when saved to the
database. Since ``EncryptedField`` uses symmetrical encryption, this
allows for bi-directional data retrieval.

Requirements
------------

* Python_ (2.7, 3.3, 3.4 or 3.5)
* Cryptography_ (1.3)
* Django_ (1.8 or 1.9)

Installation
------------

.. code-block:: console

   pip install django-cryptography

.. _Cryptography: https://cryptography.io/
.. _Django: https://www.djangoproject.com/
.. _Python: https://www.python.org/
.. _documentation: https://django-cryptography.readthedocs.org/en/latest/
