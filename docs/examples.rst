Cryptography by example
=======================

Using symmetrical encryption to store sensitive data in the database.
Wrap the desired model field with :function:`encrypt` to easily
protect its contents.

.. code-block:: python

   from django.db import models

   from django_cryptography.fields import encrypt


   class MyModel(models.Model):
       name = models.CharField(max_length=50)
       sensitive_data = encrypt(models.CharField(max_length=50))

The data will now be automatically encrypted when saved to the
database. :function:`encrypt` uses an encryption that allows for
bi-directional data retrieval.
