Installation
============

Requirements
------------

* Python_ (2.7, 3.3, 3.4 or 3.5)
* Cryptography_ (1.2)
* Django_ (1.8 or 1.9)

.. code-block:: console

   pip install django-cryptography

Add :data:`'django_cryptography'` to your :const:`INSTALLED_APPS`.

.. code-block:: python

   INSTALLED_APPS = [
       ...
       'django_cryptography',
   ]

.. _Cryptography: https://cryptography.io/
.. _Django: https://www.djangoproject.com/
.. _Python: https://www.python.org/
