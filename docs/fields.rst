Fields
======

``EncryptedField``
------------------

.. class:: EncryptedField(base_field, **options)

   A field for storing encrypted data

   .. attribute:: base_field

      This is a required argument.

      Specifies the underlying data type to be encrypted. It should be an
      instance of a subclass of
      :class:`~django.db.models.Field`. For example, it could be an
      :class:`~django.db.models.IntegerField` or a
      :class:`~django.db.models.CharField`. Most field types are
      permitted, with the exception of those handling relational data
      (:class:`~django.db.models.ForeignKey`,
      :class:`~django.db.models.OneToOneField` and
      :class:`~django.db.models.ManyToManyField`).

      Transformation of values between the database and the model,
      validation of data and configuration, and serialization are all
      delegated to the underlying base field.

   .. attribute:: key

      This is an optional argument.

      Allows for specifying an instance specific encryption key.

   .. attribute:: ttl

      This is an optional argument.

      The amount of time in seconds that a value can be stored for. If the
      :attr:`~ttl` of the data has passed it will become unreadable.
      Instead returning an :class:`~Expired` object.


Constants
---------

.. class:: Expired()

   Represents an expired encryption value.
