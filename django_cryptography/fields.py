import sys
from base64 import b64decode, b64encode

from django.core import checks
from django.db import models
from django.utils import six
from django.utils.encoding import force_bytes, force_text
from django.utils.translation import ugettext_lazy as _

from django_cryptography.core.signing import SignatureExpired
from django_cryptography.utils.crypto import FernetBytes

try:
    from django.utils.six.moves import cPickle as pickle
except ImportError:
    import pickle

Expired = object()
"""Represents an expired encryption value."""


class PickledField(models.Field):
    """
    A field for storing pickled objects
    """
    description = _("Pickled data")
    empty_values = [None, b'']
    supported_lookups = ('exact', 'in', 'isnull')

    def __init__(self, *args, **kwargs):
        kwargs['editable'] = False
        super(PickledField, self).__init__(*args, **kwargs)

    def _dump(self, value):
        return pickle.dumps(value)

    def _load(self, value):
        return pickle.loads(value)

    def deconstruct(self):
        name, path, args, kwargs = super(PickledField, self).deconstruct()
        del kwargs['editable']
        return name, path, args, kwargs

    def get_internal_type(self):
        return "BinaryField"

    def get_default(self):
        default = super(PickledField, self).get_default()
        if default == '':
            return b''
        return default

    def get_lookup(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(PickledField, self).get_lookup(lookup_name)

    def get_transform(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(PickledField, self).get_transform(lookup_name)

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super(PickledField, self).get_db_prep_value(value, connection, prepared)
        if value is not None:
            return connection.Database.Binary(self._dump(value))
        return value

    def from_db_value(self, value, expression, connection, context):
        if value is not None:
            return self._load(force_bytes(value))
        return value

    def value_to_string(self, obj):
        """Pickled data is serialized as base64"""
        value = self.value_from_object(obj)
        return b64encode(self._dump(value)).decode('ascii')

    def to_python(self, value):
        # If it's a string, it should be base64-encoded data
        if isinstance(value, six.text_type):
            return self._load(b64decode(force_bytes(value)))
        return value


class EncryptedField(models.Field):
    """
    A field for storing encrypted data

    :param base_field: This is a required argument.

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
    :type base_field: ~django.db.models.fields.Field
    :param bytes key: This is an optional argument.

        Allows for specifying an instance specific encryption key.
    :param int ttl: This is an optional argument.

        The amount of time in seconds that a value can be stored for. If the
        time to live of the data has passed, it will become unreadable.
        The expired value will return an :class:`Expired` object.
    """
    supported_lookups = ('isnull',)

    def __init__(self, *args, **kwargs):
        key = kwargs.pop('key', None)
        ttl = kwargs.pop('ttl', None)

        self._fernet = FernetBytes(key)
        self.ttl = ttl
        super(self.__class__, self).__init__(*args, **kwargs)

    @property
    def description(self):
        return _('Encrypted %s') % super(self.__class__, self).description

    def _dump(self, value):
        return self._fernet.encrypt(
            pickle.dumps(value)
        )

    def _load(self, value):
        try:
            return pickle.loads(
                self._fernet.decrypt(value, self.ttl)
            )
        except SignatureExpired:
            return Expired

    def check(self, **kwargs):
        errors = super(self.__class__, self).check(**kwargs)
        if getattr(self, 'remote_field', self.rel):
            errors.append(
                checks.Error(
                    'Base field for encrypted cannot be a related field.',
                    hint=None,
                    obj=self,
                    id='encrypted.E002'
                )
            )
        return errors

    def deconstruct(self):
        name, path, args, kwargs = super(self.__class__, self).deconstruct()
        base_field = six.next((base for base in self.__class__.__bases__
                               if issubclass(base, models.Field)))
        name = force_text(self.name, strings_only=True)
        path = "%s.%s" % (encrypt.__module__, encrypt.__name__)
        args = [base_field(*args, **kwargs)]
        kwargs = {}
        if self.ttl is not None:
            kwargs['ttl'] = self.ttl
        return name, path, args, kwargs

    def get_lookup(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(self.__class__, self).get_lookup(lookup_name)

    def get_transform(self, lookup_name):
        if lookup_name not in self.supported_lookups:
            return
        return super(self.__class__, self).get_transform(lookup_name)

    def get_internal_type(self):
        return "BinaryField"

    def get_db_prep_value(self, value, connection, prepared=False):
        value = models.Field.get_db_prep_value(self, value, connection, prepared)
        if value is not None:
            return connection.Database.Binary(self._dump(value))
        return value

    get_db_prep_save = models.Field.get_db_prep_save

    def from_db_value(self, value, expression, connection, context):
        if value is not None:
            return self._load(force_bytes(value))
        return value


def get_encrypted_field(base_field):
    """
    A get or create method for encrypted fields, we cache the field in
    the module to avoid recreation. This also allows us to always return
    the same class reference for a field.

    :type base_field: ~django.db.models.fields.Field
    :rtype: EncryptedField
    """
    assert not isinstance(base_field, models.Field)
    field_name = 'Encrypted' + base_field.__name__
    if not hasattr(sys.modules[__name__], field_name):
        setattr(sys.modules[__name__], field_name, type(EncryptedField)(
            field_name, (base_field,), dict(EncryptedField.__dict__)
        ))
    return getattr(sys.modules[__name__], field_name)


def encrypt(base_field, key=None, ttl=None):
    """
    A decorator for creating encrypted model fields.

    :type base_field: ~django.db.models.fields.Field
    :param bytes key: This is an optional argument.

        Allows for specifying an instance specific encryption key.
    :param int ttl: This is an optional argument.

        The amount of time in seconds that a value can be stored for. If the
        time to live of the data has passed, it will become unreadable.
        The expired value will return an :class:`Expired` object.
    :rtype: EncryptedField
    """
    if not isinstance(base_field, models.Field):
        assert key is None
        assert ttl is None
        return get_encrypted_field(base_field)

    base_class = base_field.__class__
    name, path, args, kwargs = base_field.deconstruct()
    kwargs.update({'key': key, 'ttl': ttl})
    return get_encrypted_field(base_class)(*args, **kwargs)
