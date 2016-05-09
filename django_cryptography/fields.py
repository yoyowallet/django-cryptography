from base64 import b64decode, b64encode

from django.core import checks
from django.db import models
from django.utils import six
from django.utils.encoding import force_bytes
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


class EncryptedField(PickledField):
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

    def __init__(self, base_field, **kwargs):
        # type: (models.Field, ...) -> None
        key = kwargs.pop('key', None)
        ttl = kwargs.pop('ttl', None)

        self._fernet = FernetBytes(key)
        self.ttl = ttl
        self.base_field = base_field
        super(PickledField, self).__init__(**kwargs)

    @property
    def description(self):
        return _('Encrypted %s') % self.base_field.description

    @property
    def model(self):
        try:
            return self.__dict__['model']
        except KeyError:
            raise AttributeError("'%s' object has no attribute 'model'" %
                                 self.__class__.__name__)

    @model.setter
    def model(self, model):
        self.__dict__['model'] = model
        self.base_field.model = model

    def _dump(self, value):
        return self._fernet.encrypt(
            super(EncryptedField, self)._dump(value)
        )

    def _load(self, value):
        try:
            return super(EncryptedField, self)._load(
                self._fernet.decrypt(value, self.ttl)
            )
        except SignatureExpired:
            return Expired

    def check(self, **kwargs):
        errors = super(EncryptedField, self).check(**kwargs)
        if getattr(self.base_field, 'remote_field', self.base_field.rel):
            errors.append(
                checks.Error(
                    'Base field for encrypted cannot be a related field.',
                    hint=None,
                    obj=self,
                    id='encrypted.E002'
                )
            )
        else:
            # Remove the field name checks as they are not needed here.
            base_errors = self.base_field.check()
            if base_errors:
                messages = '\n    '.join('%s (%s)' % (error.msg, error.id) for error in base_errors)
                errors.append(
                    checks.Error(
                        'Base field for encrypted has errors:\n    %s' % messages,
                        hint=None,
                        obj=self,
                        id='encrypted.E001'
                    )
                )
        return errors

    def deconstruct(self):
        name, path, args, kwargs = super(PickledField, self).deconstruct()
        kwargs['base_field'] = self.base_field
        if self.ttl is not None:
            kwargs['ttl'] = self.ttl
        return name, path, args, kwargs

    def run_validators(self, value):
        super(EncryptedField, self).run_validators(value)
        self.base_field.run_validators(value)

    def validate(self, value, model_instance):
        self.base_field.validate(value, model_instance)

    def set_attributes_from_name(self, name):
        super(EncryptedField, self).set_attributes_from_name(name)
        self.base_field.set_attributes_from_name(name)

    def pre_save(self, model_instance, add):
        return self.base_field.pre_save(model_instance, add)

    def value_to_string(self, obj):
        return self.base_field.value_to_string(obj)

    def to_python(self, value):
        return self.base_field.to_python(value)

    def formfield(self, **kwargs):
        return self.base_field.formfield(**kwargs)
