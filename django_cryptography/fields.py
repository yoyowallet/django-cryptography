from django.core import checks
from django.db import models
from django.utils import six
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
    description = _("Pickled data")
    empty_values = [None, b'']

    def __init__(self, *args, **kwargs):
        kwargs['editable'] = False
        super(PickledField, self).__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(PickledField, self).deconstruct()
        del kwargs['editable']
        return name, path, args, kwargs

    def get_internal_type(self):
        return "BinaryField"

    def get_default(self):
        if self.has_default() and not callable(self.default):
            return self.default
        default = super(PickledField, self).get_default()
        if default == '':
            return b''
        return default

    def validate(self, value, model_instance):
        pass

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super(PickledField, self).get_db_prep_value(value, connection, prepared)
        if value is not None:
            value = pickle.dumps(value)
            return connection.Database.Binary(value)
        return value

    def from_db_value(self, value, expression, connection, context):
        return self.to_python(value)

    def to_python(self, value):
        if isinstance(value, six.binary_type):
            return pickle.loads(value)
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

    @property
    def description(self):
        return _('Encrypted %s') % self.base_field.description

    def __init__(self, base_field, **kwargs):
        # type: (models.Field, ...) -> None
        key = kwargs.pop('key', None)
        ttl = kwargs.pop('ttl', None)

        self._fernet = FernetBytes(key)
        self._ttl = ttl
        self.base_field = base_field
        super(EncryptedField, self).__init__(**kwargs)

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
        name, path, args, kwargs = super(EncryptedField, self).deconstruct()
        kwargs.update({
            'base_field': self.base_field,
        })
        return name, path, args, kwargs

    def run_validators(self, value):
        super(EncryptedField, self).run_validators(value)
        self.base_field.run_validators(value)

    def validate(self, value, model_instance):
        super(EncryptedField, self).validate(value, model_instance)
        self.base_field.validate(value, model_instance)

    def set_attributes_from_name(self, name):
        super(EncryptedField, self).set_attributes_from_name(name)
        self.base_field.set_attributes_from_name(name)

    def get_internal_type(self):
        return "BinaryField"

    def pre_save(self, model_instance, add):
        return self._fernet.encrypt(
            pickle.dumps(self.base_field.pre_save(model_instance, add)))

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super(EncryptedField, self).get_db_prep_value(value, connection, prepared)
        if value is not None:
            return connection.Database.Binary(value)
        return value

    def from_db_value(self, value, expression, connection, context):
        if value:
            try:
                return pickle.loads(self._fernet.decrypt(value, self._ttl))
            except SignatureExpired:
                return Expired
        return value

    def formfield(self, **kwargs):
        return self.base_field.formfield(**kwargs)
