from django.core import checks
from django.db import models
from django.utils.translation import ugettext_lazy as _

from django_cryptography.core.signing import SignatureExpired
from django_cryptography.utils.crypto import FernetBytes

try:
    from django.utils.six.moves import cPickle as pickle
except ImportError:
    import pickle

Expired = object()


class EncryptedField(models.Field):
    @property
    def description(self):
        return _('Encrypted %s') % self.base_field.description

    def __init__(self, base_field, **kwargs):
        """
        :type base_field: django.db.models.fields.Field
        :rtype: None
        """
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
