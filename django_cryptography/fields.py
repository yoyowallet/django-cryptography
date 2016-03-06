from django.core import checks
from django.db import models

from django_cryptography.core.signing import SignatureExpired
from django_cryptography.utils.crypto import Fernet

try:
    from django.utils.six.moves import cPickle as pickle
except ImportError:
    import pickle

Expired = object()


class EncryptedField(models.Field):
    def __init__(self, base_field, **kwargs):
        """
        :type base_field: django.db.models.fields.Field
        :rtype: None
        """
        key = kwargs.pop('key', None)
        ttl = kwargs.pop('ttl', None)

        self._fernet = Fernet(key)
        self._ttl = ttl
        self.base_field = base_field
        super(EncryptedField, self).__init__(**kwargs)

    # def __getattr__(self, item):
    #     # Map back to base_field instance
    #     return getattr(self.base_field, item)

    def check(self, **kwargs):
        errors = super(EncryptedField, self).check(**kwargs)
        if self.base_field.rel:
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

    def set_attributes_from_name(self, name):
        super(EncryptedField, self).set_attributes_from_name(name)
        self.base_field.set_attributes_from_name(name)

    @property
    def description(self):
        return 'Encrypted %s' % self.base_field.description

    def get_internal_type(self):
        return "BinaryField"

    def deconstruct(self):
        name, path, args, kwargs = super(EncryptedField, self).deconstruct()
        kwargs.update({
            'base_field': self.base_field,
        })
        return name, path, args, kwargs

    def pre_save(self, model_instance, add):
        return self._fernet.encrypt(
            pickle.dumps(self.base_field.pre_save(model_instance, add)))

    def from_db_value(self, value, expression, connection, context):
        if value:
            try:
                return pickle.loads(self._fernet.decrypt(value, self._ttl))
            except SignatureExpired:
                return Expired
        return value

    def validate(self, value, model_instance):
        super(EncryptedField, self).validate(value, model_instance)
        self.base_field.validate(value, model_instance)

    def run_validators(self, value):
        super(EncryptedField, self).run_validators(value)
        self.base_field.run_validators(value)
