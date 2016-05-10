from django.db import models

from django_cryptography.fields import EncryptedField, PickledField


class PickledModel(models.Model):
    field = PickledField()


class NullablePickledModel(models.Model):
    field = PickledField(blank=True, null=True)


class EncryptedIntegerModel(models.Model):
    field = EncryptedField(models.IntegerField())


class EncryptedNullableIntegerModel(models.Model):
    field = EncryptedField(models.IntegerField(), blank=True, null=True)


class EncryptedTTLIntegerModel(models.Model):
    field = EncryptedField(models.IntegerField(), ttl=60)


class EncryptedCharModel(models.Model):
    field = EncryptedField(models.CharField(max_length=15))


class EncryptedDateTimeModel(models.Model):
    datetime = EncryptedField(models.DateTimeField())
    date = EncryptedField(models.DateField())
    time = EncryptedField(models.TimeField())
    auto_now = EncryptedField(models.DateTimeField(auto_now=True))


class OtherEncryptedTypesModel(models.Model):
    ip = EncryptedField(models.GenericIPAddressField())
    uuid = EncryptedField(models.UUIDField())
    decimal = EncryptedField(models.DecimalField(max_digits=5, decimal_places=2))


class EncryptedFieldSubclass(EncryptedField):
    def __init__(self, *args, **kwargs):
        super(EncryptedFieldSubclass, self).__init__(models.IntegerField())
