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
    datetimes = EncryptedField(models.DateTimeField())
    dates = EncryptedField(models.DateField())
    times = EncryptedField(models.TimeField())


class OtherEncryptedTypesModel(models.Model):
    ips = EncryptedField(models.GenericIPAddressField())
    uuids = EncryptedField(models.UUIDField())
    decimals = EncryptedField(models.DecimalField(max_digits=5, decimal_places=2))


class EncryptedFieldSubclass(EncryptedField):
    def __init__(self, *args, **kwargs):
        super(EncryptedFieldSubclass, self).__init__(models.IntegerField())
