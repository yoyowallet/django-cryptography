from django.db import models
from django.utils.translation import ugettext_lazy as _

from django_cryptography.fields import EncryptedField, PickledField


class TestModel(models.Model):
    boolean = models.BooleanField(_('boolean'))
    encrypted_boolean = EncryptedField(models.BooleanField())
    char = models.CharField(_('char'), max_length=50)
    encrypted_char = EncryptedField(models.CharField(max_length=50))
    decimal = models.DecimalField(_('decimal'))
    encrypted_decimal = EncryptedField(models.DecimalField())
    duration = models.DurationField(_('duration'))
    encrypted_duration = EncryptedField(models.DurationField())
    date = models.DateField(_('date'), auto_now=True)
    encrypted_date = EncryptedField(models.DateField(auto_now=True))
    float = models.FloatField(_('float'))
    encrypted_float = EncryptedField(models.FloatField())
    integer = models.IntegerField(_('integer'))
    encrypted_integer = EncryptedField(models.IntegerField())
    ip_addres = models.GenericIPAddressField(_('ip address'))
    encrypted_ip_addres = EncryptedField(models.GenericIPAddressField())
    text = models.TextField(_('text'))
    encrypted_text = EncryptedField(models.TextField())
    uuid = models.UUIDField(_('uuid'))
    encrypted_uuid = EncryptedField(models.UUIDField())


class PickledModel(models.Model):
    field = PickledField()


class NullablePickledModel(models.Model):
    field = PickledField(blank=True, null=True)


class EncryptedIntegerModel(models.Model):
    field = EncryptedField(models.IntegerField())


class EncryptedNullableIntegerModel(models.Model):
    field = EncryptedField(models.IntegerField(), blank=True, null=True)


class EncryptedCharModel(models.Model):
    field = EncryptedField(models.CharField(max_length=10))


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
