from django.db import models
from django.utils.translation import ugettext_lazy as _

from django_cryptography.fields import EncryptedField


class Test(models.Model):
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
