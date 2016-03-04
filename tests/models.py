from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_encrypted.fields import EncryptedField


class Test(models.Model):
    char = models.CharField(_('char'), max_length=50)
    encrypted_char = EncryptedField(models.CharField(_('char'), max_length=50))
    boolean = models.BooleanField(_('boolean'))
    encrypted_boolean = EncryptedField(models.BooleanField(_('boolean')))
    integer = models.IntegerField(_('integer'))
    encrypted_integer = EncryptedField(models.IntegerField(_('integer')))
    datetime = models.DateField(_('datetime'), auto_now=True)
    encrypted_datetime = EncryptedField(models.DateField(_('datetime'), auto_now=True))
