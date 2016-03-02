from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _

from .conf import EncryptedConf


class EncryptedConfig(AppConfig):
    name = 'django_encrypted'
    verbose_name = _("Django Encrypted")

    def ready(self):
        EncryptedConf()
