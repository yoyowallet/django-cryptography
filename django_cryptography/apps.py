from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _

from .conf import CryptographyConf


class CryptographyConfig(AppConfig):
    name = 'django_cryptography'
    verbose_name = _("Django Cryptography")

    def ready(self):
        CryptographyConf()
