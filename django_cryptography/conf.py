import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from django.conf import settings
from django.utils.encoding import force_bytes
from appconf import AppConf

kdf = pbkdf2.PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=os.urandom(16),
    iterations=30000,
    backend=default_backend()
)


class CryptographyConf(AppConf):
    KEY = None
    HASH = hashes.SHA256()

    class Meta:
        prefix = 'cryptography'

    def configure_key(self, value):
        return kdf.derive(force_bytes(value or settings.SECRET_KEY))
