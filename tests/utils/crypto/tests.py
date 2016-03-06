import unittest

from cryptography.hazmat.primitives import hashes
from django.test import override_settings
from django.utils.crypto import salted_hmac as django_salted_hmac
from django_cryptography.utils.crypto import salted_hmac


class SaltedHMACTestCase(unittest.TestCase):
    SALT = 'salted_hmac'
    VALUE = 'Hello, World!'

    @override_settings(CRYPTOGRAPHY_HASH=hashes.SHA1())
    def test_django_compatible_hmac(self):
        django_hmac = django_salted_hmac(self.SALT, self.VALUE)
        cryptography_hmac = salted_hmac(self.SALT, self.VALUE)

        self.assertEqual(django_hmac.digest(), cryptography_hmac.finalize())
