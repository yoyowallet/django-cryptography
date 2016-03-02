import os
import pickle
import struct
import time

from cryptography.fernet import _MAX_CLOCK_SKEW, InvalidToken, InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from django.conf import settings
from django.db import models
from django.utils import six


class EncryptedField(models.BinaryField):
    # FIXME: `base_field` has issues with date/time fields
    def __init__(self, base_field, *args, **kwargs):
        """
        :type base_field: django.db.models.fields.Field
        :rtype: None
        """
        backend = kwargs.pop('backend', None)
        if backend is None:
            backend = default_backend()

        self.ttl = kwargs.pop('ttl', None)
        self._signing_key = settings.SECRET_KEY.encode()
        self._encryption_key = settings.DJANGO_ENCRYPTED_KEY
        self._backend = backend
        self.base_field = base_field
        self.field = base_field(*args, **kwargs)
        super(EncryptedField, self).__init__()

    def __getattr__(self, item):
        # Map back to field instance
        return getattr(self.field, item)

    def deconstruct(self):
        name, path, args, kwargs = super(EncryptedField, self).deconstruct()
        args.append(self.base_field)
        return name, path, args, kwargs

    def get_db_prep_save(self, value, connection):
        value = self.field.get_db_prep_save(value, connection)
        if value is None:
            return value

        current_time = int(time.time())
        iv = os.urandom(16)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(pickle.dumps(value)) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(settings.DJANGO_ENCRYPTED_KEY), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b'\x80' + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()

        return basic_parts + hmac

    def from_db_value(self, value, expression, connection, context):
        current_time = int(time.time())

        if not value or six.indexbytes(value, 0) != 0x80:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", value[1:9])
        except struct.error:
            raise InvalidToken
        if self.ttl is not None:
            if timestamp + self.ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(value[:-32])
        try:
            h.verify(value[-32:])
        except InvalidSignature:
            raise InvalidToken

        iv = value[9:25]
        ciphertext = value[25:-32]
        decryptor = Cipher(
            algorithms.AES(settings.DJANGO_ENCRYPTED_KEY), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return pickle.loads(unpadded)
