import struct
import time

from cryptography import fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from django.conf import settings
from django.utils import six


class Fernet(fernet.Fernet):
    def __init__(self, key=None, backend=None):
        if backend is None:
            backend = settings.CRYPTOGRAPHY_BACKEND

        self._signing_key = settings.SECRET_KEY.encode()
        self._encryption_key = key or settings.CRYPTOGRAPHY_KEY
        self._backend = backend

    def _encrypt_from_parts(self, data, current_time, iv):
        if not isinstance(data, six.binary_type):
            raise TypeError("data must be bytes.")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()

        return basic_parts + hmac

    def decrypt(self, data, ttl=None):
        if not isinstance(data, six.binary_type):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        if not data or six.indexbytes(data, 0) != 0x80:
            raise fernet.InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise fernet.InvalidToken
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise fernet.InvalidToken
        if current_time + fernet._MAX_CLOCK_SKEW < timestamp:
            raise fernet.InvalidToken
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except fernet.InvalidSignature:
            raise fernet.InvalidToken

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise fernet.InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise fernet.InvalidToken
        return unpadded
