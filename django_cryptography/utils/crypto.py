from __future__ import unicode_literals

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from django.conf import settings
from django.core.signing import BadSignature, SignatureExpired
from django.utils.crypto import constant_time_compare
from django.utils.encoding import force_bytes, force_str, force_text


def salted_hmac(key_salt, value, secret=None):
    """
    Returns the HMAC-SHA1 of 'value', using a key generated from key_salt and a
    secret (which defaults to settings.SECRET_KEY).

    A different key_salt should be passed in for every application of HMAC.
    """
    if secret is None:
        secret = settings.SECRET_KEY

    key_salt = force_bytes(key_salt)
    secret = force_bytes(secret)

    # We need to generate a derived key from our base key.  We can do this by
    # passing the key_salt and our base key through a pseudo-random function and
    # SHA1 works nicely.
    digest = hashes.Hash(settings.CRYPTOGRAPHY_HASH, backend=default_backend())
    digest.update(key_salt + secret)
    key = digest.finalize()

    # If len(key_salt + secret) > sha_constructor().block_size, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.
    h = HMAC(key, settings.CRYPTOGRAPHY_HASH, backend=default_backend())
    h.update(force_bytes(value))
    return h


class Signer(object):

    def __init__(self, key=None, sep=':', salt=None):
        # Use of native strings in all versions of Python
        self.sep = force_str(sep)
        self.key = force_bytes(key or settings.SECRET_KEY)
        self.salt = force_bytes(salt or
            '%s.%s' % (self.__class__.__module__, self.__class__.__name__))

    def signature(self, value):
        signature = base64_hmac(self.salt + b'signer', value, self.key)
        h = HMAC(self.salt + b'signer' + self.key, hashes.SHA256(), backend=self._backend)
        h.update(force_bytes(value))
        hmac = h.finalize()
        # Convert the signature from bytes to str only on Python 3
        return force_str(signature)

    def sign(self, value):
        value = force_str(value)
        return str('%s%s%s') % (value, self.sep, self.signature(value))

    def unsign(self, signed_value):
        signed_value = force_str(signed_value)
        if self.sep not in signed_value:
            raise BadSignature('No "%s" found in value' % self.sep)
        value, sig = signed_value.rsplit(self.sep, 1)
        if constant_time_compare(sig, self.signature(value)):
            return force_text(value)
        raise BadSignature('Signature "%s" does not match' % sig)
