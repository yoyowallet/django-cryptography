from cryptography.hazmat.primitives import constant_time, hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.utils import crypto
from django.utils.encoding import force_bytes


def salted_hmac(key_salt, value, secret=None):
    """
    Returns the HMAC-HASH of 'value', using a key generated from key_salt and a
    secret (which defaults to settings.SECRET_KEY).

    A different key_salt should be passed in for every application of HMAC.

    :type key_salt: any
    :type value: any
    :type secret: any
    :rtype: HMAC
    """
    if secret is None:
        secret = settings.SECRET_KEY

    key_salt = force_bytes(key_salt)
    secret = force_bytes(secret)

    # We need to generate a derived key from our base key.  We can do this by
    # passing the key_salt and our base key through a pseudo-random function and
    # SHA1 works nicely.
    digest = hashes.Hash(settings.CRYPTOGRAPHY_DIGEST,
                         backend=settings.CRYPTOGRAPHY_BACKEND)
    digest.update(key_salt + secret)
    key = digest.finalize()

    # If len(key_salt + secret) > sha_constructor().block_size, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.
    h = HMAC(key, settings.CRYPTOGRAPHY_DIGEST,
             backend=settings.CRYPTOGRAPHY_BACKEND)
    h.update(force_bytes(value))
    return h


get_random_string = crypto.get_random_string


def constant_time_compare(val1, val2):
    """
    :type val1: any
    :type val2: any
    :rtype: bool
    """
    return constant_time.bytes_eq(force_bytes(val1), force_bytes(val2))


def pbkdf2(password, salt, iterations, dklen=0, digest=None):
    """
    Implements PBKDF2 with the same API as Django's existing
    implementation, using cryptography.

    :type password: any
    :type salt: any
    :type iterations: int
    :type dklen: int
    :type digest: cryptography.hazmat.primitives.hashes.HashAlgorithm
    """
    if digest is None:
        digest = settings.CRYPTOGRAPHY_DIGEST
    if not dklen:
        dklen = digest.digest_size
    password = force_bytes(password)
    salt = force_bytes(salt)
    kdf = PBKDF2HMAC(
        algorithm=digest, length=dklen, salt=salt,
        iterations=iterations, backend=settings.CRYPTOGRAPHY_BACKEND
    )
    return kdf.derive(password)
