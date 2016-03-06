from __future__ import unicode_literals

import datetime
import re
import time
import zlib

from django.conf import settings
from django.core import signing
from django.utils import baseconv
from django.utils.encoding import force_bytes, force_str, force_text

from ..utils.crypto import constant_time_compare, salted_hmac

_SEP_UNSAFE = re.compile(r'^[A-z0-9-_=]*$')

BadSignature = signing.BadSignature
SignatureExpired = signing.SignatureExpired
b64_encode = signing.b64_encode
b64_decode = signing.b64_decode


def base64_hmac(salt, value, key):
    return b64_encode(salted_hmac(salt, value, key).finalize())


get_cookie_signer = signing.get_cookie_signer
JSONSerializer = signing.JSONSerializer


def dumps(obj, key=None, salt='django.core.signing', serializer=JSONSerializer, compress=False):
    """
    Returns URL-safe, sha1 signed base64 compressed JSON string. If key is
    None, settings.SECRET_KEY is used instead.

    If compress is True (not the default) checks if compressing using zlib can
    save some space. Prepends a '.' to signify compression. This is included
    in the signature, to protect against zip bombs.

    Salt can be used to namespace the hash, so that a signed string is
    only valid for a given namespace. Leaving this at the default
    value or re-using a salt value across different parts of your
    application without good cause is a security risk.

    The serializer is expected to return a bytestring.
    """
    data = serializer().dumps(obj)

    # Flag for if it's been compressed or not
    is_compressed = False

    if compress:
        # Avoid zlib dependency unless compress is being used
        compressed = zlib.compress(data)
        if len(compressed) < (len(data) - 1):
            data = compressed
            is_compressed = True
    base64d = b64_encode(data)
    if is_compressed:
        base64d = b'.' + base64d
    return TimestampSigner(key, salt=salt).sign(base64d)


def loads(s, key=None, salt='django.core.signing', serializer=JSONSerializer, max_age=None):
    """
    Reverse of dumps(), raises BadSignature if signature fails.

    The serializer is expected to accept a bytestring.
    """
    # TimestampSigner.unsign always returns unicode but base64 and zlib
    # compression operate on bytes.
    base64d = force_bytes(TimestampSigner(key, salt=salt).unsign(s, max_age=max_age))
    decompress = False
    if base64d[:1] == b'.':
        # It's compressed; uncompress it first
        base64d = base64d[1:]
        decompress = True
    data = b64_decode(base64d)
    if decompress:
        data = zlib.decompress(data)
    return serializer().loads(data)


class Signer(object):

    def __init__(self, key=None, sep=':', salt=None):
        # Use of native strings in all versions of Python
        self.key = key or settings.SECRET_KEY
        self.sep = force_str(sep)
        if _SEP_UNSAFE.match(self.sep):
            raise ValueError(
                'Unsafe Signer separator: %r (cannot be empty or consist of '
                'only A-z0-9-_=)' % sep,
            )
        self.salt = force_str(salt or
            '%s.%s' % (self.__class__.__module__, self.__class__.__name__))

    def signature(self, value):
        signature = base64_hmac(self.salt + 'signer', value, self.key)
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


class TimestampSigner(Signer):

    def timestamp(self):
        return baseconv.base62.encode(int(time.time()))

    def sign(self, value):
        value = force_str(value)
        value = str('%s%s%s') % (value, self.sep, self.timestamp())
        return super(TimestampSigner, self).sign(value)

    def unsign(self, value, max_age=None):
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.
        """
        result = super(TimestampSigner, self).unsign(value)
        value, timestamp = result.rsplit(self.sep, 1)
        timestamp = baseconv.base62.decode(timestamp)
        if max_age is not None:
            if isinstance(max_age, datetime.timedelta):
                max_age = max_age.total_seconds()
            # Check timestamp is not older than max_age
            age = time.time() - timestamp
            if age > max_age:
                raise SignatureExpired(
                    'Signature age %s > %s seconds' % (age, max_age))
        return value
