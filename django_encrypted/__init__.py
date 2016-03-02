from django_encrypted.utils.version import get_version

VERSION = (0, 1, 0, 'alpha', 0)

__version__ = get_version(VERSION)

default_app_config = 'django_encrypted.apps.EncryptedConfig'
