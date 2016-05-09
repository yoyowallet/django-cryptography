from django_cryptography.utils.version import get_version

VERSION = (0, 1, 0, 'rc', 1)

__version__ = get_version(VERSION)

default_app_config = 'django_cryptography.apps.CryptographyConfig'
