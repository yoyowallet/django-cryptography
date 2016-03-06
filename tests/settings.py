SECRET_KEY = 'ThisIsATestSecret'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
    }
}

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sites',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin.apps.SimpleAdminConfig',
    'django.contrib.staticfiles',
    'django_cryptography',
    'tests',
]

SIGNING_BACKEND = 'django_cryptography.core.signing.TimestampSigner'
