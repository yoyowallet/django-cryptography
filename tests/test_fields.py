from django.conf import settings
from django.test import TestCase
from django.utils.six import binary_type

from .models import Test


class EncryptedFieldTestCase(TestCase):
    def test_settings_has_key(self):
        key = settings.DJANGO_ENCRYPTED_KEY
        self.assertIsNotNone(key)
        self.assertIsInstance(key, binary_type)

    def test_field_match(self):
        obj = Test(char='Hello, world!', boolean=True, integer=42)
        obj.encrypted_char = obj.char
        obj.encrypted_boolean = obj.boolean
        obj.encrypted_integer = obj.integer
        obj.save()
        del obj

        # Fetch the object
        obj = Test.objects.get()
        self.assertEqual(obj.char, obj.encrypted_char)
        self.assertEqual(obj.boolean, obj.encrypted_boolean)
        self.assertEqual(obj.integer, obj.encrypted_integer)
        # self.assertEqual(obj.datetime, obj.encrypted_datetime)
