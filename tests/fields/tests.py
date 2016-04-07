import uuid
from datetime import timedelta
from decimal import Decimal

from django.conf import settings
from django.db import models
from django.test import TestCase
from django.utils.six import binary_type
from django_cryptography.fields import EncryptedField

from .models import Test


class TestEncryptedField(TestCase):
    def test_settings_has_key(self):
        key = settings.CRYPTOGRAPHY_KEY
        self.assertIsNotNone(key)
        self.assertIsInstance(key, binary_type)

    def test_field_match(self):
        obj = Test(boolean=True, char='Hello, world!',
                   decimal=Decimal('1.00'), duration=timedelta(1),
                   float=42.0, integer=42, ip_addres='::1',
                   text='Too short...', uuid=uuid.uuid4())
        obj.encrypted_boolean = obj.boolean
        obj.encrypted_char = obj.char
        obj.encrypted_decimal = obj.decimal
        obj.encrypted_duration = obj.duration
        obj.encrypted_float = obj.float
        obj.encrypted_integer = obj.integer
        obj.encrypted_ip_addres = obj.ip_addres
        obj.encrypted_text = obj.text
        obj.encrypted_uuid = obj.uuid
        obj.save()
        del obj

        # Fetch the object
        obj = Test.objects.get()
        self.assertEqual(obj.boolean, obj.encrypted_boolean)
        self.assertEqual(obj.char, obj.encrypted_char)
        self.assertEqual(obj.date, obj.encrypted_date)
        self.assertEqual(obj.decimal, obj.encrypted_decimal)
        self.assertEqual(obj.duration, obj.encrypted_duration)
        self.assertEqual(obj.float, obj.encrypted_float)
        self.assertEqual(obj.integer, obj.encrypted_integer)
        self.assertEqual(obj.ip_addres, obj.encrypted_ip_addres)
        self.assertEqual(obj.text, obj.encrypted_text)
        self.assertEqual(obj.uuid, obj.encrypted_uuid)

    def test_field_checks(self):
        class BadField(models.Model):
            field = EncryptedField(models.CharField())

        model = BadField()
        errors = model.check()
        self.assertEqual(len(errors), 1)
        # The inner CharField is missing a max_length.
        self.assertEqual('encrypted.E001', errors[0].id)
        self.assertIn('max_length', errors[0].msg)

    def test_invalid_base_fields(self):
        class Related(models.Model):
            field = EncryptedField(models.ForeignKey('fields.Test'))

        obj = Related()
        errors = obj.check()

        self.assertEqual(1, len(errors))
        self.assertEqual('encrypted.E002', errors[0].id)
