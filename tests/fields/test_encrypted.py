import decimal
import unittest
import uuid
from datetime import timedelta
from decimal import Decimal

from django import forms
from django.conf import settings
from django.core.management import call_command
from django.db import IntegrityError, connection, models
from django.test import TestCase, override_settings
from django.utils import timezone
from django.utils.six import binary_type

from django_cryptography.fields import EncryptedField
from .models import (
    EncryptedFieldSubclass,  EncryptedIntegerModel,
    EncryptedNullableIntegerModel, EncryptedCharModel, EncryptedDateTimeModel,
    OtherEncryptedTypesModel, TestModel,
)


class TestSaveLoad(TestCase):

    def test_integer(self):
        instance = EncryptedIntegerModel(field=42)
        instance.save()
        loaded = EncryptedIntegerModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_char(self):
        instance = EncryptedCharModel(field='Hello, world!')
        instance.save()
        loaded = EncryptedCharModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_dates(self):
        instance = EncryptedDateTimeModel(
            datetimes=timezone.now(),
            dates=timezone.now().date(),
            times=timezone.now().time(),
        )
        instance.save()
        loaded = EncryptedDateTimeModel.objects.get()
        self.assertEqual(instance.datetimes, loaded.datetimes)
        self.assertEqual(instance.dates, loaded.dates)
        self.assertEqual(instance.times, loaded.times)

    def test_default_null(self):
        instance = EncryptedNullableIntegerModel()
        instance.save()
        loaded = EncryptedNullableIntegerModel.objects.get(pk=instance.pk)
        self.assertEqual(loaded.field, None)
        self.assertEqual(instance.field, loaded.field)

    def test_null_handling(self):
        instance = EncryptedNullableIntegerModel(field=None)
        instance.save()
        loaded = EncryptedNullableIntegerModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

        instance = EncryptedIntegerModel(field=None)
        with self.assertRaises(IntegrityError):
            instance.save()

    def test_other_array_types(self):
        instance = OtherEncryptedTypesModel(
            ips='192.168.0.1',
            uuids=uuid.uuid4(),
            decimals=decimal.Decimal(1.25),
        )
        instance.save()
        loaded = OtherEncryptedTypesModel.objects.get()
        self.assertEqual(instance.ips, loaded.ips)
        self.assertEqual(instance.uuids, loaded.uuids)
        self.assertEqual(instance.decimals, loaded.decimals)


class TestEncryptedField(TestCase):
    def test_settings_has_key(self):
        key = settings.CRYPTOGRAPHY_KEY
        self.assertIsNotNone(key)
        self.assertIsInstance(key, binary_type)

    def test_field_match(self):
        obj = TestModel(boolean=True, char='Hello, world!',
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

        # Fetch the object
        obj = TestModel.objects.get()
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

        # Update object
        obj.encrypted_boolean = not obj.boolean
        obj.encrypted_char = 'Goodbye, world!'
        obj.save()

        # Fetch the object
        obj = TestModel.objects.get()
        self.assertNotEqual(obj.boolean, obj.encrypted_boolean)
        self.assertNotEqual(obj.char, obj.encrypted_char)

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
            field = EncryptedField(models.ForeignKey('models.TestModel'))

        obj = Related()
        errors = obj.check()

        self.assertEqual(1, len(errors))
        self.assertEqual('encrypted.E002', errors[0].id)


class TestMigrations(TestCase):
    available_apps = ['tests.fields']

    def test_deconstruct(self):
        field = EncryptedField(models.IntegerField())
        name, path, args, kwargs = field.deconstruct()
        new = EncryptedField(*args, **kwargs)
        self.assertEqual(type(new.base_field), type(field.base_field))

    def test_deconstruct_args(self):
        field = EncryptedField(models.CharField(max_length=20))
        name, path, args, kwargs = field.deconstruct()
        new = EncryptedField(*args, **kwargs)
        self.assertEqual(new.base_field.max_length, field.base_field.max_length)

    def test_subclass_deconstruct(self):
        field = EncryptedField(models.IntegerField())
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual('django_cryptography.fields.EncryptedField', path)

        field = EncryptedFieldSubclass()
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual('tests.fields.models.EncryptedFieldSubclass', path)

    @override_settings(MIGRATION_MODULES={
        'fields': 'tests.fields.encrypted_default_migrations'})
    def test_adding_field_with_default(self):
        table_name = 'fields_integerencrypteddefaultmodel'
        with connection.cursor() as cursor:
            self.assertNotIn(table_name, connection.introspection.table_names(cursor))
        call_command('migrate', 'fields', verbosity=0)
        with connection.cursor() as cursor:
            self.assertIn(table_name, connection.introspection.table_names(cursor))
        call_command('migrate', 'fields', 'zero', verbosity=0)
        with connection.cursor() as cursor:
            self.assertNotIn(table_name, connection.introspection.table_names(cursor))


class TestSimpleFormField(TestCase):

    def test_model_field_formfield(self):
        model_field = EncryptedField(models.CharField(max_length=27))
        form_field = model_field.formfield()
        self.assertIsInstance(form_field, forms.CharField)
        self.assertEqual(form_field.max_length, 27)
