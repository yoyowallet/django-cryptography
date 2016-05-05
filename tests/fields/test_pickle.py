from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from django_cryptography.fields import PickledField

from .models import PickledModel, NullablePickledModel


class TestSaveLoad(TestCase):

    def test_integer(self):
        instance = PickledModel(field=42)
        instance.save()
        loaded = PickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_string(self):
        instance = PickledModel(field='Hello, world!')
        instance.save()
        loaded = PickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_datetime(self):
        instance = PickledModel(field=timezone.now())
        instance.save()
        loaded = PickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

    def test_default_null(self):
        instance = NullablePickledModel()
        instance.save()
        loaded = NullablePickledModel.objects.get(pk=instance.pk)
        self.assertEqual(loaded.field, None)
        self.assertEqual(instance.field, loaded.field)

    def test_null_handling(self):
        instance = NullablePickledModel(field=None)
        instance.save()
        loaded = NullablePickledModel.objects.get()
        self.assertEqual(instance.field, loaded.field)

        instance = PickledModel(field=None)
        with self.assertRaises(IntegrityError):
            instance.save()


class TestValidation(TestCase):

    def test_validate(self):
        field = PickledField()
        field.clean(None, None)
