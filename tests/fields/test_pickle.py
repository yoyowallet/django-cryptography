import unittest

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


class TestQuerying(TestCase):

    def setUp(self):
        self.objs = [
            NullablePickledModel.objects.create(field=[1]),
            NullablePickledModel.objects.create(field=[2]),
            NullablePickledModel.objects.create(field=[2, 3]),
            NullablePickledModel.objects.create(field=[20, 30, 40]),
            NullablePickledModel.objects.create(field=None),
        ]

    def test_exact(self):
        self.assertSequenceEqual(
            NullablePickledModel.objects.filter(field__exact=[1]),
            self.objs[:1]
        )

    def test_isnull(self):
        self.assertSequenceEqual(
            NullablePickledModel.objects.filter(field__isnull=True),
            self.objs[-1:]
        )

    def test_in(self):
        self.assertSequenceEqual(
            NullablePickledModel.objects.filter(field__in=[[1], [2]]),
            self.objs[:2]
        )

    def test_unsupported(self):
        with self.assertRaises(TypeError):
            NullablePickledModel.objects.filter(field__contains=[2]).count()


class TestValidation(TestCase):

    def test_validate(self):
        field = PickledField()
        field.clean(None, None)
