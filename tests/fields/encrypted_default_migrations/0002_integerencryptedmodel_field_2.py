# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import django_cryptography.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fields', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='integerencrypteddefaultmodel',
            name='field_2',
            field=django_cryptography.fields.EncryptedField(models.IntegerField()),
            preserve_default=False,
        ),
    ]
