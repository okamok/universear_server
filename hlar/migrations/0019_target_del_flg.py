# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2017-09-25 14:07
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hlar', '0018_auto_20170925_2249'),
    ]

    operations = [
        migrations.AddField(
            model_name='target',
            name='del_flg',
            field=models.BooleanField(default=False),
        ),
    ]
