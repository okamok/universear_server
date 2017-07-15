# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2017-06-27 09:39
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hlar', '0008_auto_20170627_1534'),
    ]

    operations = [
        migrations.AddField(
            model_name='oauth',
            name='created_date',
            field=models.DateTimeField(auto_now_add=True, null=True),
        ),
        migrations.AddField(
            model_name='oauth',
            name='id_in_auth_app',
            field=models.CharField(max_length=80, null=True),
        ),
        migrations.AddField(
            model_name='oauth',
            name='modified_date',
            field=models.DateTimeField(auto_now=True, null=True),
        ),
    ]