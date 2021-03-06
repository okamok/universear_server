# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2017-08-10 15:39
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('hlar', '0013_auto_20170718_1043'),
    ]

    operations = [
        migrations.CreateModel(
            name='Payment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.IntegerField(null=True)),
                ('brought_view_count', models.IntegerField(null=True)),
                ('token_id', models.CharField(max_length=200, null=True)),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('modified_date', models.DateTimeField(auto_now=True)),
                ('target', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hlar.Target')),
            ],
        ),
        migrations.AlterModelOptions(
            name='user',
            options={'verbose_name': 'ユーザ', 'verbose_name_plural': 'ユーザ達'},
        ),
        migrations.AddField(
            model_name='payment',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
