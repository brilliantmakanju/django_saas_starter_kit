# Generated by Django 5.1.4 on 2025-01-12 17:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_socialmediaaccount'),
    ]

    operations = [
        migrations.AddField(
            model_name='post',
            name='priority',
            field=models.BooleanField(default=False),
        ),
    ]
