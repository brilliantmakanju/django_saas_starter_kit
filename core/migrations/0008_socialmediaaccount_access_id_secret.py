# Generated by Django 5.1.4 on 2025-01-14 06:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0007_post_priority'),
    ]

    operations = [
        migrations.AddField(
            model_name='socialmediaaccount',
            name='access_id_secret',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
