# Generated by Django 5.1.2 on 2025-01-11 14:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0004_postgroup_description_postgroup_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="post",
            name="actual_publish_time",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="post",
            name="scheduled_publish_time",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
