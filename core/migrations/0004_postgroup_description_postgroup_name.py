# Generated by Django 5.1.2 on 2025-01-11 13:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_postgroup_organization"),
    ]

    operations = [
        migrations.AddField(
            model_name="postgroup",
            name="description",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="postgroup",
            name="name",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
