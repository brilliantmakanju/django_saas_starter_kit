# Generated by Django 5.1.2 on 2025-01-11 01:19

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
        ("auth", "0012_alter_user_first_name_max_length"),
        ("organizations", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="useraccount",
            name="organizations",
            field=models.ManyToManyField(
                blank=True, related_name="users", to="organizations.organization"
            ),
        ),
        migrations.AddField(
            model_name="useraccount",
            name="user_permissions",
            field=models.ManyToManyField(
                blank=True,
                help_text="Specific permissions for this user.",
                related_name="user_set",
                related_query_name="user",
                to="auth.permission",
                verbose_name="user permissions",
            ),
        ),
    ]
