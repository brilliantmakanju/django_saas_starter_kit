# Generated by Django 5.1.2 on 2025-01-11 01:19

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserAccount",
            fields=[
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("first_name", models.CharField(max_length=255)),
                ("last_name", models.CharField(max_length=255)),
                ("username", models.CharField(blank=True, max_length=255, null=True)),
                ("email", models.EmailField(max_length=255, unique=True)),
                ("profile", models.CharField(blank=True, max_length=255, null=True)),
                (
                    "plan",
                    models.CharField(
                        choices=[("basic", "basic"), ("pro", "pro")],
                        default="basic",
                        max_length=20,
                    ),
                ),
                ("subscription", models.CharField(default="", max_length=100)),
                ("bio", models.TextField(blank=True, null=True)),
                ("preferences", models.JSONField(blank=True, default=dict)),
                ("github_connected", models.BooleanField(default=False)),
                ("google_connected", models.BooleanField(default=False)),
                ("is_active", models.BooleanField(default=True)),
                ("is_staff", models.BooleanField(default=False)),
                (
                    "stripe_subscription_id",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                (
                    "subscription_status",
                    models.CharField(default="active", max_length=20),
                ),
                ("subscription_end_date", models.DateTimeField(blank=True, null=True)),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
