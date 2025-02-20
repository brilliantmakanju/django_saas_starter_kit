import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db.utils import OperationalError, ProgrammingError

class Command(BaseCommand):
    help = "Create a superuser if none exists"

    def handle(self, *args, **kwargs):
        User = get_user_model()
        try:
            if not User.objects.filter(is_superuser=True).exists():
                User.objects.create_superuser(
                    email=os.getenv("DJANGO_SUPERUSER_EMAIL", "admin@example.com"),
                    password=os.getenv("DJANGO_SUPERUSER_PASSWORD", "SuperSecurePassword123"),
                )
                self.stdout.write(self.style.SUCCESS("Superuser created!"))
            else:
                self.stdout.write(self.style.NOTICE("Superuser already exists."))
        except (OperationalError, ProgrammingError):
            self.stdout.write(self.style.WARNING("Database not ready, skipping superuser creation."))
