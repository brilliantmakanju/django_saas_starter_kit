
import uuid
from django.utils import timezone
from django.db import models

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager

class UserAccountManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class UserAccount(AbstractBaseUser, PermissionsMixin):

        BASIC = 'basic'
        PRO = "pro"

        CHOICES_PLANS = (
            (BASIC, "basic"),
            (PRO, "pro"),
        )
        id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

        first_name = models.CharField(max_length=255)
        last_name = models.CharField(max_length=255)
        username = models.CharField(max_length=255, blank=True, null=True)
        email = models.EmailField(max_length=255, unique=True)
        profile = models.CharField(max_length=255, null=True, blank=True)
        plan = models.CharField(max_length=20, choices=CHOICES_PLANS, default=BASIC)
        subscription = models.CharField(max_length=100, default="")

        bio = models.TextField(null=True, blank=True)  # Optional bio field
        preferences = models.JSONField(default=dict, blank=True)  # Store user preferences in JSON format
        github_connected = models.BooleanField(default=False)  # Track if GitHub is linked
        google_connected = models.BooleanField(default=False)  # Track if Google is linked

        is_active = models.BooleanField(default=True)
        is_staff = models.BooleanField(default=False)

        stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True)  # Track Stripe subscription ID
        subscription_status = models.CharField(max_length=20,
                                               default="active")  # Track subscription status: 'active' or 'canceled'
        subscription_end_date = models.DateTimeField(null=True, blank=True)  # Track when the subscription should end

        # Multi-tenant related fields
        organizations = models.ManyToManyField('organizations.Organization', related_name="users", blank=True)

        objects = UserAccountManager()

        USERNAME_FIELD = 'email'
        REQUIRED_FIELDS = ['first_name', 'last_name']

        def get_full_name(self):
            return f"{self.first_name} {self.last_name}"

        def get_short_name(self):
            return self.first_name
        
        def __str__(self):
            return self.email

        def link_social_account(self, provider):
            """
            Marks a social account as linked based on the provider.
            """
            if provider == 'google':
                self.google_connected = True
            elif provider == 'github':
                self.github_connected = True
            self.save()

        def unlink_social_account(self, provider):
            """
            Marks a social account as unlinked based on the provider.
            """
            if provider == 'google':
                self.google_connected = False
            elif provider == 'github':
                self.github_connected = False
            self.save()

        def has_active_subscription(self):
            """
            Checks if the user currently has an active subscription.
            """
            if self.subscription_status == 'active':
                return True
            elif self.subscription_status == 'canceled' and self.subscription_end_date:
                # User can access until the end of their current billing period
                return timezone.now() < self.subscription_end_date
            return False


