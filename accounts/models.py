
import uuid
from django.utils import timezone
from datetime import timedelta
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

        BASIC = "basic"
        PRO = "pro"
        LTD = "ltd"

        CHOICES_PLANS = (
            (BASIC, "basic"),
            (PRO, "pro"),
            (LTD, "ltd"),
        )

        id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
        first_name = models.CharField(max_length=255)
        last_name = models.CharField(max_length=255)
        username = models.CharField(max_length=255, blank=True, null=True, unique=True, db_index=True)
        email = models.EmailField(max_length=255, unique=True, db_index=True)
        profile = models.CharField(max_length=255, null=True, blank=True)
        plan = models.CharField(max_length=20, choices=CHOICES_PLANS, default=BASIC)
        subscription = models.CharField(max_length=100, default="")

        bio = models.TextField(null=True, blank=True)
        preferences = models.JSONField(default=dict, blank=True)  # Store user preferences in JSON format
        github_connected = models.BooleanField(default=False)
        google_connected = models.BooleanField(default=False)

        is_active = models.BooleanField(default=True)
        is_staff = models.BooleanField(default=False)

        stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True)
        subscription_status = models.CharField(
            max_length=20, default="unactive", db_index=True
        )  # Faster lookups for subscription filtering
        subscription_end_date = models.DateTimeField(null=True, blank=True)
        # stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)

        # Multi-tenant related fields
        organizations = models.ManyToManyField('organizations.Organization', related_name="users", blank=True)

        objects = UserAccountManager()

        USERNAME_FIELD = 'email'
        REQUIRED_FIELDS = ['first_name', 'last_name']

        def __str__(self):
            return self.email

        def get_full_name(self):
            return f"{self.first_name} {self.last_name}"

        def get_short_name(self):
            return self.first_name

        def link_social_account(self, provider):
            """Marks a social account as linked."""
            if provider in ['google', 'github']:
                setattr(self, f"{provider}_connected", True)
                self.save(update_fields=[f"{provider}_connected"])

        def unlink_social_account(self, provider):
            """Marks a social account as unlinked."""
            if provider in ['google', 'github']:
                setattr(self, f"{provider}_connected", False)
                self.save(update_fields=[f"{provider}_connected"])

        def has_active_subscription(self):
            """Checks if the user currently has an active subscription."""
            if self.subscription_status == 'active':
                return True
            if self.subscription_status == 'canceled' and self.subscription_end_date:
                return self.subscription_end_date > timezone.now()
            return False

        def update_subscription_status(self):
            """
            Ensures subscription status is updated if the subscription has expired.
            If expired, the user is reverted back to the basic plan.
            """
            if self.subscription_status == "active" and self.subscription_end_date and self.subscription_end_date < timezone.now():
                self.subscription_status = "canceled"
                self.plan = UserAccount.BASIC

            if self.subscription_status == "canceled" and self.subscription_end_date and self.subscription_end_date < timezone.now():
                self.plan = UserAccount.BASIC  # Revert to basic plan

            self.save(update_fields=["subscription_status", "plan"])


class SubscriptionPlan(models.Model):
    BASIC = "basic"
    PRO = "pro"
    LTD = "ltd"

    CHOICES_PLANS = (
        (BASIC, "basic"),
        (PRO, "pro"),
        (LTD, "ltd"),
    )

    name = models.CharField(max_length=50, choices=CHOICES_PLANS)
    stripe_price_id = models.CharField(max_length=255, unique=True)  # Price ID from Stripe
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.get_name_display()} ({self.stripe_price_id}) ({self.description})"







class Payment(models.Model):
    PLAN_CHOICES = [
        ('pro', 'Pro'),
        ('lifetime', 'Lifetime Deal'),
    ]
    PERIOD_CHOICES = [
        ('monthly', 'Monthly'),
        ('annually', 'Annually'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('expired', 'Expired'),
        ('verified', 'Verified'),
    ]

    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    plan = models.CharField(max_length=50, choices=PLAN_CHOICES)
    period = models.CharField(max_length=50, choices=PERIOD_CHOICES, default='monthly', blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    starts_at = models.DateTimeField(null=True, blank=True)
    ends_at = models.DateTimeField(null=True, blank=True)
    proof_of_payment = models.ImageField(upload_to='payment_proofs/', blank=True, null=True)
    transaction_ref = models.CharField(max_length=255, blank=True, null=True)
    additional_note = models.TextField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.status == 'verified' and not self.starts_at:
            self.starts_at = timezone.now()
            if self.plan == 'lifetime':
                self.ends_at = self.starts_at + timedelta(days=365 * 99999)
            elif self.plan == 'pro' and self.period == 'monthly':
                self.ends_at = self.starts_at + timedelta(days=30)
            elif self.plan == 'pro' and self.period == 'annually':
                self.ends_at = self.starts_at + timedelta(days=365)

        super().save(*args, **kwargs)