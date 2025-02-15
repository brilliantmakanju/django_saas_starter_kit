from django.db import models
from django_tenants.models import TenantMixin, DomainMixin
from django.contrib.auth import get_user_model
import uuid, random
from django.utils import timezone
from datetime import timedelta


class Organization(TenantMixin):
    TONE_CHOICES = [
        ('professional', 'Professional'),
        ('casual', 'Casual'),
        ('humorous', 'Humorous'),
        ('empathetic', 'Empathetic'),
        ('persuasive', 'Persuasive'),
        ('friendly', 'Friendly'),
    ]

    # Unique identifier for the organization
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Organization details
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)

    # Relationship to the user (owner of the organization)
    owner = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True,
                              related_name='owned_organizations')

    # Date when the organization was created
    created_on = models.DateTimeField(auto_now_add=True)

    # Auto create and drop schema flag
    auto_create_schema = True
    # auto_drop_schema = True

    # New fields for tone selection
    selected_tone = models.CharField(max_length=255, choices=TONE_CHOICES, default='professional')
    shuffle_tones = models.BooleanField(default=False)

    # New fields for social media platform configuration
    has_twitter = models.BooleanField(default=False, help_text="Enable Twitter integration for the organization.")
    has_linkedin = models.BooleanField(default=False, help_text="Enable LinkedIn integration for the organization.")

    def __str__(self):
        return self.name

    def get_tone(self):
        """
        Return the tone to use based on shuffle_tones setting.
        """
        if self.shuffle_tones:
            return random.choice([choice[0] for choice in self.TONE_CHOICES])
        return self.selected_tone

    # Methods for validation and checking platform status
    def can_generate_webhook(self):
        """
        Check if the organization has enabled at least one platform.
        """
        return self.has_twitter or self.has_linkedin

class Domain(DomainMixin):
    pass

class UserOrganizationRole(models.Model):
    ROLE_CHOICES = (
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
    )

    user = models.ForeignKey('accounts.UserAccount', on_delete=models.CASCADE)  # Replace with your custom User model
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='organization')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES)

    def __str__(self):
        return f"{self.user.email} - {self.organization.name} - {self.role}"

    def save(self, *args, **kwargs):
        # Prevent a user from being assigned to the organization as a 'member' if they are already an 'owner' or 'admin'
        if self.role == 'owner' and self.organization.owner != self.user:
            raise ValueError("Only the organization owner can be assigned the 'owner' role.")
        super().save(*args, **kwargs)

class InviteCode(models.Model):
    # Using UUID as the secret, or you could use a random long string
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    code = models.CharField(max_length=7, unique=True, editable=False)  # 7-character alphanumeric code
    expires = models.DateTimeField()  # When the invite will expire
    status = models.CharField(
        max_length=50,
        choices=[('pending', 'Pending'), ('used', 'Used'), ('expired', 'Expired')],
        default='pending'
    )
    invited_by = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True,
                                   blank=True)  # User who sent the invite
    used_at = models.DateTimeField(null=True, blank=True)  # When the invite was used
    invitee_email = models.EmailField()  # Email of the invited user
    role = models.CharField(max_length=50, choices=[('admin', 'Admin'), ('member', 'Member')],
                            default='member')  # Role within the organization
    created_at = models.DateTimeField(auto_now_add=True)  # When the invite was created
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)  # Organization this invite is linked to

    def __str__(self):
        return f"Invite for {self.invitee_email} to {self.invited_by} for organization {self.organization.name}"
    #
    def save(self, *args, **kwargs):
        # Automatically set the expiry date to 3 days from the creation
        if not self.expires:
            self.expires = timezone.now() + timedelta(days=3)

        if not self.code:
            # Generate a 6-character alphanumeric code from UUID
            self.code = self.generate_code()

        super().save(*args, **kwargs)

    def is_expired(self):
        """
        Check if the invite has expired by comparing the current time with the expiration time.
        If expired, also update the status field to 'expired'.
        """
        if self.expires < timezone.now():
            self.status = 'expired'
            self.save()
        return self.status == 'expired'

    def mark_as_used(self):
        self.status = 'used'
        self.used_at = timezone.now()
        self.save()

    def generate_code(self):
        """Generate a 6-character alphanumeric code using a UUID and insert a hyphen"""
        # Generate a UUID and take the first 6 alphanumeric characters
        code = str(uuid.uuid4()).replace('-', '')[:6].upper()
        # Insert the hyphen after the 3rd character
        return f"{code[:3]}-{code[3:]}"






