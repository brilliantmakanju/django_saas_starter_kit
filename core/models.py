from django.contrib.auth import get_user_model
from django.db import models
from django.conf import settings
import uuid
from cryptography.fernet import Fernet
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from organizations.models import Organization


class Platform(models.TextChoices):
    TWITTER = 'twitter', 'Twitter'
    LINKEDIN = 'linkedin', 'LinkedIn'

class PostGroup(models.Model):
    """
    A group that contains multiple posts generated for different platforms but from the same content.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, blank=True, null=True)  # Ensure this field exists
    description = models.TextField(blank=True, null=True)  # Ensure this field exists

    # ForeignKey to connect the post to the organization
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="posts_group_organization")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Post Group {self.id} - Created at {self.created_at}"

class Post(models.Model):
    class Status(models.TextChoices):
        DRAFTED = 'drafted', 'Drafted'
        PUBLISHED = 'published', 'Published'
        SCHEDULED = 'scheduled', 'Scheduled'
        DELETED = 'deleted', 'Deleted'
        INACTIVE = 'inactive', 'Inactive'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    content = models.TextField()
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.DRAFTED)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Scheduling fields
    scheduled_publish_time = models.DateTimeField(null=True, blank=True)
    actual_publish_time = models.DateTimeField(null=True, blank=True)

    # Track the original status of the post before deletion or inactivity
    original_status = models.CharField(max_length=10, choices=Status.choices, null=True, blank=True)

    # Cloudinary URLs for the media
    image_urls = models.JSONField(default=list, blank=True)  # List of image URLs
    video_url = models.URLField(blank=True, null=True)  # Single video URL

    # Trash field to store deleted posts
    platform = models.CharField(max_length=50, choices=Platform.choices)  # The platform for which this post is intended
    original_post = models.ForeignKey("self", on_delete=models.CASCADE, null=True, blank=True,
                                      related_name="platform_posts")

    # Grouping field to link posts from different platforms together
    post_group = models.ForeignKey(PostGroup, on_delete=models.CASCADE, related_name="posts", null=True, blank=True)

    # Track post group when AI generates for multiple platforms
    is_grouped = models.BooleanField(default=False)  # Indicate if this post is part of a group

    # ForeignKey to connect the post to the organization
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="posts")

    # Track if a post has been deleted or is inactive
    is_deleted = models.BooleanField(default=False)  # To indicate if the post is deleted
    is_inactive = models.BooleanField(default=False)  # To indicate if the post is inactive

    # Priority Check to make sure we post the one set by the user if selected.
    priority = models.BooleanField(default=False) # To indicate which to post

    def clean(self):
        if self.image_urls and self.video_url:
            raise ValidationError("You can't upload both images and videos in the same post.")
        # if not self.image_urls and not self.video_url:
        #     raise ValidationError("At least one image or video must be uploaded.")

    def delete(self, *args, **kwargs):
        # If the post is being deleted, store its original status and set it as deleted
        self.original_status = self.status
        self.status = self.Status.DELETED
        self.is_deleted = True  # Mark it as deleted
        self.is_inactive = False  # Ensure it's not inactive when deleted
        self.save()

    def deactivate(self):
        # If the post is being deactivated, store its original status and set it as inactive
        self.original_status = self.status
        self.status = self.Status.INACTIVE
        self.is_inactive = True  # Mark it as inactive
        self.is_deleted = False  # Ensure it's not marked as deleted
        self.save()

    @classmethod
    def clear_trash(cls):
        cls.objects.filter(is_deleted=True).delete()
        cls.objects.filter(is_inactive=True).delete()


    @classmethod
    def restore(cls, post_id):
        post = cls.objects.get(id=post_id)
        post.status = post.original_status or cls.Status.DRAFTED  # Restore to the original status or drafted
        post.is_deleted = False
        post.is_inactive = False
        post.save()

    def __str__(self):
        return f"Post {self.content[:50]}... ({self.platform}) - {self.organization.name}"


    def schedule_publish(self, delay_minutes=15):
        """Schedule the post to be published after a certain delay."""
        self.scheduled_publish_time = timezone.now() + timedelta(minutes=delay_minutes)
        self.save()

    def publish(self):
        """Mark the post as published."""
        self.status = Post.Status.PUBLISHED
        self.actual_publish_time = timezone.now()
        self.save()

    def is_ready_to_publish(self):
        """Check if the post is ready to be published."""
        # Check if the post is in draft or scheduled state and not marked as deleted or inactive
        return self.status in [Post.Status.DRAFTED,
                               Post.Status.SCHEDULED] and not self.is_deleted and not self.is_inactive and self.scheduled_publish_time <= timezone.now()


class SocialMediaAccount(models.Model):
    """
    Represents a social media account (Twitter, LinkedIn) connected to an organization.
    """
    TWITTER = 'twitter'
    LINKEDIN = 'linkedin'
    PLATFORM_CHOICES = [
        (TWITTER, 'Twitter'),
        (LINKEDIN, 'LinkedIn'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('organizations.Organization', on_delete=models.CASCADE, related_name="social_media_accounts")
    user = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True, blank=True)  # The user who connected the account
    platform = models.CharField(max_length=50, choices=PLATFORM_CHOICES)
    access_token = models.CharField(max_length=512)
    access_token_secret = models.CharField(max_length=255, null=True, blank=True)  # For Twitter only
    access_id_secret = models.CharField(max_length=255, null=True, blank=True)  # For LinkedIn only
    connected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.organization.name} - {self.platform}'

    class Meta:
        unique_together = ['organization', 'platform']

# Helper function to generate and encrypt a secret
def generate_encrypted_secret():
    # Generate a new UUID secret
    secret = str(uuid.uuid4())

    # Encrypt using the FERNET_KEY
    fernet = Fernet(settings.FERNET_KEY.encode())  # Using the correct Fernet key
    encrypted_secret = fernet.encrypt(secret.encode()).decode()
    return encrypted_secret

class Webhook(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField(Organization, on_delete=models.CASCADE, related_name="webhook")
    public_secret = models.CharField(max_length=255, blank=True, null=True)  # Secret shown to user for GitHub
    private_secret = models.CharField(max_length=255, blank=True, null=True)  # Secret used for internal validation
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)
    url = models.URLField(max_length=500, blank=True, null=True)  # GitHub webhook URL
    allowed_ips = models.TextField(blank=True, null=True)  # Comma separated list of allowed IPs for security

    repo = models.CharField(max_length=255, blank=False, null=False, default="repo")  # GitHub repository
    branch = models.CharField(max_length=100, blank=False, null=False, default="main")  # GitHub branch

    # Ensuring secret is generated and encrypted upon creation
    def save(self, *args, **kwargs):
        if not self.public_secret or not self.private_secret:
            self.public_secret = generate_encrypted_secret()  # Generate public secret on save
            self.private_secret = generate_encrypted_secret()  # Generate private secret on save
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Webhook for {self.organization.name}"

    def clean(self):
        if Webhook.objects.filter(organization=self.organization).exists() and not self.pk:
            raise ValidationError("An organization can only have one webhook.")