from django.db import models
import uuid
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType


class Notification(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read_by = models.ManyToManyField(
        get_user_model(),
        related_name='read_notifications',
        blank=True
    )
    triggered_by = models.ForeignKey(
        get_user_model(),
        on_delete=models.SET_NULL,
        null=True,
        blank=True,  # Allow triggered_by to be completely optional
        related_name='triggered_notifications'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    # Optional: Link to a specific object (e.g., post, user action)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    object_id = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )
    related_object = GenericForeignKey('content_type', 'object_id')

    def __str__(self):
        return f"Notification for {self.organization.name}: {self.title}"
