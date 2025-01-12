from notifications.models import Notification
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from organizations.models import UserOrganizationRole
from django.contrib.contenttypes.models import ContentType

def create_and_notify(organization, title, message, triggered_by=None, related_object=None, template_path=None):
    """
    Create a notification and send an email to organization admins and owner.

    Args:
        organization: The organization instance for which the notification is created.
        title (str): Title of the notification.
        message (str): Message body of the notification.
        triggered_by: (Optional) User instance that triggered the notification.
        related_object: (Optional) Object associated with the notification (e.g., a post, user action).

    Returns:
        Notification: The created notification instance.
    """
    # Create the notification
    content_type = None
    object_id = None

    if related_object:
        content_type = ContentType.objects.get_for_model(related_object)
        object_id = related_object.id


    notification = Notification.objects.create(
        organization=organization,
        title=title,
        message=message,
        triggered_by=triggered_by,
        content_type=content_type,
        object_id=object_id
    )

    # Send email to admins and owner
    _send_notification_email(organization, notification, template_path=template_path)

    return notification


def _send_notification_email(organization, notification, template_path='emails/notification_email.html'):
    """
    Send an email to organization admins and owner about the notification.

    Args:
        organization: The organization instance for which the email is sent.
        notification: The notification instance containing the title and message.

    Returns:
        None
    """
    # Fetch admins and owner
    admin_roles = UserOrganizationRole.objects.filter(
        organization=organization,
        role__in=["admin", "owner"]
    ).select_related('user')

    if not admin_roles.exists():
        return  # No valid recipients to send the email to

    for role_entry in admin_roles:
        user = role_entry.user
        if not user.email:
            continue  # Skip users without email addresses

        # Render email HTML content with user role and notification details
        subject = f"New Notification for {organization.name}: {notification.title}"
        html_message = render_to_string(template_path, {
            'organization': organization,
            'notification': notification,
            'user_role': role_entry.role.capitalize(),  # Admin or Owner
            'message': notification.message,
            'title': notification.title,
            'triggered_by': notification.triggered_by.username if notification.triggered_by else 'System',
        })


        # Initialize and send the email
        email = EmailMessage(
            subject=subject,
            body=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.content_subtype = "html"  # Specify HTML content type
        email.send(fail_silently=False)






