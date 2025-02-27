from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Notification
from .serializers import NotificationSerializer
from rest_framework.permissions import IsAuthenticated
from accounts.permissions import TenantAccessPermission


class NotificationListView(APIView):
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get(self, request):
        """
        Fetch all notifications for the organization and return them along with a count.
        """
        organization = getattr(request, 'organization', None)
        if not organization:
            return Response({"error": "Organization context not found."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch notifications for the organization, ordered by created_at descending.
        notifications = Notification.objects.filter(organization=organization).order_by('-created_at')

        # Serialize notifications, passing the request context.
        serializer = NotificationSerializer(notifications, many=True, context={'request': request})

        # Count total notifications.
        total_count = notifications.count()

        # Count unread notifications for the current user using the computed field.
        unread_count = notifications.exclude(is_read_by=request.user).count()

        return Response({
            "total_count": total_count,
            "unread_count": unread_count,
            "notifications": serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Mark a specific notification as read by the logged-in user.
        Pass notification ID in the request data.
        """
        notification_id = request.GET.get("notification_id")
        if not notification_id:
            return Response({"error": "Notification ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            notification = Notification.objects.get(id=notification_id)
            # Ensure the notification belongs to the same organization
            if notification.organization != getattr(request, 'organization', None):
                return Response({"error": "You do not have access to this notification."}, status=status.HTTP_403_FORBIDDEN)

            # Mark notification as read for the user
            notification.is_read_by.add(request.user)
            notification.save()

            return Response({"message": "Notification marked as read."}, status=status.HTTP_200_OK)

        except Notification.DoesNotExist:
            return Response({"error": "Notification not found."}, status=status.HTTP_404_NOT_FOUND)


class UnreadNotificationCheckView(APIView):
    """
    Endpoint to check if there are unread notifications for the user.
    """
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get(self, request):
        organization = getattr(request, 'organization', None)
        if not organization:
            return Response({"error": "Organization context not found."}, status=status.HTTP_400_BAD_REQUEST)

        # Check unread notifications for the user
        unread_notifications = Notification.objects.filter(
            organization=organization
        ).exclude(is_read_by=request.user).exists()

        return Response({"has_unread": unread_notifications}, status=status.HTTP_200_OK)


class RecentNotificationsView(APIView):
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get(self, request):
        """
        Fetch the 5 most recent notifications for the organization.
        """
        organization = getattr(request, 'organization', None)
        if not organization:
            return Response({"error": "Organization context not found."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch only the 5 most recent notifications
        recent_notifications = Notification.objects.filter(organization=organization).order_by('-created_at')[:5]

        # Serialize the notifications
        serializer = NotificationSerializer(recent_notifications, many=True, context={'request': request})

        return Response({
            "notifications": serializer.data
        }, status=status.HTTP_200_OK)


# def create_notification(organization, title, message, triggered_by, related_object=None):
#     """
#     Utility function to create a new notification.
#     """
#     notification = Notification.objects.create(
#         organization=organization,
#         title=title,
#         message=message,
#         triggered_by=triggered_by,
#     )
#     if related_object:
#         notification.content_type = ContentType.objects.get_for_model(related_object)
#         notification.object_id = related_object.id
#         notification.save()
#
#     # Trigger email notifications for owners/admins
#     send_email_notification(organization, title, message)
#
#
# def send_email_notification(organization, title, message):
#     """
#     Send email notification to organization owners and admins.
#     """
#     recipients = organization.users.filter(is_owner=True) | organization.users.filter(is_admin=True)
#     recipient_emails = [user.email for user in recipients]
#
#     # Logic to send emails (using Django's send_mail or an external provider)
#     send_mail(
#         subject=title,
#         message=message,
#         from_email='noreply@yourdomain.com',
#         recipient_list=recipient_emails,
#     )
