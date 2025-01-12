from django.urls import path
from .views import NotificationListView, UnreadNotificationCheckView

urlpatterns = [
    # List all notifications for the organization or mark one as read
    path('', NotificationListView.as_view(), name='notification-list'),

    # Check if there are unread notifications
    path('unread/', UnreadNotificationCheckView.as_view(), name='notification-unread'),
]
