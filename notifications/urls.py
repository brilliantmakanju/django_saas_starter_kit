from django.urls import path
from .views import NotificationListView, UnreadNotificationCheckView, RecentNotificationsView

urlpatterns = [
    # List all notifications for the organization or mark one as read
    path('', NotificationListView.as_view(), name='notification-list'),

    # Check if there are unread notifications
    path('unread/', UnreadNotificationCheckView.as_view(), name='notification-unread'),

    # Fetch the 5 most recent notifications
    path('recent/', RecentNotificationsView.as_view(), name='recent-notifications'),
]
