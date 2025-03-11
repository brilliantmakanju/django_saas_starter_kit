from django.contrib import admin
from django.conf import settings
from django.urls import path, include
from django.conf.urls.static import static

urlpatterns = [
    # Use the custom admin URL defined in the environment variable
    path(f'{settings.CUSTOM_ADMIN_URL}/', admin.site.urls),  # Custom URL for the admin panel

    # Authentication and JWT-related URLs
    path('api/v1/auth/', include('djoser.urls')),  # Djoser authentication endpoints
    path('api/v1/auth/jwt/', include('djoser.urls.jwt')),  # JWT-specific auth endpoints
    path('api/v1/auth/social/', include('drf_social_oauth2.urls', namespace='drf')),  # Social auth endpoints

    # Management-related endpoints (Profiles, Refresh Tokens, etc.)
    path('api/v1/managements/', include('accounts.urls')),  # User management endpoints

    # Organization-related endpoints
    path('api/v1/organizations/', include('organizations.urls')),  # All organization related actions

    # Notifications (Accessing and marking notifications as read)
    path('api/v1/notifications/', include('notifications.urls')),  # Notifications management

    # Core (Webhook and related functionality)
    path('api/v1/', include('core.urls')),  # Prefix all core URLs with api/v1/ for core app routes

    # Subscription and Stripe Webhooks
    # path('api/v1/subscriptions/', include('subscriptions.urls')),  # Subscription endpoints like creating, managing
    # path('api/v1/stripe/webhook/', include('subscriptions.urls')),  # Stripe webhook to handle subscriptions
]



# Serve media files during development
# if settings.DEBUG:
# removed for now.
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)