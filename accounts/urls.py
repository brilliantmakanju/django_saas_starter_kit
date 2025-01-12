from django.urls import path
from .views import (
    UserProfileUpdateView,
    RefreshTokenView,
    CustomTokenObtainPairView,
    LogoutView,
    CreateSubscriptionAPIView,
    get_jwt_from_oauth,
    stripe_webhook,
    ProtectedRouteView,
    SocialCallBack
)

urlpatterns = [
    # Authentication Endpoints
    path('login/', CustomTokenObtainPairView.as_view(), name="auth-login"),
    path('logout/', LogoutView.as_view(), name="auth-logout"),
    path('refresh/', RefreshTokenView.as_view(), name="auth-refresh"),
    path('jwt-access/', get_jwt_from_oauth, name='auth-jwt-access'),
    path('twitter/callback/', SocialCallBack.as_view(), name='social-twitter-callback'),

    # Subscription Endpoints
    path('subscriptions/create/', CreateSubscriptionAPIView.as_view(), name='subscriptions-create'),

    # Stripe Webhook
    path('webhooks/stripe/', stripe_webhook, name='stripe-webhook'),

    # Protected Route (Only accessible to authenticated users)
    path('protected/', ProtectedRouteView.as_view(), name='protected-route'),

    # User Profile Endpoints
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update')
]
