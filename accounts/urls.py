from django.urls import path
from .views import (
    UserProfileUpdateView,
    RefreshTokenView,
    CustomTokenObtainPairView,
    LogoutView,
    get_jwt_from_oauth,
    stripe_webhook,
    SocialCallBack, LinkedInSocialCallBack,
    ConfirmMagicLinkView, SendMagicLinkView, PaymentView, CreateSubscriptionAPIViews
)


urlpatterns = [
    # Authentication Endpoints
    path('login/', CustomTokenObtainPairView.as_view(), name="auth-login"),
    path('logout/', LogoutView.as_view(), name="auth-logout"),
    path('refresh/', RefreshTokenView.as_view(), name="auth-refresh"),
    path('jwt-access/', get_jwt_from_oauth, name='auth-jwt-access'),
    path('twitter/callback/', SocialCallBack.as_view(), name='social-twitter-callback'),
    path('linkedin/callback/', LinkedInSocialCallBack.as_view(), name='social-linkedin-callback'),
    path('magic-link/send/', SendMagicLinkView.as_view(), name='auth-send-magic-link'),
    path('magic-link/confirm/', ConfirmMagicLinkView.as_view(), name='auth-confirm-magic-link'),

    # Subscription Endpoints
    path('subscriptions/create/', CreateSubscriptionAPIViews.as_view(), name='subscriptions-create'),

    # Stripe Webhook
    path('webhooks/stripe/', stripe_webhook, name='stripe-webhook'),

    # User Profile Endpoints
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update'),

    # Payment Endpoints
    path('payment/create/', PaymentView.as_view(), name='payment-create'),
]
