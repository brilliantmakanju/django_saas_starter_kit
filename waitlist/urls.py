from django.urls import path
from .views import NewsletterSubscribeView, NewsletterSubscriberCountView, ContactMessageView

urlpatterns = [
    path('newsletter/subscribe/', NewsletterSubscribeView.as_view()),
    path('contact/', ContactMessageView.as_view()),
    # path('newsletter/<str:platform_name>/count/', NewsletterSubscriberCountView.as_view()),
]