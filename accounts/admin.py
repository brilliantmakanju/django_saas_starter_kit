from django.contrib import admin
from .models import UserAccount, SubscriptionPlan

# Register your models here.

admin.site.register(UserAccount)
admin.site.register(SubscriptionPlan)

# STRIPE_TEST_PUBLIC_KEY = os.getenv("STRIPE_TEST_PUBLIC_KEY")
# STRIPE_TEST_SECRET_KEY = os.getenv("STRIPE_TEST_SECRET_KEY")
# STRIPE_LIVE_SECRET_KEY = os.getenv("STRIPE_TEST_SECRET_KEY")


