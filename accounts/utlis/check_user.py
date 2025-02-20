from rest_framework.exceptions import PermissionDenied
from rest_framework import status
from accounts.models import UserAccount

def check_new_user(user):
    """
    Check if a user is marked as a new user.
    """
    if not user.organizations.exists():  # Adjust based on your logic
        raise PermissionDenied(detail="User must create an organization first.", code=status.HTTP_401_UNAUTHORIZED)

def has_pro_access(user):
    """
    Checks if a user has an active 'pro' subscription.
    Returns True if they do, otherwise False.
    """
    if not user.is_authenticated:
        return False  # Ensure the user is logged in

    # Update the subscription status (this refreshes the model in case of webhook updates)
    user.update_subscription_status()

    return user.plan == UserAccount.PRO and user.has_active_subscription()