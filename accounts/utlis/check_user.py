from rest_framework.exceptions import PermissionDenied
from rest_framework import status

def check_new_user(user):
    """
    Check if a user is marked as a new user.
    """
    if not user.organizations.exists():  # Adjust based on your logic
        raise PermissionDenied(detail="User must create an organization first.", code=status.HTTP_401_UNAUTHORIZED)
