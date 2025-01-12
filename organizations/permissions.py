from rest_framework.permissions import BasePermission
from .models import OrganizationMember, Permission, Organization


class HasPermission(BasePermission):
    def has_permission(self, request, view):
        # Assuming 'organization_slug' is passed in the URL
        organization_slug = view.kwargs['organization_slug']
        organization = Organization.objects.get(slug=organization_slug)

        # Get the user’s membership in the organization
        try:
            membership = OrganizationMember.objects.get(user=request.user, organization=organization)
        except OrganizationMember.DoesNotExist:
            return False

        # Check if the user has the required permission
        required_permission = view.permission_required
        return membership.permissions.filter(name=required_permission).exists()
