from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied
from django_tenants.utils import get_tenant_model
from organizations.models import UserOrganizationRole


class TenantAccessPermission(BasePermission):
    def has_permission(self, request, view):
        # Extract the host (domain) from the request
        host = request.get_host().split(':')[0]  # Remove port number if present

        # Ensure the request is coming from localhost (default host)


        # Get the tenant model to check domain
        tenant_model = get_tenant_model()

        # Try to find the tenant associated with the domain (host)
        tenant = tenant_model.objects.filter(domains__domain=host).first()

        if not tenant:
            raise PermissionDenied("No tenant associated with this domain.")

        # Get the current user making the request
        user = request.user

        if not user:
            raise PermissionDenied("User is not authenticated.")

        # Check if the user is connected to the tenant (organization)
        # Assuming `User` model has a `organizations` relationship (ManyToMany or ForeignKey)
        # We filter user organizations to check if user is part of the organization associated with the domain
        # Filter through UserOrganizationRole to ensure the user is part of the organization
        user_organization_role = UserOrganizationRole.objects.filter(
            user=user,  # The logged-in user
            organization__domains__domain=host  # Matching the organization's domain with the host
        ).select_related('organization').first()

        # Check if the user is associated with the organization
        if not user_organization_role:
            raise PermissionDenied("User is not connected to this organization.")

        # Ensure the tenant's schema matches the organization's schema
        if tenant.schema_name != user_organization_role.organization.schema_name:
            raise PermissionDenied("User does not have access to this tenant's resources.")

        # If all checks pass, return True
        return True
