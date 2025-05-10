from django.db import transaction
from dotenv import load_dotenv
from organizations.models import Organization, Domain, UserOrganizationRole
import uuid
from accounts.serializers import get_base_domain
from django.utils.text import slugify
import threading

load_dotenv()

def create_organization_for_user(user, first_name, last_name):
    """
    Create a friendly organization name and associated domain and role.
    """
    if not UserOrganizationRole.objects.filter(user=user).exists():
        unique_identifier = uuid.uuid4().hex[:4]

        # Create a friendly, readable org name
        raw_org_name = f"{first_name}-{last_name}-{unique_identifier}"
        organization_name = slugify(raw_org_name)

        base_domain = get_base_domain()
        full_domain = f"{organization_name}.{base_domain}"

        with transaction.atomic():
            organization = Organization.objects.create(
                owner=user,
                name=organization_name.replace('-', ' ').title(),  # Human-readable for UI:
                schema_name=organization_name  # Slugified, domain-safe
            )

            Domain.objects.bulk_create([
                Domain(domain=full_domain, tenant=organization, is_primary=True)
            ])

            UserOrganizationRole.objects.create(
                user=user,
                organization=organization,
                role='owner'
            )

def create_organization_in_background(user, first_name, last_name):
    def _worker():
        try:
            create_organization_for_user(user, first_name, last_name)
        except Exception as e:
            # Optional: log this error
            print(f"[OrgCreationError] {user.email}: {str(e)}")

    threading.Thread(target=_worker, daemon=True).start()
