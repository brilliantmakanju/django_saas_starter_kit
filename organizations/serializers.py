from rest_framework import serializers
from django.utils.text import slugify
from .models import Organization, Domain, UserOrganizationRole
import re, os, uuid
from django.conf import settings
from rest_framework.exceptions import ValidationError

def validate_domain(domain):
    if not re.match(r'^[a-z0-9-]+$', domain):
        raise ValidationError("Domain can only contain lowercase letters, numbers, and hyphens.")
    if Domain.objects.filter(domain=domain).exists():
        raise ValidationError("Domain name is already in use.")
    return domain

def validate_name(name):
    if Organization.objects.filter(name=name).exists():
        raise ValidationError("Name is already in use.")
    return name

def generate_schema_name(name):
    """
    Generates a unique schema name by slugifying the name and appending a UUID.
    """
    base_schema_name = slugify(name)
    unique_schema_name = f"{base_schema_name}-{uuid.uuid4().hex[:8]}"  # Append a short UUID for uniqueness
    return unique_schema_name
#
def get_base_domain():
    """
    Dynamically determines the base domain depending on whether the app is in local or production environment.
    """
    if settings.DEBUG:  # If running in local (DEBUG=True)
        return 'localhost'  # Or another local domain if preferred
    else:
        return os.getenv('HOST_DOMAIN', 'example.com')  # Use the environment variable for production domain


class CommaSeparatedListField(serializers.CharField):
    """
    A custom field that accepts a list of strings and stores them as a comma-separated string,
    and outputs the comma-separated string as a list.
    """
    def to_internal_value(self, data):
        # If data is a list, join it into a comma-separated string.
        if isinstance(data, list):
            data = ','.join(data)
        return super().to_internal_value(data)

    def to_representation(self, value):
        # If the value is a non-empty string, split it by commas and strip whitespace.
        if value:
            return [item.strip() for item in value.split(',') if item.strip()]
        return []

class OrganizationSerializer(serializers.ModelSerializer):
    domain = serializers.CharField(write_only=True, required=False)  # Optional for user input

    class Meta:
        model = Organization
        fields = ['id', 'name', 'description', 'domain']

    def validate(self, attrs):
        # Validate organization name
        attrs['name'] = validate_name(attrs['name'])
        attrs['schema_name'] = generate_schema_name(attrs['name'])  # Generate schema name with UUID

        # Validate domain
        domain = attrs.get('domain', None)

        if not domain:
            # Assign default domain if not provided
            domain = slugify(attrs['name'])
            base_domain = get_base_domain()  # Get base domain (localhost or production)
            domain = f"{domain}.{base_domain}"
        else:
            # Validate the provided domain
            domain = validate_domain(domain)

        attrs['domain'] = domain  # Set the domain in validated data
        return attrs


    def create(self, validated_data):
        domain_name = validated_data.pop('domain')  # Extract domain name
        request = self.context['request']
        user = request.user

        # Create the organization
        organization = Organization.objects.create(owner=user, **validated_data)

        # Create a domain for the organization
        Domain.objects.create(
            domain=domain_name,
            tenant=organization,
            is_primary=True
        )

        # Add the user to the organization with the role specified in the invite
        UserOrganizationRole.objects.create(
            user=user,
            organization=organization,
            role='owner'
        )


        # Add the created organization to the user's organizations
        user.organizations.add(organization)

        return organization




class UpdateOrganizationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Organization
        fields = ['name', 'description']  # Only these fields can be updated

    def validate(self, attrs):
        # Validate organization name
        name = attrs.get('name', None)

        if name:
            # Check if organization name already exists and it's not the same as the current one
            if Organization.objects.filter(name=name).exclude(id=attrs.get('id')).exists():
                raise serializers.ValidationError("Name already exists")

        return attrs

    def update(self, instance, validated_data):
        # Only update the name and description, no domain or other fields
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)

        print(instance)

        # Save the updated organization
        instance.save()

        return instance