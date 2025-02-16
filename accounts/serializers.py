from djoser.serializers import UserCreateSerializer as BaseUserCreateSerializer
from organizations.models import Organization, Domain
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from organizations.models import InviteCode, UserOrganizationRole
from django.db import transaction
from django.contrib.auth import get_user_model
from rest_framework import serializers
import re, os, requests, uuid
from django.utils.text import slugify
from dotenv import load_dotenv
from rest_framework.exceptions import ValidationError
from django.conf import settings


# Load environment variables from .env file
load_dotenv()


User = get_user_model()

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

def get_base_domain():
    """
    Dynamically determines the base domain depending on whether the app is in local or production environment.
    """
    if settings.DEBUG:  # If running in local (DEBUG=True)
        return 'localhost'  # Or another local domain if preferred
    else:
        return os.getenv('HOST_DOMAIN', 'example.com')  # Use the environment variable for production domain



class UserCreateSerializer(BaseUserCreateSerializer):
    invite_code = serializers.CharField(required=False, write_only=True)

    class Meta(BaseUserCreateSerializer.Meta):
        model = User
        fields = BaseUserCreateSerializer.Meta.fields + ('invite_code',)

    def validate(self, attrs):
        """
        Validate the invite code if provided.
        """
        invite_code = attrs.pop('invite_code', None)

        # Validate the invite code if provided
        if invite_code:
            try:
                invite = InviteCode.objects.get(secret=invite_code)
            except InviteCode.DoesNotExist:
                raise ValidationError({'invite_code': 'Invalid invite code.'})

            if invite.is_expired():
                raise ValidationError({'invite_code': 'The invite code has expired.'})

            if invite.invitee_email != attrs['email']:
                raise ValidationError({'invite_code': 'This invite code is not associated with the provided email.'})

            # Store the valid invite in the serializer context for later use
            self.context['invite'] = invite

        return super().validate(attrs)

    def create(self, validated_data):
        """
        Create the user and handle invite acceptance if an invite is used.
        """
        # Create the user
        user = super().create(validated_data)

        # If there is a valid invite, proceed to handle it
        invite = self.context.get('invite_code', None)

        # If invite exists and is valid, add the user to the organization
        if invite:
            try:
                # Assign the user to the organization and role specified in the invite
                with transaction.atomic():  # Ensure atomicity of the process
                    UserOrganizationRole.objects.create(
                        user=user,
                        organization=invite.organization,
                        role=invite.role
                    )

                    # Mark the invite as used
                    invite.mark_as_used()

            except Exception as e:
                # If anything goes wrong, we roll back by deleting the user
                user.delete()
                raise ValidationError({'invite_code': 'An error occurred while processing the invite. Please try again.'})

        # Return the created user
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField(required=False, allow_blank=True)

    email = serializers.EmailField(read_only=True)
    preferences = serializers.JSONField(read_only=True)
    stripe_subscription_id = serializers.CharField(read_only=True)
    github_connected = serializers.BooleanField(read_only=True)
    google_connected = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            'full_name', 'first_name', 'last_name', 'profile', 'bio', 'email',
            'preferences', 'stripe_subscription_id', 'github_connected', 'google_connected'
        ]
        read_only_fields = ['first_name', 'last_name']  # These will be set through `full_name`

    def validate_full_name(self, value):
        """
        Splits full_name into first_name and last_name before saving.
        """
        value = value.strip()
        if value:
            name_parts = value.split(" ", 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            self.initial_data['first_name'] = first_name
            self.initial_data['last_name'] = last_name

        return value

    def to_representation(self, instance):
        """
        Returns full_name dynamically from first_name and last_name.
        """
        representation = super().to_representation(instance)
        representation['full_name'] = f"{instance.first_name} {instance.last_name}".strip()
        return representation


class UserLoginSerializer(serializers.ModelSerializer):
    """
    Serialize non-sensitive user data for the login response.
    """
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'first_name',
            'last_name',
            'bio',
            'preferences',
            'github_connected',
            'google_connected'
        )

class CreateSubscriptionSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    payment_method = serializers.CharField(max_length=255)
    price_id = serializers.CharField(max_length=255)
    plan_id = serializers.CharField(max_length=255)



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    first_name = serializers.CharField( read_only=True)
    last_name = serializers.CharField(read_only=True)
    email = serializers.CharField(read_only=True)
    profile = serializers.CharField(allow_blank=True, read_only=True)
    bio = serializers.CharField(allow_blank=True, read_only=True)
    preferences = serializers.JSONField(default=dict, read_only=True)
    stripe_subscription_id = serializers.CharField(allow_blank=True, read_only=True)
    github_connected = serializers.BooleanField(read_only=True)
    google_connected = serializers.BooleanField(read_only=True)

    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        # Check if the user belongs to any organization
        # organization = user.organizations.first()
        organization = UserOrganizationRole.objects.filter(user=user).first()


        # Determine if the user is a new user
        new_user = not organization and (not user.first_name or not user.last_name)
        data['new_user'] = new_user


        # Create an organization if user has no organization but has first_name and last_name
        if not organization and user.first_name and user.last_name:
            # Generate a unique organization name using first_name, last_name, and a UUID
            unique_identifier = str(uuid.uuid4())  # Generate a UUID
            organization_name = f"{user.first_name[:3]}{unique_identifier[:4]}{user.last_name[-3:]}".lower()

            # Create the organization
            organization = Organization.objects.create(
                owner=user,
                name=organization_name,
                schema_name=organization_name
            )

            domain = slugify(organization_name)
            base_domain = get_base_domain()  # Get base domain (localhost or production)
            domain = f"{domain}.{base_domain}"


            # Create a domain for the organization
            Domain.objects.create(
                domain=domain,
                tenant=organization,
                is_primary=True
            )

            # Add the user to the organization with the role specified in the invite
            UserOrganizationRole.objects.create(
                user=user,
                organization=organization,
                role='owner'
            )

            data['new_user'] = False



        # Add user-related information to the response
        data.update({
            'first_name': user.first_name,
            'last_name': user.last_name,
            'profile': user.profile if user.profile else None,
            'bio': user.bio,
            'email': user.email,
            'preferences': user.preferences,
            'stripe_subscription_id': user.stripe_subscription_id,
            'github_connected': user.github_connected,
            'google_connected': user.google_connected,
        })

        return data

    @classmethod
    def get_token(cls, user):

        # Blacklist all outstanding tokens for the user
        outstanding_tokens = OutstandingToken.objects.filter(user=user)

        for outstanding_token in outstanding_tokens:
            try:
                # Add to BlacklistedToken model
                BlacklistedToken.objects.get_or_create(token=outstanding_token)
            except Exception as e:
                raise serializers.ValidationError(
                    f"Failed to blacklist user"
                )


        token = super().get_token(user)
        return token




















