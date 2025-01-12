from djoser.serializers import UserCreateSerializer as BaseUserCreateSerializer
from rest_framework import serializers
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from organizations.models import InviteCode, UserOrganizationRole
from rest_framework.exceptions import ValidationError
from django.db import transaction
from django.contrib.auth import get_user_model
from rest_framework import serializers
import re, os, requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


User = get_user_model()


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
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'profile', 'bio']

    def validate_profile(self, value):
        """
                Validate the profile image URL to ensure it belongs to Cloudinary and is accessible.
                """
        if value:
            # Ensure the URL is a valid Cloudinary URL (basic structure check)
            cloudinary_url_pattern = re.compile(r"https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+")
            if not cloudinary_url_pattern.match(value):
                raise serializers.ValidationError("Invalid Cloudinary URL format.")

            # Extract the Cloud name from the URL (the second part of the URL is the Cloud name)
            cloud_name = value.split("/")[3]
            expected_cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME')  # Retrieve Cloud name from environment variables

            # Ensure the Cloud name matches the one stored in your .env file
            if cloud_name != expected_cloud_name:
                raise serializers.ValidationError(
                    f"Cloudinary image does not belong to the correct cloud. Expected {expected_cloud_name}.")

            # Optionally, perform a lightweight check to ensure the image is accessible (using a HEAD request)
            try:
                response = requests.head(value, timeout=5)
                if response.status_code != 200:
                    raise serializers.ValidationError("Cloudinary image is not accessible.")
            except requests.exceptions.RequestException:
                raise serializers.ValidationError("Unable to verify the Cloudinary image URL.")

        return value

    # Additional validation for the bio text (optional, for length or forbidden characters)
    def validate_bio(self, value):
        if value and len(value) > 500:
            raise serializers.ValidationError("Bio cannot be longer than 500 characters.")
        return value

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
        organization = user.organizations.first()

        # If the user does not belong to any organization, add `new_user = True` in the response
        if not organization:
            data['new_user'] = True
        else:
            data['new_user'] = False

        # Add user-related information to the response
        data.update({
            'first_name': user.first_name,
            'last_name': user.last_name,
            'profile': user.profile if user.profile else None,
            'bio': user.bio,
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
                    f"Failed to blacklist token: {str(e)}"
                )


        token = super().get_token(user)
        return token




















