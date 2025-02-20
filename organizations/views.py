from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.utlis.check_user import has_pro_access
from core.utlis import is_organization_owner_or_admin
from django.contrib.auth import get_user_model

from accounts.permissions import TenantAccessPermission
from .models import Organization, Domain, UserOrganizationRole, InviteCode
from .serializers import OrganizationSerializer, UpdateOrganizationSerializer

from accounts.utlis.utlis import is_organization_owner, send_invitation_email

class OrganizationView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
           Creates a new organization for the authenticated user.

           **Request Body**:
           - `name`: Name of the organization (required).
           - `description`: Description of the organization (optional).
           - `domain`: Custom domain for the organization (optional).

           **Response**:
           - `message`: Success message.
           - `organization`: Created organization details.
       """
        user = request.user

        # Restrict organization creation to PRO users
        if not has_pro_access(user):
            return Response({
                "error": "Permission denied",
                "message": "You need a Pro subscription to create an organization."
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = OrganizationSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            # Save organization and related domain
            organization = serializer.save()

            return Response({
                'message': 'Organization created successfully.',
                'organization': {
                    'id': organization.id,
                    'name': organization.name,
                    'description': organization.description,
                }
            }, status=status.HTTP_201_CREATED)
        # If serializer is not valid, return errors with status 400
        return Response({
            'error': 'Validation failed',
            'message': 'Please provide valid data.',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """
        Get all organizations associated with the logged-in user.
        For each organization, find and append the associated domains.
        """
        user = request.user

        org_id = request.GET.get("id")

        if org_id:
            try:
                organization = Organization.objects.get(id=org_id, owner=user)
                serializer = OrganizationSerializer(organization)
                domain = Domain.objects.filter(tenant=organization).values_list("domain", flat=True)
                data = serializer.data
                data["domains"] = list(domain)
                return Response(data, status=status.HTTP_200_OK)
            except Organization.DoesNotExist:
                return Response({"message": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            # Fetch all organizations associated with the user, ordered alphabetically
            user_organizations = UserOrganizationRole.objects.filter(user=user).select_related('organization')
            organizations = [user_org.organization for user_org in user_organizations]
            organizations = sorted(organizations, key=lambda org: org.name.lower())  # Order alphabetically by name

            # Prepare a list to hold the organizations with their associated domains
            organization_data = []

            for organization in organizations:
                # Get the domains associated with this organization
                domains = Domain.objects.filter(tenant=organization)

                # Serialize the domains into a list
                domain_list = [domain.domain for domain in domains]

                # Serialize the organization data using OrganizationSerializer
                organization_serializer = OrganizationSerializer(organization)

                # Add the domains to the organization data
                org_data = organization_serializer.data
                org_data['domains'] = domain_list

                # Append the modified organization data to the list
                organization_data.append(org_data)

            # Return a response with the list of organizations and their associated domains
            return Response({
                'message': 'Organizations fetched successfully.',
                'organizations': organization_data,
                'user_id': request.user.id
            }, status=status.HTTP_200_OK)

    def put(self, request):
        """
        Handle the PUT request for updating an organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to update the organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        try:
            # Check if the current user is the owner of the organization
            if organization.owner != request.user:
                return Response({
                    'message': 'You do not have permission to update this organization.'
                }, status=status.HTTP_403_FORBIDDEN)

            # Create and validate the serializer
            serializer = UpdateOrganizationSerializer(organization, data=request.data, partial=True,
                                                context={'request': request})

            if serializer.is_valid():
                updated_organization = serializer.save()

                # Retrieve the updated organization instance with all fields (including domain, etc.)
                updated_organization = Organization.objects.get(id=updated_organization.id)
                updated_domain = Domain.objects.get(tenant=updated_organization.id)

                print(updated_domain, "Domains and ALl right")


                # Return success response with the updated organization data
                return Response({
                    'message': 'Organization updated successfully.',
                    'organization': {
                        'id': updated_organization.id,
                        'name': updated_organization.name,
                        'description': updated_organization.description,
                        'domain': f'{updated_domain}',
                    }
                }, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Organization.DoesNotExist:
            return Response({
                'message': 'Organization not found.'
            }, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request):
        """
        Handle the DELETE request for deleting an organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to add delete organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        try:
            # Delete the organization
            organization.delete()

            # Return success response
            return Response({
                'message': 'Organization deleted successfully.'
            }, status=status.HTTP_204_NO_CONTENT)

        except Organization.DoesNotExist:
            return Response({
                'message': 'Organization not found.'
            }, status=status.HTTP_404_NOT_FOUND)

class IsOwner(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        Check if the user is the owner of the organization.
        Returns True if the user is the owner, False otherwise.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'is_owner': False}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is the owner
        organization_owner = is_organization_owner(request.user, organization)

        return Response({'is_owner': organization_owner}, status=status.HTTP_200_OK)

class TeamMembersView(APIView):
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]

    def post(self, request):
        """
        Add or Update a team member in the organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to add team members.'},
                            status=status.HTTP_403_FORBIDDEN)

        user_email = request.data.get('user_email')
        role = request.data.get('role')

        if not user_email or not role:
            return Response({'message': 'Email and role are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if role.lower() == "owner":
            # Send a special message if the role is 'owner'
            return Response({
                'message': 'The organization owner role cannot be assigned manually. Please use the proper channels to transfer ownership.'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if the user exists
        user = get_user_model().objects.filter(email=user_email).first()
        if user:
            # Check if the user is already a member of the organization
            if UserOrganizationRole.objects.filter(organization=organization, user=user).exists():
                return Response({'message': f'{user_email} is already a member of the organization.'},
                                status=status.HTTP_400_BAD_REQUEST)
            # Send an invitation email to the user
            send_invitation_email(user_email, organization, role, action_type="invite")
            return Response({
                'message': f'{user_email} has been invited to join the organization.'
            }, status=status.HTTP_200_OK)
        else:
            # If the user does not exist, send an invitation email to sign up
            send_invitation_email(user_email, organization, role, action_type="join")
            return Response({'message': 'User invitation sent successfully. They will receive an email to join the organization.'}, status=status.HTTP_200_OK)

    def patch(self, request):
        """
        Update the role of a user in an organization.
        """
        organization = getattr(request, 'organization', None)
        target_user = request.GET.get('id')

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to edit team members.'},
                            status=status.HTTP_403_FORBIDDEN)


        # Fetch the user to be updated
        try:
            target_user_role = UserOrganizationRole.objects.get(user_id=target_user, organization=organization)
        except UserOrganizationRole.DoesNotExist:
            return Response({"detail": "User not found in this organization."}, status=status.HTTP_404_NOT_FOUND)

        # Prevent deleting the owner
        if target_user_role.role == "owner":
            return Response({"detail": "The organization owner role cannot be edited."}, status=status.HTTP_400_BAD_REQUEST)


        # Validate the new role
        new_role = request.data.get("role")
        if new_role not in ["admin", "member"]:  # Adjust roles as per your application's needs
            return Response({"detail": "Invalid role."}, status=status.HTTP_400_BAD_REQUEST)

        # Update the role
        target_user_role.role = new_role
        target_user_role.save()

        return Response({"detail": "User role updated successfully."}, status=status.HTTP_200_OK)

    def delete(self, request):
        """
        Remove a user from an organization.
        """
        user = request.user

        organization = getattr(request, 'organization', None)
        target_user = request.GET.get('id')

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to delete team members.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Fetch the user to be deleted
        try:
            target_user_role = UserOrganizationRole.objects.get(user_id=target_user, organization=organization)
        except UserOrganizationRole.DoesNotExist:
            return Response({"detail": "User not found in this organization."}, status=status.HTTP_404_NOT_FOUND)

        # Prevent deleting the owner
        if target_user_role.role == "owner":
            return Response({"detail": "The organization owner cannot be deleted."}, status=status.HTTP_400_BAD_REQUEST)

        # Delete the user
        target_user_role.delete()

        return Response({"detail": "User removed from the organization."}, status=status.HTTP_200_OK)

class JoinOrganizationView(APIView):
    """
    API endpoint for users to join an organization using an invite code.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        invite_code = request.data.get('invite_code')

        if not invite_code:
            return Response({"error": "Invite code is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the invite based on the code
            invite = InviteCode.objects.get(code=invite_code)
        except InviteCode.DoesNotExist:
            return Response({"error": "Invalid invite code."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the invite is expired or already used
        if invite.is_expired() or invite.status != "pending":
            return Response({"error": "Invite code is expired or already used."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the invite matches the user's email
        if invite.invitee_email != request.user.email:
            return Response({"error": "This invite code is not associated with your account."}, status=status.HTTP_403_FORBIDDEN)

        # Add the user to the organization with the role specified in the invite
        UserOrganizationRole.objects.create(
            user=request.user,
            organization=invite.organization,
            role=invite.role
        )

        # Mark the invite as used
        invite.mark_as_used()

        return Response({"message": f"You have successfully joined {invite.organization.name} as {invite.role}."}, status=status.HTTP_200_OK)

class OrganizationJoinView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Join an organization using an invite token.
        """
        secret = request.GET.get("id")
        action = request.data.get("action")  # 'accept' or 'reject'

        if not secret or not action:
            return Response({"detail": "Both 'secret' and 'action' are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the token
        try:
            invite = InviteCode.objects.get(secret=secret)
        except InviteCode.DoesNotExist:
            return Response({"detail": "Invalid or expired invitation token."}, status=status.HTTP_400_BAD_REQUEST)


        # Check if the token is already used
        if invite.status == "used":
            return Response({"detail": "This invitation token has already been used."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is expired
        if invite.is_expired():
            return Response({"detail": "This invitation token has expired."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the token matches the logged-in user
        if invite.invitee_email != request.user.email:
            return Response({"detail": "This token is not associated with your email."}, status=status.HTTP_403_FORBIDDEN)

        if action.lower() == "accept":
            # Check if user is already part of the organization
            if UserOrganizationRole.objects.filter(user=request.user, organization=invite.organization).exists():
                return Response({"detail": "You are already a member of this organization."}, status=status.HTTP_400_BAD_REQUEST)

            # Add the user to the organization
            UserOrganizationRole.objects.create(
                user=request.user,
                organization=invite.organization,
                role=invite.role
            )

            # Mark the token as used
            invite.mark_as_used()

            return Response({"detail": "You have successfully joined the organization."}, status=status.HTTP_200_OK)

        elif action.lower() == "reject":
            # Mark the token as used but not add the user
            invite.status = "used"
            invite.save()

            return Response({"detail": "You have rejected the invitation."}, status=status.HTTP_200_OK)

        return Response({"detail": "Invalid action. Use 'accept' or 'reject'."}, status=status.HTTP_400_BAD_REQUEST)

class TransferOwnershipView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        new_owner_id = request.data.get('new_owner_id')
        organization_slug = kwargs['organization_slug']

        organization = Organization.objects.get(slug=organization_slug)
        current_owner = organization.owner

        # Check if the current user is the owner
        if request.user != current_owner:
            return Response({"detail": "You are not the owner of this organization."}, status=status.HTTP_403_FORBIDDEN)

        # Set the new owner
        new_owner = get_user_model().objects.get(id=new_owner_id)
        organization.owner = new_owner
        organization.save()

        return Response({"detail": "Ownership transferred successfully."})

class UpdateToneSettingsView(APIView):
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        """
        Retrieve the tone settings for the organization, including:
          - The current selected tone.
          - Whether tones are set to shuffle.
          - A list of all available tone choices.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user has permission to view tone settings
        if not is_organization_owner_or_admin(request.user, organization):
            return Response({'message': 'You are not authorized to view tone settings.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Get available tone choices from the Organization model.
        # Assuming Organization.TONE_CHOICES exists, e.g.:
        # TONE_CHOICES = (
        #     ('formal', 'Formal'),
        #     ('casual', 'Casual'),
        #     ('friendly', 'Friendly'),
        # )
        available_tones = [{'value': value, 'display': display} for value, display in organization.TONE_CHOICES]

        data = {
            'selected_tone': organization.selected_tone,
            'shuffle_tones': organization.shuffle_tones,
            'available_tones': available_tones
        }
        return Response(data, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        """
        Update tone settings for the organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user has permission to update settings
        if not is_organization_owner_or_admin(request.user, organization):
            return Response({'message': 'You are not authorized to update tone settings.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Restrict organization creation to PRO users
        if not has_pro_access(request.user):
            return Response({
                "error": "Permission denied",
                "message": "You need a Pro subscription to add or update ai tones."
            }, status=status.HTTP_403_FORBIDDEN)

        # Validate and update tone settings
        tone = request.data.get('selected_tone')
        shuffle = request.data.get('shuffle_tones', False)
        print(tone, "Tones Selected")
        print(shuffle, "Shuffle tone")

        if tone:
            # If tone is a list, validate each tone and join them into a comma-separated string
            if isinstance(tone, list):
                for t in tone:
                    if t not in dict(Organization.TONE_CHOICES):
                        return Response({'message': 'Invalid tone selected: {}'.format(t)},
                                        status=status.HTTP_400_BAD_REQUEST)
                tone_str = ','.join(tone)
            else:
                # If tone is not a list, validate it normally
                if tone not in dict(Organization.TONE_CHOICES):
                    return Response({'message': 'Invalid tone selected.'}, status=status.HTTP_400_BAD_REQUEST)
                tone_str = tone
            organization.selected_tone = tone_str

        organization.shuffle_tones = shuffle
        organization.save()

        # When returning, convert the stored comma-separated tones back into a list
        tones_list = [t.strip() for t in organization.selected_tone.split(',') if t.strip()]

        return Response({
            'message': 'Tone settings updated successfully.',
            'selected_tones': tones_list,
            'shuffle_tones': organization.shuffle_tones
        }, status=status.HTTP_200_OK)

class OrganizationStatusView(APIView):
    """
    View to check the social media connection status (Twitter & LinkedIn) of an organization.
    """
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]


    def get(self, request, *args, **kwargs):
        """
        Retrieves the organization's connection status for Twitter and LinkedIn.
        Only the organization owner can access this information.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to add delete organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        try:
            # Get the social media connection status
            has_twitter = organization.has_twitter  # Assuming you have a field for this
            has_linkedin = organization.has_linkedin  # Assuming you have a field for this

            return Response({
                "organization": organization.name,
                "has_twitter": has_twitter,
                "has_linkedin": has_linkedin
            }, status=status.HTTP_200_OK)

        except Organization.DoesNotExist:
            return Response({"detail": "Organization not found."}, status=status.HTTP_404_NOT_FOUND)
