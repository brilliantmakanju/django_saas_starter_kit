from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from organizations.models import UserOrganizationRole
from django.core.exceptions import ObjectDoesNotExist
from organizations.models import InviteCode



# Helper function to check if the current user is the organization owner
def is_organization_owner(user, organization):
    """
    Check if the user has access to the organization by verifying:
    1. The user's role in the organization via UserOrganizationRole.
    2. If the user is the owner of the organization.

    If both conditions are true, return True; otherwise, return False.
    """
    try:
        # Check if the user has a valid role in the organization
        user_role = UserOrganizationRole.objects.filter(user=user, organization=organization).first()
        print(user_role.role, "Role")
        # Check if the user is the owner of the organization
        is_owner = organization.owner == user
        print(is_owner, "Is Owner")

        # If both conditions are true, return True
        if user_role.role == "owner" and is_owner:
            return True

        # Return False if either condition is not satisfied
        return False

    except ObjectDoesNotExist:
        # Handle case where organization or roles do not exist
        return False
    # return organization.owner == user

# Helper function to get or create an invite code
def get_or_create_invite_code(user_email, organization, role, invited_by):
    """
    Check for an existing invite code, or create a new one if none exists.
    """
    # Check if a valid invite already exists
    existing_invite = InviteCode.objects.filter(
        invitee_email=user_email,
        organization=organization,
        status='pending',
    ).first()

    if existing_invite and not existing_invite.is_expired():
        # If a valid invite exists, reuse it
        return existing_invite

    # If no valid invite exists, create a new one
    invite_code = InviteCode(
        invitee_email=user_email,
        organization=organization,
        role=role,
        invited_by=invited_by
    )
    invite_code.save()  # Use save to trigger the logic in the model
    return invite_code

# Helper function to send the invitation email
def send_invitation_email(user_email, organization, role="member", action_type="invite"):
    """
    Send an invitation email either to an existing user or a new user with the proper link.
    Also generates an invite code and stores it in the InviteCode model.
    """
    subject = f"You've been invited to join {organization.name}"

    # Generate or retrieve the invite code
    invite_code = get_or_create_invite_code(
        user_email=user_email,
        organization=organization,
        role=role,
        invited_by=organization.owner,  # Assuming the organization has an owner field
    )

    # Prepare the URL with the generated invite code
    invitation_url = f"{settings.FRONTEND_DOMAIN}/invitations/{organization.id}/?email={user_email}&invite_code={invite_code.code}"

    # Determine the email content based on the action type (new user or existing user)
    if action_type == "invite":
        # For existing users, send them a link to view the invitation
        message = render_to_string(
            'emails/invitation_existing_user.html',
            {
                'organization_name': organization.name,
                'user_email': user_email,
                'invitation_url': invitation_url
            }
        )
    elif action_type == "join":
        # For new users, send them a sign-up link and an alternative code link
        signup_url = f"{settings.FRONTEND_DOMAIN}/signup/?invite_code={invite_code.code}"

        message = render_to_string(
            'emails/invitation_new_user.html',
            {
                'organization_name': organization.name,
                'user_email': user_email,
                'signup_url': signup_url,
                'invite_code': invite_code.code
            }
        )

    # Send the email as HTML content
    email = EmailMessage(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user_email]
    )
    email.content_subtype = "html"  # This tells Django to send the email as HTML

    email.send(fail_silently=False)




def send_email(subject, recipient_list, context=None, template=None, plain_message=None, from_email=None):
    """
    Helper function to send emails with optional HTML and plain text support.

    Args:
        subject (str): The subject of the email.
        recipient_list (list): List of email recipients.
        context (dict, optional): Data for rendering the email template. Defaults to None.
        template (str, optional): Path to the HTML template for the email. Defaults to None.
        plain_message (str, optional): Fallback plain text message if template is not provided. Defaults to None.
        from_email (str, optional): Email address of the sender. Defaults to settings.DEFAULT_FROM_EMAIL.

    Returns:
        dict: A dictionary indicating success or error with details.
    """
    try:
        if not recipient_list or not subject:
            raise ValueError("Recipient list and subject are required.")

        from_email = from_email or settings.DEFAULT_FROM_EMAIL

        # Render the HTML content if a template is provided
        html_content = render_to_string(template, context) if template else None

        # Use the plain message as a fallback
        plain_content = plain_message or "This email contains HTML content. Please use an email client that supports HTML."

        # Create the email
        email = EmailMultiAlternatives(subject, plain_content, from_email, recipient_list)

        if html_content:
            email.attach_alternative(html_content, "text/html")

        # Send the email
        email.send()

        return {"success": True, "message": "Email sent successfully."}

    except Exception as e:
        return {"success": False, "error": str(e)}








