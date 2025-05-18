import re
from django.utils.timezone import now
from django.db import connection
from accounts.utlis.check_user import has_pro_access

import logging
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.exceptions import ObjectDoesNotExist

from sesame.utils import get_query_string
from django.conf import settings

from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

from .permissions import TenantAccessPermission
from drf_social_oauth2.views import AccessToken

from dotenv import load_dotenv
from django.contrib.auth import get_user_model

from .models import UserAccount, SubscriptionPlan, Payment
from .serializers import UserProfileSerializer

from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
import os
from accounts.utlis.utlis import is_organization_owner
from .social_service import (twitter_initiate_oauth,
                             twitter_callback_oauth,
                             linkedin_initiate_oauth,
                             linkedin_callback_oauth)

from organizations.models import Organization, Domain, UserOrganizationRole
import uuid
from accounts.serializers import get_base_domain
from django.utils.text import slugify
from accounts.utlis.utlis import send_email
from sesame.utils import get_user as sesame_get_user

import requests
from paddle_billing.Entities.Notifications import NotificationEvent
from paddle_billing.Notifications import Secret, Verifier
from pathlib import Path
from paddle_billing.Notifications.Requests import Headers
# Load environment variables
from datetime import timedelta
from rest_framework.throttling import AnonRateThrottle
from .utlis.create_organization import create_organization_in_background
load_dotenv()

logger = logging.getLogger(__name__)

User = get_user_model()

secret = os.getenv("PADDLE_WEBHOOK_SECRET")
api_key = os.getenv("PADDLE_API_KEY")


# Debug print to check if the API key is loaded
if secret is None or api_key is None:
    logger.info("WEBHOOK SECRET or API KEY not found. Please check your environment variables.")
else:
    logger.info("WEBHOOK SECRET and API KEY loaded successfully.")

class Request:
    def __init__(self, headers: Headers, body: bytes | str):
        self.headers = headers if headers is not None else {}
        self.body = body.encode() if isinstance(body, str) else body

    @staticmethod
    def create_from_fixture(filename: str, headers: Headers) -> "Request":
        fixture_path = Path(__file__).parent.parent.parent / "_fixtures" / filename

        fixture_data = None
        with fixture_path.open("r") as file:
            fixture_data = file.read().strip()

        return Request(headers=headers, body=fixture_data)

@csrf_exempt
@require_POST
def stripe_webhook(request):
    """
    Handles Paddle webhook events for subscription lifecycle.
    """
    payload = request.POST.dict()
    logger.info(f"Paddle webhook payload: {payload}")

    # Step 1: Verify the signature
    integrity_check = Verifier().verify(request, Secret(secret))

    if integrity_check is True:
        logger.info("Webhook is verified ✅")

        # Parse event from request
        notification = NotificationEvent.from_request(request)

        logger.info(f"Notification ID: {notification.notification_id}")
        logger.info(f"Event ID: {notification.event_id}")
        logger.info(f"Event Type: {notification.event_type}")
        logger.info(f"Occurred At: {notification.occurred_at}")

        event_type = notification.event_type
        # Route based on event type
        if event_type == "customer.created":
            handle_customer_created(notification.data)
        elif event_type == "subscription.activated" or event_type == "subscription.resumed":
            handle_transaction_paid(notification.data)
        elif event_type == "subscription.updated" or event_type == "subscription.canceled":
            handle_subscription_updated(notification.data)

    else:
        logger.error("Webhook signature verification failed ❌")
        return JsonResponse({"error": "Invalid signature"}, status=400)

    return JsonResponse({"status": "success"}, status=200)

def handle_subscription_updated(subscription):
    """
    Handles subscription updates from Paddle.
    Maps Paddle subscription statuses to our UserAccount model.
    """
    customer_id = subscription.customer_id
    status = subscription.status
    price_id = subscription.items[0].price.id if subscription.items else None
    ends_at = subscription.current_billing_period.ends_at if subscription.current_billing_period else None

    if not customer_id or not price_id:
        logger.error("Missing customer_id or price_id in subscription.updated")
        return

    try:
        user = UserAccount.objects.get(stripe_subscription_id=customer_id)
        plan = SubscriptionPlan.objects.filter(stripe_price_id=price_id).first()

        if not plan:
            logger.error(f"No matching plan found for Paddle price ID: {price_id}")
            return

        user.plan = plan.name

        if status == "active":
            user.subscription_status = "active"
            user.subscription_end_date = None  # clear end date if reactivated
        elif status in ["canceled", "paused", "past_due"]:
            # Map Paddle to your internal status
            status_map = {
                "canceled": "canceled",
                "paused": "paused",
                "past_due": "payment_failed",
            }
            user.subscription_status = "canceled"
            user.subscription_end_date = ends_at
        elif status == "trialing":
            logger.warning(f"Ignoring 'trialing' status for user {user.email}, trials not supported")
            return
        else:
            logger.warning(f"Unhandled subscription status: {status}")
            return

        user.save()
        logger.info(f"Subscription updated for user {user.email}, status: {user.subscription_status}, plan: {plan.name}")
    except ObjectDoesNotExist:
        logger.warning(f"User not found for subscription update: {customer_id}")

def handle_transaction_paid(transaction):
    """
    Handles new paid transaction from Paddle.
    - Links the payment to a user
    - Activates subscription
    - Updates the user's plan, status, and dates
    """
    customer_id = transaction.customer_id
    items = transaction.items
    created_at = transaction.created_at
    status = transaction.status

    if not customer_id:
        logger.error("Missing customer_id or user_id in transaction.paid")
        return

    try:
        user = UserAccount.objects.get(stripe_subscription_id=customer_id)

        # Get the plan name from first product name
        main_item = items[0]
        price_id = main_item.price.id if main_item.price else "unknown"
        plan = SubscriptionPlan.objects.filter(stripe_price_id=price_id).first()

        if not plan:
            logger.error(f"No matching plan found for Stripe price ID: {price_id}")
            return

        # user.customer_id = customer_id
        user.subscription_status = status
        user.subscription_start_date = created_at

        if "ltd" in plan.name:
            user.subscription_end_date = timezone.now() + timedelta(days=365 * 999)
        else:
            user.subscription_end_date = None

        user.plan = plan.name
        user.save()

        logger.info(f"Subscription activated via Paddle for user {user.email}, plan: {plan.name}")
    except ObjectDoesNotExist:
        logger.error(f"User not found for transaction.paid user_id: {customer_id}")

def handle_customer_created(customer):
    """
    Handles new Paddle customer creation.
    - Extracts and logs customer info.
    - Optionally stores or syncs user in your DB.
    """
    customer_id = customer.id
    email = customer.email

    logger.info(f"New Paddle customer created:")
    logger.info(f"- ID: {customer_id}")
    logger.info(f"- Email: {email}")


    try:
        user, created = UserAccount.objects.get_or_create(
            email=email,
            defaults={
                "stripe_subscription_id": customer_id
            }
        )
        # ✅ Create organization for new user with name
        if not created:
            logger.info(f"User already exists for email: {email}, updating info.")
            user.stripe_subscription_id = customer_id
            user.save()
    except Exception as e:
        logger.error(f"Failed to create or update user from Paddle customer: {e}")

def blacklist_existing_tokens(user):
    """
    Blacklists all outstanding tokens for the given user.
    This ensures that any previously issued tokens are invalidated.
    """
    with connection.cursor() as cursor:
        cursor.execute("SET search_path TO public")

    tokens = OutstandingToken.objects.filter(user=user)
    for token in tokens:
        # Blacklist each token
        _, created = BlacklistedToken.objects.get_or_create(token=token)
        if created:
            print(f"Token blacklisted: {token}")

@api_view(['POST'])
def get_jwt_from_oauth(request):
    try:
        # Get the OAuth2 access token from the request
        oauth_token = request.data.get('oauth_token')

        # Check if the access token exists
        access_token = AccessToken.objects.get(token=oauth_token)

        # Retrieve the associated user
        user = access_token.user

        # Blacklist any outstanding tokens for this user
        blacklist_existing_tokens(user)

        # Generate a new JWT token pair (refresh and access)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        })
    except AccessToken.DoesNotExist:
        return Response({'error': 'Invalid OAuth2 token'}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """
    Handles user logout by blacklisting the refresh token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh_token = request.headers.get("X-Refresh-Token")
        # Ensure the refresh token is provided in the request headers
        if not refresh_token:
            return Response(
                {"detail": "Refresh token is missing. Please provide a valid refresh token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            outstanding_refresh_token = OutstandingToken.objects.get(token=refresh_token)
        except OutstandingToken.DoesNotExist:
            # Refresh token not found in OutstandingToken
            return JsonResponse(
                {"status": "error", "message": "Refresh token not found in OutstandingToken."},
                status=401  # Unauthorized
            )

        # Check if the refresh token has been blacklisted
        if BlacklistedToken.objects.filter(token=outstanding_refresh_token).exists():
            # The refresh token is blacklisted
            return JsonResponse(
                {"status": "error", "message": "Refresh token is blacklisted. Access denied."},
                status=401  # Unauthorized
            )


        # User for whom the token was issued
        user = outstanding_refresh_token.user

        # Blacklist the old refresh token (done in the background)
        BlacklistedToken.objects.get_or_create(token=outstanding_refresh_token)
        return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]

class UserProfileUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        """
        Update the user's profile (first_name, last_name, profile image, bio) and create an organization if required.
        """

        user = request.user
        serializer = UserProfileSerializer(user, data=request.data, partial=True, context={'request': request})

        if serializer.is_valid():
            updated_data = serializer.validated_data

            # Handle full_name, first_name, last_name, and organization creation logic
            full_name = updated_data.get('full_name', '').strip()

            if full_name:
                name_parts = full_name.split(" ", 1)
                first_name = name_parts[0]
                last_name = name_parts[1] if len(name_parts) > 1 else ""

                user.first_name = first_name
                user.last_name = last_name
                user.save(update_fields=["first_name", "last_name"])

                if not UserOrganizationRole.objects.filter(user=user).exists():
                    unique_identifier = str(uuid.uuid4())
                    organization_name = f"{first_name[:3]}{unique_identifier[:4]}{last_name[-3:]}".lower()

                    organization = Organization.objects.create(
                        owner=user,
                        name=organization_name,
                        schema_name=organization_name
                    )

                    domain_slug = slugify(organization_name)
                    base_domain = get_base_domain()
                    full_domain = f"{domain_slug}.{base_domain}"

                    Domain.objects.create(
                        domain=full_domain,
                        tenant=organization,
                        is_primary=True
                    )

                    UserOrganizationRole.objects.create(
                        user=user,
                        organization=organization,
                        role='owner'
                    )

            # Check profile image URL
            profile = updated_data.get('profile')
            if profile:
                if not re.match(r"https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+", profile):
                    return Response({"detail": "Invalid Cloudinary URL."}, status=status.HTTP_400_BAD_REQUEST)

            # Validate bio length
            bio = updated_data.get('bio')
            if bio and len(bio) > 500:
                return Response({"detail": "Bio cannot exceed 500 characters."}, status=status.HTTP_400_BAD_REQUEST)

            # Save other validated fields
            for field, value in updated_data.items():
                if field not in ["full_name", "first_name", "last_name"]:  # Already handled separately
                    setattr(user, field, value)

            user.save()

            # Return all requested fields in the response
            return Response({
                'detail': 'Profile updated successfully.',
                'user': UserProfileSerializer(user).data
            }, status=status.HTTP_200_OK)

        return Response({
            'detail': 'Invalid data.',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Retrieve the refresh token from headers
        refresh_token = request.headers.get("X-Refresh-Token")

        # Ensure the refresh token is provided in the request headers
        if not refresh_token:
            return Response(
                {"detail": "Refresh token is missing. Please provide a valid refresh token."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            outstanding_refresh_token = OutstandingToken.objects.get(token=refresh_token)
        except OutstandingToken.DoesNotExist:
            # Refresh token not found in OutstandingToken
            return JsonResponse(
                {"status": "error", "message": "Refresh token not found in OutstandingToken."},
                status=401  # Unauthorized
            )

        # Check if the refresh token has been blacklisted
        if BlacklistedToken.objects.filter(token=outstanding_refresh_token).exists():
            # The refresh token is blacklisted
            return JsonResponse(
                {"status": "error", "message": "Refresh token is blacklisted. Access denied."},
                status=401  # Unauthorized
            )


        # User for whom the token was issued
        user = outstanding_refresh_token.user

        # Blacklist the old refresh token (done in the background)
        BlacklistedToken.objects.get_or_create(token=outstanding_refresh_token)

        # Create new refresh and access tokens for the user
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh)
            },
            status=status.HTTP_200_OK
        )


### Social callback to add tokens for posting
class SocialCallBack(APIView):
    # permission_classes = [AllowAny]
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        """
        Initiates the Twitter OAuth process and returns the authorization URL.
        The user should visit the URL to authorize the app to connect to their account.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to link an account to the organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Call the function that starts the Twitter OAuth process
        return twitter_initiate_oauth(request)

    def post(self, request, *args, **kwargs):
        """
        Handles the callback and completes the Twitter OAuth process.
        Retrieves the access tokens and connects the account to the organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to link an account to the organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Call the callback function for Twitter OAuth
        return twitter_callback_oauth(request, organization)

class LinkedInSocialCallBack(APIView):
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        """
        Initiates the LinkedIn OAuth process and returns the authorization URL.
        The user should visit the URL to authorize the app to connect to their account.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update linkedin status for connection
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to link an account to the organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Call the function that starts the LinkedIn OAuth process
        return linkedin_initiate_oauth(request)

    def post(self, request, *args, **kwargs):
        """
        Handles the callback and completes the LinkedIn OAuth process.
        Retrieves the access tokens and connects the account to the organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to link an account to the organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Call the callback function for LinkedIn OAuth
        return linkedin_callback_oauth(request, organization)


class PaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        plan = request.data.get('plan')
        period = request.data.get('period', 'monthly')
        proof_of_payment = request.data.get('proof_of_payment')
        additional_note = request.data.get('additional_note', '')
        transaction_ref = request.data.get('transaction_ref', '')

        # Decode the base64 image if provided
        if proof_of_payment:
            import base64
            from django.core.files.base import ContentFile
            format, imgstr = proof_of_payment.split(';base64,')
            ext = format.split('/')[-1]
            proof_of_payment = ContentFile(base64.b64decode(imgstr), name=f'proof_of_payment.{ext}')


        # Check for existing pending payment
        existing_pending_payment = Payment.objects.filter(user=user, status='pending').exists()
        if existing_pending_payment:
            return Response({'message': 'You have a pending payment. Please wait for approval or rejection before creating a new one.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Create new payment
        payment = Payment.objects.create(
            user=user,
            plan=plan,
            period=period,
            transaction_ref=transaction_ref,
            proof_of_payment=proof_of_payment,
            additional_note=additional_note
        )

        # Send email notification with detailed context
        send_email(
            subject="New Payment Created",
            recipient_list=[settings.DJANGO_PRODUCT_OWNER_EMAIL],
            context={

                "payment_id": payment.id,
                "user": user.email,
                "plan": payment.get_plan_display(),
                "period": payment.get_period_display(),
                "additional_note": payment.additional_note,
                "message": "A new payment has been created and is pending approval."
            },
            template="emails/new_payment_notification.html",
            plain_message="A new payment has been created."
        )

        return Response({'message': 'Payment created successfully. Awaiting approval.'}, status=status.HTTP_201_CREATED)

### Magic Link VIEW ( Send and Confirm Links )
class SendMagicLinkView(APIView):
    throttle_classes = [AnonRateThrottle]
    """
    API view to send a magic link for login or signup.
    """

    def post(self, request):
        email = request.data.get("email")
        first_name = request.data.get("first_name", "").strip()
        last_name = request.data.get("last_name", "").strip()

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        if not self.is_valid_email_format(email):
            return Response({"error": "Invalid email format."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                return Response(
                    {"error": "This account is inactive. Please contact support."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        except User.DoesNotExist:
            user = None

        if user:
            magic_link = f"{settings.FRONTEND_DOMAIN}/{get_query_string(user)}"
            message = "Click the link to log in to your account."

        elif first_name and last_name:
            user = User.objects.create(
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True
            )

            # ✅ Create organization for new user with name
            create_organization_in_background(user, first_name, last_name)

            magic_link = f"{settings.FRONTEND_DOMAIN}/{get_query_string(user)}"
            message = "Click the link to sign up and create your account."



        else:
            # Do not create user if no name; just return success response
            return Response(
                {"message": "If this email is registered, a magic link will be sent."},
                status=status.HTTP_200_OK
            )

        email_result = send_email(
            subject="Your Magic Link for Authenticating",
            recipient_list=[email],
            context={"magic_link": magic_link, "year": now().year, "message": message},
            template="emails/magic_link_email.html",
            plain_message="Click the link to Authenticate."
        )

        if not email_result.get("success"):
            return Response(
                {"error": "Failed to send the magic link."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"message": "If this email is registered, a magic link will be sent."},
            status=status.HTTP_200_OK
        )

    def is_valid_email_format(self, email):
        try:
            validate_email(email)
        except ValidationError:
            return False
        return True

class ConfirmMagicLinkView(APIView):
    throttle_classes = [AnonRateThrottle]
    """
    API view to confirm the magic link and authenticate the user.
    """

    def get(self, request):
        # Retrieve the token from the query parameters
        token = request.query_params.get("token")

        # Validate the presence of the token
        if not token:
            return Response({"error": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Attempt to retrieve the user using the sesame token
        try:
            user = sesame_get_user(token)
        except Exception as e:
            return Response({"error": f"Invalid or expired link."}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure the user is active
        if not user or not user.is_active:
            return Response({"error": "This account is inactive or invalid."}, status=status.HTTP_403_FORBIDDEN)

        # Blacklist all outstanding tokens for the user to force a fresh login (for security)
        try:
            outstanding_tokens = OutstandingToken.objects.filter(user=user)

            for outstanding_token in outstanding_tokens:
                # Add to BlacklistedToken model to invalidate the token
                BlacklistedToken.objects.get_or_create(token=outstanding_token)
        except Exception as e:
            return Response(
                {"error": f"Failed to blacklist tokens"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Generate a new JWT token pair (refresh and access)
        refresh = RefreshToken.for_user(user)

        # Optionally: Log the login event
        user.last_login = now()
        user.save(update_fields=["last_login"])

        # Check if the user has no organization
        organization = UserOrganizationRole.objects.filter(user=user).first()

        # Determine if the user is a new user
        if not organization or (not user.first_name and not user.last_name):
            new_user = True
        else:
            new_user = False

        # Collect user details to send in the response
        user_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'profile': user.profile if user.profile else None,
            'bio': user.bio,
            'email': user.email,
            'preferences': user.preferences,
            'stripe_subscription_id': user.stripe_subscription_id,
            'github_connected': user.github_connected,
            'google_connected': user.google_connected,
            'new_user': new_user,
            'plan': user.plan,
            'subscription_status': user.subscription_status,
            'subscription_end_date': user.subscription_end_date,
            'type': 'magic'
        }

        return Response({
            "message": "Login successful.",
            "user": user_data,
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }, status=status.HTTP_200_OK)


class CreateSubscriptionAPIViews(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # User is on free plan, so return nothing (not an error)
        if not has_pro_access(user):
            logger.info("ℹ️ User on free plan; skipping portal session creation.")
            return Response(status=status.HTTP_204_NO_CONTENT)

        if not user.stripe_subscription_id:
            return Response(
                {"error": "Missing Paddle customer or subscription ID."},
                status=status.HTTP_400_BAD_REQUEST
            )

        paddle_url = f"https://sandbox-api.paddle.com/customers/{user.stripe_subscription_id}/portal-sessions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        try:
            response = requests.post(paddle_url, headers=headers)
            response.raise_for_status()

            portal_data = response.json().get("data", {})
            portal_url = portal_data.get("urls", {}).get("general", {}).get("overview")

            if not portal_url:
                logger.error("No overview URL found in Paddle response.")
                return Response(
                    {"error": "Could not get the customer portal URL."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response({"portal_url": portal_url}, status=status.HTTP_200_OK)

        except requests.RequestException as e:
            try:
                error_detail = response.json()
            except Exception:
                error_detail = response.text
            logger.error(f"Paddle customer portal error: {str(e)} | Detail: {error_detail}")
            return Response(
                {"error": "Could not create customer portal session.", "detail": error_detail},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )