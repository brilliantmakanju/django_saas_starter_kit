import os
import stripe
import re
from django.db import connection
from oauthlib.oauth2 import BackendApplicationClient

from .utlis.check_user import check_new_user
from django.utils import timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.authentication import JWTAuthentication

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

from .models import UserAccount
from .serializers import UserProfileSerializer, CreateSubscriptionSerializer

from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer
import os
from accounts.utlis.utlis import is_organization_owner
from .social_service import (twitter_initiate_oauth,
                             twitter_callback_oauth,
                             linkedin_initiate_oauth,
                             linkedin_callback_oauth)


# Load environment variables


load_dotenv()


# logging.basicConfig(level=logging.DEBUG)


User = get_user_model()
# Initialize Stripe with your secret key
stripe.api_key = os.getenv("STRIPE_TEST_SECRET_KEY")

# Debug print to check if the API key is loaded
if stripe.api_key is None:
    print("Stripe API key not found. Please check your environment variables.")
else:
    print("Stripe API key loaded successfully.")

@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        # Verify the webhook signature to ensure the request is from Stripe
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        # Invalid payload
        return JsonResponse({'error': 'Invalid payload'}, status=400)
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return JsonResponse({'error': 'Invalid signature'}, status=400)

    # Handle the event type
    if event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        stripe_subscription_id = subscription['id']

        # Find the user with this subscription
        try:
            user = UserAccount.objects.get(stripe_subscription_id=stripe_subscription_id)
            # Update subscription status to 'canceled' and set the subscription_end_date
            user.subscription_status = 'canceled'
            user.subscription_end_date = timezone.datetime.fromtimestamp(
                subscription['current_period_end'], timezone.utc
            )
            user.save()
        except UserAccount.DoesNotExist:
            print("User not found subscription cancel")
            return JsonResponse({'error': 'User not found'}, status=404)

    # elif event['type'] == 'payment_intent.succeeded':
    #     # This event confirms that a subscription payment was successful, meaning the subscription is active
    #     invoice = event['data']['object']
    #     print(invoice)
    #     stripe_subscription_id = invoice['subscription']
    #
    #     # Find the user with this subscription
    #     try:
    #         user = UserAccount.objects.get(stripe_subscription_id=stripe_subscription_id)
    #         user.subscription_status = 'active'
    #         user.subscription_end_date = None  # Reset the end date to allow access
    #         user.save()
    #     except UserAccount.DoesNotExist:
    #         print("User not found Invoice Payment")
    #         return JsonResponse({'error': 'User not found'}, status=404)

    # Handle other events as needed
    return JsonResponse({'status': 'success'}, status=200)

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

class CreateSubscriptionAPIView(APIView):
    """
    API view for creating a subscription.
    """

    def get_or_create_customer(self, user, payment_method):
        """
        Retrieve or create a Stripe customer for the authenticated user.
        """
        try:
            # Check if the customer already exists in Stripe
            print(f"Checking if customer exists for email: {user.email}")
            customers = stripe.Customer.list(email=user.email, limit=1).data
            if customers:
                customer = customers[0]
                print(f"Existing Stripe customer found: {customer['id']}")
            else:
                # Create a new Stripe customer
                print("Creating a new Stripe customer.")
                customer = stripe.Customer.create(
                    name=user.get_full_name(),
                    email=user.email,
                    payment_method=payment_method,
                    invoice_settings={"default_payment_method": payment_method},
                )
                print(f"New Stripe customer created: {customer['id']}")

            return customer
        except Exception as e:
            print("Error retrieving/creating customer:", e)
            raise

    def create_subscription(self, customer_id, price_id):
        """
        Create a new subscription for the Stripe customer.
        """
        try:
            print(f"Creating subscription for customer {customer_id} with price {price_id}")
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{"price": price_id}],
                expand=["latest_invoice.payment_intent"],
            )
            print("Subscription created successfully.")
            return subscription
        except Exception as e:
            print("Error creating subscription:", e)
            raise

    def post(self, request):
        user = request.user
        print(f"Processing subscription for user: {user.email}")

        # Check if the user already has an active subscription
        if user.subscription:
            try:
                print(f"Retrieving existing subscription: {user.subscription}")
                subscription = stripe.Subscription.retrieve(user.subscription)

                if subscription.status == "active":
                    print("User already has an active subscription.")
                    return Response(
                        {"message": "You already have an active subscription."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except stripe.error.InvalidRequestError:
                print("Existing subscription not found on Stripe; proceeding to create a new one.")
                pass  # Proceed to create a new subscription

        # Validate request data
        serializer = CreateSubscriptionSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            payment_method = data["payment_method"]
            print("Payment Method ID:", payment_method)
            price_id = data["price_id"]

            try:
                # Retrieve or create the Stripe customer
                customer = self.get_or_create_customer(user, payment_method)

                # Create the subscription
                subscription = self.create_subscription(customer["id"], price_id)

                # Update the user with subscription details
                user.subscription = subscription["id"]
                user.plan = data["plan_id"]
                user.save()
                print(f"User subscription updated: {user.subscription}, Plan: {user.plan}")

                # Return the client secret for payment processing
                client_secret = subscription["latest_invoice"]["payment_intent"]["client_secret"]
                return Response(
                    {"clientSecret": client_secret, "subscriptionId": subscription["id"]},
                    status=status.HTTP_201_CREATED,
                )

            except stripe.error.StripeError as e:
                print("Stripe error:", e)
                return Response(
                    {"error": "There was an issue with Stripe. Please try again."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            except Exception as e:
                print("Unexpected error:", e)
                return Response(
                    {"error": "An unexpected error occurred. Please try again."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        else:
            print("Invalid data:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class CreateSubscriptionAPIView(APIView):
#     def post(self, request):
#         user = request.user.email
#         print("User:", user)
#
#         # Check if the user already has an active subscription
#         if user.subscription:
#             print("User has an existing subscription:", user.subscription)
#             try:
#                 # Retrieve the subscription from Stripe
#                 subscription = stripe.Subscription.retrieve(user.subscription)
#                 print("Retrieved subscription:", subscription)
#
#                 if subscription.status == "active":
#                     print("Subscription is active; no need to create a new one.")
#                     return Response(
#                         {"message": "You already have an active subscription."},
#                         status=status.HTTP_400_BAD_REQUEST,
#                     )
#             except stripe.error.InvalidRequestError:
#                 print("Subscription not found on Stripe, creating a new one.")
#                 pass  # Continue to create a new subscription
#
#         # Validate the input data using the serializer
#         serializer = CreateSubscriptionSerializer(data=request.data)
#         if serializer.is_valid():
#             data = serializer.validated_data
#             print("Serializer is valid. Data:", data)
#
#             payment_method = data["payment_method"]
#             print("Retrieving payment method:", payment_method)
#             payment_method_obj = stripe.PaymentMethod.retrieve(payment_method)
#             print("Retrieved payment method from Stripe:", payment_method_obj)
#
#             try:
#                 # Retrieve or create a Stripe customer
#                 print("Checking if customer exists with email:", user.email)
#                 customers = stripe.Customer.list(email=user.email, limit=1).data
#                 if customers:
#                     customer = customers[0]
#                     print("Found existing customer:", customer)
#                 else:
#                     print("Creating a new Stripe customer.")
#                     customer = stripe.Customer.create(
#                         name=user.get_full_name(),
#                         email=user.email,
#                         payment_method=payment_method,
#                         invoice_settings={
#                             "default_payment_method": payment_method,
#                         },
#                     )
#
#                 # Create a new subscription in Stripe
#                 print("Creating subscription with price ID:", data["price_id"])
#                 subscription = stripe.Subscription.create(
#                     customer=customer.id,
#                     items=[{"price": data["price_id"]}],
#                     expand=["latest_invoice.payment_intent"],
#                 )
#                 print("Created subscription:", subscription)
#
#                 # Save subscription and plan information to the user
#                 user.subscription = subscription.id
#                 user.plan = data["plan_id"]
#                 user.save()
#                 print("Updated user subscription and plan:", user.subscription, user.plan)
#
#                 # Provide the client secret for payment processing
#                 client_secret = subscription.latest_invoice.payment_intent.client_secret
#                 print("Client secret:", client_secret)
#                 return Response(
#                     {
#                         "clientSecret": client_secret,
#                         "subscriptionId": subscription.id,
#                     },
#                     status=status.HTTP_201_CREATED,
#                 )
#
#             except Exception as e:
#                 print("Error during subscription creation:", e)
#                 return Response(
#                     {"error": str(e)},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
#
#         else:
#             print("Serializer errors:", serializer.errors)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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

class ProtectedRouteView(APIView):
    """
    A protected route that requires a valid token to access.
    """
    permission_classes = [IsAuthenticated, TenantAccessPermission]
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):
        check_new_user(request.user)
        user = request.user  # Retrieve the authenticated user
        aiPost = []
        return Response(
            {
                "message": "You have accessed a protected route!",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "aiPost": aiPost,
                },
            },
            status=200,
        )

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

    def patch(self, request):
        """
        Update the user's profile (first_name, last_name, profile image, bio).
        """

        # Ensure the user is authenticated
        user = request.user

        # Serialize the data with the user instance and partial data (only fields provided)
        serializer = UserProfileSerializer(user, data=request.data, partial=True)

        # Validate data and ensure it is correct
        if serializer.is_valid():
            # Check if any fields have been modified, and apply them
            updated_data = serializer.validated_data

            # Check profile image URL
            profile = updated_data.get('profile')
            if profile:
                # Ensure the profile URL is valid (additional checks are performed in serializer)
                if not re.match(r"https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+", profile):
                    return Response({"detail": "Invalid Cloudinary URL."}, status=status.HTTP_400_BAD_REQUEST)

            # Validate bio length (optional)
            bio = updated_data.get('bio')
            if bio and len(bio) > 500:
                return Response({"detail": "Bio cannot exceed 500 characters."}, status=status.HTTP_400_BAD_REQUEST)

            # Save the validated data to the user model
            for field, value in updated_data.items():
                setattr(user, field, value)

            user.save()

            # Return success response with updated data
            return Response({
                'detail': 'Profile updated successfully.',
                'user': UserProfileSerializer(user).data
            }, status=status.HTTP_200_OK)

        # Return validation errors if serializer is not valid
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
    # permission_classes = [AllowAny]
    permission_classes = [IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        """
        Initiates the LinkedIn OAuth process and returns the authorization URL.
        The user should visit the URL to authorize the app to connect to their account.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
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


