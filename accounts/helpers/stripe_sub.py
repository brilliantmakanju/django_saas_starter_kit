
"""
Stripe Integration commented out for furture use
"""

# import stripe
# import logging
# from django.http import JsonResponse
# from django.utils import timezone
# from django.views.decorators.csrf import csrf_exempt
# from django.views.decorators.http import require_POST
# from django.core.exceptions import ObjectDoesNotExist
#
# from dotenv import load_dotenv
# from django.contrib.auth import get_user_model
# import os
#
#
# # Load environment variables
# from datetime import timedelta
#
# from accounts.models import UserAccount, SubscriptionPlan
#
# load_dotenv()
#
# logger = logging.getLogger(__name__)
#
# User = get_user_model()
# # Initialize Stripe with your secret key
# stripe.api_key = os.getenv("STRIPE_TEST_SECRET_KEY")
# WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
#
# # Initialize Stripe with your secret key
# stripe.api_key = os.getenv("STRIPE_TEST_SECRET_KEY")
# WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
#
# # Debug print to check if the API key is loaded
# if stripe.api_key is None:
#     print("Stripe API key not found. Please check your environment variables.")
# else:
#     print("Stripe API key loaded successfully.")
#
#
#
# @csrf_exempt
# @require_POST
# def stripe_webhook(request):
#     """
#     Handles Stripe webhook events for subscription lifecycle.
#     """
#     payload = request.body
#     sig_header = request.META.get("HTTP_STRIPE_SIGNATURE")
#
#     try:
#         event = stripe.Webhook.construct_event(payload, sig_header, WEBHOOK_SECRET)
#     except ValueError:
#         logger.error("Invalid payload received from Stripe")
#         return JsonResponse({"error": "Invalid payload"}, status=400)
#     except stripe.error.SignatureVerificationError:
#         logger.error("Invalid Stripe signature")
#         return JsonResponse({"error": "Invalid signature"}, status=400)
#
#     event_type = event.get("type")
#     data = event.get("data", {}).get("object", {})
#
#     logger.info(f"Received Stripe webhook event: {event_type}")
#
#     if event_type == "checkout.session.completed":
#         handle_checkout_completed(data)
#     elif event_type == "invoice.payment_succeeded":
#         handle_payment_success(data)
#     elif event_type == "invoice.payment_failed":
#         handle_payment_failure(data)
#     elif event_type == "customer.subscription.updated":
#         handle_subscription_update(data)
#     elif event_type == "customer.subscription.deleted":
#         handle_subscription_cancel(data)
#     elif event_type == "customer.deleted":
#         handle_customer_deleted(data)
#
#     return JsonResponse({"status": "success"}, status=200)
#
# def handle_checkout_completed(data):
#     """ Handles new subscription activation """
#     customer_id = data.get("customer")
#     user_id = data["metadata"].get("user_id")
#     price_id = data["metadata"].get("price_id")
#
#     if not customer_id or not user_id or not price_id:
#         logger.error("Missing customer_id, user_id, or price_id in checkout.session.completed")
#         return
#
#     try:
#         user = UserAccount.objects.get(id=user_id)
#         plan = SubscriptionPlan.objects.filter(stripe_price_id=price_id).first()
#
#         if not plan:
#             logger.error(f"No matching plan found for Stripe price ID: {price_id}")
#             return
#
#         user.stripe_subscription_id = customer_id
#         user.subscription_status = "active"
#         user.subscription_start_date = timezone.now()
#         if plan.name.lower() == "ltd":  # Check if the plan is the lifetime plan
#             user.subscription_end_date = timezone.now() + timedelta(days=365 * 999)  # 999 years
#         else:
#             user.subscription_end_date = None  # For monthly/annual plans
#
#         user.plan = plan.name  # Update user plan (basic/pro/ltd)
#         user.save()
#
#         logger.info(f"Subscription activated for user {user.email}, assigned plan: {plan.name}")
#     except ObjectDoesNotExist:
#         logger.error(f"User not found for checkout session: {user_id}")
#
# def handle_payment_success(data):
#     """ Handles successful subscription renewals """
#     customer_id = data.get("customer")
#     if not customer_id:
#         logger.error("Missing customer_id in invoice.payment_succeeded")
#         return
#
#     try:
#         user = UserAccount.objects.get(stripe_subscription_id=customer_id)
#         user.subscription_status = "active"
#         user.subscription_end_date = None
#         user.save()
#         logger.info(f"Subscription renewed for user {user.email}")
#     except ObjectDoesNotExist:
#         logger.warning(f"User not found for successful invoice payment: {customer_id}")
#
# def handle_subscription_update(data):
#     """ Handles subscription plan changes or updates """
#     customer_id = data.get("customer")
#     price_id = data["items"]["data"][0]["price"]["id"]
#     status = data.get("status")
#
#     if not customer_id or not price_id:
#         logger.error("Missing customer_id or price_id in customer.subscription.updated")
#         return
#
#     try:
#         user = UserAccount.objects.get(stripe_subscription_id=customer_id)
#         plan = SubscriptionPlan.objects.filter(stripe_price_id=price_id).first()
#
#         if not plan:
#             logger.error(f"No matching plan found for updated Stripe price ID: {price_id}")
#             return
#
#         user.subscription_status = status
#         user.plan = plan.name  # Update user plan based on new price ID
#         user.save()
#         logger.info(f"Subscription updated for user {user.email}, new status: {status}, new plan: {plan.name}")
#     except ObjectDoesNotExist:
#         logger.warning(f"User not found for subscription update: {customer_id}")
#
# def handle_payment_failure(data):
#     """ Handles failed subscription payments (user might need to update payment details) """
#     customer_id = data.get("customer")
#     if not customer_id:
#         logger.error("Missing customer_id in invoice.payment_failed")
#         return
#
#     try:
#         user = UserAccount.objects.get(stripe_subscription_id=customer_id)
#         user.subscription_status = "payment_failed"
#         user.save()
#         logger.warning(f"Subscription payment failed for user {user.email}")
#     except ObjectDoesNotExist:
#         logger.warning(f"User not found for failed payment: {customer_id}")
#
# def handle_subscription_cancel(data):
#     """ Handles subscription cancellations """
#     customer_id = data.get("customer")
#     if not customer_id:
#         logger.error("Missing customer_id in customer.subscription.deleted")
#         return
#
#     try:
#         user = UserAccount.objects.get(stripe_subscription_id=customer_id)
#         user.subscription_status = "canceled"
#         user.subscription_end_date = timezone.datetime.fromtimestamp(
#             data["current_period_end"], timezone.utc
#         )
#         user.save()
#         logger.info(f"Subscription canceled for user {user.email}")
#     except ObjectDoesNotExist:
#         logger.warning(f"User not found for canceled subscription: {customer_id}")
#
# def handle_customer_deleted(data):
#     """ Handles customer deletion (when user deletes their Stripe account) """
#     customer_id = data.get("id")
#     if not customer_id:
#         logger.error("Missing customer_id in customer.deleted")
#         return
#
#     try:
#         user = UserAccount.objects.get(stripe_subscription_id=customer_id)
#         user.subscription_status = "deleted"
#         user.stripe_subscription_id = None
#         user.save()
#         logger.info(f"User {user.email} deleted their Stripe account")
#     except ObjectDoesNotExist:
#         logger.warning(f"User not found for deleted customer: {customer_id}")






# class CreateSubscriptionAPIView(APIView):
#     """
#     API view for creating a subscription.
#     """
#
#     def get_or_create_customer(self, user, payment_method):
#         """
#         Retrieve or create a Stripe customer for the authenticated user.
#         """
#         try:
#             # Check if the customer already exists in Stripe
#             print(f"Checking if customer exists for email: {user.email}")
#             customers = stripe.Customer.list(email=user.email, limit=1).data
#             if customers:
#                 customer = customers[0]
#                 print(f"Existing Stripe customer found: {customer['id']}")
#             else:
#                 # Create a new Stripe customer
#                 print("Creating a new Stripe customer.")
#                 customer = stripe.Customer.create(
#                     name=user.get_full_name(),
#                     email=user.email,
#                     payment_method=payment_method,
#                     invoice_settings={"default_payment_method": payment_method},
#                 )
#                 print(f"New Stripe customer created: {customer['id']}")
#
#             return customer
#         except Exception as e:
#             print("Error retrieving/creating customer:", e)
#             raise
#
#     def create_subscription(self, customer_id, price_id):
#         """
#         Create a new subscription for the Stripe customer.
#         """
#         try:
#             print(f"Creating subscription for customer {customer_id} with price {price_id}")
#             subscription = stripe.Subscription.create(
#                 customer=customer_id,
#                 items=[{"price": price_id}],
#                 expand=["latest_invoice.payment_intent"],
#             )
#             print("Subscription created successfully.")
#             return subscription
#         except Exception as e:
#             print("Error creating subscription:", e)
#             raise
#
#     def post(self, request):
#         user = request.user
#         print(f"Processing subscription for user: {user.email}")
#
#         # Check if the user already has an active subscription
#         if user.subscription:
#             try:
#                 print(f"Retrieving existing subscription: {user.subscription}")
#                 subscription = stripe.Subscription.retrieve(user.subscription)
#
#                 if subscription.status == "active":
#                     print("User already has an active subscription.")
#                     return Response(
#                         {"message": "You already have an active subscription."},
#                         status=status.HTTP_400_BAD_REQUEST,
#                     )
#             except stripe.error.InvalidRequestError:
#                 print("Existing subscription not found on Stripe; proceeding to create a new one.")
#                 pass  # Proceed to create a new subscription
#
#         # Validate request data
#         serializer = CreateSubscriptionSerializer(data=request.data)
#         if serializer.is_valid():
#             data = serializer.validated_data
#             payment_method = data["payment_method"]
#             print("Payment Method ID:", payment_method)
#             price_id = data["price_id"]
#
#             try:
#                 # Retrieve or create the Stripe customer
#                 customer = self.get_or_create_customer(user, payment_method)
#
#                 # Create the subscription
#                 subscription = self.create_subscription(customer["id"], price_id)
#
#                 # Update the user with subscription details
#                 user.subscription = subscription["id"]
#                 user.plan = data["plan_id"]
#                 user.save()
#                 print(f"User subscription updated: {user.subscription}, Plan: {user.plan}")
#
#                 # Return the client secret for payment processing
#                 client_secret = subscription["latest_invoice"]["payment_intent"]["client_secret"]
#                 return Response(
#                     {"clientSecret": client_secret, "subscriptionId": subscription["id"]},
#                     status=status.HTTP_201_CREATED,
#                 )
#
#             except stripe.error.StripeError as e:
#                 print("Stripe error:", e)
#                 return Response(
#                     {"error": "There was an issue with Stripe. Please try again."},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
#             except Exception as e:
#                 print("Unexpected error:", e)
#                 return Response(
#                     {"error": "An unexpected error occurred. Please try again."},
#                     status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 )
#
#         else:
#             print("Invalid data:", serializer.errors)
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#

# class CreateSubscriptionAPIView(APIView):
#     permission_classes = [IsAuthenticated]
#     """
#     API view for creating a Stripe checkout session and returning the payment URL.
#     """
#
#     def get_or_create_customer(self, user):
#         """
#         Retrieve or create a Stripe customer for the user.
#         """
#         try:
#             customers = stripe.Customer.list(email=user.email, limit=1).data
#             if customers:
#                 customer = customers[0]
#                 logger.info(f"Existing Stripe customer found: {customer['id']}")
#             else:
#                 customer = stripe.Customer.create(
#                     email=user.email,
#                     name=user.get_full_name(),
#                 )
#                 logger.info(f"New Stripe customer created: {customer['id']}")
#
#             return customer
#         except stripe.error.StripeError as e:
#             logger.error(f"Stripe error retrieving/creating customer: {e}")
#             raise
#
#     def create_checkout_session(self, customer_id, price_id, user):
#         """
#         Create a Stripe Checkout session and return the session URL.
#         """
#         try:
#             session = stripe.checkout.Session.create(
#                 customer=customer_id,
#                 payment_method_types=["card"],
#                 line_items=[{"price": price_id, "quantity": 1}],
#                 mode="subscription",
#                 success_url=f"{settings.FRONTEND_DOMAIN}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
#                 cancel_url=f"{settings.FRONTEND_DOMAIN}/payment-cancelled",
#                 metadata={"user_id": user.id},
#             )
#             logger.info(f"Checkout session created: {session['id']}")
#             return session.url
#         except stripe.error.StripeError as e:
#             logger.error(f"Stripe error creating checkout session: {e}")
#             raise
#
#     def post(self, request):
#         user = request.user
#         # print(stripe.Price.list(limit=3))
#         logger.info(f"Processing subscription request for user: {user.email}")
#
#         serializer = CreateSubscriptionSerializer(data=request.data)
#         if not serializer.is_valid():
#             logger.error(f"Invalid data: {serializer.errors}")
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
#         data = serializer.validated_data
#         price_id = data["price_id"]
#         # plan_id = data["plan_id"]
#
#         try:
#             customer = self.get_or_create_customer(user)
#             checkout_url = self.create_checkout_session(customer["id"], price_id, user)
#
#             return Response({"checkout_url": checkout_url}, status=status.HTTP_201_CREATED)
#
#         except stripe.error.StripeError:
#             return Response(
#                 {"error": "There was an issue with Stripe. Please try again."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         except Exception:
#             return Response(
#                 {"error": "An unexpected error occurred. Please try again."},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )


# class CreateSubscriptionAPIView(APIView):
#     permission_classes = [IsAuthenticated]
#     """
#     API view for creating a Stripe checkout session and returning the payment URL.
#     Prevents users with active subscriptions from creating a new checkout session.
#     """
#
#     def get_or_create_customer(self, user):
#         """
#         Retrieve or create a Stripe customer for the user.
#         """
#         try:
#             customers = stripe.Customer.list(email=user.email, limit=1).data
#             if customers:
#                 customer = customers[0]
#                 logger.info(f"Existing Stripe customer found: {customer['id']}")
#             else:
#                 customer = stripe.Customer.create(
#                     email=user.email,
#                     name=user.get_full_name(),
#                 )
#                 logger.info(f"New Stripe customer created: {customer['id']}")
#
#             return customer
#         except stripe.error.StripeError as e:
#             logger.error(f"Stripe error retrieving/creating customer: {e}")
#             raise
#
#     def create_checkout_session(self, customer_id, price_id, plan_id, user):
#         """
#         Create a Stripe Checkout session and return the session URL.
#         """
#         try:
#             # Determine the checkout mode based on the plan type
#             mode = "payment" if plan_id.lower() == "ltd_plan_id" else "subscription"
#
#             session = stripe.checkout.Session.create(
#                 customer=customer_id,
#                 payment_method_types=["card"],
#                 line_items=[{"price": price_id, "quantity": 1}],
#                 mode=mode,
#                 success_url=f"{settings.FRONTEND_DOMAIN}/payment-success?session_id={{CHECKOUT_SESSION_ID}}",
#                 cancel_url=f"{settings.FRONTEND_DOMAIN}/payment-cancelled",
#                 metadata={"user_id": user.id, "price_id": price_id, "plan_id": plan_id},
#             )
#
#             logger.info(f"Checkout session created: {session['id']}")
#             return session.url
#         except stripe.error.StripeError as e:
#             logger.error(f"Stripe error creating checkout session: {e}")
#             raise
#
#     def post(self, request):
#         user = request.user
#         logger.info(f"Processing subscription request for user: {user.email}")
#
#         # Check if the user already has an active subscription
#         user.update_subscription_status()
#         if user.has_active_subscription():
#             return Response({
#                 "message": "You already have an active subscription. No need to subscribe again."
#             }, status=status.HTTP_400_BAD_REQUEST)
#
#         serializer = CreateSubscriptionSerializer(data=request.data)
#         if not serializer.is_valid():
#             logger.error(f"Invalid data: {serializer.errors}")
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#
#         data = serializer.validated_data
#         price_id = data["price_id"]
#         plan_id = data["plan_id"]
#         print(plan_id, "Plan Id pricing")
#
#         try:
#             customer = self.get_or_create_customer(user)
#             checkout_url = self.create_checkout_session(customer["id"], price_id, plan_id, user)
#
#             return Response({"checkout_url": checkout_url}, status=status.HTTP_201_CREATED)
#
#         except stripe.error.StripeError:
#             return Response(
#                 {"error": "There was an issue with Stripe. Please try again."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#         except Exception:
#             return Response(
#                 {"error": "An unexpected error occurred. Please try again."},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )
#
#     def get(self, request):
#         user = request.user
#
#         if not user.stripe_subscription_id:
#             return Response({"error": "No active subscription found."}, status=status.HTTP_400_BAD_REQUEST)
#
#         try:
#             session = stripe.billing_portal.Session.create(
#                 customer=user.stripe_subscription_id,
#                 return_url=f"{settings.FRONTEND_DOMAIN}/dashboard",
#             )
#             return Response({"portal_url": session.url}, status=status.HTTP_200_OK)
#
#         except stripe.error.StripeError as e:
#             logger.error(f"Stripe error creating customer portal: {e}")
#             return Response({"error": "Could not create customer portal."},
#                             status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#




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


### Authentication Views

### Authentication Views
