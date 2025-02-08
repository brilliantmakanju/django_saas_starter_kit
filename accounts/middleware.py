from django.http import JsonResponse
import os
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from django.http import HttpResponse
from organizations.models import Domain, Organization


class SubdomainMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        subdomain = self.get_subdomain_from_request(request)

        print(f"Subdomain: {subdomain}")  # Debugging subdomain

        if subdomain:
            # Try to fetch the domain object based on the subdomain
            print(f"Subdomain: {subdomain}")  # Debugging subdomain

            try:
                print(f"Subdomain: {subdomain}")  # Debugging subdomain
                domain = Domain.objects.get(domain=subdomain)
                # Attach the organization to the request object
                request.organization = domain.tenant
            except Domain.DoesNotExist:
                return HttpResponse("Organization not found for this subdomain.", status=404)
        else:
            # If no subdomain found, proceed normally
            request.organization = None

        # Proceed with the normal flow
        response = self.get_response(request)
        return response

    def get_subdomain_from_request(self, request):
        """Extract subdomain from the request's Host header"""
        host = request.get_host().split(":")[0]  # Remove port if present
        parts = host.split('.')  # Split the host by dots to get parts

        print(f"Host: {host}")  # Debugging the host
        print(f"parts: {parts}")  # Debugging the host


        # In production, use the base domain from the environment variable
        base_domain = os.getenv('HOST_DOMAIN', 'example.com')
        if host == base_domain:
            print("Production mode: Base domain matched.")
            return None  # No subdomain, just the base domain

         # ✅ If the domain contains subdomains (e.g., "sub.devbackend.jolexhive.com"), return full host
        if len(parts) > 2 and host.endswith(base_domain):
            subdomain = parts[0]  # Extract subdomain
            print(f"Subdomain detected: {subdomain}")
            return subdomain  # Return the subdomain part only

        # # Check if it's a subdomain (e.g., samsung.localhost)
        # if len(parts) > 1:
        #     # It's a subdomain, return it
        #     return host  # First part is the subdomain (e.g., "samsung" in "samsung.localhost")

        # If no subdomain, check if it's localhost or an IP address, based on DEBUG setting
        if settings.DEBUG:
            if host in ['localhost', '127.0.0.1']:
                # Return None if it's localhost or IP in debug mode
                print("DEBUG mode: Localhost or 127.0.0.1")
                return None  # No subdomain, use default domain



        # If no subdomain and it's not localhost or the base domain, return None
        return None


class CustomJWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware to check for blacklisted JWT tokens in the request header.
    """

    def process_request(self, request):
        auth_header = request.headers.get("Authorization")
        refresh_token = request.headers.get("X-Refresh-Token")

        if not auth_header:
            # No token present, allow request to pass without authentication
            request.user = AnonymousUser()
            return None

        try:
            # Split the Authorization header into token type and token value
            token_type, token = auth_header.split()

            if token_type.lower() != "bearer":
                # Invalid token type
                return JsonResponse(
                    {"status": "error", "message": "Invalid token type. Expected 'Bearer'."},
                    status=400  # Bad Request
                )

            # Decode and validate the access token
            validated_token = AccessToken(token)

            # Extract `jti` from the access token
            jti = validated_token.get("jti")
            if not jti:
                # Missing or invalid `jti` in token
                return JsonResponse(
                    {"status": "error", "message": "Token does not contain a valid JTI."},
                    status=400  # Bad Request
                )

            # Now, check the associated refresh token in OutstandingToken
            if not refresh_token:
                # No associated refresh token in the request header
                return JsonResponse(
                    {"status": "error", "message": "No associated refresh token found."},
                    status=400  # Bad Request
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

            # Attach the user to the request
            user_id = validated_token.get("user_id")
            if not user_id:
                # Missing user ID in the token
                return JsonResponse(
                    {"status": "error", "message": "User ID not found in token."},
                    status=401  # Unauthorized
                )

            # Assuming user_id is valid, get the user (handle exception as needed)
            from django.contrib.auth import get_user_model
            try:
                user = get_user_model().objects.get(id=user_id)
                request.user = user
            except get_user_model().DoesNotExist:
                # User not found in the database
                return JsonResponse(
                    {"status": "error", "message": "User not found in the database."},
                    status=404  # Not Found
                )

        except ValueError:
            # Invalid Authorization header format
            return JsonResponse(
                {"status": "error", "message": "Invalid Authorization header format. Please provide a valid token."},
                status=400  # Bad Request
            )
        except Exception as e:
            # General error during token validation
            return JsonResponse(
                {"status": "error", "message": f"Token validation failed: {str(e)}. Please try again."},
                status=500  # Internal Server Error
            )

        return None
