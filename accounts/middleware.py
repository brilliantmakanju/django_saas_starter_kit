import logging
import os
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from organizations.models import Domain

logger = logging.getLogger(__name__)


class SubdomainMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        logger.debug(f"[SubdomainMiddleware] Incoming request: {request.method} {request.path}")
        logger.debug(f"[SubdomainMiddleware] Host: {request.get_host()}")
        subdomain = self.get_subdomain_from_request(request)

        logger.debug(f"[SubdomainMiddleware] Extracted subdomain: {subdomain}")

        if subdomain:
            try:
                logger.debug(f"[SubdomainMiddleware] Fetching domain object for subdomain: {subdomain}")
                domain = Domain.objects.get(domain=subdomain)
                request.organization = domain.tenant
                logger.debug(f"[SubdomainMiddleware] Organization attached: {request.organization}")
            except Domain.DoesNotExist:
                logger.warning(f"[SubdomainMiddleware] No domain found for subdomain: {subdomain}")
                return HttpResponse("Organization not found for this subdomain.", status=404)
        else:
            logger.debug("[SubdomainMiddleware] No subdomain detected, setting request.organization = None")
            request.organization = None

        response = self.get_response(request)
        return response

    def get_subdomain_from_request(self, request):
        host = request.get_host().split(":")[0]
        parts = host.split('.')

        logger.debug(f"[SubdomainMiddleware] Full host: {host}")
        logger.debug(f"[SubdomainMiddleware] Host parts: {parts}")

        base_domain = os.getenv('HOST_DOMAIN', 'example.com')
        logger.debug(f"[SubdomainMiddleware] Base domain: {base_domain}")

        if host == base_domain:
            logger.debug("[SubdomainMiddleware] Host matches base domain; no subdomain.")
            return None

        if len(parts) > 2 and host.endswith(base_domain):
            logger.debug(f"[SubdomainMiddleware] Host has subdomain: {parts[0]}")
            return host

        if settings.DEBUG and len(parts) > 1:
            logger.debug("[SubdomainMiddleware] DEBUG: Returning full host for subdomain.")
            return host

        if settings.DEBUG and host in ['localhost', '127.0.0.1']:
            logger.debug("[SubdomainMiddleware] DEBUG: Localhost or 127.0.0.1 detected; no subdomain.")
            return None

        logger.debug("[SubdomainMiddleware] No valid subdomain found.")
        return None


class CustomJWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        logger.debug(f"[AuthMiddleware] Request Path: {request.path} | Method: {request.method}")

        auth_header = request.headers.get("Authorization")
        refresh_token = request.headers.get("X-Refresh-Token")

        if not auth_header:
            logger.debug("[AuthMiddleware] No Authorization header. Anonymous user.")
            request.user = AnonymousUser()
            return None

        try:
            token_type, token = auth_header.split()
            logger.debug(f"[AuthMiddleware] Token type: {token_type}")

            if token_type.lower() != "bearer":
                logger.warning("[AuthMiddleware] Invalid token type provided.")
                return JsonResponse(
                    {"status": "error", "message": "Invalid token type. Expected 'Bearer'."},
                    status=400
                )

            validated_token = AccessToken(token)
            jti = validated_token.get("jti")
            logger.debug(f"[AuthMiddleware] JTI from token: {jti}")

            if not jti:
                logger.warning("[AuthMiddleware] Token missing JTI.")
                return JsonResponse(
                    {"status": "error", "message": "Token does not contain a valid JTI."},
                    status=400
                )

            if not refresh_token:
                logger.warning("[AuthMiddleware] Missing refresh token in request headers.")
                return JsonResponse(
                    {"status": "error", "message": "No associated refresh token found."},
                    status=400
                )

            try:
                outstanding_refresh_token = OutstandingToken.objects.get(token=refresh_token)
                logger.debug(f"[AuthMiddleware] Refresh token is valid and found.")
            except OutstandingToken.DoesNotExist:
                logger.warning("[AuthMiddleware] Refresh token not found in OutstandingToken.")
                return JsonResponse(
                    {"status": "error", "message": "Refresh token not found in OutstandingToken."},
                    status=401
                )

            if BlacklistedToken.objects.filter(token=outstanding_refresh_token).exists():
                logger.warning("[AuthMiddleware] Refresh token is blacklisted.")
                return JsonResponse(
                    {"status": "error", "message": "Refresh token is blacklisted. Access denied."},
                    status=401
                )

            user_id = validated_token.get("user_id")
            logger.debug(f"[AuthMiddleware] User ID from token: {user_id}")

            if not user_id:
                logger.warning("[AuthMiddleware] Missing user_id in token.")
                return JsonResponse(
                    {"status": "error", "message": "User ID not found in token."},
                    status=401
                )

            from django.contrib.auth import get_user_model
            try:
                user = get_user_model().objects.get(id=user_id)
                request.user = user
                logger.debug(f"[AuthMiddleware] User authenticated: {user.email}")
            except get_user_model().DoesNotExist:
                logger.warning(f"[AuthMiddleware] User ID {user_id} not found in database.")
                return JsonResponse(
                    {"status": "error", "message": "User not found in the database."},
                    status=404
                )

        except ValueError:
            logger.warning("[AuthMiddleware] Invalid Authorization header format.")
            return JsonResponse(
                {"status": "error", "message": "Invalid Authorization header format. Please provide a valid token."},
                status=400
            )
        except Exception as e:
            logger.exception("[AuthMiddleware] Unexpected error during token validation.")
            return JsonResponse(
                {"status": "error", "message": f"Server Error. Please try again."},
                status=500
            )

        return None
