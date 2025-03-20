import hmac
import hashlib
import json, ipaddress
from rest_framework.pagination import PageNumberPagination
from django.http import JsonResponse
from django.views import View
from django.conf import settings
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist

from accounts.utlis.check_user import has_pro_access
from .serializers import PostSerializer
from django.db.models import Max
from .models import generate_encrypted_secret, Platform
from organizations.models import Organization, UserOrganizationRole
from .models import Webhook, Post, PostGroup
from django.core.mail import send_mail
from django.core.exceptions import PermissionDenied
from rest_framework import status, permissions
import logging
from .utlis import is_organization_owner_or_admin, generate_post_with_ai
from datetime import datetime
from rest_framework.response import Response
from accounts.permissions import TenantAccessPermission
from accounts.utlis.utlis import is_organization_owner

from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from datetime import timedelta




logger = logging.getLogger(__name__)

class PostPagination(PageNumberPagination):
    """
    Custom pagination for Posts.
    """
    page_size = 50  # Default page size
    page_size_query_param = 'page'  # Allows client to specify page size
    max_page_size = 50  # Prevent excessive queries

    def get_paginated_response(self, data):
        """
        Returns a structured paginated response.
        """
        return Response({
            'count': self.page.paginator.count,  # Total number of posts
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data  # Paginated posts
        })

class PostView(APIView):
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]
    pagination_class = PostPagination

    def get(self, request, *args, **kwargs):
        """
        Retrieve all posts for the organization, grouped and ungrouped.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to get post in this organization.'},
                            status=status.HTTP_403_FORBIDDEN)

            # Fetch posts and separate grouped/ungrouped
        # all_posts = Post.objects.filter(organization=organization, is_deleted=False, platform=Platform.LINKEDIN).order_by('-created_at')
        all_posts = Post.objects.filter(
            organization=organization,
            is_deleted=False,
            is_inactive=False,
            platform=Platform.LINKEDIN
        ).order_by('-created_at')

        # grouped_posts = Post.objects.filter(post_group__isnull=False, organization=organization, is_deleted=False, platform=Platform.LINKEDIN)
        # ungrouped_posts = all_posts.filter(post_group__isnull=True)

        grouped_posts = all_posts.filter(post_group__isnull=False)
        ungrouped_posts = all_posts.filter(post_group__isnull=True)

        grouped_data = (
            grouped_posts.values('post_group')
            .annotate(latest_created=Max('created_at'))
            .order_by('-latest_created')
        )

        grouped_result = []
        for group in grouped_data:
            group_id = group['post_group']
            posts_in_group = grouped_posts.filter(post_group_id=group_id).order_by('-created_at')
            serialized_group = {
                'group_id': group_id,
                'posts': PostSerializer(posts_in_group, many=True).data,
                'latest_created_at': group['latest_created']
            }
            grouped_result.append(serialized_group)

        ungrouped_result = PostSerializer(ungrouped_posts, many=True).data

        # Convert 'created_at' and 'latest_created_at' to datetime objects if they are strings
        def ensure_datetime(value):
            if isinstance(value, str):
                return datetime.fromisoformat(value)
            return value

        # Ensure all datetime fields are datetime objects
        for item in grouped_result + ungrouped_result:
            if 'latest_created_at' in item:
                item['latest_created_at'] = ensure_datetime(item['latest_created_at'])
            if 'created_at' in item:
                item['created_at'] = ensure_datetime(item['created_at'])

        # Now sort the combined result
        combined_result = sorted(
            grouped_result + ungrouped_result,
            key=lambda x: x.get('latest_created_at', x.get('created_at')),
            reverse=True
        )

        # return Response(combined_result, status=status.HTTP_200_OK)
        # Apply pagination
        paginator = self.pagination_class()
        paginated_result = paginator.paginate_queryset(combined_result, request)

        return paginator.get_paginated_response(paginated_result)

    def post(self, request, *args, **kwargs):
        """
        Create a new post.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to add team members.'},
                            status=status.HTTP_403_FORBIDDEN)

        data = request.data
        data['organization'] = organization.id

        serializer = PostSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        """
        Edit an existing post.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check user role (owner or admin only)
        try:
            is_organization_owner_or_admin(request.user, organization)
        except PermissionDenied:
            return Response({'message': 'You are not authorized to perform this action.'},
                            status=status.HTTP_403_FORBIDDEN)

        post_id = request.query_params.get("id")
        post = get_object_or_404(Post, id=post_id, organization=organization, is_deleted=False)

        if request.data.get("scheduled_publish_time"):
            # Restrict organization creation to PRO users
            if not has_pro_access(request.user):
                return Response({
                    "error": "Permission denied",
                    "message": "You need a Pro reshudele post."
                }, status=status.HTTP_403_FORBIDDEN)

        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            post.is_edited = True
            post.priority = True
            # If scheduled_publish_time exists, set status to "scheduled"
            if request.data.get("scheduled_publish_time"):
                post.status = Post.Status.SCHEDULED

            post.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        """
        Soft-delete a specific post.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check user role (owner or admin only)
        try:
            is_organization_owner_or_admin(request.user, organization)
        except PermissionDenied:
            return Response({'message': 'You are not authorized to perform this action.'},
                            status=status.HTTP_403_FORBIDDEN)

        post_id = request.query_params.get("id")
        post = get_object_or_404(Post, id=post_id, organization=organization, is_deleted=False)
        post.is_deleted = True
        post.save()
        return Response({"success": True, "message": "Post moved to trash."}, status=status.HTTP_200_OK)

    def patch(self, request, *args, **kwargs):
        """
        Restore a deleted post.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check user role (owner or admin only)
        try:
            is_organization_owner_or_admin(request.user, organization)
        except PermissionDenied:
            return Response({'message': 'You are not authorized to perform this action.'},
                            status=status.HTTP_403_FORBIDDEN)


        post_id = request.query_params.get("id")
        post = get_object_or_404(Post, id=post_id, organization=organization, is_deleted=True)
        post.is_deleted = False
        post.save()
        return Response({"message": "Post restored successfully."}, status=status.HTTP_200_OK)

class PostGroupView(APIView):
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        """
        Retrieve all posts in a specific group.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        group_id = request.query_params.get("group_id")
        group = get_object_or_404(PostGroup, id=group_id, organization=organization)

        posts = Post.objects.filter(post_group=group, is_deleted=False).order_by('-created_at')
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        """
        Clear all posts in the trash for the organization.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check user role (owner or admin only)
        try:
            is_organization_owner_or_admin(request.user, organization)
        except PermissionDenied:
            return Response({'message': 'You are not authorized to perform this action.'},
                            status=status.HTTP_403_FORBIDDEN)

        trashed_posts = Post.objects.filter(organization=organization, is_deleted=True)
        count = trashed_posts.count()
        trashed_posts.delete()
        return Response({"message": f"Trash cleared. {count} posts permanently deleted."}, status=status.HTTP_200_OK)

class CsrfExemptMixin:
    """
    Mixin to exempt specific views from CSRF verification.
    """
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

# --- VALIDATION LOGIC ---
# Check if the request is coming from GitHub and is authenticated.

# Code for validating GitHub signature and IP

# --- FETCH WEBHOOK OBJECT ---
# Retrieve the appropriate webhook instance for the organization.

# --- PROCESS EVENT DATA ---
# Parse and handle the payload from GitHub's webhook.

# --- RESPONSE HANDLING ---

class GitHubWebhookView(CsrfExemptMixin, View):
    # @method_decorator(csrf_exempt)  # Disable CSRF for webhook creation (since GitHub is making the request)
    def post(self, request):
        print("📌 Webhook received - Processing started.")

        # 1. Retrieve the organization and the secret from the URL
        organization = getattr(request, 'organization', None)
        print(f"🔍 Retrieved organization: {organization}")

        if not organization:
            print("❌ Organization not found.")
            return JsonResponse({'error': 'Organization not found.'}, status=404)

        # **NEW: Retrieve the organization owner**
        try:
            owner = UserOrganizationRole.objects.get(organization=organization, role='owner').user
            print(f"👤 Organization owner found: {owner.email}")
        except UserOrganizationRole.DoesNotExist:
            print("❌ Organization owner not found.")
            return JsonResponse({'error': 'Organization owner not found.'}, status=403)

        # Count published posts in the organization
        published_posts_count = Post.objects.filter(
            organization=organization
        ).count()
        print(f"📝 Published posts count: {published_posts_count}")

        # **NEW: Check if the owner is on the free plan and has 5+ published posts**
        if has_pro_access(owner) is False and published_posts_count >= 5:
            print("🚫 Post limit reached for free plan.")
            return JsonResponse({'error': 'Post limit reached for free plan.'}, status=403)

        # Check if the organization has platform(s) enabled and generate webhook details
        if not organization.can_generate_webhook():
            print("⚠️ No platform enabled for webhook generation.")
            return JsonResponse({
                "message": "You must enable at least one platform (Twitter or LinkedIn) to generate webhook details."
            }, status=403)

        secret_key = request.GET.get('secret_key', '')
        print("🔑 Secret key received.")

        if not secret_key:
            print("❌ Missing secret key.")
            return JsonResponse({'error': 'Missing secret_key.'}, status=400)

        # 2. Find the corresponding webhook for the organization
        print(f"🔎 Looking up webhook for organization: {organization}")
        organization_instance = Organization.objects.get(name=organization)
        try:
            webhook = Webhook.objects.get(organization=organization_instance, enabled=True, public_secret=secret_key)
            print(f"✅ Webhook found: {webhook.id}")
        except Webhook.DoesNotExist:
            print("❌ Webhook not found or inactive.")
            return JsonResponse({'error': 'Webhook not configured or inactive for this organization.'}, status=400)

        # 3. Verify the secret key
        print("🔐 Verifying secret key...")
        if not self._verify_secret(secret_key, webhook.public_secret):
            print("🚫 Secret key verification failed.")
            raise PermissionDenied("Invalid secret key.")
        print("✅ Secret key verified.")

        # 4. Perform security checks to validate the request is from GitHub (IP validation)
        print("🌍 Validating GitHub request source...")
        if not self._is_github_request(request, webhook.private_secret):
            print("🚫 Invalid request source (Not from GitHub).")
            raise PermissionDenied("Invalid request source.")
        print("✅ GitHub request source validated.")

        # 5. Verify that the request is a 'push' event
        github_event = request.headers.get('X-GitHub-Event')
        print(f"📢 GitHub event received: {github_event}")

        if github_event != 'push':
            print("⚠️ Not a push event. Ignoring request.")
            return JsonResponse({'error': 'This endpoint only handles push events.'}, status=200)

        # 6. Check the repository and branch in the payload
        print("📦 Loading request payload...")
        payload = json.loads(request.body)
        branch = payload.get('ref', '').split('/')[-1]  # Get branch name from ref (refs/heads/<branch>)
        print(f"🌿 Branch extracted from payload: {branch}")

        if branch != webhook.branch:
            print(f"🚫 Branch mismatch: Expected {webhook.branch}, but received {branch}.")
            return JsonResponse({'error': 'Repository or branch mismatch.'}, status=200)

        # 7. Get the commit message and print it
        commit_message = payload.get('head_commit', {}).get('message', '')
        print(f"📝 Commit message: {commit_message}")

        if commit_message:
            print("🤖 Generating AI post...")
            post_tone = organization.get_tone()
            generate_post_with_ai(commit_message, tone=post_tone, secret_key=webhook.private_secret)
            print("✅ AI post generation complete.")

        # 8. Send a success response
        print("✅ Webhook processed successfully.")
        return JsonResponse({'message': 'Webhook processed successfully.'}, status=200)

    # def post(self, request):
    #     # 1. Retrieve the organization and the secret from the URL
    #     organization = getattr(request, 'organization', None)
    #     print("Starting")
    #
    #     if not organization:
    #         return JsonResponse({'error': 'Organization not found.'}, status=404)
    #
    #     # **NEW: Retrieve the organization owner**
    #     try:
    #         owner = UserOrganizationRole.objects.get(organization=organization, role='owner').user
    #     except UserOrganizationRole.DoesNotExist:
    #         return JsonResponse({'error': 'Organization owner not found.'}, status=403)
    #
    #     # Count published posts in the organization
    #     published_posts_count = Post.objects.filter(
    #         organization=self.organization
    #     ).count()
    #
    #     # **NEW: Check if the owner is on the free plan and has 5+ published posts**
    #     if has_pro_access(owner) is False and published_posts_count >= 5:
    #         return JsonResponse({'error': 'Post limit reached for free plan.'}, status=403)
    #
    #     # Check if the organization has platform(s) enabled and generate webhook details
    #     if not organization.can_generate_webhook():
    #         return JsonResponse({
    #             "message": "You must enable at least one platform (Twitter or LinkedIn) to generate webhook details."
    #         }, status=403)
    #
    #
    #     secret_key = request.GET.get('secret_key', '')
    #     if not secret_key:
    #         return JsonResponse({'error': 'Missing secret_key.'}, status=400)
    #
    #     # 2. Find the corresponding webhook for the organization
    #     organization_instance = Organization.objects.get(name=organization)
    #     try:
    #         webhook = Webhook.objects.get(organization=organization_instance, enabled=True, public_secret=secret_key)
    #     except Webhook.DoesNotExist:
    #         return JsonResponse({'error': 'Webhook not configured or inactive for this organization.'}, status=400)
    #
    #     # 3. Verify the secret key
    #     if not self._verify_secret(secret_key, webhook.public_secret):
    #         raise PermissionDenied("Invalid secret key.")
    #
    #     # 4. Perform security checks to validate the request is from GitHub (IP validation)
    #     if not self._is_github_request(request, webhook.private_secret):
    #         raise PermissionDenied("Invalid request source.")
    #
    #     # 5. Verify that the request is a 'push' event
    #     if request.headers.get('X-GitHub-Event') != 'push':
    #         return JsonResponse({'error': 'This endpoint only handles push events.'}, status=200)
    #
    #     # 6. Check the repository and branch in the payload
    #     payload = json.loads(request.body)
    #
    #     branch = payload.get('ref', '').split('/')[-1]  # Get branch name from ref (refs/heads/<branch>)
    #
    #     if branch != webhook.branch:
    #         return JsonResponse({'error': 'Repository or branch mismatch.'}, status=200)
    #
    #     # 7. Get the commit message and print it
    #     commit_message = payload.get('head_commit', {}).get('message', '')
    #
    #     if commit_message:
    #         post_tone = organization.get_tone()
    #         # Generate post from AI
    #         generate_post_with_ai(commit_message, tone=post_tone, secret_key=webhook.private_secret)
    #
    #     # 8. Send a success response
    #     return JsonResponse({'message': 'Webhook processed successfully.'}, status=200)

    def _verify_secret(self, secret_key, webhook_secret):
        """
        Verifies the secret key provided in the request against the stored secret key.
        """
        return hmac.compare_digest(secret_key, webhook_secret)

    def _is_github_request(self, request, private_key):
        """
        Validates that the request is coming from GitHub by checking the headers and IP.
        """
        # List of GitHub IPs that send webhooks
        github_ips = [
            "192.30.252.0/22",
            "185.199.108.0/22",
            "140.82.112.0/20",
            "143.55.64.0/20",
            "2a0a:a440::/29",
            "2606:50c0::/32"
        ]

        # Security Check: Verify that the request is coming from GitHub
        print("Checking if the request is from GitHub...")

        # Check if the request is coming from a GitHub IP
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR')
        print(f"Client IP: {client_ip}")
        print(f"GitHub IP ranges: {github_ips}")

        # Check if the client IP is in any of GitHub's IP ranges
        is_valid_ip = False
        for ip_range in github_ips:
            try:
                network = ipaddress.ip_network(ip_range, strict=False)
                if ipaddress.ip_address(client_ip) in network:
                    is_valid_ip = True
                    print(f"Client IP {client_ip} is within GitHub's IP range {ip_range}")
                    break
            except ValueError as e:
                print(f"Error with IP range {ip_range}: {e}")
                continue

        if not is_valid_ip:
            print("Request is not from a GitHub IP.")
            return JsonResponse({'error': 'Invalid IP address. Not from GitHub.'}, status=403)

        # 7. Validate the signature (GitHub's way)
        signature = request.META.get('HTTP_X_HUB_SIGNATURE_256', '')
        print(f"Received signature: {signature}")

        if not signature:
            print("No signature provided in the request.")
            return JsonResponse({'error': 'Signature is required.'},
                                status=400)  # Signature is required, if not present return False

        # Recreate the signature using the secret key and payload (body of the request)
        computed_signature = self._compute_signature(request.body, private_key)
        print(f"Computed signature: {computed_signature}")

        # Compare the signatures to verify the authenticity of the request
        if not hmac.compare_digest(signature, computed_signature):
            print("Signatures do not match.")
            return JsonResponse({'error': 'Invalid signature.'},
                                status=403)  # Signatures do not match, request is not valid

        print("Request is valid from GitHub.")

        #
        # print(request.META)
        # # Check if the request is coming from a GitHub IP
        # client_ip = request.META.get('HTTP_X_FORWARDED_FOR')
        # if client_ip not in github_ips:
        #     return False
        #
        # # Validate the signature (GitHub's way)
        # signature = request.META.get('HTTP_X_HUB_SIGNATURE_256', '')
        # if not signature:
        #     return False  # Signature is required, if not present return False
        #
        # # Recreate the signature using the secret key and payload (body of the request)
        # computed_signature = self._compute_signature(request.body, private_key)
        #
        # # Compare the signatures to verify the authenticity of the request
        # if not hmac.compare_digest(signature, computed_signature):
        #     return False  # Signatures do not match, request is not valid

        return True  # Valid GitHub request

    def _compute_signature(self, payload, private_key):
        """
        Compute the HMAC-SHA256 signature using the private key (secret key).
        """
        secret = private_key.encode('utf-8')  # Convert the private key to bytes
        return 'sha256=' + hmac.new(secret, payload, hashlib.sha256).hexdigest()

    def _send_error_email(self, error_msg):
        """
        Sends an email to the Django product owner in case of an error.
        """
        subject = "GitHub Webhook Error"
        message = f"An error occurred while processing a GitHub webhook:\n\n{error_msg}"
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [settings.DJANGO_PRODUCT_OWNER_EMAIL]  # Product owner's email

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

    def handle_exception(self, exc):
        """
        Handles exceptions globally and sends an error email if something goes wrong.
        """
        error_msg = str(exc)
        self._send_error_email(error_msg)
        logger.error(f"GitHub Webhook Error: {error_msg}")
        return JsonResponse({'error': 'An error occurred while processing the webhook.'}, status=500)

# --- WEBHOOK GROUPING UTILITIES ---
# You can create additional views related to Webhook here, for example:
# - A view to retrieve webhook configurations
# - A view to regenerate webhook secrets
# - A view to toggle webhook enable/disable state

class CreateOrRegenerateWebhookView(APIView):
    """
    View to create a new webhook or regenerate the secret key for an existing webhook.
    """
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]


    def post(self, request):
        """
        POST method to either create a new webhook or regenerate the secret for an existing one.

        Args:
            organization_id: The organization for which the webhook is being created.
        """
        # Ensure the user has permission (owner or admin of the organization)
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You do not have permission to modify webhooks for this organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Check if the organization has platform(s) enabled and generate webhook details
        if not organization.can_generate_webhook():
            return JsonResponse({
                "message": "You must enable at least one platform (Twitter or LinkedIn) to generate webhook details."
            }, status=403)

        # Check if webhook already exists for the organization
        webhook, created = Webhook.objects.get_or_create(organization=organization)

        # Build the webhook URL
        # Generate new secrets (for both new and regenerated webhooks)
        webhook.private_secret = generate_encrypted_secret()
        webhook.public_secret = generate_encrypted_secret()
        webhook.save()

        # Build the webhook URL and force HTTPS if necessary
        webhook_url = request.build_absolute_uri('/api/v1/webhook/')
        if  webhook_url.startswith("http://"):
            webhook_url = "https://" + webhook_url[len("http://"):]
        webhook_url_with_secret = f"{webhook_url}?secret_key={webhook.public_secret}"

        if created:
            return JsonResponse({
                'message': 'Webhook created successfully.',
                'secret_key_url': webhook_url_with_secret,
                'private_secret': webhook.private_secret
            })
        else:
            return JsonResponse({
                'message': 'Webhook secret regenerated successfully.',
                'secret_key_url': webhook_url_with_secret,
                'private_secret': webhook.private_secret
            })

class UpdateWebhookSettingsView(APIView):
    """
    API endpoint to retrieve and update the GitHub webhook settings for an organization.
    Only the organization owner is allowed to view or modify these settings.

    GET: Returns the current branch and repo associated with the organization's webhook.
    PUT: Updates the branch and repo fields for the organization's webhook.
    """
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        # Retrieve the organization from the request (e.g., via middleware)
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You do not have permission to modify webhooks for this organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Check if the organization has platform(s) enabled and generate webhook details
        if not organization.can_generate_webhook():
            return JsonResponse({
                "message": "You must enable at least one platform (Twitter or LinkedIn) to generate webhook details."
            }, status=403)

        try:
            # Since Organization has a OneToOne relation with Webhook (via related_name "webhook")
            webhook = organization.webhook
        except ObjectDoesNotExist:
            return Response({'message': 'Webhook not found for this organization.'},
                            status=status.HTTP_404_NOT_FOUND)

        # Return the current branch and repo settings.
        return Response({
            'repo': webhook.repo,
            'branch': webhook.branch
        }, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        # Retrieve the organization from the request (via middleware)
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You do not have permission to modify webhooks for this organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Check if the organization has platform(s) enabled and generate webhook details
        if not organization.can_generate_webhook():
            return JsonResponse({
                "message": "You must enable at least one platform (Twitter or LinkedIn) to generate webhook details."
            }, status=403)

        try:
            webhook = organization.webhook
        except ObjectDoesNotExist:
            return Response({'message': 'Webhook not found for this organization.'},
                            status=status.HTTP_404_NOT_FOUND)

        # Retrieve new repo and branch from the request data.
        repo = request.data.get('repo')
        branch = request.data.get('branch')

        if not branch:
            return Response({'message': 'Branch fields must be provided.'},
                            status=status.HTTP_400_BAD_REQUEST)

        # Update webhook settings.
        # webhook.repo = repo
        webhook.branch = branch
        webhook.save()

        # Return the updated settings.
        return Response({
            'message': 'Webhook settings updated successfully.',
            # 'repo': webhook.repo,
            'branch': webhook.branch,
        }, status=status.HTTP_200_OK)

class GetOrganizationWebhookView(APIView):
    """
    View to retrieve the webhook for the authenticated user's organization.
    """
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]

    def get(self, request):
        """
        GET method to retrieve the webhook for the authenticated user's organization.

        Returns:
            - If a webhook exists: webhook details.
            - If no webhook exists: an appropriate message.
        """
        # Ensure the user has permission (owner or admin of the organization)
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You do not have permission to modify webhooks for this organization.'},
                            status=status.HTTP_403_FORBIDDEN)

        # Check if the organization has platform(s) enabled and generate webhook details
        if not organization.can_generate_webhook():
            return JsonResponse({
                "message": "You must enable at least one platform (Twitter or LinkedIn) to generate webhook details."
            }, status=403)

        try:
            # Retrieve the webhook for the organization
            webhook = Webhook.objects.get(organization=organization)

            # Construct the webhook URL with the public secret
            webhook_url = request.build_absolute_uri('/api/v1/webhook/')
            if webhook_url.startswith("http://"):
                webhook_url = "https://" + webhook_url[len("http://"):]
            webhook_url_with_secret = f"{webhook_url}?secret_key={webhook.public_secret}"

            return JsonResponse({
                'message': 'Webhook retrieved successfully.',
                'secret_key_url': webhook_url_with_secret,
                'private_secret': webhook.private_secret
            })

        except Webhook.DoesNotExist:
            return Response({'message': 'No webhook found for this organization.'}, status=status.HTTP_404_NOT_FOUND)


class OrganizationDashboardView(APIView):
    """
    API View to retrieve dashboard statistics for an organization.
    Provides insights into scheduled posts, generated posts, platform usage,
    and content type distribution over the last 7 days.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """
        GET method to fetch dashboard statistics for an organization.

        Returns:
            - Number of scheduled posts in the last 7 days
            - Number of posts generated in the last 7 days
        """
        # Retrieve the authenticated user's organization
        organization = getattr(request, 'organization', None)
        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Define the timeframe (last 7 days)
        last_7_days = now() - timedelta(days=7)

        # Count of scheduled posts in the last 7 days
        scheduled_posts_count = Post.objects.filter(
            organization=organization, status=Post.Status.SCHEDULED,
            scheduled_publish_time__gte=last_7_days, platform=Platform.LINKEDIN,
            is_deleted=False, is_inactive=False
        ).count()

        # Count of posts generated in the last 7 days
        generated_posts_count = Post.objects.filter(
            organization=organization, created_at__gte=last_7_days,
            platform=Platform.LINKEDIN, is_deleted=False, is_inactive=False
        ).count()

        # Construct the response data
        data = {
            "scheduled_posts_count": scheduled_posts_count,  # Number of scheduled posts
            "generated_posts_count": generated_posts_count,  # Number of generated posts
        }

        return Response(data, status=status.HTTP_200_OK)



class UpcomingPosts(APIView):
    permission_classes = [permissions.IsAuthenticated, TenantAccessPermission]

    def get(self, request, *args, **kwargs):
        """
        Retrieve all posts for the organization, grouped and ungrouped.
        """
        organization = getattr(request, 'organization', None)

        if not organization:
            return Response({'message': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the organization owner can add or update team members
        if not is_organization_owner(request.user, organization):
            return Response({'message': 'You are not authorized to get post in this organization.'},
                            status=status.HTTP_403_FORBIDDEN)

            # Fetch posts and separate grouped/ungrouped

        # Fetch only the first 5 scheduled posts
        scheduled_posts = Post.objects.filter(
            organization=organization,
            is_deleted=False,
            is_inactive=False,
            status="scheduled",
            platform=Platform.LINKEDIN
        ).order_by('-created_at')[:5]

        # Serialize the posts
        serialized_posts = PostSerializer(scheduled_posts, many=True).data

        return Response(serialized_posts, status=status.HTTP_200_OK)