from django.urls import path
from .views import (
    GitHubWebhookView,
    CreateOrRegenerateWebhookView,
    GetOrganizationWebhookView,
    PostView,
    PostGroupView,
    UpdateWebhookSettingsView  # New endpoint for updating webhook settings (branch and repo)
)

urlpatterns = [
    # Webhook endpoint for GitHub (Handles incoming push events from GitHub)
    path('webhook/', GitHubWebhookView.as_view(), name='webhook'),

    # Create or Regenerate Webhook secrets for GitHub
    path('webhook/create_or_regenerate/', CreateOrRegenerateWebhookView.as_view(), name='create_or_regenerate_webhook'),

    # Retrieve Webhook secrets for GitHub
    path('webhook/retrieve/', GetOrganizationWebhookView.as_view(), name='get_organization_webhook'),

    # Update GitHub webhook settings (edit branch and repo)
    path('webhook/settings/', UpdateWebhookSettingsView.as_view(), name='update_webhook_settings'),

    # PostView: Retrieve, Create, Edit, Delete Posts, Restore Deleted Post
    path('posts/', PostView.as_view(), name='posts'),

    # PostGroupView: Manage Post Groups, Retrieve all posts in a group, Clear trash
    path('posts/groups/', PostGroupView.as_view(), name='post_groups'),
]
