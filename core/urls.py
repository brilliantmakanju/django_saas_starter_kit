from django.urls import path
from .views import GitHubWebhookView, CreateOrRegenerateWebhookView, PostView, PostGroupView

urlpatterns = [
    # Webhook endpoint for GitHub (Handles incoming push events from GitHub)
    path('webhook/', GitHubWebhookView.as_view(), name='webhook'),

    # Create or Regenerate Webhook secrets for GitHub
    path('webhook/create_or_regenerate/', CreateOrRegenerateWebhookView.as_view(), name='create_or_regenerate_webhook'),

    # PostView: Retrieve, Create, Edit, Delete Posts, Restore Deleted Post
    path('posts/', PostView.as_view(), name='posts'),  # For getting all posts, creating new post, and editing post

    # PostGroupView: Manage Post Groups, Retrieve all posts in a group, Clear trash
    path('posts/groups/', PostGroupView.as_view(), name='post_groups'),  # For viewing posts in a group and clearing trash
]
