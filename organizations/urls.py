from django.urls import path
from .views import (
    OrganizationView,
    TeamMembersView,
    JoinOrganizationView,
    OrganizationJoinView,
    IsOwner,
    UpdateToneSettingsView,  # Import the UpdateToneSettingsView
    OrganizationStatusView,
)

urlpatterns = [
    path('is-owner/', IsOwner.as_view(), name='is_owner'),  # Is Owner
    path('', OrganizationView.as_view(), name='organization_view'),  # Handles organization-related actions
    path('team-members/', TeamMembersView.as_view(), name='team_members_view'),  # Manage team members
    path('join/', JoinOrganizationView.as_view(), name='join_organization_view'),  # Endpoint for joining organizations
    path('join-link/', OrganizationJoinView.as_view(), name='organization_join_view'),  # Join organizations via a link
    path('tone-settings/', UpdateToneSettingsView.as_view(), name='update_tone_settings_view'),  # Update tone and shuffle settings
    path('status/', OrganizationStatusView.as_view(), name='organization_status_view'), # Get Org social status
]