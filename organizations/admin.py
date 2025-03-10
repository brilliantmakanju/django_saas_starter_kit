from django_tenants.admin import TenantAdminMixin

from .models import Domain

from django.utils import timezone
from datetime import timedelta
from django.contrib import admin
from .models import InviteCode, Organization, UserOrganizationRole
from django.utils.html import format_html
from unfold.admin import ModelAdmin


class InviteCodeAdmin(ModelAdmin):
    list_display = (
        'code',
        'invitee_email',
        'role',
        'organization',
        'status',
        'expires',
        'invited_by',
        'created_at',
        'used_at',
        'is_expired',
        'secret'
    )
    search_fields = ('invitee_email', 'code', 'organization__name', 'invited_by__email')
    list_filter = ('status', 'role', 'organization', 'created_at')

    # This is to format the invite code in a more readable way (add a link to the invitee)
    def is_expired(self, obj):
        if obj.is_expired():
            return format_html('<span style="color:red;">Expired</span>')
        return format_html('<span style="color:green;">Active</span>')

    is_expired.short_description = 'Status'

    # Adding a way to quickly edit the expiration date
    def set_expiry(self, request, queryset):
        queryset.update(expires=timezone.now() + timedelta(days=3))  # Automatically extend expiry by 3 days

    set_expiry.short_description = "Extend expiry by 3 days"

    actions = [set_expiry]

    # Adding ordering and default filter options
    ordering = ('-created_at',)  # Orders by creation date, most recent first

admin.site.register(InviteCode, InviteCodeAdmin)

class UserOrganizationRoleAdmin(ModelAdmin):
    list_display = ('user', 'organization', 'role')  # Display these fields in the admin list view
    list_filter = ('role',)  # Add filtering by role
    search_fields = ('user__email', 'organization__name')  # Enable search by user email and organization name
    ordering = ('organization', 'role')  # Order by organization and role
    # autocomplete_fields = ('user', 'organization')  # Enable autocomplete for related fields

    def get_readonly_fields(self, request, obj=None):
        """
        Make the 'role' field readonly for existing objects to prevent modification of critical roles.
        """
        if obj:
            return ['role']
        return []

# Register the model with the customized admin class
admin.site.register(UserOrganizationRole, UserOrganizationRoleAdmin)

class OrganizationAdmin(TenantAdminMixin, ModelAdmin):
    list_display = ('name', 'schema_name', 'created_on', 'selected_tone', 'shuffle_tones', 'has_twitter', 'has_linkedin')  # Added new fields
    list_filter = ('created_on', 'selected_tone', 'shuffle_tones', 'has_twitter', 'has_linkedin')  # Allow filtering by tone and shuffle status
    search_fields = ('name', 'schema_name', 'owner__username')  # Search includes owner username
    ordering = ('name',)

    fieldsets = (
        (None, {
            'fields': ('name', 'schema_name', 'owner')
        }),
        ('Tone Settings', {
            'fields': ('selected_tone', 'shuffle_tones'),  # Added tone settings
        }),
        (
            'Platform', {
                'fields': ('has_twitter', 'has_linkedin')
            }
        ),
        ('Metadata', {
            'fields': ('created_on',),
            'classes': ('collapse',),
        }),
    )

    readonly_fields = ('created_on',)  # Make `created_on` read-only
    exclude = ()  # Ensure fields are not excluded from the form

    def save_model(self, request, obj, form, change):
        if not obj.schema_name:
            obj.schema_name = obj.name.lower().replace(" ", "_")
        obj.save()


class DomainAdmin(ModelAdmin):
    list_display = ('domain', 'tenant', 'is_primary')
    list_filter = ('is_primary',)
    search_fields = ('domain',)

    fieldsets = (
        (None, {
            'fields': ('domain', 'tenant', 'is_primary')
        }),
    )

admin.site.register(Organization, OrganizationAdmin)
admin.site.register(Domain, DomainAdmin)