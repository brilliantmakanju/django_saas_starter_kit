from django.contrib import admin
from .models import Webhook, Post, PostGroup, SocialMediaAccount
from django.utils.html import format_html

@admin.register(Webhook)
class WebhookAdmin(admin.ModelAdmin):
    list_display = ['organization', 'enabled', 'created_at', 'updated_at']
    search_fields = ['organization__name']
    list_filter = ['enabled']



class PostAdmin(admin.ModelAdmin):
    list_display = (
        'content_preview',
        'status',
        'original_status',
        'platform',
        'created_at',
        'updated_at',
        'is_deleted',
        'is_inactive',
        'organization',
        'post_group_link'
    )
    list_filter = ('status', 'platform', 'is_deleted', 'is_inactive', 'created_at', 'updated_at', 'organization')
    search_fields = ('content', 'organization__name',)
    readonly_fields = ('original_status', 'status', 'is_deleted', 'is_inactive', 'created_at', 'updated_at')

    # Add actions to the admin interface for deleting and restoring posts
    actions = ['mark_as_deleted', 'mark_as_inactive', 'restore_post', 'clear_trash']

    def content_preview(self, obj):
        """Display a short preview of the post content."""
        return format_html(f"<span>{obj.content[:50]}...</span>")

    def post_group_link(self, obj):
        """Link to the post group to view all related posts."""
        if obj.post_group:
            return format_html(
                f'<a href="/admin/app_name/postgroup/{obj.post_group.id}/change/">{obj.post_group.id}</a>')
        return "No group"

    post_group_link.short_description = "Post Group"

    def mark_as_deleted(self, request, queryset):
        """Mark selected posts as deleted."""
        queryset.update(status=Post.Status.DELETED, is_deleted=True, is_inactive=False)

    mark_as_deleted.short_description = "Mark selected posts as deleted"

    def mark_as_inactive(self, request, queryset):
        """Mark selected posts as inactive."""
        queryset.update(status=Post.Status.INACTIVE, is_inactive=True, is_deleted=False)

    mark_as_inactive.short_description = "Mark selected posts as inactive"

    def restore_post(self, request, queryset):
        """Restore selected posts to their original status."""
        for post in queryset:
            post.status = post.original_status or Post.Status.DRAFTED
            post.is_deleted = False
            post.is_inactive = False
            post.save()

    restore_post.short_description = "Restore selected posts"

    def clear_trash(self, request, queryset):
        """Clear deleted posts permanently."""
        queryset.filter(is_deleted=True).delete()

    clear_trash.short_description = "Clear trash (permanently delete posts)"

    def get_queryset(self, request):
        """Override queryset to add custom filtering logic."""
        queryset = super().get_queryset(request)
        # Only show posts for the current user’s organization
        if request.user.is_staff:
            return queryset
        return queryset.filter(organization=request.user.organization)

    def save_model(self, request, obj, form, change):
        """Override save logic to set some fields automatically."""
        if not obj.id:  # Only set the organization if the post is being created
            obj.organization = request.user.organization
        super().save_model(request, obj, form, change)


@admin.register(PostGroup)
class PostGroupAdmin(admin.ModelAdmin):
    """
    Admin configuration for the PostGroup model to make it more detailed and user-friendly.
    """
    list_display = ("id", "name", "organization", "description_short", "created_at", "updated_at")
    list_filter = ("created_at", "updated_at", "organization")
    search_fields = ("id", "name", "description", "organization__name")
    ordering = ("-created_at",)
    readonly_fields = ("id", "created_at", "updated_at")
    fieldsets = (
        ("General Information", {
            "fields": ("id", "name", "description", "organization"),
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
        }),
    )

    def description_short(self, obj):
        """
        Returns a truncated version of the description for display in the list view.
        """
        return obj.description[:50] + "..." if obj.description and len(obj.description) > 50 else obj.description

    description_short.short_description = "Description (short)"


# class PostGroupAdmin(admin.ModelAdmin):
#     list_display = ("id", "name", "organization", "created_at", "updated_at")
#     list_filter = ("organization",)
#     # search_fields


# Register the Post and PostGroup models with the admin interface
admin.site.register(Post, PostAdmin)
# admin.site.register(PostGroup, PostGroupAdmin)


class SocialMediaAccountAdmin(admin.ModelAdmin):
    list_display = (
        'organization',
        'platform',
        'user',
        'connected_at',
        'access_token',
        'access_token_secret'
    )
    list_filter = ('platform', 'organization', 'user')
    search_fields = ('organization__name', 'platform', 'user__email', 'access_token')
    list_per_page = 20
    ordering = ('-connected_at',)

    # You can use this to limit field choices for the platform (Twitter, LinkedIn)
    fieldsets = (
        (None, {
            'fields': ('organization', 'user', 'platform')
        }),
        ('Access Credentials', {
            'fields': ('access_token', 'access_token_secret'),
            'classes': ('collapse',),
        }),
        ('Connection Info', {
            'fields': ('connected_at',),
            'classes': ('collapse',),
        }),
    )

    # Display platform choices more clearly
    def platform_display(self, obj):
        return obj.get_platform_display()

    platform_display.short_description = 'Platform'

    # Add inlines for showing the related social media accounts if needed
    def get_readonly_fields(self, request, obj=None):
        if obj:
            return ['access_token', 'access_token_secret']
        return self.readonly_fields


# Register your models
admin.site.register(SocialMediaAccount, SocialMediaAccountAdmin)