from django.contrib import admin
from .models import NewsletterPlatform, NewsletterSubscriber, ContactMessage
from django.utils.html import format_html
from django.utils.timezone import localtime

@admin.register(NewsletterPlatform)
class NewsletterPlatformAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'subscriber_count', 'created_at')
    search_fields = ('name',)
    ordering = ('name',)
    readonly_fields = ('created_at',)

    def get_queryset(self, request):
        # Prefetch subscribers to avoid N+1 queries in subscriber_count
        queryset = super().get_queryset(request)
        return queryset.prefetch_related('subscribers')

    def subscriber_count(self, obj):
        return obj.subscribers.count()

    subscriber_count.short_description = 'Subscribers'

    def created_at(self, obj):
        # Get the earliest subscriber timestamp
        earliest = obj.subscribers.order_by('subscribed_at').first()
        return earliest.subscribed_at if earliest else "-"

    created_at.short_description = "First Subscriber At"


@admin.action(description="Mark selected subscribers as inactive")
def deactivate_subscribers(modeladmin, request, queryset):
    updated = queryset.update(is_active=False)
    modeladmin.message_user(request, f"{updated} subscriber(s) deactivated.")


@admin.action(description="Mark selected subscribers as active")
def activate_subscribers(modeladmin, request, queryset):
    updated = queryset.update(is_active=True)
    modeladmin.message_user(request, f"{updated} subscriber(s) activated.")


@admin.register(NewsletterSubscriber)
class NewsletterSubscriberAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'email', 'platform', 'is_active', 'subscribed_at'
    )
    list_filter = (
        'platform', 'is_active', 'subscribed_at'
    )
    search_fields = ('email',)
    ordering = ('-subscribed_at',)
    autocomplete_fields = ['platform']
    actions = [deactivate_subscribers, activate_subscribers]
    list_display_links = ('email',)
    readonly_fields = ('subscribed_at',)
    date_hierarchy = 'subscribed_at'

    def get_queryset(self, request):
        # Optimize query with select_related
        queryset = super().get_queryset(request)
        return queryset.select_related('platform')





@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("name", "email", "short_message", "responded", "formatted_created_at")
    list_filter = ("responded", "created_at")
    search_fields = ("name", "email", "message")
    readonly_fields = ("name", "email", "message", "created_at")
    ordering = ("-created_at",)

    fieldsets = (
        (None, {
            "fields": ("name", "email", "message")
        }),
        ("Status", {
            "fields": ("responded", "created_at"),
        }),
    )

    def short_message(self, obj):
        return obj.message[:50] + "..." if len(obj.message) > 50 else obj.message
    short_message.short_description = "Message Preview"

    def formatted_created_at(self, obj):
        return localtime(obj.created_at).strftime("%Y-%m-%d %H:%M")
    formatted_created_at.short_description = "Submitted At"
