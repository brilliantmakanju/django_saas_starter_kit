from django.contrib import admin
from .models import Notification

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('title', 'organization', 'triggered_by', 'created_at')
    list_filter = ('organization', 'created_at')
    search_fields = ('title', 'message', 'organization__name', 'triggered_by__username')
    raw_id_fields = ('organization', 'triggered_by')
    readonly_fields = ('created_at',)
