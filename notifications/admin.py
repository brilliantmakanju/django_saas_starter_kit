from django.contrib import admin
from .models import Notification
from unfold.admin import ModelAdmin

@admin.register(Notification)
class NotificationAdmin(ModelAdmin):
    list_display = ('title', 'organization', 'triggered_by', 'created_at')
    list_filter = ('organization', 'created_at')
    search_fields = ('title', 'message', 'organization__name', 'triggered_by__username')
    raw_id_fields = ('organization', 'triggered_by')
    readonly_fields = ('created_at',)
