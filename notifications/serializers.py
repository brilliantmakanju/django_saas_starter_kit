from rest_framework import serializers
from .models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    triggered_by = serializers.StringRelatedField()

    class Meta:
        model = Notification
        fields = ['id', 'organization', 'title', 'message', 'triggered_by', 'is_read_by', 'created_at']
