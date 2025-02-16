from rest_framework import serializers
from .models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    triggered_by = serializers.StringRelatedField()
    is_read = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = [
            'id',
            'organization',
            'title',
            'message',
            'triggered_by',
            'is_read_by',
            'is_read',
            'created_at'
        ]

    def get_is_read(self, obj):
        """
        Returns True if the current user's ID is present in the notification's is_read_by list.
        """
        request = self.context.get('request', None)
        if request and hasattr(request, 'user'):
            # For ManyToMany fields, we can check if the current user exists in the related set.
            return obj.is_read_by.filter(id=request.user.id).exists()
        return False