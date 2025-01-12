from rest_framework import serializers
from .models import Post, PostGroup


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = [
            'id', 'content', 'platform', 'status', 'original_status',
            'image_urls', 'video_url', 'is_deleted', 'is_inactive',
            'post_group', 'created_at', 'updated_at', 'organization',
        ]
        # read_only_fields = ['id', 'created_at', 'updated_at', 'organization']


class PostGroupSerializer(serializers.ModelSerializer):
    posts = PostSerializer(many=True, read_only=True, source='post_set')

    class Meta:
        model = PostGroup
        fields = ['id', 'created_at', 'updated_at', 'posts']
        read_only_fields = ['id', 'created_at', 'updated_at']
