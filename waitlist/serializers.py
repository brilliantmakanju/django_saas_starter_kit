from rest_framework import serializers
from .models import NewsletterPlatform, NewsletterSubscriber, ContactMessage


class NewsletterSubscribeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    platform = serializers.CharField()

    def validate(self, data):
        email = data['email']
        platform_name = data['platform'].strip()

        platform, _ = NewsletterPlatform.objects.get_or_create(name=platform_name)

        # Save reference for use in `create`
        data['platform_obj'] = platform

        if NewsletterSubscriber.objects.filter(email=email, platform=platform).exists():
            raise serializers.ValidationError("You are already subscribed to this platform.")

        return data

    def create(self, validated_data):
        return NewsletterSubscriber.objects.create(
            email=validated_data['email'],
            platform=validated_data['platform_obj']
        )


class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'message']

    def validate_message(self, value):
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Message is too short.")
        return value