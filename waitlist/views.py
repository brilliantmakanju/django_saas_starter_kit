from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .background_tasks import send_contact_email_in_background
from .serializers import NewsletterSubscribeSerializer, ContactMessageSerializer
from .models import NewsletterPlatform


class NewsletterSubscribeView(APIView):
    def post(self, request):
        serializer = NewsletterSubscribeSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({
                "success": True,
                "message": "Successfully subscribed to the newsletter."
            }, status=status.HTTP_201_CREATED)

        # Check for already subscribed case
        error_message = serializer.errors.get("non_field_errors")
        if error_message and "already subscribed" in error_message[0].lower():
            return Response({
                "success": False,
                "message": "You are already subscribed to this newsletter."
            }, status=status.HTTP_200_OK)

        # Other validation errors
        return Response({
            "success": False,
            "message": "Invalid data submitted.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


class NewsletterSubscriberCountView(APIView):
    def get(self, request, platform_name):
        try:
            platform = NewsletterPlatform.objects.get(name=platform_name)
            count = platform.subscribers.filter(is_active=True).count()
            return Response({"platform": platform_name, "subscribers": count})
        except NewsletterPlatform.DoesNotExist:
            return Response({"error": "Platform not found."}, status=status.HTTP_404_NOT_FOUND)


class ContactMessageView(APIView):
    def post(self, request):
        serializer = ContactMessageSerializer(data=request.data)

        if serializer.is_valid():
            data = serializer.validated_data
            name = data['name']
            email = data['email']
            message = data['message']

            # Save to DB
            serializer.save()

            # Send email in background
            send_contact_email_in_background(name, email, message)

            return Response({
                "success": True,
                "message": "Your message has been received. We'll get back to you shortly."
            }, status=status.HTTP_201_CREATED)

        return Response({
            "success": False,
            "message": "Invalid input.",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

