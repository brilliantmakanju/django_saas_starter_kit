import threading
from django.conf import settings
from django.utils.timezone import now
from accounts.utlis.utlis import send_email

def send_contact_email_in_background(name, email, message):
    def _send():
        try:
            context = {
                "CONTACT_NAME": name,
                "CONTACT_EMAIL": email,
                "CONTACT_MESSAGE": message,
                "SUBMISSION_DATE": now().strftime("%B %d, %Y %I:%M %p"),
            }
            send_email(
                subject=f"New Contact Message from {name}",
                recipient_list=[settings.DJANGO_PRODUCT_OWNER_EMAIL],
                context=context,
                template="emails/contact_message_email.html",
                plain_message=f"Message from {name} ({email}):\n\n{message}"
            )
        except Exception as e:
            # Log the error silently
            import logging
            logger = logging.getLogger(__name__)
            logger.error("Failed to send contact email: %s", str(e))

    threading.Thread(target=_send, daemon=True).start()
