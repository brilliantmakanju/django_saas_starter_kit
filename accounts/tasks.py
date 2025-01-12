# tasks.py
from background_task import background
from accounts.models import UserAccount
from django.core.mail import send_mail
from django.conf import settings

@background(schedule=10)  # Schedule the task to run 60 seconds after being called
def send_email_to_all_users():
    users = UserAccount.objects.all()  # Retrieve all users in the database
    subject = 'Important Notification'
    message = 'This is a scheduled notification sent to all users.'

    # Loop through each user and send an email
    for user in users:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,  # From email address
            [user.email],  # Send to user's email address
            fail_silently=False,
        )
