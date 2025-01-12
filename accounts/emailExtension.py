from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from djoser import utils
from djoser.conf import settings
from django.conf import settings as django_settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


class BaseEmail:
    template_name = None

    def __init__(self, request=None, context=None, *args, **kwargs):
        self.request = request
        self.context = {} if context is None else context

    def get_context_data(self, user, context=None):
        context = context or {}
        site = get_current_site(self.request)
        protocol = "https" if self.request and self.request.is_secure() else "http"
        domain = django_settings.FRONTEND_DOMAIN or site.domain

        return {
            "user": user,
            "domain": domain,
            "protocol": protocol,
            "site_name": getattr(django_settings, "SITE_NAME", "Your Site"),
            **context,
        }

    def send(self, user, context=None):
        context = self.get_context_data(user, context)
        subject = render_to_string(f"{self.template_name}_subject.txt", context).strip()
        body = render_to_string(f"{self.template_name}.html", context)
        email_message = EmailMultiAlternatives(
            subject,
            body,
            django_settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )
        email_message.attach_alternative(body, "text/html")
        email_message.send()


class CustomActivationEmail(BaseEmail):
    template_name = "accounts/emails/custom_activation_email"

    def get_context_data(self, user, context=None):
        context = super().get_context_data(user, context)
        context["uid"] = utils.encode_uid(user)
        context["token"] = default_token_generator.make_token(user)
        context["url"] = settings.ACTIVATION_URL.format(**context)
        return context


class CustomPasswordResetEmail(BaseEmail):
    template_name = "accounts/emails/custom_password_reset_email"

    def get_context_data(self, user, context=None):
        context = super().get_context_data(user, context)
        context["uid"] = utils.encode_uid(user.pk)
        context["token"] = default_token_generator.make_token(user)
        context["url"] = settings.PASSWORD_RESET_CONFIRM_URL.format(**context)
        return context


class CustomUsernameResetEmail(BaseEmail):
    template_name = "accounts/emails/custom_username_reset_email"

    def get_context_data(self, user, context=None):
        context = super().get_context_data(user, context)
        context["uid"] = utils.encode_uid(user.pk)
        context["token"] = default_token_generator.make_token(user)
        context["url"] = settings.USERNAME_RESET_CONFIRM_URL.format(**context)
        return context






















# from djoser.email import ActivationEmail, PasswordResetEmail, PasswordChangedConfirmationEmail, UsernameChangedConfirmationEmail
# from django.core.mail import send_mail
# from django.template.loader import render_to_string
# from django.conf import settings
#
#
# class CustomActivationEmail(ActivationEmail):
#     def send(self, context):
#         if isinstance(context, list):  # Handle when context is a list
#             recipient = context[0]
#             # Fetch user object manually based on recipient
#             from django.contrib.auth import get_user_model
#             User = get_user_model()
#             try:
#                 user = User.objects.get(email=recipient)
#             except User.DoesNotExist:
#                 raise ValueError(f"No user found with email: {recipient}")
#
#             # Manually fetch the token for the user
#             from rest_framework_simplejwt.tokens import RefreshToken
#             token = RefreshToken.for_user(user)
#
#             # Construct activation URL and send email
#             activation_url = f"{settings.FRONTEND_DOMAIN}/inbox/{user.id}/{token}"
#
#             print(token, "Token")
#             print(user.id, "Devins")
#             subject = "Activate Your Account"
#             message = render_to_string('accounts/emails/custom_activation_email.html', {
#                 'user': user,
#                 'uid': user.id,
#                 'token': token,
#                 'domain': settings.FRONTEND_DOMAIN,
#                 'protocol': "https",
#                 'activation_url': activation_url,
#             })
#
#             send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient])
#         else:
#             # Default behavior for dictionary-based context
#             super().send(context)
#     # def send(self, context):
#     #     print(context, "Context")
#     #     # print(self, "Self is self")
#     #     # # print("Tojen")
#     #     """
#     #     Send the activation email with a custom template and context.
#     #     """
#         # user = context.get("user")
#         # token = context.get("token")
#         # activation_url = f"{settings.FRONTEND_URL}/inbox/{user.id}/{token}"
#         #
#         # subject = "Activate Your Account"
#         # message = render_to_string('accounts/emails/custom_activation_email.html', {
#         #     'user': user,
#         #     'activation_url': activation_url,
#         # })
#
#         # send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
#         # pass
#         # subject = "Activate Your Account"
#         # activation_url = f"{settings.FRONTEND_URL}/inbox/{user.id}/{token}"
#         # message = render_to_string('templates/accounts/emails/custom_activation_email.html', {
#         #     'user': user,
#         #     'token': token,
#         #     'activation_url': activation_url,
#         # })
#         # send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
#
#
# class CustomPasswordResetEmail(PasswordResetEmail):
#     def send(self, user, token):
#         subject = "Reset Your Password"
#         reset_url = f"{settings.FRONTEND_URL}/password/reset/{user.id}/{token}"
#         message = render_to_string('accounts/emails/custom_password_reset_email.html', {
#             'user': user,
#             'token': token,
#             'reset_url': reset_url,
#         })
#         send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
#
#
# class CustomPasswordChangedConfirmationEmail(PasswordChangedConfirmationEmail):
#     def send(self, user):
#         subject = "Your Password Was Changed"
#         message = render_to_string('accounts/emails/custom_password_changed_confirmation_email.html', {
#             'user': user,
#         })
#         send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
#
#
# class CustomUsernameChangedConfirmationEmail(UsernameChangedConfirmationEmail):
#     def send(self, user):
#         subject = "Your Username Was Changed"
#         message = render_to_string('accounts/emails/custom_username_changed_confirmation_email.html', {
#             'user': user,
#         })
#         send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
# # from djoser.email import ActivationEmail, PasswordResetEmail, PasswordChangedConfirmationEmail, UsernameChangedConfirmationEmail
# # from django.conf import settings
# # from django.template.loader import render_to_string
# # from django.core.mail import EmailMessage
# #
# #
# # class EmailHelper:
# #     @staticmethod
# #     def send_email(subject, template_name, context, recipient_email):
# #         # Add FRONTEND_DOMAIN to the context for dynamic links
# #         context['domain'] = settings.FRONTEND_DOMAIN
# #         message = render_to_string(template_name, context)
# #         email = EmailMessage(subject, message, to=[recipient_email])
# #         email.content_subtype = "html"
# #         email.send()
# #
# #     @staticmethod
# #     def send_activation_email(user, token):
# #         context = {
# #             'user': user,
# #             'url': f"{settings.FRONTEND_DOMAIN}/inbox/{user.pk}/{token}",
# #         }
# #         EmailHelper.send_email(
# #             "Activate Your Account",
# #             "emails/custom_activation_email.html",
# #             context,
# #             user.email,
# #         )
# #
# #     @staticmethod
# #     def send_password_reset_email(user, token):
# #         context = {
# #             'user': user,
# #             'url': f"{settings.FRONTEND_DOMAIN}/reset/{user.pk}/{token}",
# #         }
# #         EmailHelper.send_email(
# #             "Reset Your Password",
# #             "emails/custom_password_reset_email.html",
# #             context,
# #             user.email,
# #         )
# #
# #     @staticmethod
# #     def send_welcome_email(user):
# #         context = {
# #             'user': user,
# #             'url': f"{settings.FRONTEND_DOMAIN}/dashboard",
# #         }
# #         EmailHelper.send_email(
# #             "Welcome to Our Platform",
# #             "emails/custom_welcome_email.html",
# #             context,
# #             user.email,
# #         )
# #
# #
# # class CustomActivationEmail(ActivationEmail):
# #     template_name = 'emails/custom_activation_email.html'
# #
# #
# # class CustomPasswordResetEmail(PasswordResetEmail):
# #     template_name = 'emails/custom_password_reset_email.html'
# #
# #
# # class CustomPasswordChangedConfirmationEmail(PasswordChangedConfirmationEmail):
# #     template_name = 'emails/custom_password_changed_confirmation_email.html'
# #
# #
# # class CustomUsernameChangedConfirmationEmail(UsernameChangedConfirmationEmail):
# #     template_name = 'emails/custom_username_changed_confirmation_email.html'
# #
