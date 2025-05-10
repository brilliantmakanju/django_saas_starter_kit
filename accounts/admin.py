from django.contrib import admin
from .models import UserAccount, SubscriptionPlan, Payment
from unfold.admin import ModelAdmin

class SubscriptionPlanAdmin(ModelAdmin):
    list_display = ('name', 'stripe_price_id', 'description', 'created_at')
    search_fields = ('name', 'description')
    list_filter = ('name', 'created_at')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)


class UserAccountAdmin(ModelAdmin):
    list_display = (
        'email', 'first_name', 'last_name', 'username',
        'plan', 'subscription_status', 'subscription_end_date',
        'is_active', 'is_staff', 'show_connected_accounts',
    )
    search_fields = ('email', 'first_name', 'last_name', 'username')
    list_filter = ('plan', 'subscription_status', 'is_active', 'is_staff')
    # ordering = ('-created-at',)
    readonly_fields = ('id',)
    fieldsets = (
        ('Personal Info', {
            'fields': ('first_name', 'last_name', 'email', 'username', 'bio', 'profile', 'password')
        }),
        ('Subscription Info', {
            'fields': ('plan', 'subscription_status', 'subscription_end_date', 'stripe_subscription_id')
        }),
        ('Social Media Connections', {
            'fields': ('google_connected', 'github_connected')
        }),
        ('Organizations', {
            'fields': ('organizations',)
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
    )

    actions = ['activate_users', 'deactivate_users', 'reset_user_subscription']

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        if obj and not obj.password:
            form.base_fields['password'].required = False
        return form

    def show_connected_accounts(self, obj):
        connections = []
        if obj.google_connected:
            connections.append('Google')
        if obj.github_connected:
            connections.append('GitHub')
        return ', '.join(connections) if connections else 'None'
    show_connected_accounts.short_description = 'Connected Accounts'

    def activate_users(self, request, queryset):
        updated = queryset.update(is_active=True)
        self.message_user(request, f'{updated} users activated successfully.')

    def deactivate_users(self, request, queryset):
        updated = queryset.update(is_active=False)
        self.message_user(request, f'{updated} users deactivated successfully.')

    def reset_user_subscription(self, request, queryset):
        for user in queryset:
            user.plan = UserAccount.BASIC
            user.subscription_status = 'unactive'
            user.subscription_end_date = None
            user.save()
        self.message_user(request, 'Selected user subscriptions have been reset.')



class PaymentAdmin(ModelAdmin):
    list_display = ('user', 'plan', 'period', 'status', 'starts_at', 'ends_at')
    list_filter = ('plan', 'status', 'period')
    search_fields = ('user__email', 'transaction_ref')
    actions = ['approve_payment', 'reject_payment', 'verify_payment']

    def approve_payment(self, request, queryset):
        for payment in queryset:
            payment.status = 'verified'
            payment.save()
            # send_mail(
            #     'Payment Approved',
            #     f'Payment for {payment.user.email} has been approved.',
            #     settings.DEFAULT_FROM_EMAIL,
            #     ['youremail@example.com'],
            # )

    def reject_payment(self, request, queryset):
        queryset.update(status='expired')

    def verify_payment(self, request, queryset):
        for payment in queryset:
            if payment.status == 'pending':
                payment.status = 'verified'
                payment.save()

admin.site.register(Payment, PaymentAdmin)
admin.site.register(UserAccount, UserAccountAdmin)
admin.site.register(SubscriptionPlan, SubscriptionPlanAdmin)


