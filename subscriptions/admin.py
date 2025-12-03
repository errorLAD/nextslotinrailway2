"""
Admin configuration for Subscription models.
Enhanced with editable list view and custom display methods.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import SubscriptionPlan, Payment


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'plan_badge', 'price_display', 
        'appointments_limit', 'services_limit', 
        'is_active', 'display_order'
    ]
    list_filter = ['plan_type', 'is_active']
    search_fields = ['name']
    readonly_fields = ['created_at', 'updated_at', 'features_display']
    ordering = ['display_order', 'price_monthly']
    
    # Enable list editing for quick updates
    list_editable = ['is_active', 'display_order']
    
    fieldsets = (
        ('Plan Information', {
            'fields': ('name', 'plan_type', 'price_monthly', 'display_order')
        }),
        ('Limits', {
            'fields': ('max_appointments_per_month', 'max_services')
        }),
        ('Features', {
            'fields': ('features', 'features_display'),
            'description': 'JSON object containing plan features. Example: {"sms": true, "analytics": true}'
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    # Custom display methods
    def plan_badge(self, obj):
        """Display plan type with colored badge."""
        if obj.plan_type == 'pro':
            return format_html(
                '<span style="background-color: #28a745; color: white; padding: 3px 10px; '
                'border-radius: 3px; font-weight: bold;">PRO</span>'
            )
        else:
            return format_html(
                '<span style="background-color: #6c757d; color: white; padding: 3px 10px; '
                'border-radius: 3px; font-weight: bold;">FREE</span>'
            )
    plan_badge.short_description = 'Type'
    plan_badge.admin_order_field = 'plan_type'
    
    def price_display(self, obj):
        """Display price with currency."""
        if obj.price_monthly == 0:
            return format_html('<span style="color: green; font-weight: bold;">FREE</span>')
        return f"₹{obj.price_monthly}/month"
    price_display.short_description = 'Price'
    price_display.admin_order_field = 'price_monthly'
    
    def appointments_limit(self, obj):
        """Display appointments limit."""
        if obj.max_appointments_per_month is None:
            return format_html('<span style="color: green;">♾️ Unlimited</span>')
        return f"{obj.max_appointments_per_month}/month"
    appointments_limit.short_description = 'Appointments'
    
    def services_limit(self, obj):
        """Display services limit."""
        if obj.max_services is None:
            return format_html('<span style="color: green;">♾️ Unlimited</span>')
        return str(obj.max_services)
    services_limit.short_description = 'Services'
    
    def features_display(self, obj):
        """Display features in a readable format."""
        if not obj.features:
            return "No features defined"
        
        features_html = "<ul>"
        for key, value in obj.features.items():
            icon = "✅" if value else "❌"
            features_html += f"<li>{icon} {key.replace('_', ' ').title()}</li>"
        features_html += "</ul>"
        return format_html(features_html)
    features_display.short_description = 'Features'


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'provider_link', 'plan', 'amount_display', 
        'status_badge', 'payment_method', 'created_at'
    ]
    list_filter = ['status', 'plan', 'created_at', 'payment_method']
    search_fields = [
        'id', 'provider__business_name', 'provider__user__email',
        'razorpay_order_id', 'razorpay_payment_id'
    ]
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'
    list_per_page = 50
    
    # Custom actions
    actions = ['mark_as_success', 'mark_as_failed', 'send_receipt']
    
    fieldsets = (
        ('Payment Information', {
            'fields': ('provider', 'plan', 'amount', 'status')
        }),
        ('Razorpay Details', {
            'fields': (
                'razorpay_order_id', 'razorpay_payment_id', 
                'razorpay_signature', 'payment_method'
            )
        }),
        ('Additional Info', {
            'fields': ('notes',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        """Optimize queries."""
        return super().get_queryset(request).select_related('provider', 'plan', 'provider__user')
    
    # Custom display methods
    def provider_link(self, obj):
        """Display provider with link."""
        url = reverse('admin:providers_serviceprovider_change', args=[obj.provider.id])
        return format_html('<a href="{}">{}</a>', url, obj.provider.business_name)
    provider_link.short_description = 'Provider'
    provider_link.admin_order_field = 'provider__business_name'
    
    def amount_display(self, obj):
        """Display amount with currency."""
        return f"₹{obj.amount}"
    amount_display.short_description = 'Amount'
    amount_display.admin_order_field = 'amount'
    
    def status_badge(self, obj):
        """Display status with colored badge."""
        colors = {
            'pending': '#ffc107',
            'success': '#28a745',
            'failed': '#dc3545',
            'refunded': '#6c757d',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_status_display().upper()
        )
    status_badge.short_description = 'Status'
    status_badge.admin_order_field = 'status'
    
    # Custom actions
    def mark_as_success(self, request, queryset):
        """Mark selected payments as successful."""
        updated = queryset.filter(status='pending').update(status='success')
        self.message_user(request, f'{updated} payment(s) marked as successful.')
    mark_as_success.short_description = 'Mark as Successful'
    
    def mark_as_failed(self, request, queryset):
        """Mark selected payments as failed."""
        updated = queryset.filter(status='pending').update(status='failed')
        self.message_user(request, f'{updated} payment(s) marked as failed.')
    mark_as_failed.short_description = 'Mark as Failed'
    
    def send_receipt(self, request, queryset):
        """Send payment receipt emails."""
        from utils.email_utils import send_payment_receipt_email
        
        count = 0
        for payment in queryset.filter(status='success'):
            # Create a mock subscription payment object for the email
            class MockPayment:
                def __init__(self, payment_obj):
                    self.id = payment_obj.id
                    self.provider = payment_obj.provider
                    self.amount = payment_obj.amount
                    self.payment_date = payment_obj.created_at
                    self.payment_method = payment_obj.payment_method or 'online'
                    self.razorpay_payment_id = payment_obj.razorpay_payment_id
                    self.duration_months = 1
                    self.plan_start_date = payment_obj.provider.plan_start_date
                    self.plan_end_date = payment_obj.provider.plan_end_date
            
            if send_payment_receipt_email(MockPayment(payment)):
                count += 1
        
        self.message_user(request, f'Sent {count} payment receipt(s).')
    send_receipt.short_description = 'Send payment receipt'
