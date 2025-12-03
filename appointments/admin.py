"""
Admin configuration for Appointment model.
Enhanced with custom actions, filters, and display methods.
"""
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import Appointment


@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'client_name', 'client_phone', 'provider_link', 'service', 
        'appointment_date', 'appointment_time', 'status_badge', 
        'payment_badge', 'reminder_status', 'created_at'
    ]
    list_filter = [
        'status', 'payment_status', 'appointment_date', 
        'reminder_sent', 'created_at', 
        'service_provider__business_type', 'service_provider__current_plan'
    ]
    search_fields = [
        'id', 'client_name', 'client_phone', 'client_email',
        'service_provider__business_name', 'service__service_name'
    ]
    readonly_fields = [
        'created_at', 'updated_at', 'appointment_status_display',
        'provider_plan_info'
    ]
    date_hierarchy = 'appointment_date'
    list_per_page = 50
    
    # Custom actions
    actions = [
        'mark_as_confirmed', 
        'mark_as_completed', 
        'mark_as_cancelled',
        'mark_as_no_show',
        'mark_as_paid',
        'send_reminder_emails'
    ]
    
    fieldsets = (
        ('Provider & Service', {
            'fields': ('service_provider', 'service', 'provider_plan_info')
        }),
        ('Client Information', {
            'fields': ('client', 'client_name', 'client_phone', 'client_email')
        }),
        ('Appointment Details', {
            'fields': (
                'appointment_date', 'appointment_time', 
                'status', 'appointment_status_display', 'notes'
            )
        }),
        ('Payment Information', {
            'fields': ('total_price', 'payment_status', 'payment_method')
        }),
        ('Notifications', {
            'fields': ('reminder_sent',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        """Optimize queries with select_related."""
        return super().get_queryset(request).select_related(
            'service_provider', 'service', 'client', 'service_provider__user'
        )
    
    # Custom display methods
    def provider_link(self, obj):
        """Display provider with link to provider admin."""
        url = reverse('admin:providers_serviceprovider_change', args=[obj.service_provider.id])
        return format_html('<a href="{}">{}</a>', url, obj.service_provider.business_name)
    provider_link.short_description = 'Provider'
    provider_link.admin_order_field = 'service_provider__business_name'
    
    def status_badge(self, obj):
        """Display status with colored badge."""
        colors = {
            'pending': '#ffc107',
            'confirmed': '#28a745',
            'completed': '#007bff',
            'cancelled': '#dc3545',
            'no_show': '#6c757d',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-weight: bold;">{}</span>',
            color, obj.get_status_display().upper()
        )
    status_badge.short_description = 'Status'
    status_badge.admin_order_field = 'status'
    
    def payment_badge(self, obj):
        """Display payment status with colored badge."""
        colors = {
            'pending': '#ffc107',
            'paid': '#28a745',
            'refunded': '#dc3545',
        }
        color = colors.get(obj.payment_status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 8px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_payment_status_display().upper()
        )
    payment_badge.short_description = 'Payment'
    payment_badge.admin_order_field = 'payment_status'
    
    def reminder_status(self, obj):
        """Display reminder sent status."""
        if obj.reminder_sent:
            return format_html('<span style="color: green;">✅ Sent</span>')
        else:
            return format_html('<span style="color: gray;">⏳ Pending</span>')
    reminder_status.short_description = 'Reminder'
    reminder_status.admin_order_field = 'reminder_sent'
    
    def appointment_status_display(self, obj):
        """Detailed appointment status for detail view."""
        if obj.is_upcoming:
            return "✅ Upcoming appointment"
        elif obj.is_past:
            return "⏰ Past appointment"
        else:
            return "📅 Scheduled"
    appointment_status_display.short_description = 'Appointment Status'
    
    def provider_plan_info(self, obj):
        """Display provider's plan information."""
        provider = obj.service_provider
        if provider.is_pro():
            return format_html(
                '<span style="color: green; font-weight: bold;">PRO Plan</span> '
                '(SMS notifications enabled)'
            )
        else:
            return format_html(
                '<span style="color: gray;">FREE Plan</span> '
                '(Email notifications only)'
            )
    provider_plan_info.short_description = 'Provider Plan'
    
    # Custom actions
    def mark_as_confirmed(self, request, queryset):
        """Confirm selected appointments and send notifications."""
        from utils.tasks import send_appointment_confirmation_task
        
        updated = 0
        for appointment in queryset.filter(status='pending'):
            appointment.status = 'confirmed'
            appointment.save()
            
            # Send confirmation email (and SMS if PRO)
            send_sms = appointment.service_provider.is_pro()
            send_appointment_confirmation_task.delay(
                appointment.id, 
                to_provider=False, 
                send_sms=send_sms
            )
            updated += 1
        
        self.message_user(request, f'{updated} appointments confirmed and notifications sent.')
    mark_as_confirmed.short_description = 'Confirm and notify'
    
    def mark_as_completed(self, request, queryset):
        """Mark selected appointments as completed."""
        updated = queryset.filter(status='confirmed').update(status='completed')
        self.message_user(request, f'{updated} appointments marked as completed.')
    mark_as_completed.short_description = 'Mark as Completed'
    
    def mark_as_cancelled(self, request, queryset):
        """Cancel selected appointments and send notifications."""
        from utils.tasks import send_appointment_cancelled_task
        
        updated = 0
        for appointment in queryset.filter(status__in=['pending', 'confirmed']):
            appointment.status = 'cancelled'
            appointment.save()
            
            # Send cancellation notification
            send_sms = appointment.service_provider.is_pro()
            send_appointment_cancelled_task.delay(
                appointment.id,
                cancelled_by='admin',
                send_sms=send_sms
            )
            updated += 1
        
        self.message_user(request, f'{updated} appointments cancelled and notifications sent.')
    mark_as_cancelled.short_description = 'Cancel and notify'
    
    def mark_as_no_show(self, request, queryset):
        """Mark selected appointments as no-show."""
        updated = queryset.filter(status='confirmed').update(status='no_show')
        self.message_user(request, f'{updated} appointments marked as no-show.')
    mark_as_no_show.short_description = 'Mark as No-Show'
    
    def mark_as_paid(self, request, queryset):
        """Mark selected appointments as paid."""
        updated = queryset.filter(payment_status='pending').update(payment_status='paid')
        self.message_user(request, f'{updated} appointments marked as paid.')
    mark_as_paid.short_description = 'Mark as Paid'
    
    def send_reminder_emails(self, request, queryset):
        """Send reminder emails for selected appointments."""
        from utils.tasks import send_appointment_reminder_task
        
        count = 0
        for appointment in queryset.filter(
            status__in=['pending', 'confirmed'],
            reminder_sent=False
        ):
            send_sms = appointment.service_provider.is_pro()
            send_appointment_reminder_task.delay(appointment.id, send_sms=send_sms)
            count += 1
        
        self.message_user(request, f'Queued {count} reminder notifications.')
    send_reminder_emails.short_description = 'Send reminder notifications'
