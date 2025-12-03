"""
Client portal models for favorite providers and preferences.
"""
from django.db import models
from django.conf import settings


class FavoriteProvider(models.Model):
    """
    Allows clients to save their favorite service providers for quick booking.
    """
    
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='favorite_providers'
    )
    
    provider = models.ForeignKey(
        'providers.ServiceProvider',
        on_delete=models.CASCADE,
        related_name='favorited_by'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Favorite Provider'
        verbose_name_plural = 'Favorite Providers'
        unique_together = ['client', 'provider']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.client.email} → {self.provider.business_name}"


class ClientNotificationPreference(models.Model):
    """
    Client notification preferences for email, SMS, WhatsApp.
    """
    
    client = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notification_preferences'
    )
    
    # Email notifications
    email_enabled = models.BooleanField(
        default=True,
        help_text='Receive email notifications'
    )
    
    # SMS notifications (if provider is PRO)
    sms_enabled = models.BooleanField(
        default=True,
        help_text='Receive SMS notifications (if provider has PRO plan)'
    )
    
    # Notification types
    booking_confirmation = models.BooleanField(
        default=True,
        help_text='Receive booking confirmation notifications'
    )
    
    appointment_reminders = models.BooleanField(
        default=True,
        help_text='Receive appointment reminder notifications'
    )
    
    cancellation_updates = models.BooleanField(
        default=True,
        help_text='Receive cancellation/rescheduling notifications'
    )
    
    promotional_emails = models.BooleanField(
        default=False,
        help_text='Receive promotional emails from providers'
    )
    
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Notification Preference'
        verbose_name_plural = 'Notification Preferences'
    
    def __str__(self):
        return f"Preferences for {self.client.email}"
