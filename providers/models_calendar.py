"""
Google Calendar integration models (PRO plan only).
Stores OAuth tokens and calendar sync settings.
"""
from django.db import models
from django.conf import settings
from .models import ServiceProvider


class GoogleCalendarIntegration(models.Model):
    """
    Google Calendar OAuth credentials and settings (PRO plan only).
    Stores refresh tokens for accessing provider's Google Calendar.
    """
    
    service_provider = models.OneToOneField(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='google_calendar'
    )
    
    # OAuth 2.0 credentials
    google_email = models.EmailField(
        help_text='Google account email'
    )
    
    access_token = models.TextField(
        blank=True,
        help_text='Google OAuth access token (short-lived)'
    )
    
    refresh_token = models.TextField(
        help_text='Google OAuth refresh token (long-lived, encrypted)'
    )
    
    token_expiry = models.DateTimeField(
        null=True,
        blank=True,
        help_text='When the access token expires'
    )
    
    # Calendar settings
    calendar_id = models.CharField(
        max_length=255,
        default='primary',
        help_text='Google Calendar ID (usually "primary")'
    )
    
    # Sync settings
    is_active = models.BooleanField(
        default=True,
        help_text='Whether calendar sync is active'
    )
    
    sync_enabled = models.BooleanField(
        default=True,
        help_text='Enable automatic syncing'
    )
    
    two_way_sync = models.BooleanField(
        default=False,
        help_text='Enable two-way sync (advanced feature)'
    )
    
    # Sync status
    last_sync = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Last successful sync timestamp'
    )
    
    sync_errors = models.TextField(
        blank=True,
        help_text='Recent sync errors (for debugging)'
    )
    
    # Timestamps
    connected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Google Calendar Integration'
        verbose_name_plural = 'Google Calendar Integrations'
    
    def __str__(self):
        return f"Google Calendar for {self.service_provider.business_name}"
    
    def is_token_valid(self):
        """Check if access token is still valid."""
        from django.utils import timezone
        if not self.token_expiry:
            return False
        return timezone.now() < self.token_expiry
    
    def needs_refresh(self):
        """Check if token needs to be refreshed."""
        return not self.is_token_valid()


class CalendarEventMapping(models.Model):
    """
    Maps appointments to Google Calendar events for sync tracking.
    """
    
    appointment = models.OneToOneField(
        'appointments.Appointment',
        on_delete=models.CASCADE,
        related_name='calendar_event'
    )
    
    google_event_id = models.CharField(
        max_length=255,
        help_text='Google Calendar event ID'
    )
    
    calendar_integration = models.ForeignKey(
        GoogleCalendarIntegration,
        on_delete=models.CASCADE,
        related_name='event_mappings'
    )
    
    # Sync status
    last_synced = models.DateTimeField(auto_now=True)
    
    sync_status = models.CharField(
        max_length=20,
        choices=[
            ('synced', 'Synced'),
            ('pending', 'Pending'),
            ('error', 'Error'),
        ],
        default='synced'
    )
    
    error_message = models.TextField(
        blank=True,
        help_text='Error message if sync failed'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = 'Calendar Event Mapping'
        verbose_name_plural = 'Calendar Event Mappings'
    
    def __str__(self):
        return f"Event {self.google_event_id} for Appointment #{self.appointment.id}"
