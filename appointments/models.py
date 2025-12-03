"""
Appointment model for booking management.
"""
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from django.utils import timezone
from providers.models import ServiceProvider, Service


class Appointment(models.Model):
    """
    Appointment booking model.
    Supports both registered clients and walk-in customers.
    """
    
    STATUS_CHOICES = [
        ('pending', 'Pending Confirmation'),
        ('confirmed', 'Confirmed'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('no_show', 'No Show'),
    ]
    
    PAYMENT_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('refunded', 'Refunded'),
    ]
    
    PAYMENT_METHOD_CHOICES = [
        ('upi', 'UPI'),
        ('cash', 'Cash'),
        ('card', 'Card'),
        ('online', 'Online Payment'),
    ]
    
    # Provider and Service
    service_provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='appointments'
    )
    
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name='appointments'
    )
    
    # Staff Member (optional - for PRO plan multi-staff support)
    staff_member = models.ForeignKey(
        'providers.StaffMember',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='appointments',
        help_text='Staff member assigned to this appointment (PRO plan only)'
    )
    
    # Client Information (can be null for walk-ins)
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='appointments',
        help_text='Registered client (null for walk-ins)'
    )
    
    # Walk-in customer details
    client_name = models.CharField(
        max_length=200,
        help_text='Client name (for walk-ins or override)'
    )
    
    client_phone = models.CharField(
        max_length=15,
        help_text='Client phone number'
    )
    
    client_email = models.EmailField(
        blank=True,
        help_text='Client email (optional for walk-ins)'
    )
    
    # Appointment Details
    appointment_date = models.DateField(
        help_text='Date of appointment'
    )
    
    appointment_time = models.TimeField(
        help_text='Time of appointment'
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    
    # Payment Information
    total_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        help_text='Total amount for the service'
    )
    
    payment_status = models.CharField(
        max_length=20,
        choices=PAYMENT_STATUS_CHOICES,
        default='pending'
    )
    
    payment_method = models.CharField(
        max_length=20,
        choices=PAYMENT_METHOD_CHOICES,
        blank=True,
        help_text='Payment method used'
    )
    
    # Additional Information
    notes = models.TextField(
        blank=True,
        help_text='Special requests or notes'
    )
    
    # Notifications
    reminder_sent = models.BooleanField(
        default=False,
        help_text='Whether reminder notification was sent'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Appointment'
        verbose_name_plural = 'Appointments'
        ordering = ['-appointment_date', '-appointment_time']
        indexes = [
            models.Index(fields=['appointment_date', 'appointment_time']),
            models.Index(fields=['service_provider', 'status']),
        ]
    
    def __str__(self):
        return f"{self.client_name} - {self.service.service_name} on {self.appointment_date}"
    
    def save(self, *args, **kwargs):
        # Set total_price from service if not set
        if not self.total_price:
            self.total_price = self.service.price
        
        # Auto-fill client details if client is registered
        if self.client and not self.client_name:
            self.client_name = self.client.get_full_name()
            self.client_phone = self.client.phone or ''
            self.client_email = self.client.email
        
        super().save(*args, **kwargs)
    
    @property
    def is_upcoming(self):
        """Check if appointment is in the future."""
        appointment_datetime = timezone.make_aware(
            timezone.datetime.combine(self.appointment_date, self.appointment_time)
        )
        return appointment_datetime > timezone.now() and self.status in ['pending', 'confirmed']
    
    @property
    def is_past(self):
        """Check if appointment is in the past."""
        appointment_datetime = timezone.make_aware(
            timezone.datetime.combine(self.appointment_date, self.appointment_time)
        )
        return appointment_datetime < timezone.now()
    
    def can_cancel(self):
        """Check if appointment can be cancelled."""
        return self.status in ['pending', 'confirmed'] and self.is_upcoming
    
    def cancel(self):
        """Cancel the appointment."""
        if self.can_cancel():
            self.status = 'cancelled'
            self.save(update_fields=['status'])
            return True
        return False
    
    def confirm(self):
        """Confirm the appointment."""
        if self.status == 'pending':
            self.status = 'confirmed'
            self.save(update_fields=['status'])
            return True
        return False
    
    def complete(self):
        """Mark appointment as completed."""
        if self.status == 'confirmed' and self.is_past:
            self.status = 'completed'
            self.save(update_fields=['status'])
            return True
        return False
    
    def mark_paid(self, payment_method):
        """Mark appointment as paid."""
        self.payment_status = 'paid'
        self.payment_method = payment_method
        self.save(update_fields=['payment_status', 'payment_method'])
