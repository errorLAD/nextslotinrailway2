"""
Staff Member models for multi-staff support (PRO plan only).
FREE plan providers can only manage themselves.
"""
from django.db import models
from django.conf import settings
from django.core.validators import MinValueValidator
from .models import ServiceProvider, Service


class StaffMember(models.Model):
    """
    Staff member model for PRO plan providers.
    Allows providers to add team members who can provide services.
    
    PRO PLAN ONLY - FREE plan providers cannot create staff members.
    """
    
    service_provider = models.ForeignKey(
        ServiceProvider,
        on_delete=models.CASCADE,
        related_name='staff_members',
        help_text='The service provider this staff member belongs to'
    )
    
    # Staff Information
    name = models.CharField(
        max_length=200,
        help_text='Full name of the staff member'
    )
    
    email = models.EmailField(
        blank=True,
        help_text='Email address for notifications (optional)'
    )
    
    phone = models.CharField(
        max_length=15,
        help_text='Contact phone number'
    )
    
    # Optional: Link to user account for staff dashboard access
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='staff_profile',
        help_text='Optional: Link to user account for staff login'
    )
    
    # Services this staff member can provide
    services = models.ManyToManyField(
        Service,
        related_name='staff_members',
        blank=True,
        help_text='Services this staff member can provide'
    )
    
    # Profile
    bio = models.TextField(
        blank=True,
        help_text='Brief bio or description'
    )
    
    profile_image = models.ImageField(
        upload_to='staff_images/',
        blank=True,
        null=True,
        help_text='Staff member photo'
    )
    
    # Status
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this staff member is currently active'
    )
    
    # Display order
    display_order = models.IntegerField(
        default=0,
        help_text='Order in which to display staff members'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Staff Member'
        verbose_name_plural = 'Staff Members'
        ordering = ['display_order', 'name']
        unique_together = ['service_provider', 'email']
    
    def __str__(self):
        return f"{self.name} - {self.service_provider.business_name}"
    
    def get_services(self):
        """Get list of services this staff member can provide."""
        return self.services.filter(is_active=True)
    
    def get_availability(self):
        """Get availability slots for this staff member."""
        return self.availability_slots.filter(is_available=True)
    
    def has_service(self, service):
        """Check if staff member can provide a specific service."""
        return self.services.filter(id=service.id, is_active=True).exists()


class StaffAvailability(models.Model):
    """
    Availability schedule for individual staff members.
    Similar to provider availability but at staff level.
    """
    
    DAY_CHOICES = [
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday'),
    ]
    
    staff_member = models.ForeignKey(
        StaffMember,
        on_delete=models.CASCADE,
        related_name='availability_slots'
    )
    
    day_of_week = models.IntegerField(
        choices=DAY_CHOICES,
        help_text='Day of the week (0=Monday, 6=Sunday)'
    )
    
    start_time = models.TimeField(
        help_text='Start time for this availability slot'
    )
    
    end_time = models.TimeField(
        help_text='End time for this availability slot'
    )
    
    is_available = models.BooleanField(
        default=True,
        help_text='Whether the staff member is available on this day'
    )
    
    class Meta:
        verbose_name = 'Staff Availability'
        verbose_name_plural = 'Staff Availability Slots'
        ordering = ['day_of_week', 'start_time']
        unique_together = ['staff_member', 'day_of_week']
    
    def __str__(self):
        day_name = dict(self.DAY_CHOICES)[self.day_of_week]
        if self.is_available:
            return f"{self.staff_member.name} - {day_name}: {self.start_time.strftime('%I:%M %p')} - {self.end_time.strftime('%I:%M %p')}"
        return f"{self.staff_member.name} - {day_name}: Closed"
