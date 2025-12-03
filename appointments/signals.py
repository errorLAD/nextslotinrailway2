"""
Signals for appointment tracking and usage counting.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from appointments.models import Appointment


@receiver(post_save, sender=Appointment)
def increment_appointment_counter(sender, instance, created, **kwargs):
    """
    Increment provider's monthly appointment counter when a new appointment is created.
    """
    if created:
        # Increment the counter for the provider
        instance.service_provider.increment_appointment_count()
