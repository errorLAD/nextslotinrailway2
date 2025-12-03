"""
Signals for automatic provider profile creation and appointment tracking.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from accounts.models import CustomUser
from providers.models import ServiceProvider


@receiver(post_save, sender=CustomUser)
def create_provider_profile(sender, instance, created, **kwargs):
    """
    Automatically create ServiceProvider profile when a provider user is created.
    """
    if created and instance.user_type == 'provider':
        # Don't create profile automatically - let user complete setup
        pass


@receiver(post_save, sender=CustomUser)
def save_provider_profile(sender, instance, **kwargs):
    """
    Save provider profile when user is saved.
    """
    if instance.user_type == 'provider' and hasattr(instance, 'provider_profile'):
        instance.provider_profile.save()
