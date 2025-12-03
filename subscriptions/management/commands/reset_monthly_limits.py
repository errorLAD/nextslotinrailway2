"""
Management command to reset monthly appointment limits for FREE plan users.
Usage: python manage.py reset_monthly_limits
Should be run on the 1st of every month (via cron or Celery Beat)
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from providers.models import ServiceProvider


class Command(BaseCommand):
    help = 'Reset monthly appointment counters for all service providers'
    
    def handle(self, *args, **options):
        self.stdout.write('Resetting monthly appointment limits...')
        
        # Get all providers
        providers = ServiceProvider.objects.filter(is_active=True)
        reset_count = 0
        
        for provider in providers:
            # Reset counter
            old_count = provider.appointments_this_month
            provider.reset_monthly_counter()
            reset_count += 1
            
            self.stdout.write(
                f'  ✓ {provider.business_name}: {old_count} → 0 appointments'
            )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Successfully reset counters for {reset_count} providers'
            )
        )
        self.stdout.write(f'Reset date: {timezone.now().date()}')
