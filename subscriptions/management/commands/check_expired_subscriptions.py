"""
Management command to check and handle expired subscriptions.
Usage: python manage.py check_expired_subscriptions
Should be run daily via cron or Celery Beat
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from providers.models import ServiceProvider


class Command(BaseCommand):
    help = 'Check for expired subscriptions and trials, and downgrade to FREE plan'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--send-emails',
            action='store_true',
            help='Send email notifications to affected providers',
        )
    
    def handle(self, *args, **options):
        self.stdout.write('Checking for expired subscriptions and trials...')
        
        today = timezone.now().date()
        send_emails = options['send_emails']
        
        # Check expired PRO subscriptions
        expired_pro = ServiceProvider.objects.filter(
            current_plan='pro',
            plan_end_date__lt=today,
            is_active=True
        )
        
        pro_count = 0
        for provider in expired_pro:
            self.stdout.write(f'  ⚠ Downgrading {provider.business_name} (PRO expired)')
            provider.downgrade_to_free()
            pro_count += 1
            
            if send_emails:
                self.send_expiry_email(provider)
        
        # Check expired trials
        expired_trials = ServiceProvider.objects.filter(
            is_trial_active=True,
            trial_end_date__lt=today,
            current_plan='free',
            is_active=True
        )
        
        trial_count = 0
        for provider in expired_trials:
            self.stdout.write(f'  ⚠ Trial expired for {provider.business_name}')
            provider.is_trial_active = False
            provider.save(update_fields=['is_trial_active'])
            trial_count += 1
            
            if send_emails:
                self.send_trial_expiry_email(provider)
        
        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Processed {pro_count} expired PRO subscriptions'
            )
        )
        self.stdout.write(
            self.style.SUCCESS(
                f'✅ Processed {trial_count} expired trials'
            )
        )
        
        if send_emails:
            self.stdout.write(self.style.SUCCESS('📧 Email notifications sent'))
    
    def send_expiry_email(self, provider):
        """Send email notification for expired PRO subscription."""
        subject = 'Your PRO subscription has expired'
        message = f"""
        Hi {provider.user.get_short_name()},
        
        Your PRO subscription for {provider.business_name} has expired.
        
        You've been automatically downgraded to the FREE plan with the following limits:
        - 5 appointments per month
        - Maximum 3 services
        - Basic features only
        
        To continue enjoying unlimited bookings and PRO features, please upgrade:
        {settings.SITE_URL}/pricing/
        
        Thank you for using {settings.SITE_NAME}!
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [provider.user.email],
            fail_silently=True,
        )
    
    def send_trial_expiry_email(self, provider):
        """Send email notification for expired trial."""
        subject = 'Your 14-day PRO trial has ended'
        message = f"""
        Hi {provider.user.get_short_name()},
        
        Your 14-day PRO trial for {provider.business_name} has ended.
        
        You're now on the FREE plan with these limits:
        - 5 appointments per month
        - Maximum 3 services
        - Basic features only
        
        Loved the PRO features? Upgrade for just ₹199/month:
        {settings.SITE_URL}/pricing/
        
        Thank you for trying {settings.SITE_NAME}!
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [provider.user.email],
            fail_silently=True,
        )
