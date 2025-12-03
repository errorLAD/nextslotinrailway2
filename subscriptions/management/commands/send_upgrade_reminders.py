"""
Management command to send upgrade reminders to FREE plan users.
Usage: python manage.py send_upgrade_reminders
Should be run weekly via cron or Celery Beat
"""
from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from providers.models import ServiceProvider


class Command(BaseCommand):
    help = 'Send upgrade reminders to FREE plan users approaching their limits'
    
    def handle(self, *args, **options):
        self.stdout.write('Sending upgrade reminders...')
        
        # Find FREE plan users who have used 4 or 5 appointments (80%+ of limit)
        providers_near_limit = ServiceProvider.objects.filter(
            current_plan='free',
            is_trial_active=False,
            appointments_this_month__gte=4,
            is_active=True
        )
        
        sent_count = 0
        for provider in providers_near_limit:
            remaining = provider.remaining_appointments()
            
            if remaining == 0:
                # Already at limit
                subject = "You've reached your monthly booking limit"
                message = f"""
                Hi {provider.user.get_short_name()},
                
                You've used all 5 appointments for this month on your FREE plan.
                
                To accept more bookings, upgrade to PRO for just ₹199/month:
                ✓ Unlimited appointments
                ✓ Unlimited services
                ✓ WhatsApp notifications
                ✓ Professional salon website
                ✓ And much more!
                
                Upgrade now: {settings.SITE_URL}/pricing/
                
                Or wait until next month when your limit resets.
                
                Best regards,
                {settings.SITE_NAME} Team
                """
            else:
                # Near limit (1 remaining)
                subject = f"Only {remaining} booking left this month"
                message = f"""
                Hi {provider.user.get_short_name()},
                
                You've used {provider.appointments_this_month} out of 5 appointments this month.
                Only {remaining} booking remaining!
                
                Don't let your business stop. Upgrade to PRO for unlimited bookings:
                ✓ Unlimited appointments every month
                ✓ Unlimited services
                ✓ WhatsApp + SMS notifications
                ✓ Professional salon website
                ✓ Remove branding
                ✓ Advanced analytics
                
                Just ₹199/month: {settings.SITE_URL}/pricing/
                
                Best regards,
                {settings.SITE_NAME} Team
                """
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [provider.user.email],
                fail_silently=True,
            )
            
            sent_count += 1
            self.stdout.write(
                f'  📧 Sent reminder to {provider.business_name} '
                f'({provider.appointments_this_month}/5 used)'
            )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\n✅ Sent {sent_count} upgrade reminder emails'
            )
        )
