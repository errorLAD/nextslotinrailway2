"""
Management command to create default subscription plans.
Usage: python manage.py create_default_plans
"""
from django.core.management.base import BaseCommand
from subscriptions.models import SubscriptionPlan


class Command(BaseCommand):
    help = 'Create default FREE and PRO subscription plans'
    
    def handle(self, *args, **options):
        self.stdout.write('Creating default subscription plans...')
        
        # FREE Plan
        free_plan, created = SubscriptionPlan.objects.get_or_create(
            plan_type='free',
            defaults={
                'name': 'Free Plan',
                'price_monthly': 0,
                'max_appointments_per_month': 5,
                'max_services': 3,
                'display_order': 1,
                'features': {
                    'appointments_per_month': 5,
                    'max_services': 3,
                    'booking_page': True,
                    'salon_website': False,
                    'email_notifications': True,
                    'whatsapp_notifications': False,
                    'sms_notifications': False,
                    'branding_removal': False,
                    'google_calendar_sync': False,
                    'multi_staff': False,
                    'analytics': False,
                    'priority_support': False,
                    'custom_url': False,
                    'features_list': [
                        '5 appointments per month',
                        'Maximum 3 services',
                        'Basic booking page',
                        'Email notifications only',
                        'Powered by BookingSaaS branding',
                        'Basic email support'
                    ]
                }
            }
        )
        
        if created:
            self.stdout.write(self.style.SUCCESS('✓ Created FREE Plan'))
        else:
            self.stdout.write(self.style.WARNING('FREE Plan already exists'))
        
        # PRO Plan
        pro_plan, created = SubscriptionPlan.objects.get_or_create(
            plan_type='pro',
            defaults={
                'name': 'Pro Plan',
                'price_monthly': 199,
                'max_appointments_per_month': None,  # Unlimited
                'max_services': None,  # Unlimited
                'display_order': 2,
                'features': {
                    'appointments_per_month': 'unlimited',
                    'max_services': 'unlimited',
                    'booking_page': True,
                    'salon_website': True,
                    'email_notifications': True,
                    'whatsapp_notifications': True,
                    'sms_notifications': True,
                    'branding_removal': True,
                    'google_calendar_sync': True,
                    'multi_staff': True,
                    'analytics': True,
                    'priority_support': True,
                    'custom_url': True,
                    'features_list': [
                        'Unlimited appointments',
                        'Unlimited services',
                        'Professional salon website',
                        'WhatsApp + Email + SMS notifications',
                        'Remove branding (white-label)',
                        'Google Calendar sync',
                        'Multi-staff support',
                        'Advanced analytics dashboard',
                        'Priority support (WhatsApp + phone)',
                        'Custom booking URL'
                    ]
                }
            }
        )
        
        if created:
            self.stdout.write(self.style.SUCCESS('✓ Created PRO Plan'))
        else:
            self.stdout.write(self.style.WARNING('PRO Plan already exists'))
        
        self.stdout.write(self.style.SUCCESS('\n✅ Subscription plans setup complete!'))
        self.stdout.write('\nAvailable plans:')
        for plan in SubscriptionPlan.objects.all():
            self.stdout.write(f'  - {plan.name}: ₹{plan.price_monthly}/month')
