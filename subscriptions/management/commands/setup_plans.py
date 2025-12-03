from django.core.management.base import BaseCommand
from subscriptions.models import SubscriptionPlan

class Command(BaseCommand):
    help = 'Set up or update subscription plans'

    def handle(self, *args, **options):
        # Free Plan
        free_plan, created = SubscriptionPlan.objects.update_or_create(
            plan_type='free',
            defaults={
                'name': 'Free Plan',
                'price_monthly': 0,
                'max_appointments_per_month': 10,  # Example limit
                'max_services': 3,  # Example limit
                'features': {
                    'appointments_limit': 10,
                    'services_limit': 3,
                    'analytics': False,
                    'custom_domain': False,
                    'email_support': False,
                    'priority_support': False,
                    'featured': False,
                },
                'is_active': True
            }
        )
        
        # Pro Plan
        pro_plan, created = SubscriptionPlan.objects.update_or_create(
            plan_type='pro',
            defaults={
                'name': 'Pro Plan',
                'price_monthly': 199,
                'max_appointments_per_month': None,  # Unlimited
                'max_services': None,  # Unlimited
                'features': {
                    'appointments_limit': 'Unlimited',
                    'services_limit': 'Unlimited',
                    'analytics': True,
                    'custom_domain': True,
                    'email_support': True,
                    'priority_support': True,
                    'featured': True,
                },
                'is_active': True
            }
        )
        
        self.stdout.write(self.style.SUCCESS('Successfully set up subscription plans'))
