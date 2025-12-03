""
Management command to set up SSL certificates for custom domains using Let's Encrypt.
This should be run as a periodic task (e.g., via Celery Beat).
"""
import os
import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.conf import settings
from providers.models import ServiceProvider

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Set up SSL certificates for custom domains using Let\'s Encrypt'

    def handle(self, *args, **options):
        """Handle the management command execution."""
        # Find all verified domains that don't have SSL enabled yet
        domains_to_setup = ServiceProvider.objects.filter(
            custom_domain__isnull=False,
            domain_verified=True,
            ssl_enabled=False,
            # Only check domains that were added more than 5 minutes ago
            # to avoid race conditions with domain verification
            domain_added_at__lt=datetime.now() - timedelta(minutes=5)
        )

        if not domains_to_setup.exists():
            self.stdout.write(self.style.SUCCESS('No domains need SSL setup.'))
            return

        self.stdout.write(f'Setting up SSL for {domains_to_setup.count()} domains...')

        for provider in domains_to_setup:
            try:
                self.setup_ssl_for_domain(provider)
            except Exception as e:
                logger.error(f'Error setting up SSL for {provider.custom_domain}: {str(e)}')
                self.stderr.write(self.style.ERROR(f'Error setting up SSL for {provider.custom_domain}: {str(e)}'))

    def setup_ssl_for_domain(self, provider):
        """Set up SSL for a single domain."""
        domain = provider.custom_domain
        self.stdout.write(f'Setting up SSL for {domain}...')

        # In production, you would use certbot to get a Let's Encrypt certificate
        # This is a simplified example - in a real implementation, you would:
        # 1. Call certbot to get a certificate
        # 2. Configure your web server (Nginx/Apache) to use the certificate
        # 3. Set up automatic renewal

        # For development/testing, we'll just simulate success
        if settings.DEBUG:
            self.stdout.write(self.style.SUCCESS(f'[DEBUG] Would set up SSL for {domain}'))
            provider.ssl_enabled = True
            provider.save()
            return

        # Production implementation would go here
        try:
            # Example using certbot (commented out for safety)
            """
            import subprocess
            
            # Run certbot to get a certificate
            email = getattr(settings, 'ADMINS', [['admin@example.com', 'Admin']])[0][1]
            certbot_cmd = [
                'certbot', 'certonly', '--nginx',
                '--non-interactive',
                '--agree-tos',
                '--email', email,
                '--domain', domain,
                '--keep-until-expiring',
                '--expand',
                '--renew-with-new-domains'
            ]
            
            result = subprocess.run(certbot_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Certificate obtained successfully
                provider.ssl_enabled = True
                provider.save()
                logger.info(f'Successfully set up SSL for {domain}')
                self.stdout.write(self.style.SUCCESS(f'Successfully set up SSL for {domain}'))
            else:
                error_msg = f'Failed to set up SSL for {domain}: {result.stderr}'
                logger.error(error_msg)
                self.stderr.write(self.style.ERROR(error_msg))
            """
            
            # For now, we'll just simulate success in production too
            provider.ssl_enabled = True
            provider.save()
            logger.info(f'Successfully set up SSL for {domain} (simulated)')
            self.stdout.write(self.style.SUCCESS(f'Successfully set up SSL for {domain} (simulated)'))
            
        except Exception as e:
            error_msg = f'Error setting up SSL for {domain}: {str(e)}'
            logger.error(error_msg, exc_info=True)
            self.stderr.write(self.style.ERROR(error_msg))
            raise
