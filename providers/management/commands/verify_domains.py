""
Management command to verify domain ownership by checking DNS records.
This should be run as a periodic task (e.g., via Celery Beat).
"""
import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.conf import settings
from django.utils import timezone
from providers.models import ServiceProvider
from providers.domain_utils import verify_domain_dns

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Verify domain ownership by checking DNS records'

    def handle(self, *args, **options):
        """Handle the management command execution."""
        # Find all domains that need verification
        domains_to_verify = ServiceProvider.objects.filter(
            custom_domain__isnull=False,
            domain_verified=False,
            # Only check domains that were added more than 5 minutes ago
            # to avoid race conditions with domain verification
            domain_added_at__lt=timezone.now() - timedelta(minutes=5)
        )

        if not domains_to_verify.exists():
            self.stdout.write(self.style.SUCCESS('No domains need verification.'))
            return

        self.stdout.write(f'Verifying {domains_to_verify.count()} domains...')

        for provider in domains_to_verify:
            try:
                self.verify_domain(provider)
            except Exception as e:
                logger.error(f'Error verifying {provider.custom_domain}: {str(e)}')
                self.stderr.write(self.style.ERROR(f'Error verifying {provider.custom_domain}: {str(e)}'))

    def verify_domain(self, provider):
        """Verify a single domain's DNS records."""
        domain = provider.custom_domain
        self.stdout.write(f'Verifying {domain}...')

        try:
            if provider.custom_domain_type == 'subdomain':
                # For subdomains, check CNAME record
                result = verify_domain_dns(
                    domain=domain,
                    expected_cname=settings.DEFAULT_DOMAIN,
                    expected_txt=provider.domain_verification_code
                )
            else:
                # For custom domains, check both CNAME and TXT records
                result = verify_domain_dns(
                    domain=domain,
                    expected_cname=settings.DEFAULT_DOMAIN,
                    expected_txt=provider.domain_verification_code
                )

            if result['success']:
                # Domain verified successfully
                provider.domain_verified = True
                provider.save()
                
                # Log the success
                logger.info(f'Successfully verified domain: {domain}')
                self.stdout.write(self.style.SUCCESS(f'Successfully verified domain: {domain}'))
                
                # Return True to indicate success
                return True
            else:
                # Domain verification failed
                error_msg = f'Failed to verify {domain}: ' + ' '.join(result.get('messages', ['Unknown error']))
                logger.warning(error_msg)
                self.stdout.write(self.style.WARNING(error_msg))
                return False
                
        except Exception as e:
            error_msg = f'Error verifying {domain}: {str(e)}'
            logger.error(error_msg, exc_info=True)
            self.stderr.write(self.style.ERROR(error_msg))
            raise
