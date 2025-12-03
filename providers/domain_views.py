"""
Views for managing custom domains for service providers.
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _

from .models import ServiceProvider
from .domain_utils import setup_custom_domain, verify_domain_dns, generate_verification_code

@login_required
def domain_settings(request):
    """
    View for managing domain settings.
    Only available for PRO users.
    """
    # Only service providers can access this page
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to access this page.")
    
    provider = request.user.provider_profile
    is_pro = provider.has_pro_features()
    
    # If not PRO, show the page but with limited functionality
    if not is_pro:
        messages.info(request, 'Custom domains are only available for PRO users. Upgrade to PRO to use this feature.')
    
    context = {
        'provider': provider,
        'default_domain': settings.DEFAULT_DOMAIN,
        'is_pro': is_pro,
    }
    
    return render(request, 'providers/domain/settings.html', context)

@login_required
@require_http_methods(['POST'])
def add_custom_domain(request):
    """
    Handle adding a custom domain or subdomain.
    Only available for PRO users.
    """
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to perform this action.")
    
    provider = request.user.provider_profile
    
    # Check if user has PRO features
    if not provider.has_pro_features():
        messages.warning(request, 'Custom domains are only available on the PRO plan. Please upgrade to continue.')
        return redirect('subscriptions:upgrade_to_pro')
    
    domain = request.POST.get('domain', '').strip().lower()
    domain_type = request.POST.get('domain_type', 'subdomain')
    
    # Validate domain type
    if domain_type not in ['subdomain', 'domain']:
        messages.error(request, 'Invalid domain type.')
        return redirect('providers:domain_settings')
    
    # For subdomains, validate and construct full domain
    if domain_type == 'subdomain':
        # Basic validation
        if not domain.replace('-', '').isalnum():
            messages.error(request, 'Subdomain can only contain letters, numbers, and hyphens.')
            return redirect('providers:domain_settings')
        
        if len(domain) < 3 or len(domain) > 63:
            messages.error(request, 'Subdomain must be between 3 and 63 characters long.')
            return redirect('providers:domain_settings')
        
        # Construct full domain
        domain = f"{domain}.{settings.DEFAULT_DOMAIN}"
    else:
        # For custom domains, validate the domain format
        if not is_valid_domain(domain):
            messages.error(request, 'Please enter a valid domain name.')
            return redirect('providers:domain_settings')
    
    # Setup the domain
    success, message, verification_code = setup_custom_domain(provider, domain, domain_type)
    
    if success:
        messages.info(request, message)
        return redirect('providers:domain_verification')
    else:
        messages.error(request, message)
        return redirect('domain_settings')

def is_valid_domain(domain):
    """
    Basic domain validation.
    """
    if not domain or len(domain) > 255:
        return False
    
    # Check for at least one dot and no spaces
    if '.' not in domain or ' ' in domain:
        return False
    
    # Check each part of the domain
    parts = domain.split('.')
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not all(c.isalnum() or c == '-' for c in part):
            return False
        if part.startswith('-') or part.endswith('-'):
            return False
    
    return True

@login_required
def domain_verification(request):
    """
    Show domain verification instructions and status.
    """
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to access this page.")
    
    provider = request.user.provider_profile
    
    if not provider.custom_domain:
        messages.warning(request, 'No custom domain configured.')
        return redirect('providers:domain_settings')
    
    context = {
        'provider': provider,
        'default_domain': settings.DEFAULT_DOMAIN,
        'verification_code': provider.domain_verification_code,
    }
    
    return render(request, 'providers/domain/verification.html', context)

@login_required
def verify_domain(request):
    """
    Verify domain ownership by checking DNS records.
    """
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to perform this action.")
    
    provider = request.user.provider_profile
    
    if not provider.has_pro_features():
        messages.warning(request, 'Custom domains are only available on the PRO plan. Please upgrade to continue.')
        return redirect('subscriptions:upgrade')
    
    if not provider.custom_domain or not provider.domain_verification_code:
        messages.error(request, 'No domain or verification code found.')
        return redirect('providers:domain_settings')
    
    success, message = verify_domain_ownership(provider)
    
    if success:
        messages.success(request, message)
    else:
        messages.error(request, message)
    
    return redirect('providers:domain_verification')

def verify_domain_ownership(provider):
    """
    Verify domain ownership by checking DNS records.
    
    Args:
        provider (ServiceProvider): The service provider with domain to verify
        
    Returns:
        tuple: (success: bool, message: str)
    """
    # Check if provider has PRO features
    if not provider.has_pro_features():
        return False, 'Custom domains are only available on the PRO plan.'
        
    if not provider.custom_domain or not provider.domain_verification_code:
        return False, 'No domain or verification code found.'
    
    # For subdomains, we only need to verify CNAME
    if provider.custom_domain_type == 'subdomain':
        result = verify_domain_dns(
            domain=provider.custom_domain,
            expected_cname=settings.DEFAULT_DOMAIN,
            expected_txt=provider.domain_verification_code
        )
    else:
        # For full domains, we need both CNAME and TXT verification
        result = verify_domain_dns(
            domain=provider.custom_domain,
            expected_cname=settings.DEFAULT_DOMAIN,
            expected_txt=provider.domain_verification_code
        )
    
    if result['success']:
        # Update provider with verification status
        provider.domain_verified = True
        provider.ssl_enabled = True  # Auto-enable SSL for verified domains
        provider.save()
        return True, 'Domain verified successfully! SSL will be enabled shortly.'
    else:
        return False, 'Domain verification failed. ' + ' '.join(result['messages'])

@login_required
def remove_domain(request):
    """
    Remove a custom domain from the provider's account.
    """
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to perform this action.")
    
    provider = request.user.provider_profile
    
    if not provider.has_pro_features():
        messages.warning(request, 'Custom domains are only available on the PRO plan. Please upgrade to continue.')
        return redirect('subscriptions:upgrade')
    
    if request.method == 'POST':
        # Store domain name for message
        domain = provider.custom_domain
        
        # Clear the custom domain and verification status
        provider.custom_domain = None
        provider.custom_domain_type = 'none'
        provider.domain_verified = False
        provider.domain_verification_code = None
        provider.ssl_enabled = False
        provider.domain_added_at = None
        provider.save()
        
        messages.success(request, f'Custom domain "{domain}" has been removed.')
        return redirect('providers:domain_settings')
    
    # If not a POST request, show confirmation page
    return render(request, 'providers/domain/remove_confirm.html', {
        'provider': provider
    })
