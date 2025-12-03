"""
Views for managing custom domains for service providers.
Each provider gets unique CNAME and TXT record configurations.
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.utils.translation import gettext as _

from .models import ServiceProvider
from .domain_utils import (
    setup_custom_domain, 
    verify_domain_dns, 
    generate_verification_code,
    generate_unique_cname_target,
    generate_unique_txt_record_name,
    verify_domain_ownership
)

@login_required
def domain_settings(request):
    """
    View for managing domain settings.
    Only available for PRO users.
    Each provider gets unique CNAME and TXT record configurations.
    """
    # Only service providers can access this page
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to access this page.")
    
    provider = request.user.provider_profile
    is_pro = provider.has_pro_features()
    
    # If not PRO, show the page but with limited functionality
    if not is_pro:
        messages.info(request, 'Custom domains are only available for PRO users. Upgrade to PRO to use this feature.')
    
    # Get provider-specific CNAME target
    cname_target = provider.cname_target
    if not cname_target and provider.pk:
        cname_target = generate_unique_cname_target(provider.pk, provider.unique_booking_url)
    
    # Get provider-specific TXT record name
    txt_record_name = provider.txt_record_name
    if not txt_record_name and provider.pk:
        txt_record_name = generate_unique_txt_record_name(provider.pk)
    
    context = {
        'provider': provider,
        'default_domain': settings.DEFAULT_DOMAIN,
        'is_pro': is_pro,
        'cname_target': cname_target or settings.DEFAULT_DOMAIN,
        'txt_record_name': txt_record_name or '_booking-verify',
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
    Displays provider-specific CNAME and TXT record configurations.
    """
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        raise PermissionDenied("You don't have permission to access this page.")
    
    provider = request.user.provider_profile
    
    if not provider.custom_domain:
        messages.warning(request, 'No custom domain configured.')
        return redirect('providers:domain_settings')
    
    # Get provider-specific CNAME target
    cname_target = provider.cname_target or settings.DEFAULT_DOMAIN
    
    # Get provider-specific TXT record name
    txt_record_name = provider.txt_record_name or '_booking-verify'
    
    context = {
        'provider': provider,
        'default_domain': settings.DEFAULT_DOMAIN,
        'verification_code': provider.domain_verification_code,
        'cname_target': cname_target,
        'txt_record_name': txt_record_name,
    }
    
    return render(request, 'providers/domain/verification.html', context)

@login_required
def verify_domain(request):
    """
    Verify domain ownership by checking DNS records.
    Uses provider-specific CNAME and TXT configurations.
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
    
    # Use the domain_utils verify_domain_ownership which uses provider-specific values
    success, message = verify_domain_ownership(provider)
    
    if success:
        messages.success(request, message)
    else:
        messages.error(request, message)
    
    return redirect('providers:domain_verification')

@login_required
def remove_domain(request):
    """
    Remove a custom domain from the provider's account.
    Clears all domain-related fields including unique CNAME and TXT configurations.
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
        
        # Clear all custom domain and verification fields
        provider.custom_domain = None
        provider.custom_domain_type = 'none'
        provider.domain_verified = False
        provider.domain_verification_code = None
        provider.cname_target = None  # Clear unique CNAME target
        provider.txt_record_name = ''  # Clear unique TXT record name
        provider.ssl_enabled = False
        provider.domain_added_at = None
        provider.save()
        
        messages.success(request, f'Custom domain "{domain}" has been removed.')
        return redirect('providers:domain_settings')
    
    # If not a POST request, show confirmation page
    return render(request, 'providers/domain/remove_confirm.html', {
        'provider': provider
    })
