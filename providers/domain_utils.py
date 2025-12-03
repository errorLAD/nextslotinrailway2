"""
Utilities for domain verification and management.
Each service provider gets unique CNAME and TXT records for their custom domain.
"""
import dns.resolver
import random
import string
import hashlib
from django.conf import settings
from django.utils import timezone
from .models import ServiceProvider


def generate_verification_code(length=32):
    """Generate a random verification code for domain verification."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def generate_unique_cname_target(provider_id, unique_booking_url):
    """
    Generate a unique CNAME target for a provider.
    Each provider gets their own subdomain on the main platform domain.
    
    Examples:
        - p-ramesh-salon-abc123.nextslot.in
        - p-urban-unit-xyz789.nextslot.in
    
    Args:
        provider_id: The provider's database ID
        unique_booking_url: The provider's unique booking URL slug
        
    Returns:
        str: Unique CNAME target subdomain
    """
    # Create a short hash from provider ID for uniqueness
    hash_input = f"{provider_id}-{unique_booking_url}"
    short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:8]
    
    # Sanitize the booking URL (remove special chars, limit length)
    safe_slug = ''.join(c if c.isalnum() or c == '-' else '' for c in unique_booking_url)[:20]
    
    # Generate CNAME target: p-{slug}-{hash}.DEFAULT_DOMAIN
    cname_subdomain = f"p-{safe_slug}-{short_hash}"
    cname_target = f"{cname_subdomain}.{settings.DEFAULT_DOMAIN}"
    
    return cname_target


def generate_unique_txt_record_name(provider_id):
    """
    Generate a unique TXT record name for domain verification.
    
    Each provider gets their own TXT record name to avoid conflicts.
    
    Examples:
        - _nextslot-verify-abc123
        - _nextslot-verify-xyz789
    
    Args:
        provider_id: The provider's database ID
        
    Returns:
        str: Unique TXT record name
    """
    # Create a short hash from provider ID
    short_hash = hashlib.md5(str(provider_id).encode()).hexdigest()[:8]
    
    return f"_nextslot-verify-{short_hash}"

def verify_domain_dns(domain, expected_cname=None, expected_txt=None, txt_record_name='_booking-verify'):
    """
    Verify DNS records for domain ownership.
    Works with Cloudflare proxied domains.
    
    Args:
        domain (str): The domain to verify
        expected_cname (str, optional): Expected CNAME value (provider-specific)
        expected_txt (str, optional): Expected TXT record value for verification
        txt_record_name (str, optional): Name of the TXT record (provider-specific)
        
    Returns:
        dict: Verification results with status and messages
    """
    results = {
        'success': False,
        'cname_verified': False,
        'txt_verified': False,
        'a_record_found': False,
        'messages': []
    }
    
    # Extract root domain for TXT record lookup
    domain_parts = domain.split('.')
    if len(domain_parts) > 2:
        root_domain = '.'.join(domain_parts[-2:])
    else:
        root_domain = domain
    
    try:
        # Check for CNAME or A record (Cloudflare may return A records for proxied domains)
        if expected_cname:
            try:
                cname_records = dns.resolver.resolve(domain, 'CNAME')
                cname_values = [str(r.target).rstrip('.') for r in cname_records]
                
                if expected_cname in cname_values or any(expected_cname in cv for cv in cname_values):
                    results['cname_verified'] = True
                    results['messages'].append('CNAME record is correctly configured.')
                else:
                    results['messages'].append(f'CNAME points to {cname_values}, expected {expected_cname}')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # If no CNAME, check for A record (Cloudflare proxy flattens CNAME to A)
                try:
                    a_records = dns.resolver.resolve(domain, 'A')
                    if a_records:
                        results['a_record_found'] = True
                        results['cname_verified'] = True
                        results['messages'].append('A record found (Cloudflare proxy detected).')
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    results['messages'].append('No CNAME or A record found for ' + domain)
            except dns.resolver.NoNameservers:
                results['messages'].append('DNS servers not responding.')
        
        # Verify TXT record using provider-specific record name
        if expected_txt:
            txt_locations = [
                f"{txt_record_name}.{root_domain}",
                f"{txt_record_name}.{domain}",
                f"_booking-verify.{root_domain}",
                f"_booking-verify.{domain}",
                txt_record_name,
                root_domain,
                domain,
            ]
            
            txt_found = False
            for txt_domain in txt_locations:
                if txt_found:
                    break
                try:
                    txt_records = dns.resolver.resolve(txt_domain, 'TXT')
                    txt_values = []
                    for r in txt_records:
                        for s in r.strings:
                            txt_values.append(s.decode('utf-8'))
                    
                    if expected_txt in txt_values:
                        results['txt_verified'] = True
                        results['messages'].append(f'TXT verification record found at {txt_domain}.')
                        txt_found = True
                        break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    continue
                except Exception:
                    continue
            
            if not txt_found:
                results['messages'].append(f'TXT record not found. Create TXT record with name "{txt_record_name}" at {root_domain}')
        
        # Determine overall success
        if results['cname_verified']:
            if results['a_record_found']:
                results['success'] = True
                if not results['txt_verified']:
                    results['messages'].append('Verified via Cloudflare proxy. TXT record optional.')
            elif results['txt_verified']:
                results['success'] = True
            elif expected_txt is None:
                results['success'] = True
        
        return results
        
    except Exception as e:
        results['messages'].append(f'Error during DNS verification: {str(e)}')
        return results

def setup_custom_domain(provider, domain, domain_type):
    """
    Set up a custom domain for a service provider.
    Each provider gets unique CNAME and TXT record configurations.
    
    Args:
        provider (ServiceProvider): The service provider to set up the domain for
        domain (str): The custom domain (e.g., 'www.example.com' or 'salon.example.com')
        domain_type (str): Type of domain ('subdomain' or 'domain')
        
    Returns:
        tuple: (success: bool, message: str, verification_code: str)
    """
    # Validate domain type
    if domain_type not in ['subdomain', 'domain']:
        return False, 'Invalid domain type. Must be either "subdomain" or "domain".', ''
    
    # Check if domain is already in use
    if ServiceProvider.objects.filter(custom_domain=domain).exclude(pk=provider.pk).exists():
        return False, 'This domain is already in use by another account.', ''
    
    # Generate unique verification code
    verification_code = f'nextslot-verify-{generate_verification_code(16)}'
    
    # Generate unique CNAME target for this provider
    cname_target = generate_unique_cname_target(provider.pk, provider.unique_booking_url)
    
    # Generate unique TXT record name for this provider
    txt_record_name = generate_unique_txt_record_name(provider.pk)
    
    # Update provider with domain info
    provider.custom_domain = domain
    provider.custom_domain_type = domain_type
    provider.domain_verified = False
    provider.domain_verification_code = verification_code
    provider.cname_target = cname_target
    provider.txt_record_name = txt_record_name
    provider.domain_added_at = timezone.now()
    provider.save()
    
    return True, 'Domain setup initiated. Please verify ownership by adding the required DNS records.', verification_code


def verify_domain_ownership(provider):
    """
    Verify domain ownership by checking DNS records.
    Uses provider-specific CNAME target and TXT record name.
    
    Args:
        provider (ServiceProvider): The service provider with domain to verify
        
    Returns:
        tuple: (success: bool, message: str)
    """
    if not provider.custom_domain or not provider.domain_verification_code:
        return False, 'No domain or verification code found.'
    
    # Get provider-specific CNAME target (or fallback to default domain)
    expected_cname = provider.cname_target or settings.DEFAULT_DOMAIN
    
    # Get provider-specific TXT record name (or fallback to default)
    txt_record_name = provider.txt_record_name or '_booking-verify'
    
    # Verify domain with provider-specific values
    result = verify_domain_dns(
        domain=provider.custom_domain,
        expected_cname=expected_cname,
        expected_txt=provider.domain_verification_code,
        txt_record_name=txt_record_name
    )
    
    if result['success']:
        # Update provider with verification status
        provider.domain_verified = True
        provider.ssl_enabled = True  # Auto-enable SSL for verified domains
        provider.save()
        return True, 'Domain verified successfully! SSL will be enabled shortly.'
    else:
        return False, 'Domain verification failed. ' + ' '.join(result['messages'])
