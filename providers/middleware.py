"""
Middleware for subscription plan checking and trial management.
"""
import uuid
from django.utils import timezone
from django.contrib import messages
from django.conf import settings
from django.http import Http404
from .models import ServiceProvider


class SubscriptionCheckMiddleware:
    """
    Middleware to check subscription status on each request.
    Handles plan downgrades when PRO subscription expires.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check subscription status for authenticated providers
        if request.user.is_authenticated and hasattr(request.user, 'is_provider'):
            if request.user.is_provider and hasattr(request.user, 'provider_profile'):
                provider = request.user.provider_profile
                today = timezone.now().date()
                
                # Check if PRO subscription has expired
                if provider.current_plan == 'pro' and provider.plan_end_date:
                    if provider.plan_end_date < today:
                        provider.downgrade_to_free()
                        
                        # Show message only once per session
                        if not request.session.get('pro_expiry_shown'):
                            messages.warning(
                                request,
                                'Your PRO subscription has expired. You have been downgraded to the FREE plan.'
                            )
                            request.session['pro_expiry_shown'] = True
        
        response = self.get_response(request)
        return response


class CustomDomainMiddleware:
    """
    Middleware to handle custom domain routing for service providers.
    
    This middleware checks if the request is coming from a custom domain or subdomain
    and routes users to the appropriate provider's booking page.
    
    CNAME Configuration:
    - Service providers set up their custom domain (e.g., booking.rameshsalon.com)
    - They create a CNAME record pointing to: CNAME_TARGET (e.g., yourdomain.com)
    - When users visit the custom domain, they see the provider's booking page
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Skip for static/media files and admin
        if request.path.startswith(('/static/', '/media/', '/admin/')):
            return self.get_response(request)
        
        # Initialize default values
        request.custom_domain_provider = None
        request.is_custom_domain = False
            
        host = request.get_host().split(':')[0].lower()
        default_domain = getattr(settings, 'DEFAULT_DOMAIN', 'localhost').lower()
        
        # Skip if it's the default domain exactly
        if host == default_domain or host == 'localhost' or host == '127.0.0.1':
            return self.get_response(request)
        
        # Check if this is a subdomain of the default domain (e.g., ramesh-salon.yourdomain.com)
        is_subdomain_of_default = host.endswith(f'.{default_domain}')
        
        if is_subdomain_of_default:
            # Extract subdomain part
            subdomain = host.replace(f'.{default_domain}', '')
            full_subdomain = f"{subdomain}.{default_domain}"
            
            try:
                provider = ServiceProvider.objects.get(
                    custom_domain=full_subdomain,
                    custom_domain_type='subdomain',
                    domain_verified=True,
                    is_active=True
                )
                request.custom_domain_provider = provider
                request.is_custom_domain = True
                
                # Redirect to booking page if at root
                if request.path == '/' or request.path == '':
                    from django.shortcuts import redirect
                    return redirect(f'/book/{provider.unique_booking_url}/')
                
                # If SSL is enabled, ensure we're using HTTPS
                if provider.ssl_enabled and not request.is_secure():
                    from django.shortcuts import redirect
                    return redirect(f'https://{host}{request.get_full_path()}')
                    
            except ServiceProvider.DoesNotExist:
                pass
        else:
            # This is a fully custom domain (e.g., booking.rameshsalon.com or book.customdomain.com)
            try:
                provider = ServiceProvider.objects.get(
                    custom_domain=host,
                    domain_verified=True,
                    is_active=True
                )
                
                # Set provider in request for views to use
                request.custom_domain_provider = provider
                request.is_custom_domain = True
                
                # Redirect to booking page if at root
                if request.path == '/' or request.path == '':
                    from django.shortcuts import redirect
                    return redirect(f'/book/{provider.unique_booking_url}/')
                
                # If SSL is enabled, ensure we're using HTTPS
                if provider.ssl_enabled and not request.is_secure():
                    from django.shortcuts import redirect
                    return redirect(f'https://{host}{request.get_full_path()}')
                    
            except ServiceProvider.DoesNotExist:
                # Domain not found or not verified - could return 404 or redirect to main site
                pass
        
        response = self.get_response(request)
        return response
