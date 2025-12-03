"""
Decorators for feature gating based on subscription plans.
"""
from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse


def requires_pro_plan(view_func):
    """
    Decorator to restrict access to PRO plan features.
    Redirects to upgrade page if user doesn't have PRO access.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Check if user is authenticated and is a provider
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        
        if not request.user.is_provider:
            messages.error(request, 'This feature is only available for service providers.')
            return redirect('accounts:login')
        
        # Check if provider has PRO features
        try:
            provider = request.user.provider_profile
            if not provider.has_pro_features():
                messages.warning(
                    request,
                    'This feature is only available on the PRO plan. Upgrade now to unlock!'
                )
                return redirect('subscriptions:pricing')
        except AttributeError:
            messages.error(request, 'Please complete your provider profile first.')
            return redirect('providers:setup_profile')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def check_appointment_limit(view_func):
    """
    Decorator to check if provider can create more appointments.
    Shows upgrade prompt if limit is reached.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_provider:
            return redirect('accounts:login')
        
        try:
            provider = request.user.provider_profile
            if not provider.can_create_appointment():
                messages.error(
                    request,
                    f'You\'ve reached your monthly limit of {provider.appointments_this_month} appointments. '
                    f'Upgrade to PRO for unlimited bookings!'
                )
                return redirect('subscriptions:upgrade_prompt')
        except AttributeError:
            pass
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def check_service_limit(view_func):
    """
    Decorator to check if provider can add more services.
    Shows upgrade prompt if limit is reached.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_provider:
            return redirect('accounts:login')
        
        try:
            provider = request.user.provider_profile
            if not provider.can_add_service():
                messages.error(
                    request,
                    'Free plan allows maximum 3 services. Upgrade to PRO to add unlimited services!'
                )
                return redirect('subscriptions:upgrade_prompt')
        except AttributeError:
            pass
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def provider_required(view_func):
    """
    Decorator to ensure user is a service provider.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        
        if not request.user.is_provider:
            messages.error(request, 'This page is only accessible to service providers.')
            return redirect('accounts:login')
        
        # Ensure provider profile exists
        if not hasattr(request.user, 'provider_profile'):
            messages.info(request, 'Please complete your provider profile.')
            return redirect('providers:setup_profile')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper
