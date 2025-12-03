"""
Google Calendar integration views (PRO plan only).
Handles OAuth flow and calendar settings.
"""
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.conf import settings

from .models import ServiceProvider
from .models_calendar import GoogleCalendarIntegration
from utils.google_calendar import (
    get_authorization_url,
    exchange_code_for_tokens,
    disconnect_calendar
)


def require_pro_plan_calendar(view_func):
    """
    Decorator to require PRO plan for Google Calendar features.
    """
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        
        if not request.user.is_provider:
            return redirect('providers:dashboard')
        
        try:
            provider = request.user.provider_profile
        except ServiceProvider.DoesNotExist:
            return redirect('providers:setup')
        
        # CHECK PRO PLAN
        if not provider.is_pro():
            messages.warning(
                request,
                '🔒 Google Calendar sync is a PRO feature. Upgrade to sync your appointments!'
            )
            return redirect('subscriptions:upgrade_to_pro')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


@login_required
def calendar_settings(request):
    """
    Google Calendar settings page.
    Shows connection status and sync options.
    """
    provider = request.user.provider_profile
    
    # Check if provider has PRO plan
    is_pro = provider.is_pro()
    
    # Get calendar integration if exists
    calendar_integration = None
    if is_pro:
        try:
            calendar_integration = provider.google_calendar
        except GoogleCalendarIntegration.DoesNotExist:
            pass
    
    context = {
        'provider': provider,
        'is_pro': is_pro,
        'calendar_integration': calendar_integration,
    }
    
    return render(request, 'providers/calendar_settings.html', context)


@login_required
@require_pro_plan_calendar
def connect_google_calendar(request):
    """
    Initiate Google OAuth flow (PRO plan only).
    """
    provider = request.user.provider_profile
    
    # Check if already connected
    try:
        calendar_integration = provider.google_calendar
        if calendar_integration.is_active:
            messages.info(request, 'Google Calendar is already connected.')
            return redirect('providers:calendar_settings')
    except GoogleCalendarIntegration.DoesNotExist:
        pass
    
    # Build redirect URI
    redirect_uri = request.build_absolute_uri(
        reverse('providers:google_calendar_callback')
    )
    
    # Get authorization URL
    authorization_url, state = get_authorization_url(redirect_uri)
    
    # Store state in session for verification
    request.session['google_oauth_state'] = state
    request.session['google_oauth_provider_id'] = provider.id
    
    # Redirect to Google OAuth
    return redirect(authorization_url)


@login_required
@require_pro_plan_calendar
def google_calendar_callback(request):
    """
    Handle Google OAuth callback (PRO plan only).
    """
    provider = request.user.provider_profile
    
    # Verify state
    state = request.GET.get('state')
    stored_state = request.session.get('google_oauth_state')
    
    if state != stored_state:
        messages.error(request, 'Invalid OAuth state. Please try again.')
        return redirect('providers:calendar_settings')
    
    # Get authorization code
    code = request.GET.get('code')
    if not code:
        error = request.GET.get('error')
        messages.error(
            request,
            f'Google Calendar authorization failed: {error or "Unknown error"}'
        )
        return redirect('providers:calendar_settings')
    
    try:
        # Exchange code for tokens
        redirect_uri = request.build_absolute_uri(
            reverse('providers:google_calendar_callback')
        )
        
        token_info = exchange_code_for_tokens(code, redirect_uri)
        
        # Get user's Google email (from token info or API call)
        # For simplicity, we'll use the provider's email
        google_email = provider.user.email
        
        # Create or update calendar integration
        calendar_integration, created = GoogleCalendarIntegration.objects.update_or_create(
            service_provider=provider,
            defaults={
                'google_email': google_email,
                'access_token': token_info['access_token'],
                'refresh_token': token_info['refresh_token'],
                'token_expiry': token_info['token_expiry'],
                'is_active': True,
                'sync_enabled': True,
            }
        )
        
        # Clear session data
        request.session.pop('google_oauth_state', None)
        request.session.pop('google_oauth_provider_id', None)
        
        messages.success(
            request,
            '✅ Google Calendar connected successfully! Your appointments will now sync automatically.'
        )
        
    except Exception as e:
        messages.error(
            request,
            f'Failed to connect Google Calendar: {str(e)}'
        )
    
    return redirect('providers:calendar_settings')


@login_required
@require_pro_plan_calendar
def disconnect_google_calendar(request):
    """
    Disconnect Google Calendar integration (PRO plan only).
    """
    provider = request.user.provider_profile
    
    try:
        calendar_integration = provider.google_calendar
        
        if request.method == 'POST':
            disconnect_calendar(calendar_integration)
            
            messages.success(
                request,
                'Google Calendar disconnected successfully.'
            )
            return redirect('providers:calendar_settings')
        
        context = {
            'provider': provider,
            'calendar_integration': calendar_integration,
        }
        
        return render(request, 'providers/calendar_disconnect_confirm.html', context)
        
    except GoogleCalendarIntegration.DoesNotExist:
        messages.error(request, 'Google Calendar is not connected.')
        return redirect('providers:calendar_settings')


@login_required
@require_pro_plan_calendar
def toggle_calendar_sync(request):
    """
    Toggle calendar sync on/off (PRO plan only).
    """
    provider = request.user.provider_profile
    
    try:
        calendar_integration = provider.google_calendar
        
        # Toggle sync
        calendar_integration.sync_enabled = not calendar_integration.sync_enabled
        calendar_integration.save()
        
        status = 'enabled' if calendar_integration.sync_enabled else 'disabled'
        messages.success(
            request,
            f'Calendar sync {status} successfully.'
        )
        
    except GoogleCalendarIntegration.DoesNotExist:
        messages.error(request, 'Google Calendar is not connected.')
    
    return redirect('providers:calendar_settings')
