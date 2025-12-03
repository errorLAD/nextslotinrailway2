"""
Views for user authentication and registration.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.generic import CreateView
from django.urls import reverse_lazy
from django.core.mail import send_mail
from django.conf import settings
from django.utils.crypto import get_random_string
from django.utils import timezone
from datetime import timedelta
from .forms import ProviderRegistrationForm, ClientRegistrationForm, CustomLoginForm
from .models import CustomUser


def login_view(request):
    """
    Handle user login.
    """
    if request.user.is_authenticated:
        if request.user.is_provider:
            return redirect('providers:dashboard')
        return redirect('appointments:my_appointments')
    
    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {user.get_short_name()}!')
                
                # Redirect based on user type
                if user.is_provider:
                    return redirect('providers:dashboard')
                return redirect('appointments:my_appointments')
            else:
                messages.error(request, 'Invalid email or password.')
        else:
            messages.error(request, 'Invalid email or password.')
    else:
        form = CustomLoginForm()
    
    return render(request, 'accounts/login.html', {'form': form})


def register_provider_view(request):
    """
    Handle service provider registration with email verification.
    """
    if request.user.is_authenticated:
        return redirect('providers:dashboard')
    
    if request.method == 'POST':
        form = ProviderRegistrationForm(request.POST)
        if form.is_valid():
            # Create user but don't activate yet
            user = form.save(commit=False)
            user.is_active = False  # Will be activated after email verification
            user.save()
            
            # Generate verification token
            verification_token = get_random_string(64)
            
            # Store token in session (in production, use database or cache)
            request.session[f'verification_token_{user.id}'] = verification_token
            request.session[f'verification_expires_{user.id}'] = (
                timezone.now() + timedelta(hours=24)
            ).isoformat()
            
            # Send verification email
            verification_url = request.build_absolute_uri(
                f'/accounts/verify-email/{user.id}/{verification_token}/'
            )
            
            send_mail(
                subject='Verify your email - BookingSaaS',
                message=f'''
                Hi {user.get_short_name()},
                
                Welcome to BookingSaaS! Please verify your email address by clicking the link below:
                
                {verification_url}
                
                This link will expire in 24 hours.
                
                If you didn't create this account, please ignore this email.
                
                Best regards,
                BookingSaaS Team
                ''',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            
            messages.success(
                request,
                'Registration successful! Please check your email to verify your account.'
            )
            return redirect('accounts:verification_sent')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = ProviderRegistrationForm()
    
    return render(request, 'accounts/register_provider.html', {'form': form})


def register_client_view(request):
    """
    Handle client registration.
    """
    if request.user.is_authenticated:
        return redirect('appointments:my_appointments')
    
    if request.method == 'POST':
        form = ClientRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Registration successful! You can now book appointments.')
            return redirect('appointments:browse_providers')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = ClientRegistrationForm()
    
    return render(request, 'accounts/register_client.html', {'form': form})


@login_required
def logout_view(request):
    """
    Handle user logout.
    """
    logout(request)
    messages.info(request, 'You have been logged out successfully.')
    return redirect('accounts:login')


def register_choice_view(request):
    """
    Let users choose between provider or client registration.
    """
    if request.user.is_authenticated:
        if request.user.is_provider:
            return redirect('providers:dashboard')
        return redirect('appointments:my_appointments')
    
    return render(request, 'accounts/register_choice.html')


def verification_sent_view(request):
    """
    Show message that verification email has been sent.
    """
    return render(request, 'accounts/verification_sent.html')


def verify_email_view(request, user_id, token):
    """
    Verify user's email address.
    """
    try:
        user = get_object_or_404(CustomUser, id=user_id)
        
        # Check if already verified
        if user.is_active:
            messages.info(request, 'Your email is already verified. Please login.')
            return redirect('accounts:login')
        
        # Get stored token from session
        stored_token = request.session.get(f'verification_token_{user_id}')
        expires_str = request.session.get(f'verification_expires_{user_id}')
        
        if not stored_token or not expires_str:
            messages.error(request, 'Verification link is invalid or has expired.')
            return redirect('accounts:register_provider')
        
        # Check if token matches
        if token != stored_token:
            messages.error(request, 'Invalid verification link.')
            return redirect('accounts:register_provider')
        
        # Check if expired
        expires = timezone.datetime.fromisoformat(expires_str)
        if timezone.now() > expires:
            messages.error(request, 'Verification link has expired. Please register again.')
            user.delete()  # Delete unverified user
            return redirect('accounts:register_provider')
        
        # Activate user
        user.is_active = True
        user.save()
        
        # Clean up session
        del request.session[f'verification_token_{user_id}']
        del request.session[f'verification_expires_{user_id}']
        
        # Log user in
        login(request, user)
        
        messages.success(request, 'Email verified successfully! Welcome to BookingSaaS.')
        
        # Redirect based on user type
        if user.is_provider:
            return redirect('providers:setup_profile')
        return redirect('appointments:browse_providers')
    
    except Exception as e:
        messages.error(request, 'An error occurred during verification.')
        return redirect('accounts:register_provider')


def resend_verification_view(request):
    """
    Resend verification email.
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        
        try:
            user = CustomUser.objects.get(email=email, is_active=False)
            
            # Generate new token
            verification_token = get_random_string(64)
            
            # Store token in session
            request.session[f'verification_token_{user.id}'] = verification_token
            request.session[f'verification_expires_{user.id}'] = (
                timezone.now() + timedelta(hours=24)
            ).isoformat()
            
            # Send verification email
            verification_url = request.build_absolute_uri(
                f'/accounts/verify-email/{user.id}/{verification_token}/'
            )
            
            send_mail(
                subject='Verify your email - BookingSaaS',
                message=f'''
                Hi {user.get_short_name()},
                
                Here's your new verification link:
                
                {verification_url}
                
                This link will expire in 24 hours.
                
                Best regards,
                BookingSaaS Team
                ''',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            
            messages.success(request, 'Verification email sent! Please check your inbox.')
        except CustomUser.DoesNotExist:
            messages.error(request, 'No unverified account found with this email.')
    
    return render(request, 'accounts/resend_verification.html')
