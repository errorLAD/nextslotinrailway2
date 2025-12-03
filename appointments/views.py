"""
Views for public booking and client appointments.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from providers.models import ServiceProvider
from .models import Appointment


def public_booking_page(request, slug):
    """
    Public booking page for a service provider.
    Shows login/signup modal for unauthenticated users.
    """
    provider = get_object_or_404(ServiceProvider, unique_booking_url=slug, is_active=True)
    services = provider.services.filter(is_active=True)
    availability = provider.availability_slots.filter(is_available=True).order_by('day_of_week')
    
    # Initialize context with provider data
    context = {
        'provider': provider,
        'services': services,
        'availability': availability,
        'client_name': '',
        'client_email': '',
        'show_auth_modal': False
    }
    
    # If user is authenticated, pre-fill their information
    if request.user.is_authenticated:
        client_name = f"{request.user.first_name} {request.user.last_name}".strip()
        if not client_name:
            client_name = request.user.username
            
        context.update({
            'client_name': client_name,
            'client_email': request.user.email,
        })
    else:
        # Show auth modal for unauthenticated users
        context['show_auth_modal'] = True
        
        # If coming from a redirect with next parameter, show appropriate message
        if 'next' in request.GET:
            messages.info(request, 'Please sign in or create an account to continue with your booking.')
    
    return render(request, 'appointments/public_booking.html', context)


def confirm_booking(request, slug):
    """
    Confirm and create a booking from public page.
    Requires user to be logged in.
    """
    # Redirect to login if user is not authenticated
    if not request.user.is_authenticated:
        messages.warning(request, 'You need to be logged in to book a service.')
        return redirect(f'/accounts/login/?next={request.path}')
        
    provider = get_object_or_404(ServiceProvider, unique_booking_url=slug, is_active=True)
    
    if request.method == 'POST':
        service_id = request.POST.get('service')
        appointment_date = request.POST.get('appointment_date')
        appointment_time = request.POST.get('appointment_time')
        client_phone = request.POST.get('client_phone')
        notes = request.POST.get('notes', '')
        
        # Get user information from the authenticated user
        client_name = f"{request.user.first_name} {request.user.last_name}".strip()
        if not client_name:
            client_name = request.user.username
            
        client_email = request.user.email
        
        # Create appointment
        appointment = Appointment.objects.create(
            service_provider=provider,
            service_id=service_id,
            client=request.user,  # Always set the authenticated user
            client_name=client_name,
            client_phone=client_phone,
            client_email=client_email,
            appointment_date=appointment_date,
            appointment_time=appointment_time,
            status='pending',
            notes=notes
        )
        
        return redirect('appointments:booking_success', pk=appointment.pk)
    
    return redirect('appointments:public_booking', slug=slug)


def booking_success(request, pk):
    """
    Booking confirmation success page.
    This view is accessible to both authenticated and unauthenticated users
    as long as they have the correct booking ID.
    """
    # Skip provider_required decorator for this view
    appointment = get_object_or_404(Appointment, pk=pk)
    
    # If user is a provider and owns this appointment, redirect to provider's dashboard
    if hasattr(request.user, 'is_provider') and request.user.is_provider:
        return redirect('providers:dashboard')
    
    # For clients or unauthenticated users, show the booking success page
    context = {
        'appointment': appointment,
        'is_authenticated': request.user.is_authenticated,
    }
    
    # Use a different template for unauthenticated users if needed
    return render(request, 'appointments/booking_success.html', context)


@login_required
def my_appointments(request):
    """
    Client's appointment list with separate tabs for upcoming and past appointments.
    """
    if request.user.is_provider:
        return redirect('providers:dashboard')
    
    from django.utils import timezone
    
    # Get upcoming appointments (today and future)
    upcoming_appointments = Appointment.objects.filter(
        client=request.user,
        appointment_date__gte=timezone.now().date(),
        status__in=['pending', 'confirmed']
    ).order_by('appointment_date', 'appointment_time')
    
    # Get past appointments
    past_appointments = Appointment.objects.filter(
        client=request.user,
        appointment_date__lt=timezone.now().date()
    ).exclude(status__in=['pending', 'confirmed']).order_by('-appointment_date', '-appointment_time')
    
    # Get cancelled appointments
    cancelled_appointments = Appointment.objects.filter(
        client=request.user,
        status='cancelled'
    ).order_by('-updated_at')
    
    context = {
        'upcoming_appointments': upcoming_appointments,
        'past_appointments': past_appointments,
        'cancelled_appointments': cancelled_appointments,
    }
    
    return render(request, 'appointments/my_appointments.html', context)


def browse_providers(request):
    """
    Browse available service providers.
    """
    providers = ServiceProvider.objects.filter(
        is_active=True,
        is_verified=True
    ).order_by('-created_at')
    
    # Filter by business type
    business_type = request.GET.get('type')
    if business_type:
        providers = providers.filter(business_type=business_type)
    
    # Filter by city
    city = request.GET.get('city')
    if city:
        providers = providers.filter(city__icontains=city)
    
    context = {
        'providers': providers,
        'business_types': ServiceProvider.BUSINESS_TYPE_CHOICES,
    }
    
    return render(request, 'appointments/browse_providers.html', context)
