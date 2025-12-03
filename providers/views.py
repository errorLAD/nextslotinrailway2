"""
Views for service provider dashboard and management.
"""
from django.shortcuts import render, redirect, get_object_or_404, HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from .models import ServiceProvider, Service, Availability, ServiceAvailability
from .decorators import provider_required, check_service_limit, check_appointment_limit
from appointments.models import Appointment
from .forms import (
    ServiceProviderForm, ServiceForm, AvailabilityForm, 
    AvailabilityFormSet, AppointmentForm, ServiceAvailabilityForm,
    get_availability_formset
)


@login_required
@provider_required
def dashboard(request):
    """
    Provider dashboard with overview.
    """
    provider = request.user.provider_profile
    
    # Get today's appointments
    today = timezone.now().date()
    today_appointments = Appointment.objects.filter(
        service_provider=provider,
        appointment_date=today
    ).order_by('appointment_time')
    
    # Get upcoming appointments
    upcoming_appointments = Appointment.objects.filter(
        service_provider=provider,
        appointment_date__gt=today,
        status__in=['pending', 'confirmed']
    ).order_by('appointment_date', 'appointment_time')[:5]
    
    # Statistics
    total_appointments = Appointment.objects.filter(service_provider=provider).count()
    pending_appointments = Appointment.objects.filter(
        service_provider=provider,
        status='pending'
    ).count()
    
    context = {
        'provider': provider,
        'today_appointments': today_appointments,
        'upcoming_appointments': upcoming_appointments,
        'total_appointments': total_appointments,
        'pending_appointments': pending_appointments,
        'services_count': provider.services.filter(is_active=True).count(),
    }
    
    return render(request, 'providers/dashboard.html', context)


@login_required
def setup_profile(request):
    """
    Initial provider profile setup.
    """
    # Check if profile already exists
    if hasattr(request.user, 'provider_profile'):
        return redirect('providers:edit_profile')
    
    if request.method == 'POST':
        business_name = request.POST.get('business_name')
        business_type = request.POST.get('business_type')
        phone = request.POST.get('phone')
        city = request.POST.get('city')
        
        # Create provider profile
        provider = ServiceProvider.objects.create(
            user=request.user,
            business_name=business_name,
            business_type=business_type,
            phone=phone,
            city=city
        )
        
        messages.success(request, 'Profile created successfully! Start adding your services.')
        return redirect('providers:dashboard')
    
    return render(request, 'providers/setup_profile.html')


@login_required
@provider_required
def edit_profile(request):
    """
    Edit provider profile.
    """
    provider = request.user.provider_profile
    
    if request.method == 'POST':
        provider.business_name = request.POST.get('business_name')
        provider.business_type = request.POST.get('business_type')
        provider.description = request.POST.get('description', '')
        provider.phone = request.POST.get('phone')
        provider.whatsapp_number = request.POST.get('whatsapp_number', '')
        provider.business_address = request.POST.get('business_address', '')
        provider.city = request.POST.get('city', '')
        provider.state = request.POST.get('state', '')
        provider.pincode = request.POST.get('pincode', '')
        
        # Handle profile image upload
        if 'profile_image' in request.FILES:
            provider.profile_image = request.FILES['profile_image']
        
        provider.save()
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('providers:dashboard')
    
    context = {
        'provider': provider,
    }
    
    return render(request, 'providers/edit_profile.html', context)


@login_required
@provider_required
def service_list(request):
    """
    List all services for the provider.
    """
    provider = request.user.provider_profile
    services = provider.services.all().order_by('-is_active', 'service_name')
    
    context = {
        'provider': provider,
        'services': services,
        'can_add_more': provider.can_add_service(),
    }
    
    return render(request, 'providers/service_list.html', context)


@login_required
@provider_required
@check_service_limit
def add_service(request):
    """
    Add a new service.
    """
    provider = request.user.provider_profile
    
    if request.method == 'POST':
        service = Service.objects.create(
            service_provider=provider,
            service_name=request.POST.get('service_name'),
            description=request.POST.get('description', ''),
            duration_minutes=int(request.POST.get('duration_minutes')),
            price=float(request.POST.get('price')),
            is_active=True
        )
        
        messages.success(request, f'Service "{service.service_name}" added successfully!')
        return redirect('providers:service_list')
    
    context = {
        'provider': provider,
    }
    
    return render(request, 'providers/add_service.html', context)


@login_required
@provider_required
def edit_service(request, pk):
    """
    Edit an existing service.
    """
    provider = request.user.provider_profile
    service = get_object_or_404(Service, pk=pk, service_provider=provider)
    
    if request.method == 'POST':
        service.service_name = request.POST.get('service_name')
        service.description = request.POST.get('description', '')
        service.duration_minutes = int(request.POST.get('duration_minutes'))
        service.price = float(request.POST.get('price'))
        service.is_active = request.POST.get('is_active') == 'on'
        service.save()
        
        messages.success(request, 'Service updated successfully!')
        return redirect('providers:service_list')
    
    context = {
        'provider': provider,
        'service': service,
    }
    
    return render(request, 'providers/edit_service.html', context)


@login_required
@provider_required
def delete_service(request, pk):
    """
    Delete a service.
    """
    provider = request.user.provider_profile
    service = get_object_or_404(Service, pk=pk, service_provider=provider)
    
    if request.method == 'POST':
        service_name = service.service_name
        service.delete()
        messages.success(request, f'Service "{service_name}" deleted successfully!')
        return redirect('providers:service_list')
    
    context = {
        'provider': provider,
        'service': service,
    }
    
    return render(request, 'providers/delete_service.html', context)


@login_required
@provider_required
def manage_availability(request):
    """
    Manage weekly availability schedule.
    """
    provider = request.user.provider_profile
    
    if request.method == 'POST':
        # Clear existing availability
        provider.availability_slots.all().delete()
        
        # Create new availability slots
        for day in range(7):
            is_available = request.POST.get(f'day_{day}_available') == 'on'
            
            if is_available:
                start_time = request.POST.get(f'day_{day}_start')
                end_time = request.POST.get(f'day_{day}_end')
                
                if start_time and end_time:
                    Availability.objects.create(
                        service_provider=provider,
                        day_of_week=day,
                        start_time=start_time,
                        end_time=end_time,
                        is_available=True
                    )
        
        messages.success(request, 'Availability updated successfully!')
        return redirect('providers:dashboard')
    
    # Get existing availability
    availability = {}
    for slot in provider.availability_slots.all():
        availability[slot.day_of_week] = slot
    
    context = {
        'provider': provider,
        'availability': availability,
        'days': Availability.DAY_CHOICES,
    }
    
    return render(request, 'providers/manage_availability.html', context)


@login_required
@provider_required
def appointment_list(request):
    """
    List all appointments for the provider.
    """
    provider = request.user.provider_profile
    
    # Filter by status
    status_filter = request.GET.get('status', 'all')
    
    appointments = Appointment.objects.filter(service_provider=provider)
    
    if status_filter != 'all':
        appointments = appointments.filter(status=status_filter)
    
    appointments = appointments.order_by('-appointment_date', '-appointment_time')
    
    context = {
        'provider': provider,
        'appointments': appointments,
        'status_filter': status_filter,
    }
    
    return render(request, 'providers/appointment_list.html', context)


@login_required
@provider_required
@check_appointment_limit
def create_appointment(request):
    """
    Create a walk-in appointment.
    """
    provider = request.user.provider_profile
    services = provider.services.filter(is_active=True)
    
    if request.method == 'POST':
        appointment = Appointment.objects.create(
            service_provider=provider,
            service_id=request.POST.get('service'),
            client_name=request.POST.get('client_name'),
            client_phone=request.POST.get('client_phone'),
            client_email=request.POST.get('client_email', ''),
            appointment_date=request.POST.get('appointment_date'),
            appointment_time=request.POST.get('appointment_time'),
            status='confirmed',
            notes=request.POST.get('notes', '')
        )
        
        messages.success(request, 'Appointment created successfully!')
        return redirect('providers:appointment_detail', pk=appointment.pk)
    
    context = {
        'provider': provider,
        'services': services,
    }
    
    return render(request, 'providers/create_appointment.html', context)


@login_required
@provider_required
def appointment_detail(request, pk):
    """
    View appointment details.
    """
    provider = request.user.provider_profile
    appointment = get_object_or_404(Appointment, pk=pk, service_provider=provider)
    
    context = {
        'provider': provider,
        'appointment': appointment,
    }
    
    return render(request, 'providers/appointment_detail.html', context)


@login_required
@provider_required
def confirm_appointment(request, pk):
    """
    Confirm a pending appointment.
    """
    provider = request.user.provider_profile
    appointment = get_object_or_404(Appointment, pk=pk, service_provider=provider)
    
    if appointment.confirm():
        messages.success(request, 'Appointment confirmed!')
    else:
        messages.error(request, 'Cannot confirm this appointment.')
    
    return redirect('providers:appointment_detail', pk=pk)


@login_required
@provider_required
def cancel_appointment(request, pk):
    """
    Cancel an appointment.
    """
    provider = request.user.provider_profile
    appointment = get_object_or_404(Appointment, pk=pk, service_provider=provider)
    
    if appointment.cancel():
        messages.success(request, 'Appointment cancelled.')
    else:
        messages.error(request, 'Cannot cancel this appointment.')
    
    return redirect('providers:appointment_detail', pk=pk)


@login_required
@provider_required
def complete_appointment(request, pk):
    """
    Mark appointment as completed.
    """
    appointment = get_object_or_404(Appointment, pk=pk, service_provider=request.user.provider_profile)
    
    if request.method == 'POST':
        appointment.status = 'completed'
        appointment.save()
        messages.success(request, 'Appointment marked as completed.')
        return redirect('providers:appointment_list')
    
    return redirect('providers:appointment_detail', pk=appointment.pk)


@login_required
@provider_required
def manage_service_availability(request, service_id):
    """
    Manage service-specific availability.
    """
    service = get_object_or_404(
        Service,
        pk=service_id,
        service_provider=request.user.provider_profile
    )
    
    # Get the selected day or default to Monday (0)
    selected_day = request.GET.get('day', '0')
    try:
        selected_day = int(selected_day)
        if selected_day < 0 or selected_day > 6:
            selected_day = 0
    except (ValueError, TypeError):
        selected_day = 0
    
    # Get or create service availability for the selected day
    service_availability, created = ServiceAvailability.objects.get_or_create(
        service=service,
        day_of_week=selected_day,
        defaults={
            'start_time': '09:00:00',
            'end_time': '17:00:00',
            'is_available': True
        }
    )
    
    # Handle form submission
    if request.method == 'POST':
        form = ServiceAvailabilityForm(
            request.POST,
            instance=service_availability
        )
        
        if form.is_valid():
            # If using default hours, delete the custom availability
            if 'use_default' in request.POST and request.POST['use_default'] == 'on':
                if not created:  # Only delete if it existed before
                    service_availability.delete()
                messages.success(request, 'Using default availability for this day.')
            else:
                form.save()
                messages.success(request, 'Availability updated successfully.')
            
            # Redirect to the same day
            return redirect(f"{request.path}?day={selected_day}")
    else:
        form = ServiceAvailabilityForm(instance=service_availability)
    
    # Get all service availability for the service
    all_availability = service.service_availability.all()
    
    # Get default availability for reference
    default_availability = Availability.objects.filter(
        service_provider=request.user.provider_profile,
        day_of_week=selected_day
    ).first()
    
    context = {
        'service': service,
        'form': form,
        'selected_day': selected_day,
        'all_availability': all_availability,
        'default_availability': default_availability,
        'day_choices': [(i, day[1]) for i, day in enumerate(Availability.DAY_CHOICES)],
    }
    
    return render(request, 'providers/manage_service_availability.html', context)


@login_required
@provider_required
def delete_service_availability(request, service_id, availability_id=None):
    """
    Delete service-specific availability.
    """
    service = get_object_or_404(
        Service,
        pk=service_id,
        service_provider=request.user.provider_profile
    )
    
    # Get the day from query params if availability_id is 0 (for removing custom hours)
    day = request.GET.get('day', '0')
    try:
        day = int(day)
        if day < 0 or day > 6:
            day = 0
    except (ValueError, TypeError):
        day = 0
    
    if availability_id and availability_id != '0':
        # Delete specific availability
        availability = get_object_or_404(
            ServiceAvailability,
            pk=availability_id,
            service=service
        )
        day = availability.day_of_week
        availability.delete()
    else:
        # Delete availability for the specified day
        ServiceAvailability.objects.filter(
            service=service,
            day_of_week=day
        ).delete()
    
    messages.success(request, 'Custom availability removed. Using default hours.')
    return redirect('providers:manage_service_availability', service_id=service_id, day=day)
