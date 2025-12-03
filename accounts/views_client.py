"""
Client portal views for managing appointments and preferences.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q

from appointments.models import Appointment
from providers.models import ServiceProvider
from .models_client import FavoriteProvider, ClientNotificationPreference


@login_required
def client_dashboard(request):
    """
    Client dashboard showing upcoming and past appointments.
    """
    # Check if user is a client
    if not request.user.is_client:
        return redirect('providers:dashboard')
    
    # Get upcoming appointments
    upcoming_appointments = Appointment.objects.filter(
        Q(client=request.user) | Q(client_email=request.user.email),
        appointment_date__gte=timezone.now().date(),
        status__in=['pending', 'confirmed']
    ).select_related(
        'service_provider', 'service', 'staff_member'
    ).order_by('appointment_date', 'appointment_time')
    
    # Get past appointments
    past_appointments = Appointment.objects.filter(
        Q(client=request.user) | Q(client_email=request.user.email),
        status__in=['completed', 'cancelled', 'no_show']
    ).select_related(
        'service_provider', 'service', 'staff_member'
    ).order_by('-appointment_date', '-appointment_time')[:10]
    
    # Get favorite providers
    favorite_providers = FavoriteProvider.objects.filter(
        client=request.user
    ).select_related('provider')[:5]
    
    context = {
        'upcoming_appointments': upcoming_appointments,
        'past_appointments': past_appointments,
        'favorite_providers': favorite_providers,
    }
    
    return render(request, 'accounts/client_dashboard.html', context)


@login_required
def appointment_detail_client(request, pk):
    """
    View appointment details for client.
    """
    appointment = get_object_or_404(
        Appointment,
        pk=pk
    )
    
    # Check if user has access to this appointment
    if appointment.client != request.user and appointment.client_email != request.user.email:
        messages.error(request, 'You do not have access to this appointment.')
        return redirect('accounts:client_dashboard')
    
    context = {
        'appointment': appointment,
    }
    
    return render(request, 'accounts/appointment_detail_client.html', context)


@login_required
def cancel_appointment_client(request, pk):
    """
    Cancel appointment from client portal.
    """
    appointment = get_object_or_404(
        Appointment,
        pk=pk
    )
    
    # Check access
    if appointment.client != request.user and appointment.client_email != request.user.email:
        messages.error(request, 'You do not have access to this appointment.')
        return redirect('accounts:client_dashboard')
    
    # Check if can cancel
    if not appointment.can_cancel():
        messages.error(request, 'This appointment cannot be cancelled.')
        return redirect('accounts:appointment_detail', pk=pk)
    
    if request.method == 'POST':
        appointment.cancel()
        
        # Send cancellation notifications
        from utils.tasks import send_appointment_cancelled_task
        send_sms = appointment.service_provider.is_pro()
        send_appointment_cancelled_task.delay(
            appointment.id,
            cancelled_by='client',
            send_sms=send_sms
        )
        
        messages.success(
            request,
            '✅ Appointment cancelled successfully. Notification sent to provider.'
        )
        return redirect('accounts:client_dashboard')
    
    context = {
        'appointment': appointment,
    }
    
    return render(request, 'accounts/cancel_appointment_confirm.html', context)


@login_required
def reschedule_appointment_client(request, pk):
    """
    Reschedule appointment from client portal.
    """
    appointment = get_object_or_404(
        Appointment,
        pk=pk
    )
    
    # Check access
    if appointment.client != request.user and appointment.client_email != request.user.email:
        messages.error(request, 'You do not have access to this appointment.')
        return redirect('accounts:client_dashboard')
    
    # Check if can reschedule
    if not appointment.can_cancel():
        messages.error(request, 'This appointment cannot be rescheduled.')
        return redirect('accounts:appointment_detail', pk=pk)
    
    if request.method == 'POST':
        # Get new date and time from form
        new_date = request.POST.get('new_date')
        new_time = request.POST.get('new_time')
        
        if new_date and new_time:
            old_date = appointment.appointment_date
            old_time = appointment.appointment_time
            
            appointment.appointment_date = new_date
            appointment.appointment_time = new_time
            appointment.save()
            
            # Send rescheduling notification
            from utils.email_utils import send_appointment_rescheduled_email
            send_appointment_rescheduled_email(appointment, old_date, old_time)
            
            # Sync to Google Calendar if PRO
            if appointment.service_provider.is_pro():
                from utils.google_calendar import sync_appointment_to_calendar
                sync_appointment_to_calendar(appointment)
            
            messages.success(
                request,
                '✅ Appointment rescheduled successfully!'
            )
            return redirect('accounts:appointment_detail', pk=pk)
    
    context = {
        'appointment': appointment,
    }
    
    return render(request, 'accounts/reschedule_appointment.html', context)


@login_required
def favorite_providers_list(request):
    """
    List all favorite providers.
    """
    favorites = FavoriteProvider.objects.filter(
        client=request.user
    ).select_related('provider')
    
    context = {
        'favorites': favorites,
    }
    
    return render(request, 'accounts/favorite_providers.html', context)


@login_required
def add_favorite_provider(request, provider_id):
    """
    Add a provider to favorites.
    """
    provider = get_object_or_404(ServiceProvider, pk=provider_id)
    
    # Create or get favorite
    favorite, created = FavoriteProvider.objects.get_or_create(
        client=request.user,
        provider=provider
    )
    
    if created:
        messages.success(
            request,
            f'✅ {provider.business_name} added to favorites!'
        )
    else:
        messages.info(
            request,
            f'{provider.business_name} is already in your favorites.'
        )
    
    return redirect('providers:provider_detail', slug=provider.unique_booking_url)


@login_required
def remove_favorite_provider(request, provider_id):
    """
    Remove a provider from favorites.
    """
    provider = get_object_or_404(ServiceProvider, pk=provider_id)
    
    FavoriteProvider.objects.filter(
        client=request.user,
        provider=provider
    ).delete()
    
    messages.success(
        request,
        f'{provider.business_name} removed from favorites.'
    )
    
    return redirect('accounts:favorite_providers')


@login_required
def notification_preferences(request):
    """
    Manage notification preferences.
    """
    # Get or create preferences
    preferences, created = ClientNotificationPreference.objects.get_or_create(
        client=request.user
    )
    
    if request.method == 'POST':
        # Update preferences
        preferences.email_enabled = request.POST.get('email_enabled') == 'on'
        preferences.sms_enabled = request.POST.get('sms_enabled') == 'on'
        preferences.booking_confirmation = request.POST.get('booking_confirmation') == 'on'
        preferences.appointment_reminders = request.POST.get('appointment_reminders') == 'on'
        preferences.cancellation_updates = request.POST.get('cancellation_updates') == 'on'
        preferences.promotional_emails = request.POST.get('promotional_emails') == 'on'
        preferences.save()
        
        messages.success(
            request,
            '✅ Notification preferences updated successfully!'
        )
        return redirect('accounts:notification_preferences')
    
    context = {
        'preferences': preferences,
    }
    
    return render(request, 'accounts/notification_preferences.html', context)


@login_required
def rebook_appointment(request, pk):
    """
    Re-book a past appointment with the same provider and service.
    """
    old_appointment = get_object_or_404(
        Appointment,
        pk=pk
    )
    
    # Check access
    if old_appointment.client != request.user and old_appointment.client_email != request.user.email:
        messages.error(request, 'You do not have access to this appointment.')
        return redirect('accounts:client_dashboard')
    
    # Redirect to booking page with pre-filled service
    return redirect(
        'providers:book_appointment',
        slug=old_appointment.service_provider.unique_booking_url,
        service_id=old_appointment.service.id
    )
