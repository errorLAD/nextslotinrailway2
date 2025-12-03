"""
Staff management views (PRO plan only).
FREE plan users cannot access these views.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.db import transaction

from .models import ServiceProvider, Service
from .models_staff import StaffMember, StaffAvailability
from .forms_staff import StaffMemberForm, StaffAvailabilityFormSet


def require_pro_plan(view_func):
    """
    Decorator to require PRO plan for staff management features.
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
                '🔒 Staff management is a PRO feature. Upgrade to add team members!'
            )
            return redirect('subscriptions:upgrade_to_pro')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


@login_required
@require_pro_plan
def staff_list(request):
    """
    List all staff members (PRO plan only).
    """
    provider = request.user.provider_profile
    staff_members = provider.get_active_staff()
    
    context = {
        'provider': provider,
        'staff_members': staff_members,
        'can_add_more': provider.can_add_staff(),
        'max_staff': 10,
        'current_count': provider.get_staff_count(),
    }
    
    return render(request, 'providers/staff_list.html', context)


@login_required
@require_pro_plan
def staff_create(request):
    """
    Create a new staff member (PRO plan only).
    """
    provider = request.user.provider_profile
    
    # Check if can add more staff
    if not provider.can_add_staff():
        messages.error(
            request,
            f'You have reached the maximum limit of 10 staff members.'
        )
        return redirect('providers:staff_list')
    
    if request.method == 'POST':
        form = StaffMemberForm(request.POST, request.FILES, provider=provider)
        
        if form.is_valid():
            staff_member = form.save(commit=False)
            staff_member.service_provider = provider
            staff_member.save()
            form.save_m2m()  # Save many-to-many relationships (services)
            
            messages.success(
                request,
                f'✅ Staff member "{staff_member.name}" added successfully!'
            )
            return redirect('providers:staff_detail', pk=staff_member.pk)
    else:
        form = StaffMemberForm(provider=provider)
    
    context = {
        'provider': provider,
        'form': form,
        'title': 'Add Staff Member',
    }
    
    return render(request, 'providers/staff_form.html', context)


@login_required
@require_pro_plan
def staff_detail(request, pk):
    """
    View staff member details (PRO plan only).
    """
    provider = request.user.provider_profile
    staff_member = get_object_or_404(
        StaffMember,
        pk=pk,
        service_provider=provider
    )
    
    # Get staff's appointments
    upcoming_appointments = staff_member.appointments.filter(
        status__in=['pending', 'confirmed'],
        appointment_date__gte=timezone.now().date()
    ).select_related('service', 'client').order_by('appointment_date', 'appointment_time')[:10]
    
    context = {
        'provider': provider,
        'staff_member': staff_member,
        'upcoming_appointments': upcoming_appointments,
    }
    
    return render(request, 'providers/staff_detail.html', context)


@login_required
@require_pro_plan
def staff_edit(request, pk):
    """
    Edit staff member (PRO plan only).
    """
    provider = request.user.provider_profile
    staff_member = get_object_or_404(
        StaffMember,
        pk=pk,
        service_provider=provider
    )
    
    if request.method == 'POST':
        form = StaffMemberForm(
            request.POST,
            request.FILES,
            instance=staff_member,
            provider=provider
        )
        
        if form.is_valid():
            form.save()
            messages.success(
                request,
                f'✅ Staff member "{staff_member.name}" updated successfully!'
            )
            return redirect('providers:staff_detail', pk=staff_member.pk)
    else:
        form = StaffMemberForm(instance=staff_member, provider=provider)
    
    context = {
        'provider': provider,
        'form': form,
        'staff_member': staff_member,
        'title': f'Edit {staff_member.name}',
    }
    
    return render(request, 'providers/staff_form.html', context)


@login_required
@require_pro_plan
def staff_delete(request, pk):
    """
    Delete/deactivate staff member (PRO plan only).
    """
    provider = request.user.provider_profile
    staff_member = get_object_or_404(
        StaffMember,
        pk=pk,
        service_provider=provider
    )
    
    if request.method == 'POST':
        # Soft delete - just deactivate
        staff_member.is_active = False
        staff_member.save()
        
        messages.success(
            request,
            f'Staff member "{staff_member.name}" has been deactivated.'
        )
        return redirect('providers:staff_list')
    
    context = {
        'provider': provider,
        'staff_member': staff_member,
    }
    
    return render(request, 'providers/staff_confirm_delete.html', context)


@login_required
@require_pro_plan
def staff_availability(request, pk):
    """
    Manage staff member availability (PRO plan only).
    """
    provider = request.user.provider_profile
    staff_member = get_object_or_404(
        StaffMember,
        pk=pk,
        service_provider=provider
    )
    
    if request.method == 'POST':
        formset = StaffAvailabilityFormSet(
            request.POST,
            instance=staff_member
        )
        
        if formset.is_valid():
            formset.save()
            messages.success(
                request,
                f'✅ Availability updated for {staff_member.name}!'
            )
            return redirect('providers:staff_detail', pk=staff_member.pk)
    else:
        formset = StaffAvailabilityFormSet(instance=staff_member)
    
    context = {
        'provider': provider,
        'staff_member': staff_member,
        'formset': formset,
    }
    
    return render(request, 'providers/staff_availability.html', context)


# Import timezone for appointments query
from django.utils import timezone
