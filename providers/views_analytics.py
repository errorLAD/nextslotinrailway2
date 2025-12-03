"""
Analytics views for service providers.
FREE plan: Basic stats only
PRO plan: Advanced analytics with charts and exports
"""
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.db.models import Count, Sum, Avg, Q
from django.db.models.functions import TruncDate, TruncMonth, ExtractWeekDay, ExtractHour
from django.utils import timezone
from datetime import timedelta
import csv
import json

from .models import ServiceProvider
from appointments.models import Appointment


@login_required
def analytics_dashboard(request):
    """
    Analytics dashboard with plan-based feature gating.
    FREE plan: Basic stats only
    PRO plan: Advanced charts and analytics
    """
    # Check if user is a provider
    if not request.user.is_provider:
        return redirect('providers:dashboard')
    
    try:
        provider = request.user.provider_profile
    except ServiceProvider.DoesNotExist:
        return redirect('providers:setup')
    
    # Check plan status
    is_pro = provider.is_pro()
    
    # Get date ranges
    today = timezone.now().date()
    this_month_start = today.replace(day=1)
    last_month_start = (this_month_start - timedelta(days=1)).replace(day=1)
    last_30_days = today - timedelta(days=30)
    last_6_months = today - timedelta(days=180)
    
    # BASIC STATS (Available for both FREE and PRO)
    total_appointments_this_month = Appointment.objects.filter(
        service_provider=provider,
        appointment_date__gte=this_month_start
    ).count()
    
    appointments_by_status = Appointment.objects.filter(
        service_provider=provider,
        appointment_date__gte=this_month_start
    ).values('status').annotate(count=Count('id'))
    
    today_appointments = Appointment.objects.filter(
        service_provider=provider,
        appointment_date=today
    ).select_related('service').order_by('appointment_time')
    
    # Basic context (FREE plan)
    context = {
        'provider': provider,
        'is_pro': is_pro,
        'total_appointments_this_month': total_appointments_this_month,
        'appointments_by_status': list(appointments_by_status),
        'today_appointments': today_appointments,
    }
    
    # ADVANCED ANALYTICS (PRO plan only)
    if is_pro:
        # 1. Appointments Analytics
        # Compare this month vs last month
        last_month_appointments = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=last_month_start,
            appointment_date__lt=this_month_start
        ).count()
        
        # Appointments trend (last 30 days)
        appointments_trend = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=last_30_days
        ).annotate(
            date=TruncDate('appointment_date')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        # No-show rate
        total_completed = Appointment.objects.filter(
            service_provider=provider,
            status__in=['completed', 'no_show']
        ).count()
        
        no_shows = Appointment.objects.filter(
            service_provider=provider,
            status='no_show'
        ).count()
        
        no_show_rate = (no_shows / total_completed * 100) if total_completed > 0 else 0
        
        # 2. Revenue Analytics
        # Total revenue this month
        revenue_this_month = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=this_month_start,
            payment_status='paid'
        ).aggregate(total=Sum('total_price'))['total'] or 0
        
        # Revenue trend (last 6 months)
        revenue_trend = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=last_6_months,
            payment_status='paid'
        ).annotate(
            month=TruncMonth('appointment_date')
        ).values('month').annotate(
            revenue=Sum('total_price')
        ).order_by('month')
        
        # Revenue by service type
        revenue_by_service = Appointment.objects.filter(
            service_provider=provider,
            payment_status='paid'
        ).values(
            'service__service_name'
        ).annotate(
            revenue=Sum('total_price')
        ).order_by('-revenue')[:10]
        
        # Average booking value
        avg_booking_value = Appointment.objects.filter(
            service_provider=provider,
            payment_status='paid'
        ).aggregate(avg=Avg('total_price'))['avg'] or 0
        
        # 3. Client Analytics
        # Total unique clients
        total_clients = Appointment.objects.filter(
            service_provider=provider
        ).values('client_phone').distinct().count()
        
        # New clients this month
        new_clients_this_month = Appointment.objects.filter(
            service_provider=provider,
            created_at__gte=this_month_start
        ).values('client_phone').distinct().count()
        
        # Repeat client rate
        client_appointment_counts = Appointment.objects.filter(
            service_provider=provider
        ).values('client_phone').annotate(
            count=Count('id')
        )
        
        repeat_clients = sum(1 for c in client_appointment_counts if c['count'] > 1)
        repeat_client_rate = (repeat_clients / total_clients * 100) if total_clients > 0 else 0
        
        # Top 5 clients by bookings
        top_clients = Appointment.objects.filter(
            service_provider=provider
        ).values(
            'client_name', 'client_phone'
        ).annotate(
            bookings=Count('id')
        ).order_by('-bookings')[:5]
        
        # 4. Peak Times Analytics
        # Busiest days of week
        busiest_days = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=last_30_days
        ).annotate(
            day=ExtractWeekDay('appointment_date')
        ).values('day').annotate(
            count=Count('id')
        ).order_by('day')
        
        # Busiest hours
        busiest_hours = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=last_30_days
        ).annotate(
            hour=ExtractHour('appointment_time')
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('hour')
        
        # Add PRO analytics to context
        context.update({
            # Appointments
            'last_month_appointments': last_month_appointments,
            'appointments_trend': list(appointments_trend),
            'no_show_rate': round(no_show_rate, 2),
            
            # Revenue
            'revenue_this_month': revenue_this_month,
            'revenue_trend': list(revenue_trend),
            'revenue_by_service': list(revenue_by_service),
            'avg_booking_value': round(avg_booking_value, 2),
            
            # Clients
            'total_clients': total_clients,
            'new_clients_this_month': new_clients_this_month,
            'repeat_client_rate': round(repeat_client_rate, 2),
            'top_clients': list(top_clients),
            
            # Peak Times
            'busiest_days': list(busiest_days),
            'busiest_hours': list(busiest_hours),
        })
    
    return render(request, 'providers/analytics_dashboard.html', context)


@login_required
def export_analytics_csv(request):
    """
    Export analytics data as CSV (PRO plan only).
    """
    # Check if user is a provider
    if not request.user.is_provider:
        return redirect('providers:dashboard')
    
    try:
        provider = request.user.provider_profile
    except ServiceProvider.DoesNotExist:
        return redirect('providers:setup')
    
    # CHECK PRO PLAN - Feature gate for CSV export
    if not provider.is_pro():
        return HttpResponse(
            "CSV export is a PRO feature. Please upgrade your plan.",
            status=403
        )
    
    # Get all appointments
    appointments = Appointment.objects.filter(
        service_provider=provider
    ).select_related('service').order_by('-appointment_date', '-appointment_time')
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="analytics_{provider.business_name}_{timezone.now().date()}.csv"'
    
    writer = csv.writer(response)
    
    # Write header
    writer.writerow([
        'Date', 'Time', 'Client Name', 'Client Phone', 'Service', 
        'Duration (min)', 'Price', 'Status', 'Payment Status', 'Payment Method'
    ])
    
    # Write data
    for apt in appointments:
        writer.writerow([
            apt.appointment_date,
            apt.appointment_time.strftime('%I:%M %p'),
            apt.client_name,
            apt.client_phone,
            apt.service.service_name,
            apt.service.duration_minutes,
            apt.total_price,
            apt.get_status_display(),
            apt.get_payment_status_display(),
            apt.payment_method or 'N/A'
        ])
    
    return response


@login_required
def analytics_api(request):
    """
    API endpoint for chart data (PRO plan only).
    Returns JSON data for Chart.js
    """
    # Check if user is a provider
    if not request.user.is_provider:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        provider = request.user.provider_profile
    except ServiceProvider.DoesNotExist:
        return JsonResponse({'error': 'Provider profile not found'}, status=404)
    
    # CHECK PRO PLAN
    if not provider.is_pro():
        return JsonResponse({'error': 'PRO plan required'}, status=403)
    
    chart_type = request.GET.get('type', 'appointments_trend')
    
    # Get date range
    days = int(request.GET.get('days', 30))
    start_date = timezone.now().date() - timedelta(days=days)
    
    if chart_type == 'appointments_trend':
        # Daily appointments trend
        data = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=start_date
        ).annotate(
            date=TruncDate('appointment_date')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        return JsonResponse({
            'labels': [d['date'].strftime('%b %d') for d in data],
            'data': [d['count'] for d in data]
        })
    
    elif chart_type == 'revenue_trend':
        # Monthly revenue trend
        data = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=start_date,
            payment_status='paid'
        ).annotate(
            month=TruncMonth('appointment_date')
        ).values('month').annotate(
            revenue=Sum('total_price')
        ).order_by('month')
        
        return JsonResponse({
            'labels': [d['month'].strftime('%b %Y') for d in data],
            'data': [float(d['revenue']) for d in data]
        })
    
    return JsonResponse({'error': 'Invalid chart type'}, status=400)
