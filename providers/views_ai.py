"""
Views for AI-powered features.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.utils import timezone
from datetime import datetime, timedelta

from .models import ServiceProvider, Service
from appointments.models import Appointment
from utils.ai_features import (
    get_smart_time_suggestions,
    calculate_no_show_risk,
    generate_service_description,
    generate_email_template,
    chatbot_response,
    estimate_monthly_cost
)


@login_required
def ai_dashboard(request):
    """
    AI features dashboard for providers.
    """
    if not request.user.is_provider:
        return redirect('providers:dashboard')
    
    try:
        provider = request.user.provider_profile
    except ServiceProvider.DoesNotExist:
        return redirect('providers:setup')
    
    # Get AI usage stats (from cache or calculate)
    from django.core.cache import cache
    usage_stats = cache.get(f'ai_usage_{provider.id}')
    
    if not usage_stats:
        # Calculate estimated usage
        daily_appointments = Appointment.objects.filter(
            service_provider=provider,
            created_at__gte=timezone.now() - timedelta(days=30)
        ).count() / 30
        
        # Estimate API calls (1 per appointment for no-show prediction)
        estimated_calls = int(daily_appointments)
        cost_estimate = estimate_monthly_cost(estimated_calls)
        
        usage_stats = {
            'daily_appointments': int(daily_appointments),
            'estimated_calls': estimated_calls,
            'cost_estimate': cost_estimate
        }
        
        cache.set(f'ai_usage_{provider.id}', usage_stats, 3600)
    
    context = {
        'provider': provider,
        'usage_stats': usage_stats,
    }
    
    return render(request, 'providers/ai_dashboard.html', context)


@login_required
def smart_time_suggestions(request):
    """
    Show AI-powered time slot suggestions.
    """
    provider = request.user.provider_profile
    
    # Get date from request or use tomorrow
    date_str = request.GET.get('date')
    if date_str:
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except:
            date = timezone.now().date() + timedelta(days=1)
    else:
        date = timezone.now().date() + timedelta(days=1)
    
    # Get service if specified
    service_id = request.GET.get('service')
    service = None
    if service_id:
        service = get_object_or_404(Service, id=service_id, service_provider=provider)
    
    # Get AI suggestions
    suggestions = get_smart_time_suggestions(provider, date, service)
    
    context = {
        'provider': provider,
        'date': date,
        'service': service,
        'suggestions': suggestions,
        'services': provider.services.filter(is_active=True),
    }
    
    return render(request, 'providers/smart_time_suggestions.html', context)


@login_required
def no_show_predictions(request):
    """
    Show no-show risk predictions for upcoming appointments.
    """
    provider = request.user.provider_profile
    
    # Get upcoming appointments
    upcoming = Appointment.objects.filter(
        service_provider=provider,
        appointment_date__gte=timezone.now().date(),
        status__in=['pending', 'confirmed']
    ).select_related('service', 'client').order_by('appointment_date', 'appointment_time')[:20]
    
    # Calculate risk for each
    predictions = []
    for appointment in upcoming:
        risk = calculate_no_show_risk(appointment)
        predictions.append({
            'appointment': appointment,
            'risk': risk
        })
    
    # Sort by risk level
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    predictions.sort(key=lambda x: risk_order.get(x['risk']['risk_level'], 3))
    
    context = {
        'provider': provider,
        'predictions': predictions,
    }
    
    return render(request, 'providers/no_show_predictions.html', context)


@login_required
def generate_content(request):
    """
    Generate AI content (descriptions, templates).
    """
    provider = request.user.provider_profile
    
    if request.method == 'POST':
        content_type = request.POST.get('content_type')
        language = request.POST.get('language', 'english')
        
        if content_type == 'service_description':
            service_id = request.POST.get('service_id')
            service = get_object_or_404(Service, id=service_id, service_provider=provider)
            
            description = generate_service_description(
                service.service_name,
                provider.business_type,
                language
            )
            
            return JsonResponse({
                'success': True,
                'description': description
            })
        
        elif content_type == 'email_template':
            purpose = request.POST.get('purpose')
            
            template = generate_email_template(
                purpose,
                provider.business_name,
                language
            )
            
            return JsonResponse({
                'success': True,
                'template': template
            })
    
    context = {
        'provider': provider,
        'services': provider.services.filter(is_active=True),
    }
    
    return render(request, 'providers/generate_content.html', context)


@require_http_methods(["POST"])
def chatbot_api(request):
    """
    API endpoint for chatbot responses.
    """
    import json
    
    try:
        data = json.loads(request.body)
        provider_id = data.get('provider_id')
        message = data.get('message')
        conversation_history = data.get('history', [])
        
        if not provider_id or not message:
            return JsonResponse({'error': 'Missing parameters'}, status=400)
        
        provider = get_object_or_404(ServiceProvider, id=provider_id)
        
        # Get chatbot response
        response = chatbot_response(message, provider, conversation_history)
        
        return JsonResponse({
            'success': True,
            'response': response
        })
        
    except Exception as e:
        return JsonResponse({
            'error': str(e)
        }, status=500)


@login_required
def ai_settings(request):
    """
    AI features settings and configuration.
    """
    provider = request.user.provider_profile
    
    if request.method == 'POST':
        # Save AI preferences
        # (You can add model for storing preferences)
        messages.success(request, 'AI settings updated successfully!')
        return redirect('providers:ai_settings')
    
    context = {
        'provider': provider,
    }
    
    return render(request, 'providers/ai_settings.html', context)
