"""
API views for AJAX requests.
"""
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.shortcuts import get_object_or_404
from datetime import datetime
from providers.models import ServiceProvider, Service
from .utils import get_available_slots, check_slot_availability


@require_GET
def available_slots_api(request, provider_slug):
    """
    API endpoint to get available time slots for a provider, service, and date.
    
    URL: /appointments/api/slots/{provider_slug}/
    Query Parameters:
        - service_id: ID of the service
        - date: Date in YYYY-MM-DD format
    
    Returns:
        JSON: {
            'success': bool,
            'slots': [{'time': '09:00', 'display': '9:00 AM', 'available': True}, ...],
            'date': 'YYYY-MM-DD',
            'service': 'Service Name'
        }
    """
    try:
        # Get provider
        provider = get_object_or_404(ServiceProvider, unique_booking_url=provider_slug, is_active=True)
        
        # Get service ID from query params
        service_id = request.GET.get('service_id')
        if not service_id:
            return JsonResponse({
                'success': False,
                'error': 'service_id parameter is required'
            }, status=400)
        
        # Get service
        service = get_object_or_404(Service, id=service_id, service_provider=provider, is_active=True)
        
        # Get date from query params
        date_str = request.GET.get('date')
        if not date_str:
            return JsonResponse({
                'success': False,
                'error': 'date parameter is required'
            }, status=400)
        
        # Parse date
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid date format. Use YYYY-MM-DD'
            }, status=400)
        
        # Get available slots
        slots = get_available_slots(provider, service, date)
        
        return JsonResponse({
            'success': True,
            'slots': slots,
            'date': date_str,
            'service': service.service_name,
            'service_duration': service.duration_minutes,
            'provider': provider.business_name
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_GET
def check_slot_api(request, provider_slug):
    """
    API endpoint to check if a specific time slot is available.
    
    URL: /appointments/api/check-slot/{provider_slug}/
    Query Parameters:
        - service_id: ID of the service
        - date: Date in YYYY-MM-DD format
        - time: Time in HH:MM format
    
    Returns:
        JSON: {
            'success': bool,
            'available': bool,
            'reason': str
        }
    """
    try:
        # Get provider
        provider = get_object_or_404(ServiceProvider, unique_booking_url=provider_slug, is_active=True)
        
        # Get parameters
        service_id = request.GET.get('service_id')
        date_str = request.GET.get('date')
        time_str = request.GET.get('time')
        
        if not all([service_id, date_str, time_str]):
            return JsonResponse({
                'success': False,
                'error': 'service_id, date, and time parameters are required'
            }, status=400)
        
        # Get service
        service = get_object_or_404(Service, id=service_id, service_provider=provider, is_active=True)
        
        # Parse date
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid date format. Use YYYY-MM-DD'
            }, status=400)
        
        # Check availability
        result = check_slot_availability(provider, service, date, time_str)
        
        return JsonResponse({
            'success': True,
            'available': result['available'],
            'reason': result['reason']
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
