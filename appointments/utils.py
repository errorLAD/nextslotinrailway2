"""
Utility functions for appointment booking.
Includes time slot calculation and availability checking.
"""
from datetime import datetime, timedelta, time
from django.utils import timezone
from django.conf import settings
import pytz


def get_available_slots(provider, service, date, buffer_minutes=15):
    """
    Calculate available time slots for a given provider, service, and date.
    
    Args:
        provider (ServiceProvider): The service provider
        service (Service): The service to be booked
        date (date): The date for which to find slots
        buffer_minutes (int): Buffer time between appointments (default: 15 minutes)
    
    Returns:
        list: List of dictionaries with available time slots
              [{'time': '09:00', 'display': '9:00 AM', 'available': True}, ...]
    
    Logic:
        1. Get provider's availability for the day of week
        2. Get service duration
        3. Break available hours into time slots
        4. Remove slots with existing appointments
        5. Remove past slots for today
        6. Ensure slot fits service duration before closing
    """
    from appointments.models import Appointment
    
    # Get day of week (0=Monday, 6=Sunday)
    day_of_week = date.weekday()
    
    # Get provider's availability for this day
    try:
        availability = provider.availability_slots.get(
            day_of_week=day_of_week,
            is_available=True
        )
    except:
        # Provider not available on this day
        return []
    
    # Get service duration in minutes
    service_duration = service.duration_minutes
    total_slot_duration = service_duration + buffer_minutes
    
    # Generate all possible time slots
    slots = []
    current_time = datetime.combine(date, availability.start_time)
    end_time = datetime.combine(date, availability.end_time)
    
    # Indian timezone
    ist = pytz.timezone('Asia/Kolkata')
    now = timezone.now().astimezone(ist)
    
    while current_time < end_time:
        slot_end_time = current_time + timedelta(minutes=service_duration)
        
        # Check if service can be completed before closing time
        if slot_end_time <= end_time:
            slot_time = current_time.time()
            
            # Check if slot is in the past (for today only)
            is_past = False
            if date == now.date():
                slot_datetime = ist.localize(datetime.combine(date, slot_time))
                is_past = slot_datetime < now
            
            # Check if slot is already booked
            is_booked = Appointment.objects.filter(
                service_provider=provider,
                appointment_date=date,
                appointment_time=slot_time,
                status__in=['pending', 'confirmed']
            ).exists()
            
            # Add slot to list
            slots.append({
                'time': slot_time.strftime('%H:%M'),
                'display': slot_time.strftime('%I:%M %p'),
                'available': not is_booked and not is_past,
                'is_past': is_past,
                'is_booked': is_booked
            })
        
        # Move to next slot (30-minute intervals)
        current_time += timedelta(minutes=30)
    
    return slots


def check_slot_availability(provider, service, date, time_str):
    """
    Check if a specific time slot is available.
    
    Args:
        provider (ServiceProvider): The service provider
        service (Service): The service to be booked
        date (date): The appointment date
        time_str (str): Time in HH:MM format (e.g., '14:30')
    
    Returns:
        dict: {'available': bool, 'reason': str}
    """
    from appointments.models import Appointment
    
    # Parse time string
    try:
        hour, minute = map(int, time_str.split(':'))
        appointment_time = time(hour, minute)
    except:
        return {'available': False, 'reason': 'Invalid time format'}
    
    # Check if in the past
    ist = pytz.timezone('Asia/Kolkata')
    now = timezone.now().astimezone(ist)
    
    if date == now.date():
        slot_datetime = ist.localize(datetime.combine(date, appointment_time))
        if slot_datetime < now:
            return {'available': False, 'reason': 'Time slot is in the past'}
    
    # Check if date is in the past
    if date < now.date():
        return {'available': False, 'reason': 'Date is in the past'}
    
    # Check provider availability for this day
    day_of_week = date.weekday()
    try:
        availability = provider.availability_slots.get(
            day_of_week=day_of_week,
            is_available=True
        )
    except:
        return {'available': False, 'reason': 'Provider not available on this day'}
    
    # Check if time is within working hours
    if appointment_time < availability.start_time or appointment_time >= availability.end_time:
        return {'available': False, 'reason': 'Outside business hours'}
    
    # Check if service can be completed before closing
    service_end = datetime.combine(date, appointment_time) + timedelta(minutes=service.duration_minutes)
    closing_time = datetime.combine(date, availability.end_time)
    
    if service_end > closing_time:
        return {'available': False, 'reason': 'Service cannot be completed before closing time'}
    
    # Check if slot is already booked
    is_booked = Appointment.objects.filter(
        service_provider=provider,
        appointment_date=date,
        appointment_time=appointment_time,
        status__in=['pending', 'confirmed']
    ).exists()
    
    if is_booked:
        return {'available': False, 'reason': 'Time slot already booked'}
    
    return {'available': True, 'reason': 'Available'}


def get_next_available_date(provider, service, start_date=None, days_ahead=30):
    """
    Find the next available date with at least one open slot.
    
    Args:
        provider (ServiceProvider): The service provider
        service (Service): The service to be booked
        start_date (date): Date to start searching from (default: today)
        days_ahead (int): How many days to search (default: 30)
    
    Returns:
        date: Next available date, or None if no slots found
    """
    if start_date is None:
        ist = pytz.timezone('Asia/Kolkata')
        start_date = timezone.now().astimezone(ist).date()
    
    for i in range(days_ahead):
        check_date = start_date + timedelta(days=i)
        slots = get_available_slots(provider, service, check_date)
        
        # Check if any slots are available
        if any(slot['available'] for slot in slots):
            return check_date
    
    return None


def calculate_appointment_end_time(start_time, duration_minutes):
    """
    Calculate when an appointment will end.
    
    Args:
        start_time (time): Appointment start time
        duration_minutes (int): Service duration in minutes
    
    Returns:
        time: Appointment end time
    """
    start_datetime = datetime.combine(datetime.today(), start_time)
    end_datetime = start_datetime + timedelta(minutes=duration_minutes)
    return end_datetime.time()


def get_business_hours_display(provider):
    """
    Get a formatted display of provider's business hours.
    
    Args:
        provider (ServiceProvider): The service provider
    
    Returns:
        dict: Day names mapped to hours string
    """
    availability_slots = provider.availability_slots.all().order_by('day_of_week')
    
    hours = {}
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    for slot in availability_slots:
        day_name = day_names[slot.day_of_week]
        if slot.is_available:
            hours[day_name] = f"{slot.start_time.strftime('%I:%M %p')} - {slot.end_time.strftime('%I:%M %p')}"
        else:
            hours[day_name] = "Closed"
    
    return hours


def validate_appointment_time(provider, service, date, time_str):
    """
    Comprehensive validation for appointment booking.
    
    Args:
        provider (ServiceProvider): The service provider
        service (Service): The service to be booked
        date (date): Appointment date
        time_str (str): Time in HH:MM format
    
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
    """
    # Check slot availability
    result = check_slot_availability(provider, service, date, time_str)
    
    if not result['available']:
        return False, result['reason']
    
    # Check if provider can accept more appointments (FREE plan limit)
    if not provider.can_create_appointment():
        return False, f"Provider has reached their monthly limit of {provider.appointments_this_month} appointments"
    
    return True, None
