"""
SMS utility functions using Twilio.
SMS notifications are PRO PLAN ONLY.
"""
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Try to import Twilio (optional dependency)
try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    logger.warning("Twilio library not installed. SMS features will be disabled.")


def is_sms_configured():
    """Check if Twilio SMS is properly configured."""
    return (
        TWILIO_AVAILABLE and
        settings.TWILIO_ACCOUNT_SID and
        settings.TWILIO_AUTH_TOKEN and
        settings.TWILIO_PHONE_NUMBER
    )


def send_sms(to_phone, message):
    """
    Send SMS using Twilio.
    
    Args:
        to_phone: Recipient phone number (with country code, e.g., +919876543210)
        message: SMS message text
    
    Returns:
        bool: True if SMS sent successfully, False otherwise
    """
    if not is_sms_configured():
        logger.error("Twilio SMS is not configured properly")
        return False
    
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        
        message = client.messages.create(
            body=message,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=to_phone
        )
        
        logger.info(f"SMS sent successfully to {to_phone}. SID: {message.sid}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send SMS to {to_phone}: {str(e)}")
        return False


def send_appointment_confirmation_sms(appointment):
    """
    Send appointment confirmation SMS (PRO PLAN ONLY).
    
    Args:
        appointment: Appointment instance
    
    Returns:
        bool: True if SMS sent successfully, False otherwise
    """
    provider = appointment.service_provider
    
    # CHECK PRO PLAN - This is the key feature gate
    if not provider.is_pro():
        logger.info(f"SMS not sent - Provider {provider.business_name} is not on PRO plan")
        return False
    
    # Get client phone number
    phone = appointment.client_phone
    if not phone:
        logger.warning(f"No phone number for appointment {appointment.id}")
        return False
    
    # Ensure phone has country code
    if not phone.startswith('+'):
        phone = f"+91{phone}"  # Default to India
    
    # Create SMS message
    message = (
        f"Appointment Confirmed!\n"
        f"{provider.business_name}\n"
        f"Service: {appointment.service.service_name}\n"
        f"Date: {appointment.appointment_date.strftime('%d %b %Y')}\n"
        f"Time: {appointment.appointment_time.strftime('%I:%M %p')}\n"
        f"Location: {provider.city}\n"
        f"Contact: {provider.phone}"
    )
    
    return send_sms(phone, message)


def send_appointment_reminder_sms(appointment):
    """
    Send 24-hour appointment reminder SMS (PRO PLAN ONLY).
    
    Args:
        appointment: Appointment instance
    
    Returns:
        bool: True if SMS sent successfully, False otherwise
    """
    provider = appointment.service_provider
    
    # CHECK PRO PLAN
    if not provider.is_pro():
        logger.info(f"SMS reminder not sent - Provider {provider.business_name} is not on PRO plan")
        return False
    
    phone = appointment.client_phone
    if not phone:
        logger.warning(f"No phone number for appointment reminder {appointment.id}")
        return False
    
    if not phone.startswith('+'):
        phone = f"+91{phone}"
    
    message = (
        f"Reminder: Appointment Tomorrow!\n"
        f"{provider.business_name}\n"
        f"Service: {appointment.service.service_name}\n"
        f"Date: {appointment.appointment_date.strftime('%d %b %Y')}\n"
        f"Time: {appointment.appointment_time.strftime('%I:%M %p')}\n"
        f"Contact: {provider.phone}"
    )
    
    return send_sms(phone, message)


def send_appointment_cancelled_sms(appointment):
    """
    Send appointment cancellation SMS (PRO PLAN ONLY).
    
    Args:
        appointment: Appointment instance
    
    Returns:
        bool: True if SMS sent successfully, False otherwise
    """
    provider = appointment.service_provider
    
    # CHECK PRO PLAN
    if not provider.is_pro():
        logger.info(f"SMS cancellation not sent - Provider {provider.business_name} is not on PRO plan")
        return False
    
    phone = appointment.client_phone
    if not phone:
        logger.warning(f"No phone number for appointment {appointment.id}")
        return False
    
    if not phone.startswith('+'):
        phone = f"+91{phone}"
    
    message = (
        f"Appointment Cancelled\n"
        f"{provider.business_name}\n"
        f"Service: {appointment.service.service_name}\n"
        f"Date: {appointment.appointment_date.strftime('%d %b %Y')}\n"
        f"Time: {appointment.appointment_time.strftime('%I:%M %p')}\n"
        f"Please contact us to reschedule: {provider.phone}"
    )
    
    return send_sms(phone, message)


def send_custom_sms(provider, phone, message):
    """
    Send custom SMS (PRO PLAN ONLY).
    
    Args:
        provider: ServiceProvider instance
        phone: Recipient phone number
        message: Custom message text
    
    Returns:
        bool: True if SMS sent successfully, False otherwise
    """
    # CHECK PRO PLAN
    if not provider.is_pro():
        logger.warning(f"Custom SMS not sent - Provider {provider.business_name} is not on PRO plan")
        return False
    
    if not phone.startswith('+'):
        phone = f"+91{phone}"
    
    return send_sms(phone, message)
