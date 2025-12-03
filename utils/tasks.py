"""
Celery tasks for async email and SMS sending.
"""
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def send_welcome_email_task(self, user_id):
    """
    Async task to send welcome email.
    """
    try:
        from accounts.models import CustomUser
        from utils.email_utils import send_welcome_email
        
        user = CustomUser.objects.get(id=user_id)
        result = send_welcome_email(user)
        
        if not result:
            raise Exception("Failed to send welcome email")
        
        return f"Welcome email sent to {user.email}"
        
    except Exception as e:
        logger.error(f"Error sending welcome email: {str(e)}")
        # Retry with exponential backoff
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_appointment_confirmation_task(self, appointment_id, to_provider=False, send_sms=False):
    """
    Async task to send appointment confirmation email and SMS.
    
    Args:
        appointment_id: Appointment ID
        to_provider: Send to provider if True, client if False
        send_sms: Send SMS if True (PRO plan only)
    """
    try:
        from appointments.models import Appointment
        from utils.email_utils import send_appointment_confirmation_email
        from utils.sms_utils import send_appointment_confirmation_sms
        
        appointment = Appointment.objects.select_related(
            'service_provider', 'service', 'client'
        ).get(id=appointment_id)
        
        # Send email (both FREE and PRO)
        email_result = send_appointment_confirmation_email(appointment, to_provider)
        
        # Send SMS only if requested and provider is PRO
        sms_result = None
        if send_sms and not to_provider:
            sms_result = send_appointment_confirmation_sms(appointment)
        
        return {
            'email_sent': email_result,
            'sms_sent': sms_result,
            'appointment_id': appointment_id
        }
        
    except Exception as e:
        logger.error(f"Error sending appointment confirmation: {str(e)}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_appointment_reminder_task(self, appointment_id, send_sms=False):
    """
    Async task to send appointment reminder email and SMS.
    
    Args:
        appointment_id: Appointment ID
        send_sms: Send SMS if True (PRO plan only)
    """
    try:
        from appointments.models import Appointment
        from utils.email_utils import send_appointment_reminder_email
        from utils.sms_utils import send_appointment_reminder_sms
        
        appointment = Appointment.objects.select_related(
            'service_provider', 'service', 'client'
        ).get(id=appointment_id)
        
        # Check if appointment is still valid
        if appointment.status not in ['pending', 'confirmed']:
            logger.info(f"Skipping reminder for appointment {appointment_id} - status: {appointment.status}")
            return "Appointment not in valid status for reminder"
        
        # Send email (both FREE and PRO)
        email_result = send_appointment_reminder_email(appointment)
        
        # Send SMS only if requested and provider is PRO
        sms_result = None
        if send_sms:
            sms_result = send_appointment_reminder_sms(appointment)
        
        # Mark reminder as sent
        appointment.reminder_sent = True
        appointment.save(update_fields=['reminder_sent'])
        
        return {
            'email_sent': email_result,
            'sms_sent': sms_result,
            'appointment_id': appointment_id
        }
        
    except Exception as e:
        logger.error(f"Error sending appointment reminder: {str(e)}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def send_appointment_cancelled_task(self, appointment_id, cancelled_by='provider', send_sms=False):
    """
    Async task to send appointment cancellation email and SMS.
    """
    try:
        from appointments.models import Appointment
        from utils.email_utils import send_appointment_cancelled_email
        from utils.sms_utils import send_appointment_cancelled_sms
        
        appointment = Appointment.objects.select_related(
            'service_provider', 'service', 'client'
        ).get(id=appointment_id)
        
        # Send email (both FREE and PRO)
        email_result = send_appointment_cancelled_email(appointment, cancelled_by)
        
        # Send SMS only if requested and provider is PRO
        sms_result = None
        if send_sms:
            sms_result = send_appointment_cancelled_sms(appointment)
        
        return {
            'email_sent': email_result,
            'sms_sent': sms_result,
            'appointment_id': appointment_id
        }
        
    except Exception as e:
        logger.error(f"Error sending cancellation notification: {str(e)}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task
def send_daily_appointment_reminders():
    """
    Periodic task to send reminders for appointments 24 hours ahead.
    Run this task daily via Celery Beat.
    """
    from appointments.models import Appointment
    from django.utils import timezone
    
    # Get appointments for tomorrow that haven't received reminders
    tomorrow = timezone.now().date() + timedelta(days=1)
    
    appointments = Appointment.objects.filter(
        appointment_date=tomorrow,
        status__in=['pending', 'confirmed'],
        reminder_sent=False
    ).select_related('service_provider')
    
    sent_count = 0
    for appointment in appointments:
        # Check if provider has PRO plan for SMS
        send_sms = appointment.service_provider.is_pro()
        
        # Queue the reminder task
        send_appointment_reminder_task.delay(appointment.id, send_sms=send_sms)
        sent_count += 1
    
    logger.info(f"Queued {sent_count} appointment reminders for {tomorrow}")
    return f"Queued {sent_count} reminders"


@shared_task
def send_subscription_expiry_reminders():
    """
    Periodic task to send subscription expiry reminders.
    Run this task daily via Celery Beat.
    """
    from providers.models import ServiceProvider
    from utils.email_utils import send_subscription_expiry_reminder
    from django.conf import settings
    
    # Get providers whose subscription expires in 3 days
    expiry_date = timezone.now().date() + timedelta(days=settings.GRACE_PERIOD_DAYS)
    
    providers = ServiceProvider.objects.filter(
        current_plan='pro',
        plan_end_date=expiry_date,
        is_active=True
    )
    
    sent_count = 0
    for provider in providers:
        if send_subscription_expiry_reminder(provider, settings.GRACE_PERIOD_DAYS):
            sent_count += 1
    
    logger.info(f"Sent {sent_count} subscription expiry reminders")
    return f"Sent {sent_count} expiry reminders"


@shared_task
def reset_monthly_appointment_counters():
    """
    Periodic task to reset monthly appointment counters.
    Run this on the 1st of each month via Celery Beat.
    """
    from providers.models import ServiceProvider
    
    providers = ServiceProvider.objects.filter(current_plan='free')
    
    reset_count = 0
    for provider in providers:
        provider.reset_monthly_counter()
        reset_count += 1
    
    logger.info(f"Reset appointment counters for {reset_count} FREE plan providers")
    return f"Reset {reset_count} counters"
