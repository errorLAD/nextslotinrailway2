"""
Celery tasks for subscription management automation.
"""
from celery import shared_task
from django.core.management import call_command
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


@shared_task
def reset_monthly_limits():
    """
    Reset monthly appointment counters for all providers.
    Runs on the 1st of every month at midnight.
    """
    logger.info('Starting monthly limit reset task')
    try:
        call_command('reset_monthly_limits')
        logger.info('Monthly limit reset completed successfully')
    except Exception as e:
        logger.error(f'Error resetting monthly limits: {str(e)}')
        raise


@shared_task
def check_expired_subscriptions():
    """
    Check for expired PRO subscriptions and trials.
    Runs daily at 1 AM.
    """
    logger.info('Starting expired subscription check task')
    try:
        call_command('check_expired_subscriptions', '--send-emails')
        logger.info('Expired subscription check completed successfully')
    except Exception as e:
        logger.error(f'Error checking expired subscriptions: {str(e)}')
        raise


@shared_task
def send_upgrade_reminders():
    """
    Send upgrade reminders to FREE plan users near their limits.
    Runs every Monday at 10 AM.
    """
    logger.info('Starting upgrade reminder task')
    try:
        call_command('send_upgrade_reminders')
        logger.info('Upgrade reminders sent successfully')
    except Exception as e:
        logger.error(f'Error sending upgrade reminders: {str(e)}')
        raise


@shared_task
def send_appointment_reminders():
    """
    Send appointment reminders to clients.
    Runs every hour to check for appointments in the next 24 hours.
    """
    from appointments.models import Appointment
    from django.core.mail import send_mail
    from django.conf import settings
    
    logger.info('Starting appointment reminder task')
    
    # Get appointments for tomorrow that haven't been reminded
    tomorrow = timezone.now().date() + timezone.timedelta(days=1)
    appointments = Appointment.objects.filter(
        appointment_date=tomorrow,
        status__in=['pending', 'confirmed'],
        reminder_sent=False
    )
    
    sent_count = 0
    for appointment in appointments:
        try:
            # Send email reminder
            subject = f'Reminder: Appointment tomorrow at {appointment.service_provider.business_name}'
            message = f"""
            Hi {appointment.client_name},
            
            This is a reminder for your appointment:
            
            Service: {appointment.service.service_name}
            Date: {appointment.appointment_date.strftime('%B %d, %Y')}
            Time: {appointment.appointment_time.strftime('%I:%M %p')}
            Location: {appointment.service_provider.business_name}
            
            {appointment.service_provider.business_address}
            
            If you need to cancel or reschedule, please contact us at {appointment.service_provider.phone}
            
            See you tomorrow!
            """
            
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [appointment.client_email] if appointment.client_email else [],
                fail_silently=True,
            )
            
            # Mark as reminded
            appointment.reminder_sent = True
            appointment.save(update_fields=['reminder_sent'])
            sent_count += 1
            
        except Exception as e:
            logger.error(f'Error sending reminder for appointment {appointment.id}: {str(e)}')
    
    logger.info(f'Sent {sent_count} appointment reminders')
    return sent_count
