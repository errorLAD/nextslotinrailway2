"""
Email utility functions for sending notifications.
Works for both FREE and PRO plans.
"""
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.html import strip_tags
import logging

logger = logging.getLogger(__name__)


def send_email(subject, to_email, template_name, context, from_email=None):
    """
    Send HTML email with plain text fallback.
    
    Args:
        subject: Email subject
        to_email: Recipient email address
        template_name: Template name (without .html extension)
        context: Context dictionary for template rendering
        from_email: Sender email (defaults to DEFAULT_FROM_EMAIL)
    
    Returns:
        bool: True if email sent successfully, False otherwise
    """
    try:
        # Add site configuration to context
        context.update({
            'site_name': settings.SITE_NAME,
            'site_url': settings.SITE_URL,
        })
        
        # Render HTML email
        html_content = render_to_string(f'emails/{template_name}.html', context)
        
        # Create plain text version
        text_content = strip_tags(html_content)
        
        # Create email
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email or settings.DEFAULT_FROM_EMAIL,
            to=[to_email]
        )
        
        # Attach HTML version
        email.attach_alternative(html_content, "text/html")
        
        # Send email
        email.send(fail_silently=False)
        
        logger.info(f"Email sent successfully to {to_email}: {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")
        return False


def send_welcome_email(user):
    """
    Send welcome email after registration (FREE & PRO).
    """
    subject = f"Welcome to {settings.SITE_NAME}!"
    context = {
        'user': user,
        'is_provider': user.is_provider,
    }
    
    return send_email(
        subject=subject,
        to_email=user.email,
        template_name='welcome',
        context=context
    )


def send_appointment_confirmation_email(appointment, to_provider=False):
    """
    Send appointment confirmation email (FREE & PRO).
    
    Args:
        appointment: Appointment instance
        to_provider: If True, send to provider; if False, send to client
    """
    if to_provider:
        recipient = appointment.service_provider.user.email
        subject = f"New Appointment Booking - {appointment.client_name}"
        template_name = 'appointment_confirmation_provider'
    else:
        recipient = appointment.client_email or (appointment.client.email if appointment.client else None)
        if not recipient:
            logger.warning(f"No email address for appointment {appointment.id}")
            return False
        subject = f"Appointment Confirmed - {appointment.service.service_name}"
        template_name = 'appointment_confirmation_client'
    
    context = {
        'appointment': appointment,
        'provider': appointment.service_provider,
        'service': appointment.service,
    }
    
    return send_email(
        subject=subject,
        to_email=recipient,
        template_name=template_name,
        context=context
    )


def send_appointment_reminder_email(appointment):
    """
    Send 24-hour reminder email (FREE & PRO).
    """
    recipient = appointment.client_email or (appointment.client.email if appointment.client else None)
    if not recipient:
        logger.warning(f"No email address for appointment reminder {appointment.id}")
        return False
    
    subject = f"Reminder: Appointment Tomorrow - {appointment.service.service_name}"
    context = {
        'appointment': appointment,
        'provider': appointment.service_provider,
        'service': appointment.service,
    }
    
    return send_email(
        subject=subject,
        to_email=recipient,
        template_name='appointment_reminder',
        context=context
    )


def send_appointment_cancelled_email(appointment, cancelled_by='provider'):
    """
    Send appointment cancellation email (FREE & PRO).
    
    Args:
        appointment: Appointment instance
        cancelled_by: 'provider' or 'client'
    """
    # Send to both client and provider
    client_email = appointment.client_email or (appointment.client.email if appointment.client else None)
    provider_email = appointment.service_provider.user.email
    
    context = {
        'appointment': appointment,
        'provider': appointment.service_provider,
        'service': appointment.service,
        'cancelled_by': cancelled_by,
    }
    
    results = []
    
    # Email to client
    if client_email:
        results.append(send_email(
            subject=f"Appointment Cancelled - {appointment.service.service_name}",
            to_email=client_email,
            template_name='appointment_cancelled_client',
            context=context
        ))
    
    # Email to provider
    results.append(send_email(
        subject=f"Appointment Cancelled - {appointment.client_name}",
        to_email=provider_email,
        template_name='appointment_cancelled_provider',
        context=context
    ))
    
    return all(results)


def send_appointment_rescheduled_email(appointment, old_date, old_time):
    """
    Send appointment rescheduled email (FREE & PRO).
    """
    client_email = appointment.client_email or (appointment.client.email if appointment.client else None)
    if not client_email:
        logger.warning(f"No email address for appointment {appointment.id}")
        return False
    
    subject = f"Appointment Rescheduled - {appointment.service.service_name}"
    context = {
        'appointment': appointment,
        'provider': appointment.service_provider,
        'service': appointment.service,
        'old_date': old_date,
        'old_time': old_time,
    }
    
    return send_email(
        subject=subject,
        to_email=client_email,
        template_name='appointment_rescheduled',
        context=context
    )


def send_subscription_expiry_reminder(provider, days_remaining):
    """
    Send subscription expiry reminder (PRO only).
    
    Args:
        provider: ServiceProvider instance
        days_remaining: Number of days until expiry
    """
    if not provider.is_pro():
        return False
    
    subject = f"Your PRO Plan Expires in {days_remaining} Days"
    context = {
        'provider': provider,
        'days_remaining': days_remaining,
        'plan_end_date': provider.plan_end_date,
    }
    
    return send_email(
        subject=subject,
        to_email=provider.user.email,
        template_name='subscription_expiry_reminder',
        context=context
    )


def send_payment_receipt_email(subscription_payment):
    """
    Send payment receipt email (PRO only).
    
    Args:
        subscription_payment: SubscriptionPayment instance
    """
    subject = f"Payment Receipt - {settings.SITE_NAME}"
    context = {
        'payment': subscription_payment,
        'provider': subscription_payment.provider,
    }
    
    return send_email(
        subject=subject,
        to_email=subscription_payment.provider.user.email,
        template_name='payment_receipt',
        context=context
    )
