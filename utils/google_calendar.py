"""
Google Calendar API integration (PRO plan only).
Handles OAuth flow and calendar sync operations.
"""
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from django.conf import settings
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


def get_google_oauth_flow(redirect_uri):
    """
    Create Google OAuth 2.0 flow for calendar access.
    
    Args:
        redirect_uri: OAuth callback URL
    
    Returns:
        Flow object for OAuth
    """
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        },
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri=redirect_uri
    )
    return flow


def get_authorization_url(redirect_uri):
    """
    Get Google OAuth authorization URL.
    
    Args:
        redirect_uri: OAuth callback URL
    
    Returns:
        tuple: (authorization_url, state)
    """
    flow = get_google_oauth_flow(redirect_uri)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'  # Force consent to get refresh token
    )
    return authorization_url, state


def exchange_code_for_tokens(code, redirect_uri):
    """
    Exchange authorization code for access and refresh tokens.
    
    Args:
        code: Authorization code from Google
        redirect_uri: OAuth callback URL
    
    Returns:
        dict: Token information
    """
    flow = get_google_oauth_flow(redirect_uri)
    flow.fetch_token(code=code)
    
    credentials = flow.credentials
    
    return {
        'access_token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_expiry': credentials.expiry,
        'scopes': credentials.scopes
    }


def get_calendar_service(calendar_integration):
    """
    Get Google Calendar API service instance.
    
    Args:
        calendar_integration: GoogleCalendarIntegration instance
    
    Returns:
        Google Calendar API service
    """
    # Refresh token if needed
    if calendar_integration.needs_refresh():
        refresh_access_token(calendar_integration)
    
    credentials = Credentials(
        token=calendar_integration.access_token,
        refresh_token=calendar_integration.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET
    )
    
    service = build('calendar', 'v3', credentials=credentials)
    return service


def refresh_access_token(calendar_integration):
    """
    Refresh the access token using refresh token.
    
    Args:
        calendar_integration: GoogleCalendarIntegration instance
    """
    try:
        credentials = Credentials(
            token=calendar_integration.access_token,
            refresh_token=calendar_integration.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET
        )
        
        credentials.refresh(Request())
        
        # Update tokens
        calendar_integration.access_token = credentials.token
        calendar_integration.token_expiry = credentials.expiry
        calendar_integration.save(update_fields=['access_token', 'token_expiry'])
        
        logger.info(f"Refreshed access token for {calendar_integration.service_provider.business_name}")
        
    except Exception as e:
        logger.error(f"Failed to refresh token: {str(e)}")
        calendar_integration.sync_errors = str(e)
        calendar_integration.save(update_fields=['sync_errors'])


def create_calendar_event(calendar_integration, appointment):
    """
    Create a Google Calendar event for an appointment.
    
    Args:
        calendar_integration: GoogleCalendarIntegration instance
        appointment: Appointment instance
    
    Returns:
        str: Google Calendar event ID or None if failed
    """
    # CHECK PRO PLAN
    if not appointment.service_provider.is_pro():
        logger.warning(f"Cannot sync calendar - Provider {appointment.service_provider.business_name} is not on PRO plan")
        return None
    
    try:
        service = get_calendar_service(calendar_integration)
        
        # Prepare event data
        start_datetime = timezone.make_aware(
            timezone.datetime.combine(
                appointment.appointment_date,
                appointment.appointment_time
            )
        )
        
        end_datetime = start_datetime + timezone.timedelta(
            minutes=appointment.service.duration_minutes
        )
        
        event = {
            'summary': f"{appointment.service.service_name} - {appointment.client_name}",
            'description': f"""
Appointment Details:
- Client: {appointment.client_name}
- Phone: {appointment.client_phone}
- Service: {appointment.service.service_name}
- Price: ₹{appointment.total_price}
- Status: {appointment.get_status_display()}
{f"- Staff: {appointment.staff_member.name}" if appointment.staff_member else ""}
{f"- Notes: {appointment.notes}" if appointment.notes else ""}

Booked via {settings.SITE_NAME}
            """.strip(),
            'start': {
                'dateTime': start_datetime.isoformat(),
                'timeZone': settings.TIME_ZONE,
            },
            'end': {
                'dateTime': end_datetime.isoformat(),
                'timeZone': settings.TIME_ZONE,
            },
            'reminders': {
                'useDefault': False,
                'overrides': [
                    {'method': 'email', 'minutes': 24 * 60},  # 24 hours before
                    {'method': 'popup', 'minutes': 60},  # 1 hour before
                ],
            },
        }
        
        # Add attendees
        if appointment.client_email:
            event['attendees'] = [
                {'email': appointment.client_email}
            ]
        
        # Create event
        created_event = service.events().insert(
            calendarId=calendar_integration.calendar_id,
            body=event
        ).execute()
        
        logger.info(f"Created calendar event {created_event['id']} for appointment #{appointment.id}")
        
        # Update last sync time
        calendar_integration.last_sync = timezone.now()
        calendar_integration.sync_errors = ''
        calendar_integration.save(update_fields=['last_sync', 'sync_errors'])
        
        return created_event['id']
        
    except HttpError as e:
        logger.error(f"Google Calendar API error: {str(e)}")
        calendar_integration.sync_errors = str(e)
        calendar_integration.save(update_fields=['sync_errors'])
        return None
    except Exception as e:
        logger.error(f"Failed to create calendar event: {str(e)}")
        calendar_integration.sync_errors = str(e)
        calendar_integration.save(update_fields=['sync_errors'])
        return None


def update_calendar_event(calendar_integration, appointment, event_id):
    """
    Update an existing Google Calendar event.
    
    Args:
        calendar_integration: GoogleCalendarIntegration instance
        appointment: Appointment instance
        event_id: Google Calendar event ID
    
    Returns:
        bool: True if successful, False otherwise
    """
    # CHECK PRO PLAN
    if not appointment.service_provider.is_pro():
        return False
    
    try:
        service = get_calendar_service(calendar_integration)
        
        # Get existing event
        event = service.events().get(
            calendarId=calendar_integration.calendar_id,
            eventId=event_id
        ).execute()
        
        # Update event data
        start_datetime = timezone.make_aware(
            timezone.datetime.combine(
                appointment.appointment_date,
                appointment.appointment_time
            )
        )
        
        end_datetime = start_datetime + timezone.timedelta(
            minutes=appointment.service.duration_minutes
        )
        
        event['summary'] = f"{appointment.service.service_name} - {appointment.client_name}"
        event['description'] = f"""
Appointment Details:
- Client: {appointment.client_name}
- Phone: {appointment.client_phone}
- Service: {appointment.service.service_name}
- Price: ₹{appointment.total_price}
- Status: {appointment.get_status_display()}
{f"- Staff: {appointment.staff_member.name}" if appointment.staff_member else ""}
{f"- Notes: {appointment.notes}" if appointment.notes else ""}

Booked via {settings.SITE_NAME}
        """.strip()
        
        event['start'] = {
            'dateTime': start_datetime.isoformat(),
            'timeZone': settings.TIME_ZONE,
        }
        event['end'] = {
            'dateTime': end_datetime.isoformat(),
            'timeZone': settings.TIME_ZONE,
        }
        
        # Update event
        service.events().update(
            calendarId=calendar_integration.calendar_id,
            eventId=event_id,
            body=event
        ).execute()
        
        logger.info(f"Updated calendar event {event_id} for appointment #{appointment.id}")
        
        calendar_integration.last_sync = timezone.now()
        calendar_integration.sync_errors = ''
        calendar_integration.save(update_fields=['last_sync', 'sync_errors'])
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to update calendar event: {str(e)}")
        calendar_integration.sync_errors = str(e)
        calendar_integration.save(update_fields=['sync_errors'])
        return False


def delete_calendar_event(calendar_integration, event_id):
    """
    Delete a Google Calendar event.
    
    Args:
        calendar_integration: GoogleCalendarIntegration instance
        event_id: Google Calendar event ID
    
    Returns:
        bool: True if successful, False otherwise
    """
    # CHECK PRO PLAN
    if not calendar_integration.service_provider.is_pro():
        return False
    
    try:
        service = get_calendar_service(calendar_integration)
        
        service.events().delete(
            calendarId=calendar_integration.calendar_id,
            eventId=event_id
        ).execute()
        
        logger.info(f"Deleted calendar event {event_id}")
        
        calendar_integration.last_sync = timezone.now()
        calendar_integration.save(update_fields=['last_sync'])
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete calendar event: {str(e)}")
        return False


def sync_appointment_to_calendar(appointment):
    """
    Sync an appointment to Google Calendar (create or update).
    
    Args:
        appointment: Appointment instance
    
    Returns:
        bool: True if successful, False otherwise
    """
    # CHECK PRO PLAN
    if not appointment.service_provider.is_pro():
        logger.info(f"Skipping calendar sync - Provider is not on PRO plan")
        return False
    
    # Check if provider has Google Calendar connected
    try:
        calendar_integration = appointment.service_provider.google_calendar
    except:
        logger.info(f"Provider {appointment.service_provider.business_name} has not connected Google Calendar")
        return False
    
    if not calendar_integration.is_active or not calendar_integration.sync_enabled:
        return False
    
    # Check if event already exists
    try:
        event_mapping = appointment.calendar_event
        # Update existing event
        success = update_calendar_event(
            calendar_integration,
            appointment,
            event_mapping.google_event_id
        )
        if success:
            event_mapping.sync_status = 'synced'
            event_mapping.error_message = ''
            event_mapping.save()
        return success
        
    except:
        # Create new event
        event_id = create_calendar_event(calendar_integration, appointment)
        if event_id:
            # Create mapping
            from providers.models_calendar import CalendarEventMapping
            CalendarEventMapping.objects.create(
                appointment=appointment,
                google_event_id=event_id,
                calendar_integration=calendar_integration,
                sync_status='synced'
            )
            return True
        return False


def disconnect_calendar(calendar_integration):
    """
    Disconnect Google Calendar integration.
    
    Args:
        calendar_integration: GoogleCalendarIntegration instance
    """
    calendar_integration.is_active = False
    calendar_integration.sync_enabled = False
    calendar_integration.save()
    logger.info(f"Disconnected Google Calendar for {calendar_integration.service_provider.business_name}")
