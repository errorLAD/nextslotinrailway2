```markdown
# 🎯 Multi-Staff, Client Portal & Google Calendar - Complete Guide

## 📋 Overview

This guide covers three major features:
1. **Multi-Staff Management** (PRO plan only)
2. **Client Portal** (All users)
3. **Google Calendar Sync** (PRO plan only)

---

## 👥 Part 1: Multi-Staff Management (PRO PLAN ONLY)

### Overview

FREE plan providers can only manage themselves (single provider).
PRO plan providers can add up to **10 staff members** who can provide services.

### Database Models

#### StaffMember Model
```python
# Location: providers/models_staff.py

class StaffMember(models.Model):
    service_provider = ForeignKey(ServiceProvider)  # Owner
    name = CharField(max_length=200)
    email = EmailField(blank=True)
    phone = CharField(max_length=15)
    user = OneToOneField(CustomUser, null=True)  # Optional login
    services = ManyToManyField(Service)  # Services they can provide
    bio = TextField(blank=True)
    profile_image = ImageField(blank=True)
    is_active = BooleanField(default=True)
    display_order = IntegerField(default=0)
```

#### StaffAvailability Model
```python
class StaffAvailability(models.Model):
    staff_member = ForeignKey(StaffMember)
    day_of_week = IntegerField(choices=DAY_CHOICES)
    start_time = TimeField()
    end_time = TimeField()
    is_available = BooleanField(default=True)
```

#### Updated Appointment Model
```python
# Added field to appointments/models.py

class Appointment(models.Model):
    # ... existing fields ...
    staff_member = ForeignKey(
        'providers.StaffMember',
        null=True,
        blank=True,
        help_text='Staff member assigned (PRO plan only)'
    )
```

### Feature Gating

**Check PRO Plan Before Staff Operations:**
```python
# In ServiceProvider model
def can_add_staff(self):
    """Check if provider can add more staff (PRO only)."""
    if not self.is_pro():
        return False
    return self.staff_members.count() < MAX_STAFF_MEMBERS_PRO  # 10

def get_staff_count(self):
    """Get number of active staff members."""
    return self.staff_members.filter(is_active=True).count()

def get_active_staff(self):
    """Get all active staff members."""
    return self.staff_members.filter(is_active=True)
```

**Decorator for PRO-Only Views:**
```python
def require_pro_plan(view_func):
    """Decorator to require PRO plan for staff features."""
    def wrapper(request, *args, **kwargs):
        provider = request.user.provider_profile
        
        if not provider.is_pro():
            messages.warning(
                request,
                '🔒 Staff management is a PRO feature!'
            )
            return redirect('subscriptions:upgrade')
        
        return view_func(request, *args, **kwargs)
    return wrapper

# Usage
@login_required
@require_pro_plan
def staff_list(request):
    # Staff management view
    pass
```

### Staff Management URLs

```python
# providers/urls.py

urlpatterns = [
    # Staff Management (PRO only)
    path('staff/', views_staff.staff_list, name='staff_list'),
    path('staff/add/', views_staff.staff_create, name='staff_create'),
    path('staff/<int:pk>/', views_staff.staff_detail, name='staff_detail'),
    path('staff/<int:pk>/edit/', views_staff.staff_edit, name='staff_edit'),
    path('staff/<int:pk>/delete/', views_staff.staff_delete, name='staff_delete'),
    path('staff/<int:pk>/availability/', views_staff.staff_availability, name='staff_availability'),
]
```

### Booking Flow with Staff

**1. Client selects service → sees available staff:**
```python
# In booking view
def book_appointment(request, slug, service_id=None):
    provider = get_object_or_404(ServiceProvider, unique_booking_url=slug)
    
    if service_id:
        service = get_object_or_404(Service, id=service_id, service_provider=provider)
        
        # Get staff who can provide this service (if PRO)
        available_staff = None
        if provider.is_pro():
            available_staff = service.staff_members.filter(is_active=True)
        
        context = {
            'provider': provider,
            'service': service,
            'available_staff': available_staff,  # None for FREE plan
        }
```

**2. FREE Plan Behavior:**
```html
<!-- In booking template -->
{% if provider.is_pro and available_staff %}
    <div class="form-group">
        <label>Select Staff Member</label>
        <select name="staff_member" class="form-control">
            <option value="">Any available staff</option>
            {% for staff in available_staff %}
                <option value="{{ staff.id }}">{{ staff.name }}</option>
            {% endfor %}
        </select>
    </div>
{% else %}
    <!-- FREE plan: No staff selection -->
    <input type="hidden" name="staff_member" value="">
{% endif %}
```

### Staff Dashboard (Optional)

Staff members can optionally have login access:

```python
# In views_staff.py
@login_required
def staff_dashboard(request):
    """Dashboard for staff members to see their appointments."""
    try:
        staff_profile = request.user.staff_profile
    except:
        return redirect('accounts:login')
    
    my_appointments = Appointment.objects.filter(
        staff_member=staff_profile,
        status__in=['pending', 'confirmed']
    ).order_by('appointment_date', 'appointment_time')
    
    context = {
        'staff_profile': staff_profile,
        'my_appointments': my_appointments,
    }
    
    return render(request, 'staff/dashboard.html', context)
```

### Migration Strategy

**Step 1: Create migrations**
```bash
python manage.py makemigrations providers
python manage.py makemigrations appointments
```

**Step 2: Run migrations**
```bash
python manage.py migrate
```

**Step 3: Data migration (if needed)**
```python
# Create a data migration
python manage.py makemigrations --empty providers --name migrate_existing_data

# In the migration file:
def migrate_existing_appointments(apps, schema_editor):
    """
    Existing appointments don't need staff_member.
    The field is nullable, so no action needed.
    """
    pass
```

**Existing single-provider data:**
- All existing appointments remain unchanged (staff_member=None)
- Providers can start adding staff after upgrading to PRO
- No data loss or breaking changes

---

## 👤 Part 2: Client Portal

### Overview

Clients can register/login or book as guests. Registered clients get:
- Dashboard with appointments
- Cancel/reschedule functionality
- Favorite providers
- Notification preferences

### Database Models

#### FavoriteProvider Model
```python
# Location: accounts/models_client.py

class FavoriteProvider(models.Model):
    client = ForeignKey(CustomUser)
    provider = ForeignKey(ServiceProvider)
    created_at = DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['client', 'provider']
```

#### ClientNotificationPreference Model
```python
class ClientNotificationPreference(models.Model):
    client = OneToOneField(CustomUser)
    email_enabled = BooleanField(default=True)
    sms_enabled = BooleanField(default=True)
    booking_confirmation = BooleanField(default=True)
    appointment_reminders = BooleanField(default=True)
    cancellation_updates = BooleanField(default=True)
    promotional_emails = BooleanField(default=False)
```

### Client Portal URLs

```python
# accounts/urls.py

urlpatterns = [
    # Client Portal
    path('dashboard/', views_client.client_dashboard, name='client_dashboard'),
    path('appointments/<int:pk>/', views_client.appointment_detail_client, name='appointment_detail'),
    path('appointments/<int:pk>/cancel/', views_client.cancel_appointment_client, name='cancel_appointment'),
    path('appointments/<int:pk>/reschedule/', views_client.reschedule_appointment_client, name='reschedule_appointment'),
    path('appointments/<int:pk>/rebook/', views_client.rebook_appointment, name='rebook_appointment'),
    
    # Favorites
    path('favorites/', views_client.favorite_providers_list, name='favorite_providers'),
    path('favorites/add/<int:provider_id>/', views_client.add_favorite_provider, name='add_favorite'),
    path('favorites/remove/<int:provider_id>/', views_client.remove_favorite_provider, name='remove_favorite'),
    
    # Preferences
    path('preferences/', views_client.notification_preferences, name='notification_preferences'),
]
```

### Client Dashboard Features

**1. Upcoming Appointments**
```python
upcoming_appointments = Appointment.objects.filter(
    Q(client=request.user) | Q(client_email=request.user.email),
    appointment_date__gte=timezone.now().date(),
    status__in=['pending', 'confirmed']
).select_related('service_provider', 'service', 'staff_member')
```

**2. Past Appointments**
```python
past_appointments = Appointment.objects.filter(
    Q(client=request.user) | Q(client_email=request.user.email),
    status__in=['completed', 'cancelled', 'no_show']
).order_by('-appointment_date')[:10]
```

**3. Cancel Appointment**
```python
@login_required
def cancel_appointment_client(request, pk):
    appointment = get_object_or_404(Appointment, pk=pk)
    
    # Check access
    if appointment.client != request.user:
        return HttpResponseForbidden()
    
    if appointment.can_cancel():
        appointment.cancel()
        
        # Send notifications
        from utils.tasks import send_appointment_cancelled_task
        send_appointment_cancelled_task.delay(
            appointment.id,
            cancelled_by='client',
            send_sms=appointment.service_provider.is_pro()
        )
        
        messages.success(request, 'Appointment cancelled!')
    
    return redirect('accounts:client_dashboard')
```

**4. Reschedule Appointment**
```python
@login_required
def reschedule_appointment_client(request, pk):
    appointment = get_object_or_404(Appointment, pk=pk)
    
    if request.method == 'POST':
        new_date = request.POST.get('new_date')
        new_time = request.POST.get('new_time')
        
        old_date = appointment.appointment_date
        old_time = appointment.appointment_time
        
        appointment.appointment_date = new_date
        appointment.appointment_time = new_time
        appointment.save()
        
        # Send notification
        from utils.email_utils import send_appointment_rescheduled_email
        send_appointment_rescheduled_email(appointment, old_date, old_time)
        
        # Sync to Google Calendar if PRO
        if appointment.service_provider.is_pro():
            from utils.google_calendar import sync_appointment_to_calendar
            sync_appointment_to_calendar(appointment)
        
        messages.success(request, 'Appointment rescheduled!')
        return redirect('accounts:appointment_detail', pk=pk)
```

**5. Favorite Providers**
```python
@login_required
def add_favorite_provider(request, provider_id):
    provider = get_object_or_404(ServiceProvider, pk=provider_id)
    
    FavoriteProvider.objects.get_or_create(
        client=request.user,
        provider=provider
    )
    
    messages.success(request, f'{provider.business_name} added to favorites!')
    return redirect('providers:provider_detail', slug=provider.unique_booking_url)
```

### Guest Booking → Account Linking

When a guest books and later registers:

```python
# In registration view
def link_guest_bookings(user):
    """Link guest bookings to newly registered user."""
    Appointment.objects.filter(
        client_email=user.email,
        client__isnull=True
    ).update(client=user)
```

### Mobile-First Design

All client portal templates use Bootstrap 4/5 with mobile-first approach:

```html
<!-- Client dashboard template -->
<div class="container-fluid px-3">
    <div class="row">
        <div class="col-12 col-md-8">
            <!-- Main content -->
        </div>
        <div class="col-12 col-md-4">
            <!-- Sidebar -->
        </div>
    </div>
</div>
```

---

## 📅 Part 3: Google Calendar Sync (PRO PLAN ONLY)

### Overview

PRO plan providers can sync appointments to Google Calendar automatically.

**Features:**
- One-way sync: App → Google Calendar
- OAuth 2.0 authentication
- Automatic event creation/update/deletion
- Secure token storage

### Setup Google Calendar API

**Step 1: Create Google Cloud Project**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project: "BookingSaaS Calendar"
3. Enable Google Calendar API:
   - Navigate to "APIs & Services" → "Library"
   - Search for "Google Calendar API"
   - Click "Enable"

**Step 2: Create OAuth 2.0 Credentials**

1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth client ID"
3. Choose "Web application"
4. Add authorized redirect URIs:
   ```
   http://localhost:8000/providers/calendar/callback/
   https://yourdomain.com/providers/calendar/callback/
   ```
5. Copy Client ID and Client Secret

**Step 3: Configure Django Settings**

```python
# settings.py

# Google Calendar API (PRO plan only)
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID', default='')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET', default='')
```

```bash
# .env

GOOGLE_CLIENT_ID=your_client_id_here.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret_here
```

**Step 4: Install Dependencies**

```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

Update `requirements.txt`:
```
google-auth==2.23.4
google-auth-oauthlib==1.1.0
google-auth-httplib2==0.1.1
google-api-python-client==2.108.0
```

### Database Models

#### GoogleCalendarIntegration Model
```python
# Location: providers/models_calendar.py

class GoogleCalendarIntegration(models.Model):
    service_provider = OneToOneField(ServiceProvider)
    google_email = EmailField()
    access_token = TextField()  # Short-lived
    refresh_token = TextField()  # Long-lived
    token_expiry = DateTimeField()
    calendar_id = CharField(default='primary')
    is_active = BooleanField(default=True)
    sync_enabled = BooleanField(default=True)
    two_way_sync = BooleanField(default=False)
    last_sync = DateTimeField(null=True)
    sync_errors = TextField(blank=True)
```

#### CalendarEventMapping Model
```python
class CalendarEventMapping(models.Model):
    appointment = OneToOneField(Appointment)
    google_event_id = CharField(max_length=255)
    calendar_integration = ForeignKey(GoogleCalendarIntegration)
    last_synced = DateTimeField(auto_now=True)
    sync_status = CharField(choices=[...])
    error_message = TextField(blank=True)
```

### OAuth Flow Implementation

**Step 1: Initiate OAuth**
```python
@login_required
@require_pro_plan_calendar
def connect_google_calendar(request):
    """Start OAuth flow (PRO only)."""
    provider = request.user.provider_profile
    
    # Build redirect URI
    redirect_uri = request.build_absolute_uri(
        reverse('providers:google_calendar_callback')
    )
    
    # Get authorization URL
    from utils.google_calendar import get_authorization_url
    authorization_url, state = get_authorization_url(redirect_uri)
    
    # Store state in session
    request.session['google_oauth_state'] = state
    
    # Redirect to Google
    return redirect(authorization_url)
```

**Step 2: Handle Callback**
```python
@login_required
@require_pro_plan_calendar
def google_calendar_callback(request):
    """Handle OAuth callback (PRO only)."""
    provider = request.user.provider_profile
    
    # Verify state
    state = request.GET.get('state')
    if state != request.session.get('google_oauth_state'):
        messages.error(request, 'Invalid OAuth state')
        return redirect('providers:calendar_settings')
    
    # Get authorization code
    code = request.GET.get('code')
    
    # Exchange for tokens
    from utils.google_calendar import exchange_code_for_tokens
    token_info = exchange_code_for_tokens(code, redirect_uri)
    
    # Save integration
    GoogleCalendarIntegration.objects.update_or_create(
        service_provider=provider,
        defaults={
            'google_email': provider.user.email,
            'access_token': token_info['access_token'],
            'refresh_token': token_info['refresh_token'],
            'token_expiry': token_info['token_expiry'],
            'is_active': True,
            'sync_enabled': True,
        }
    )
    
    messages.success(request, '✅ Google Calendar connected!')
    return redirect('providers:calendar_settings')
```

### Calendar Sync Functions

**Create Event:**
```python
def create_calendar_event(calendar_integration, appointment):
    """Create Google Calendar event (PRO only)."""
    # CHECK PRO PLAN
    if not appointment.service_provider.is_pro():
        return None
    
    service = get_calendar_service(calendar_integration)
    
    # Prepare event
    start_datetime = timezone.make_aware(
        timezone.datetime.combine(
            appointment.appointment_date,
            appointment.appointment_time
        )
    )
    
    end_datetime = start_datetime + timedelta(
        minutes=appointment.service.duration_minutes
    )
    
    event = {
        'summary': f"{appointment.service.service_name} - {appointment.client_name}",
        'description': f"Client: {appointment.client_name}\nPhone: {appointment.client_phone}",
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
                {'method': 'email', 'minutes': 24 * 60},
                {'method': 'popup', 'minutes': 60},
            ],
        },
    }
    
    # Create event
    created_event = service.events().insert(
        calendarId=calendar_integration.calendar_id,
        body=event
    ).execute()
    
    return created_event['id']
```

**Auto-Sync on Appointment Save:**
```python
# In appointments/models.py

from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=Appointment)
def sync_to_google_calendar(sender, instance, created, **kwargs):
    """Auto-sync appointment to Google Calendar if PRO."""
    if instance.service_provider.is_pro():
        from utils.google_calendar import sync_appointment_to_calendar
        sync_appointment_to_calendar(instance)
```

### Feature Gating

**Settings Page:**
```html
<!-- providers/calendar_settings.html -->

{% if is_pro %}
    {% if calendar_integration %}
        <!-- Connected -->
        <div class="alert alert-success">
            ✅ Google Calendar Connected
            <br>
            Email: {{ calendar_integration.google_email }}
            <br>
            Last Sync: {{ calendar_integration.last_sync|date:"M d, Y g:i A" }}
        </div>
        
        <a href="{% url 'providers:disconnect_google_calendar' %}" class="btn btn-danger">
            Disconnect
        </a>
        
        <a href="{% url 'providers:toggle_calendar_sync' %}" class="btn btn-secondary">
            {% if calendar_integration.sync_enabled %}Disable{% else %}Enable{% endif %} Sync
        </a>
    {% else %}
        <!-- Not connected -->
        <a href="{% url 'providers:connect_google_calendar' %}" class="btn btn-primary">
            Connect Google Calendar
        </a>
    {% endif %}
{% else %}
    <!-- FREE plan - locked -->
    <div class="locked-feature">
        <h3>🔒 Google Calendar Sync (PRO Only)</h3>
        <p>Upgrade to PRO to automatically sync appointments to your Google Calendar.</p>
        <a href="{% url 'subscriptions:upgrade' %}" class="btn btn-upgrade">
            Upgrade to PRO
        </a>
    </div>
{% endif %}
```

### Security Considerations

**1. Encrypt Refresh Tokens:**
```python
from cryptography.fernet import Fernet

def encrypt_token(token):
    """Encrypt refresh token before storing."""
    f = Fernet(settings.SECRET_KEY[:32].encode())
    return f.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token):
    """Decrypt refresh token when using."""
    f = Fernet(settings.SECRET_KEY[:32].encode())
    return f.decrypt(encrypted_token.encode()).decode()
```

**2. Token Refresh:**
```python
def refresh_access_token(calendar_integration):
    """Refresh expired access token."""
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
    calendar_integration.save()
```

**3. Error Handling:**
```python
try:
    create_calendar_event(calendar_integration, appointment)
except HttpError as e:
    logger.error(f"Google Calendar API error: {str(e)}")
    calendar_integration.sync_errors = str(e)
    calendar_integration.save()
except Exception as e:
    logger.error(f"Failed to sync: {str(e)}")
```

### URLs Configuration

```python
# providers/urls.py

urlpatterns = [
    # Google Calendar (PRO only)
    path('calendar/settings/', views_calendar.calendar_settings, name='calendar_settings'),
    path('calendar/connect/', views_calendar.connect_google_calendar, name='connect_google_calendar'),
    path('calendar/callback/', views_calendar.google_calendar_callback, name='google_calendar_callback'),
    path('calendar/disconnect/', views_calendar.disconnect_google_calendar, name='disconnect_google_calendar'),
    path('calendar/toggle/', views_calendar.toggle_calendar_sync, name='toggle_calendar_sync'),
]
```

---

## 🚀 Complete Setup Checklist

### Multi-Staff Setup
- [ ] Run migrations for StaffMember and StaffAvailability models
- [ ] Update Appointment model with staff_member field
- [ ] Test PRO plan check for staff management
- [ ] Create staff management templates
- [ ] Test booking flow with staff selection

### Client Portal Setup
- [ ] Run migrations for FavoriteProvider and ClientNotificationPreference
- [ ] Create client dashboard templates
- [ ] Test guest booking → account linking
- [ ] Test cancel/reschedule functionality
- [ ] Test favorite providers feature

### Google Calendar Setup
- [ ] Create Google Cloud project
- [ ] Enable Google Calendar API
- [ ] Create OAuth 2.0 credentials
- [ ] Add credentials to .env file
- [ ] Install Google API libraries
- [ ] Run migrations for GoogleCalendarIntegration
- [ ] Test OAuth flow
- [ ] Test calendar sync

---

## 🧪 Testing

### Test Multi-Staff (PRO Only)

```python
# Test PRO plan check
provider = ServiceProvider.objects.first()
print(provider.can_add_staff())  # Should be False for FREE

# Upgrade to PRO
provider.upgrade_to_pro(duration_months=1)
print(provider.can_add_staff())  # Should be True

# Create staff member
staff = StaffMember.objects.create(
    service_provider=provider,
    name="John Doe",
    phone="+919876543210"
)

# Assign services
service = provider.services.first()
staff.services.add(service)

# Create appointment with staff
appointment = Appointment.objects.create(
    service_provider=provider,
    service=service,
    staff_member=staff,  # Assigned to staff
    # ... other fields
)
```

### Test Client Portal

```python
# Register client
client = CustomUser.objects.create_user(
    email='client@example.com',
    password='password',
    user_type='client'
)

# Book appointment
appointment = Appointment.objects.create(
    service_provider=provider,
    service=service,
    client=client,
    client_name=client.get_full_name(),
    client_email=client.email,
    # ... other fields
)

# Add to favorites
FavoriteProvider.objects.create(
    client=client,
    provider=provider
)

# Test cancel
appointment.cancel()
```

### Test Google Calendar (PRO Only)

```python
# Connect calendar (manual OAuth flow)
# Then test sync:

from utils.google_calendar import sync_appointment_to_calendar

appointment = Appointment.objects.first()
success = sync_appointment_to_calendar(appointment)
print(f"Sync successful: {success}")

# Check event mapping
try:
    event_mapping = appointment.calendar_event
    print(f"Google Event ID: {event_mapping.google_event_id}")
except:
    print("No calendar event found")
```

---

## 📝 Summary

### What's Implemented:

**Multi-Staff (PRO Only):**
- ✅ StaffMember and StaffAvailability models
- ✅ PRO plan checks with decorators
- ✅ Staff management views and forms
- ✅ Updated booking flow with staff selection
- ✅ Maximum 10 staff members per PRO provider
- ✅ FREE plan shows upgrade prompts

**Client Portal:**
- ✅ Client dashboard with appointments
- ✅ Cancel/reschedule functionality
- ✅ Favorite providers feature
- ✅ Notification preferences
- ✅ Guest booking → account linking
- ✅ Mobile-first responsive design

**Google Calendar (PRO Only):**
- ✅ OAuth 2.0 authentication flow
- ✅ One-way sync (App → Google)
- ✅ Automatic event creation/update/deletion
- ✅ Secure token storage and refresh
- ✅ PRO plan checks throughout
- ✅ Error handling and logging

### Next Steps:

1. Run all migrations
2. Create templates for new views
3. Test each feature thoroughly
4. Configure Google Cloud project
5. Update navigation menus
6. Add feature documentation for users

**All features include proper PRO plan checks and upgrade prompts for FREE users!** 🎉
```
