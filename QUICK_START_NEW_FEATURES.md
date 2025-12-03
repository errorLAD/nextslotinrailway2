# 🚀 Quick Start - New Features

## 📦 Installation

```bash
# Install new dependencies
pip install -r requirements.txt

# Run migrations
python manage.py makemigrations providers appointments accounts
python manage.py migrate
```

## 👥 Multi-Staff (PRO Only)

### Add Staff Member
```python
# In Django shell or view
from providers.models import ServiceProvider
from providers.models_staff import StaffMember

provider = ServiceProvider.objects.get(id=1)

# Check if can add staff (PRO only)
if provider.can_add_staff():
    staff = StaffMember.objects.create(
        service_provider=provider,
        name="John Doe",
        phone="+919876543210",
        email="john@example.com"
    )
    
    # Assign services
    service = provider.services.first()
    staff.services.add(service)
```

### URLs
```
/providers/staff/                    # List staff (PRO only)
/providers/staff/add/                # Add staff (PRO only)
/providers/staff/<id>/               # Staff details (PRO only)
/providers/staff/<id>/edit/          # Edit staff (PRO only)
/providers/staff/<id>/availability/  # Manage availability (PRO only)
```

### Check PRO Plan
```python
# In views
if not provider.is_pro():
    return redirect('subscriptions:upgrade')

# In templates
{% if provider.is_pro %}
    <!-- Show staff management -->
{% else %}
    <a href="{% url 'subscriptions:upgrade' %}">🔒 Upgrade for Team Management</a>
{% endif %}
```

## 👤 Client Portal

### Access Client Dashboard
```
/accounts/client/dashboard/          # Client dashboard
/accounts/client/appointments/<id>/  # Appointment details
/accounts/client/favorites/          # Favorite providers
/accounts/client/preferences/        # Notification preferences
```

### Cancel Appointment
```python
# In view or shell
appointment = Appointment.objects.get(id=1)

if appointment.can_cancel():
    appointment.cancel()
    
    # Send notifications
    from utils.tasks import send_appointment_cancelled_task
    send_appointment_cancelled_task.delay(
        appointment.id,
        cancelled_by='client',
        send_sms=appointment.service_provider.is_pro()
    )
```

### Add to Favorites
```python
from accounts.models_client import FavoriteProvider

FavoriteProvider.objects.create(
    client=user,
    provider=provider
)
```

## 📅 Google Calendar (PRO Only)

### Setup Google API

1. **Create Google Cloud Project:**
   - Go to https://console.cloud.google.com/
   - Create new project
   - Enable Google Calendar API

2. **Create OAuth Credentials:**
   - APIs & Services → Credentials
   - Create OAuth client ID
   - Type: Web application
   - Authorized redirect URIs:
     ```
     http://localhost:8000/providers/calendar/callback/
     https://yourdomain.com/providers/calendar/callback/
     ```

3. **Add to .env:**
   ```bash
   GOOGLE_CLIENT_ID=your_id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_secret
   ```

### Connect Calendar (PRO Only)
```
/providers/calendar/settings/     # Calendar settings
/providers/calendar/connect/      # Start OAuth (PRO only)
/providers/calendar/disconnect/   # Disconnect (PRO only)
```

### Sync Appointment
```python
# Automatic sync on save (if PRO)
appointment = Appointment.objects.create(
    service_provider=provider,
    service=service,
    # ... other fields
)
# Automatically syncs to Google Calendar if provider.is_pro()

# Manual sync
from utils.google_calendar import sync_appointment_to_calendar
sync_appointment_to_calendar(appointment)
```

### Check Calendar Status
```python
# Check if connected
try:
    calendar = provider.google_calendar
    print(f"Connected: {calendar.is_active}")
    print(f"Last sync: {calendar.last_sync}")
except:
    print("Not connected")
```

## 🔒 Feature Gating Examples

### In Views
```python
from providers.views_staff import require_pro_plan

@login_required
@require_pro_plan
def my_pro_feature(request):
    # Only accessible to PRO users
    pass
```

### In Templates
```html
<!-- Staff Management -->
{% if provider.is_pro %}
    <a href="{% url 'providers:staff_list' %}">👥 Manage Team</a>
{% else %}
    <div class="locked-feature">
        🔒 Team Management (PRO Only)
        <a href="{% url 'subscriptions:upgrade' %}">Upgrade</a>
    </div>
{% endif %}

<!-- Google Calendar -->
{% if provider.is_pro %}
    {% if calendar_integration %}
        ✅ Calendar Connected
    {% else %}
        <a href="{% url 'providers:connect_google_calendar' %}">Connect Calendar</a>
    {% endif %}
{% else %}
    🔒 Google Calendar Sync (PRO Only)
{% endif %}
```

### In Models
```python
# Check before operation
if provider.can_add_staff():
    # Add staff
else:
    # Show upgrade prompt
```

## 🧪 Testing

### Test Multi-Staff
```python
# Upgrade to PRO
provider.upgrade_to_pro(duration_months=1)

# Add staff
staff = StaffMember.objects.create(
    service_provider=provider,
    name="Test Staff",
    phone="+919876543210"
)

# Assign to service
staff.services.add(service)

# Book with staff
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
    email='client@test.com',
    password='password',
    user_type='client'
)

# Add favorite
FavoriteProvider.objects.create(
    client=client,
    provider=provider
)

# Cancel appointment
appointment.cancel()
```

### Test Google Calendar
```python
# After connecting via OAuth flow
from utils.google_calendar import sync_appointment_to_calendar

appointment = Appointment.objects.first()
success = sync_appointment_to_calendar(appointment)

# Check event mapping
event_mapping = appointment.calendar_event
print(f"Google Event ID: {event_mapping.google_event_id}")
```

## 📊 Database Queries

### Get Staff for Service
```python
# Get staff who can provide a service
staff_members = service.staff_members.filter(is_active=True)
```

### Get Staff Appointments
```python
# Get appointments for specific staff
appointments = Appointment.objects.filter(
    staff_member=staff,
    status__in=['pending', 'confirmed']
).order_by('appointment_date', 'appointment_time')
```

### Get Client Appointments
```python
# Get all appointments for a client
appointments = Appointment.objects.filter(
    Q(client=user) | Q(client_email=user.email)
).select_related('service_provider', 'service', 'staff_member')
```

### Get Favorite Providers
```python
# Get client's favorites
favorites = FavoriteProvider.objects.filter(
    client=user
).select_related('provider')
```

## 🎯 Common Tasks

### Upgrade Provider to PRO
```python
provider.upgrade_to_pro(duration_months=1)
print(provider.is_pro())  # True
```

### Check Staff Limit
```python
print(f"Staff count: {provider.get_staff_count()}/10")
print(f"Can add more: {provider.can_add_staff()}")
```

### Link Guest Bookings
```python
# After user registers
Appointment.objects.filter(
    client_email=user.email,
    client__isnull=True
).update(client=user)
```

### Toggle Calendar Sync
```python
calendar = provider.google_calendar
calendar.sync_enabled = not calendar.sync_enabled
calendar.save()
```

## 📝 URLs Summary

### Staff Management (PRO Only)
```
GET  /providers/staff/                    # List
GET  /providers/staff/add/                # Create form
POST /providers/staff/add/                # Create
GET  /providers/staff/<id>/               # Detail
GET  /providers/staff/<id>/edit/          # Edit form
POST /providers/staff/<id>/edit/          # Update
POST /providers/staff/<id>/delete/        # Delete
GET  /providers/staff/<id>/availability/  # Availability form
POST /providers/staff/<id>/availability/  # Update availability
```

### Client Portal
```
GET  /accounts/client/dashboard/                  # Dashboard
GET  /accounts/client/appointments/<id>/          # Detail
POST /accounts/client/appointments/<id>/cancel/   # Cancel
GET  /accounts/client/appointments/<id>/reschedule/ # Reschedule form
POST /accounts/client/appointments/<id>/reschedule/ # Reschedule
GET  /accounts/client/favorites/                  # List favorites
POST /accounts/client/favorites/add/<id>/         # Add favorite
POST /accounts/client/favorites/remove/<id>/      # Remove favorite
GET  /accounts/client/preferences/                # Preferences form
POST /accounts/client/preferences/                # Update preferences
```

### Google Calendar (PRO Only)
```
GET  /providers/calendar/settings/     # Settings page
GET  /providers/calendar/connect/      # Start OAuth
GET  /providers/calendar/callback/     # OAuth callback
POST /providers/calendar/disconnect/   # Disconnect
POST /providers/calendar/toggle/       # Toggle sync
```

## 🔐 Security Notes

1. **Always check PRO plan** before PRO features
2. **Encrypt refresh tokens** before storing
3. **Validate user access** to appointments
4. **Use HTTPS** for OAuth redirects in production
5. **Rate limit** API calls
6. **Log all operations** for debugging

## 💡 Tips

1. **Staff Management**: Assign staff to specific services for better organization
2. **Client Portal**: Encourage clients to register for better experience
3. **Google Calendar**: Test OAuth flow in development before production
4. **Feature Gating**: Always show upgrade prompts to FREE users
5. **Testing**: Test all features with both FREE and PRO accounts

## 📚 Documentation

- `MULTI_STAFF_CLIENT_CALENDAR_GUIDE.md` - Complete guide (500+ lines)
- `IMPLEMENTATION_SUMMARY.md` - Implementation details
- `QUICK_START_NEW_FEATURES.md` - This file

---

**Need help?** Check the comprehensive guide or implementation summary! 🚀
