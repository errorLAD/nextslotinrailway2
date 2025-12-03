# 🚀 Quick Reference Card

## 📧 Send Email Notifications

```python
# Welcome email
from utils.email_utils import send_welcome_email
send_welcome_email(user)

# Appointment confirmation
from utils.email_utils import send_appointment_confirmation_email
send_appointment_confirmation_email(appointment, to_provider=False)  # to client
send_appointment_confirmation_email(appointment, to_provider=True)   # to provider

# Reminder
from utils.email_utils import send_appointment_reminder_email
send_appointment_reminder_email(appointment)

# Cancellation
from utils.email_utils import send_appointment_cancelled_email
send_appointment_cancelled_email(appointment, cancelled_by='provider')
```

## 📱 Send SMS (PRO Plan Only)

```python
# Appointment confirmation SMS
from utils.sms_utils import send_appointment_confirmation_sms
send_appointment_confirmation_sms(appointment)  # Auto-checks PRO plan

# Reminder SMS
from utils.sms_utils import send_appointment_reminder_sms
send_appointment_reminder_sms(appointment)  # Auto-checks PRO plan

# Cancellation SMS
from utils.sms_utils import send_appointment_cancelled_sms
send_appointment_cancelled_sms(appointment)  # Auto-checks PRO plan
```

## 🔄 Queue Async Tasks

```python
from utils.tasks import *

# Welcome email (async)
send_welcome_email_task.delay(user_id)

# Appointment confirmation (async with SMS option)
send_appointment_confirmation_task.delay(
    appointment_id, 
    to_provider=False, 
    send_sms=provider.is_pro()
)

# Reminder (async with SMS option)
send_appointment_reminder_task.delay(appointment_id, send_sms=provider.is_pro())

# Cancellation (async with SMS option)
send_appointment_cancelled_task.delay(
    appointment_id, 
    cancelled_by='provider',
    send_sms=provider.is_pro()
)
```

## 🔒 Check PRO Plan

```python
# Check if provider has PRO plan
provider = ServiceProvider.objects.get(id=1)
if provider.is_pro():
    # PRO features available
    send_sms(...)
else:
    # FREE plan - show upgrade prompt
    pass

# Check in template
{% if provider.is_pro %}
    <!-- PRO features -->
{% else %}
    <!-- FREE features + upgrade prompt -->
{% endif %}
```

## 🎛️ Admin Panel Quick Actions

### Appointments
1. Select appointments
2. Actions dropdown:
   - "Confirm and notify" - Sends email + SMS (if PRO)
   - "Cancel and notify" - Sends cancellation notifications
   - "Mark as Completed"
   - "Mark as No-Show"
   - "Mark as Paid"
   - "Send reminder notifications"

### Providers
1. Select providers
2. Actions dropdown:
   - "Activate/Deactivate selected providers"
   - "Verify selected providers"
   - "Upgrade to PRO (1 month)"
   - "Reset appointment counter (FREE plan)"

### Payments
1. Select payments
2. Actions dropdown:
   - "Mark as Successful"
   - "Mark as Failed"
   - "Send payment receipt"

## 📊 Analytics URLs

```
# Analytics dashboard
/providers/analytics/

# CSV export (PRO only)
/providers/analytics/export/

# API endpoint (PRO only)
/providers/analytics/api/?type=appointments_trend&days=30
/providers/analytics/api/?type=revenue_trend&days=180
```

## 🚀 Start Services

```bash
# Start Redis
redis-server  # or redis-server.exe on Windows

# Start Celery Worker (Terminal 1)
celery -A booking_saas worker -l info

# Start Celery Beat (Terminal 2)
celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

# Start Django (Terminal 3)
python manage.py runserver
```

## 🧪 Test Commands

```bash
# Django shell
python manage.py shell

# Test email
>>> from utils.email_utils import send_welcome_email
>>> from accounts.models import CustomUser
>>> user = CustomUser.objects.first()
>>> send_welcome_email(user)

# Test SMS (PRO required)
>>> from utils.sms_utils import send_sms
>>> send_sms('+919876543210', 'Test message')

# Upgrade provider to PRO
>>> from providers.models import ServiceProvider
>>> provider = ServiceProvider.objects.first()
>>> provider.upgrade_to_pro(duration_months=1)
>>> provider.is_pro()  # Should return True
```

## 📝 Environment Variables

```bash
# Email (Gmail)
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-16-char-app-password

# SMS (Twilio - PRO only)
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+1234567890

# Celery (Redis)
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

## 🎨 Email Templates Location

```
templates/emails/
├── base_email.html                          # Base template
├── welcome.html                             # Welcome email
├── appointment_confirmation_client.html     # Client confirmation
├── appointment_confirmation_provider.html   # Provider confirmation
├── appointment_reminder.html                # 24h reminder
├── appointment_cancelled_client.html        # Cancellation (client)
├── appointment_cancelled_provider.html      # Cancellation (provider)
├── appointment_rescheduled.html            # Rescheduling
├── subscription_expiry_reminder.html       # PRO expiry
└── payment_receipt.html                    # Payment receipt
```

## 🔐 Feature Gating Checklist

### Email Notifications
- [x] FREE Plan: ✅ Available
- [x] PRO Plan: ✅ Available

### SMS Notifications
- [x] FREE Plan: ❌ Not available
- [x] PRO Plan: ✅ Available
- [x] Check: `provider.is_pro()` in all SMS functions

### Analytics
- [x] FREE Plan: ✅ Basic stats, 🔒 Locked charts
- [x] PRO Plan: ✅ Full analytics with charts
- [x] Check: `is_pro` in views and templates

### CSV Export
- [x] FREE Plan: ❌ Not available (403)
- [x] PRO Plan: ✅ Available
- [x] Check: `provider.is_pro()` in export view

## 📞 Common Issues

### Email not sending
```bash
# Check settings
python manage.py shell
>>> from django.conf import settings
>>> print(settings.EMAIL_HOST_USER)
>>> print(settings.EMAIL_HOST_PASSWORD)

# Test email
>>> from django.core.mail import send_mail
>>> send_mail('Test', 'Test message', settings.EMAIL_HOST_USER, ['test@example.com'])
```

### SMS not sending
```bash
# Check Twilio config
>>> from django.conf import settings
>>> print(settings.TWILIO_ACCOUNT_SID)
>>> print(settings.TWILIO_AUTH_TOKEN)

# Check provider plan
>>> provider.is_pro()  # Must be True for SMS
```

### Celery not working
```bash
# Check Redis is running
redis-cli ping  # Should return PONG

# Check Celery worker logs
# Look for errors in terminal where worker is running

# Check task is registered
celery -A booking_saas inspect registered
```

## 💡 Pro Tips

1. **Always use async tasks** for notifications (better performance)
2. **Check plan before SMS** - it's automatically done in utils
3. **Monitor SMS costs** - they add up quickly
4. **Use admin actions** for bulk operations
5. **Cache analytics queries** for better performance
6. **Show upgrade prompts** to FREE users
7. **Test with real data** before production

## 📚 Documentation Files

- `NOTIFICATIONS_SETUP.md` - Complete email/SMS setup
- `ADMIN_ANALYTICS_GUIDE.md` - Admin panel and analytics guide
- `NOTIFICATIONS_ADMIN_ANALYTICS_COMPLETE.md` - Implementation summary
- `QUICK_REFERENCE.md` - This file

---

**Need help?** Check the full documentation files above! 🚀
