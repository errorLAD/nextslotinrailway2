# Email & SMS Notifications Setup Guide

Complete guide for setting up email and SMS notifications with plan-based feature gating.

## 📧 Email Notifications (FREE & PRO Plans)

### Gmail SMTP Setup (Development)

1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate App Password**:
   - Go to Google Account Settings → Security
   - Under "Signing in to Google", select "App passwords"
   - Generate a new app password for "Mail"
   - Copy the 16-character password

3. **Update `.env` file**:
```bash
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-16-char-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com
```

4. **Test Email Configuration**:
```bash
python manage.py shell
```
```python
from django.core.mail import send_mail
send_mail(
    'Test Email',
    'This is a test email from BookingSaaS.',
    'your-email@gmail.com',
    ['recipient@example.com'],
    fail_silently=False,
)
```

### Production Email Setup

#### Option 1: SendGrid (Recommended)
```bash
pip install sendgrid
```

Update `.env`:
```bash
EMAIL_BACKEND=sendgrid_backend.SendgridBackend
SENDGRID_API_KEY=your_sendgrid_api_key
```

#### Option 2: AWS SES
```bash
pip install django-ses
```

Update `settings.py`:
```python
EMAIL_BACKEND = 'django_ses.SESBackend'
AWS_SES_REGION_NAME = 'us-east-1'
AWS_SES_REGION_ENDPOINT = 'email.us-east-1.amazonaws.com'
```

## 📱 SMS Notifications (PRO Plan ONLY)

### Twilio Setup

1. **Create Twilio Account**:
   - Sign up at https://www.twilio.com
   - Get a phone number (trial or paid)
   - Copy Account SID and Auth Token

2. **Install Twilio SDK**:
```bash
pip install twilio
```

3. **Update `.env` file**:
```bash
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+1234567890
```

4. **Test SMS Configuration**:
```bash
python manage.py shell
```
```python
from utils.sms_utils import send_sms
send_sms('+919876543210', 'Test SMS from BookingSaaS')
```

### Important Notes:
- SMS is **PRO PLAN ONLY** - automatically checked via `provider.is_pro()`
- FREE plan users will only receive email notifications
- SMS functions return `False` if provider is not on PRO plan

## 🔄 Celery Setup (Async Notifications)

### Install Redis (Required for Celery)

**Windows:**
1. Download Redis from https://github.com/microsoftarchive/redis/releases
2. Extract and run `redis-server.exe`

**Linux/Mac:**
```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# Mac
brew install redis
brew services start redis
```

### Install Celery
```bash
pip install celery redis django-celery-beat
```

### Start Celery Worker
```bash
# In a separate terminal
celery -A booking_saas worker -l info
```

### Start Celery Beat (Scheduled Tasks)
```bash
# In another separate terminal
celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

### Configure Periodic Tasks

Run Django shell:
```bash
python manage.py shell
```

```python
from django_celery_beat.models import PeriodicTask, IntervalSchedule

# Create schedule for daily reminders (runs every day at 9 AM)
schedule, _ = IntervalSchedule.objects.get_or_create(
    every=1,
    period=IntervalSchedule.DAYS,
)

PeriodicTask.objects.create(
    interval=schedule,
    name='Send Daily Appointment Reminders',
    task='utils.tasks.send_daily_appointment_reminders',
)

# Create schedule for monthly counter reset (runs on 1st of each month)
PeriodicTask.objects.create(
    interval=schedule,
    name='Reset Monthly Appointment Counters',
    task='utils.tasks.reset_monthly_appointment_counters',
)

# Create schedule for subscription expiry reminders
PeriodicTask.objects.create(
    interval=schedule,
    name='Send Subscription Expiry Reminders',
    task='utils.tasks.send_subscription_expiry_reminders',
)
```

## 📬 Email Types

### 1. Welcome Email (FREE & PRO)
- Sent after user registration
- Includes plan information
- Upgrade prompt for FREE users

**Usage:**
```python
from utils.email_utils import send_welcome_email
send_welcome_email(user)
```

### 2. Appointment Confirmation (FREE & PRO)
- Sent to both client and provider
- Includes appointment details
- SMS also sent if PRO plan

**Usage:**
```python
from utils.tasks import send_appointment_confirmation_task

# Send to client with SMS if PRO
send_appointment_confirmation_task.delay(
    appointment.id, 
    to_provider=False, 
    send_sms=provider.is_pro()
)

# Send to provider (email only)
send_appointment_confirmation_task.delay(
    appointment.id, 
    to_provider=True, 
    send_sms=False
)
```

### 3. Appointment Reminder (FREE & PRO)
- Sent 24 hours before appointment
- Automated via Celery Beat
- SMS also sent if PRO plan

**Automatic:** Celery Beat task runs daily

### 4. Appointment Cancelled (FREE & PRO)
- Sent when appointment is cancelled
- Sent to both client and provider

**Usage:**
```python
from utils.tasks import send_appointment_cancelled_task

send_appointment_cancelled_task.delay(
    appointment.id,
    cancelled_by='provider',  # or 'client'
    send_sms=provider.is_pro()
)
```

### 5. Subscription Expiry Reminder (PRO only)
- Sent 3 days before PRO plan expires
- Automated via Celery Beat

**Automatic:** Celery Beat task runs daily

### 6. Payment Receipt (PRO only)
- Sent after successful payment
- Includes transaction details

**Usage:**
```python
from utils.email_utils import send_payment_receipt_email
send_payment_receipt_email(subscription_payment)
```

## 🎨 Email Template Customization

Email templates are located in `templates/emails/`:
- `base_email.html` - Base template with styling
- `welcome.html` - Welcome email
- `appointment_confirmation_client.html` - Client confirmation
- `appointment_confirmation_provider.html` - Provider confirmation
- `appointment_reminder.html` - 24-hour reminder
- `appointment_cancelled_client.html` - Cancellation for client
- `appointment_cancelled_provider.html` - Cancellation for provider
- `appointment_rescheduled.html` - Rescheduling notification
- `subscription_expiry_reminder.html` - PRO plan expiry
- `payment_receipt.html` - Payment receipt

### Customization Tips:
1. Edit `base_email.html` to change overall design
2. Update colors in the `<style>` section
3. Add your business logo
4. Modify footer links and social media

## 🔒 Feature Gating (PRO vs FREE)

### Email Notifications
- ✅ Available for both FREE and PRO plans
- No restrictions

### SMS Notifications
- ❌ FREE plan: Not available
- ✅ PRO plan: Fully available
- Automatically checked via `provider.is_pro()`

**Example:**
```python
# SMS is automatically gated in the utility functions
from utils.sms_utils import send_appointment_confirmation_sms

# This will only send if provider.is_pro() returns True
result = send_appointment_confirmation_sms(appointment)
```

## 🧪 Testing Notifications

### Test Email
```bash
python manage.py shell
```
```python
from accounts.models import CustomUser
from utils.email_utils import send_welcome_email

user = CustomUser.objects.first()
send_welcome_email(user)
```

### Test SMS (PRO plan required)
```python
from providers.models import ServiceProvider
from appointments.models import Appointment
from utils.sms_utils import send_appointment_confirmation_sms

# Make sure provider is on PRO plan
provider = ServiceProvider.objects.first()
provider.upgrade_to_pro(duration_months=1)

appointment = Appointment.objects.first()
send_appointment_confirmation_sms(appointment)
```

### Test Celery Task
```python
from utils.tasks import send_welcome_email_task

user_id = 1
send_welcome_email_task.delay(user_id)
```

## 📊 Monitoring

### Check Celery Task Status
```bash
# View worker logs
celery -A booking_saas worker -l info

# View beat scheduler logs
celery -A booking_saas beat -l info
```

### Check Email Logs
```bash
# In Django shell
import logging
logger = logging.getLogger('django')
```

### Check SMS Logs
- Login to Twilio Console
- View SMS logs and delivery status

## 🚨 Troubleshooting

### Email Not Sending
1. Check Gmail app password is correct
2. Verify 2FA is enabled
3. Check `EMAIL_BACKEND` setting
4. Test with Django shell

### SMS Not Sending
1. Verify Twilio credentials
2. Check phone number format (+country code)
3. Ensure provider is on PRO plan
4. Check Twilio account balance

### Celery Not Working
1. Ensure Redis is running
2. Check Celery worker is started
3. Verify task is registered
4. Check for errors in worker logs

## 🔐 Security Best Practices

1. **Never commit `.env` file** - Add to `.gitignore`
2. **Use app passwords** - Never use main Gmail password
3. **Rotate credentials** - Change passwords regularly
4. **Monitor usage** - Check Twilio and email service usage
5. **Rate limiting** - Implement rate limits for notifications

## 📝 Production Checklist

- [ ] Switch to production email service (SendGrid/AWS SES)
- [ ] Configure proper domain for emails
- [ ] Set up email authentication (SPF, DKIM, DMARC)
- [ ] Configure Celery with supervisor/systemd
- [ ] Set up Redis persistence
- [ ] Monitor email delivery rates
- [ ] Monitor SMS costs and usage
- [ ] Set up error alerting
- [ ] Configure logging
- [ ] Test all notification types

## 💡 Tips

1. **Email Design**: Keep emails mobile-responsive
2. **SMS Length**: Keep SMS under 160 characters to avoid splitting
3. **Timing**: Send reminders at appropriate times (not too early/late)
4. **Unsubscribe**: Always include unsubscribe option in emails
5. **Testing**: Test with real phone numbers before production
6. **Costs**: Monitor SMS costs - they add up quickly
7. **Fallback**: Always have email as fallback if SMS fails
