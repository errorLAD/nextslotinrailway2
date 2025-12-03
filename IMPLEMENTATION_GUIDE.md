# 📘 Complete Implementation Guide - Appointment Booking SaaS

## 🎯 Project Overview

This is a **multi-tenant appointment booking SaaS** built with Django 5.0+ featuring a **freemium pricing model**. Service providers can manage their bookings, services, and availability, while clients can book appointments online.

---

## 🏗️ Architecture Overview

### **Multi-Tenancy Model**
- Each service provider has their own isolated data
- Shared database with tenant isolation via ForeignKey relationships
- Each provider gets a unique booking URL: `/book/{unique-slug}/`

### **Freemium Pricing Structure**

#### **FREE Plan (Default)**
- ₹0/month
- 5 appointments per month
- Maximum 3 services
- Basic booking page
- Email notifications only
- "Powered by BookingSaaS" branding
- 14-day PRO trial for new signups

#### **PRO Plan**
- ₹199/month
- Unlimited appointments
- Unlimited services
- Professional salon website
- WhatsApp + Email + SMS notifications
- Remove branding (white-label)
- Google Calendar sync
- Multi-staff support
- Advanced analytics
- Priority support

---

## 📊 Database Schema

### **1. CustomUser Model** (`accounts/models.py`)
```python
Fields:
- email (unique, used for login)
- password
- user_type ('provider' or 'client')
- first_name, last_name
- phone
- is_active, is_staff
- date_joined
```

### **2. ServiceProvider Model** (`providers/models.py`)
```python
Relationships:
- OneToOne with CustomUser

Business Info:
- business_name, business_type
- description
- phone, whatsapp_number
- business_address, city, state, pincode

Subscription Management:
- current_plan ('free' or 'pro')
- plan_start_date, plan_end_date
- trial_end_date, is_trial_active

Usage Tracking:
- appointments_this_month (counter)
- last_reset_date

Configuration:
- unique_booking_url (slug)
- profile_image
- is_verified, is_active

Methods:
- is_pro() - Check if has PRO plan
- is_on_trial() - Check if on trial
- has_pro_features() - PRO or trial
- can_create_appointment() - Check limits
- remaining_appointments() - Get remaining
- increment_appointment_count()
- reset_monthly_counter()
- upgrade_to_pro()
- downgrade_to_free()
```

### **3. Service Model** (`providers/models.py`)
```python
Relationships:
- ForeignKey to ServiceProvider

Fields:
- service_name (e.g., "Haircut")
- description
- duration_minutes (15/30/45/60/90/120/180)
- price (Decimal)
- is_active
```

### **4. Availability Model** (`providers/models.py`)
```python
Relationships:
- ForeignKey to ServiceProvider

Fields:
- day_of_week (0=Monday, 6=Sunday)
- start_time, end_time
- is_available (boolean)
```

### **5. Appointment Model** (`appointments/models.py`)
```python
Relationships:
- ForeignKey to ServiceProvider
- ForeignKey to Service
- ForeignKey to CustomUser (nullable for walk-ins)

Client Info:
- client_name, client_phone, client_email

Appointment Details:
- appointment_date, appointment_time
- status (pending/confirmed/completed/cancelled/no_show)

Payment:
- total_price
- payment_status (pending/paid/refunded)
- payment_method (upi/cash/card/online)

Other:
- notes
- reminder_sent
```

### **6. SubscriptionPlan Model** (`subscriptions/models.py`)
```python
Fields:
- name, plan_type
- price_monthly
- max_appointments_per_month (null = unlimited)
- max_services (null = unlimited)
- features (JSONField)
- is_active, display_order
```

### **7. Payment Model** (`subscriptions/models.py`)
```python
Relationships:
- ForeignKey to ServiceProvider
- ForeignKey to SubscriptionPlan

Fields:
- amount, status
- razorpay_order_id, razorpay_payment_id
- razorpay_signature
- payment_method
```

---

## 🔐 Feature Gating System

### **1. Decorators** (`providers/decorators.py`)

```python
@requires_pro_plan
# Restricts view to PRO users only
# Redirects to upgrade page if FREE

@check_appointment_limit
# Checks if user can create more appointments
# Shows upgrade prompt if limit reached

@check_service_limit
# Checks if user can add more services
# Shows upgrade prompt if limit reached

@provider_required
# Ensures user is a service provider
```

### **2. Middleware** (`providers/middleware.py`)

```python
SubscriptionCheckMiddleware:
- Runs on every request
- Checks trial expiry
- Checks PRO subscription expiry
- Auto-downgrades expired accounts
- Shows one-time notifications
```

### **3. Template Tags** (`providers/templatetags/plan_tags.py`)

```django
{% load plan_tags %}

<!-- Check if PRO -->
{% if user|is_pro %}
  <p>PRO Feature</p>
{% endif %}

<!-- Display plan badge -->
{% plan_badge user %}

<!-- Show usage meter -->
{% usage_meter user %}

<!-- Lock icon for PRO features -->
{% pro_feature_lock "WhatsApp Notifications" %}

<!-- Get remaining appointments -->
{{ user|remaining_appointments }}
```

---

## 🤖 Automation System

### **Management Commands**

#### 1. Create Default Plans
```bash
python manage.py create_default_plans
```
Creates FREE and PRO subscription plans with all features.

#### 2. Reset Monthly Limits
```bash
python manage.py reset_monthly_limits
```
Resets `appointments_this_month` counter for all providers.
**Run on:** 1st of every month at midnight

#### 3. Check Expired Subscriptions
```bash
python manage.py check_expired_subscriptions --send-emails
```
- Checks for expired PRO subscriptions
- Checks for expired trials
- Auto-downgrades to FREE
- Sends email notifications
**Run:** Daily at 1 AM

#### 4. Send Upgrade Reminders
```bash
python manage.py send_upgrade_reminders
```
Sends emails to FREE users who have used 4-5 appointments.
**Run:** Every Monday at 10 AM

### **Celery Tasks** (`subscriptions/tasks.py`)

Automated background tasks:
- `reset_monthly_limits()` - Monthly counter reset
- `check_expired_subscriptions()` - Daily expiry check
- `send_upgrade_reminders()` - Weekly reminders
- `send_appointment_reminders()` - Hourly reminder check

### **Celery Beat Schedule** (`booking_saas/celery.py`)

```python
'reset-monthly-limits': {
    'task': 'subscriptions.tasks.reset_monthly_limits',
    'schedule': crontab(hour=0, minute=0, day_of_month=1),
},
'check-expired-subscriptions': {
    'task': 'subscriptions.tasks.check_expired_subscriptions',
    'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
},
'send-upgrade-reminders': {
    'task': 'subscriptions.tasks.send_upgrade_reminders',
    'schedule': crontab(hour=10, minute=0, day_of_week='monday'),
},
```

---

## 🔄 User Flows

### **Provider Registration Flow**
1. Visit `/accounts/register/`
2. Choose "Service Provider"
3. Fill registration form
4. Auto-login after registration
5. Redirect to profile setup
6. **14-day PRO trial starts automatically**
7. Complete business profile
8. Add services (up to 3 on FREE, unlimited on trial)
9. Set availability schedule
10. Share booking URL with clients

### **Client Booking Flow**
1. Visit `/book/{provider-slug}/`
2. Browse available services
3. Select service, date, time
4. Enter contact details
5. Submit booking
6. Receive confirmation
7. Get email reminder 24 hours before

### **Upgrade to PRO Flow**
1. Hit appointment limit (5/month)
2. See upgrade prompt modal
3. Click "Upgrade to PRO"
4. Review PRO features
5. Click "Pay ₹199"
6. Razorpay payment gateway
7. Payment verification
8. Instant PRO activation
9. Unlimited features unlocked

### **Trial Expiry Flow**
1. 14 days after signup
2. Middleware detects expiry
3. `is_trial_active` set to False
4. Show notification: "Trial ended"
5. Downgrade to FREE limits
6. Prompt to upgrade to PRO

---

## 💳 Payment Integration (Razorpay)

### **Setup**
1. Get Razorpay API keys from dashboard
2. Add to `.env`:
```
RAZORPAY_KEY_ID=rzp_test_xxxxx
RAZORPAY_KEY_SECRET=xxxxx
```

### **Payment Flow**
1. User clicks "Upgrade to PRO"
2. Frontend calls `/pricing/payment/create-order/`
3. Backend creates Razorpay order
4. Returns order_id to frontend
5. Razorpay checkout modal opens
6. User completes payment
7. Razorpay sends payment_id and signature
8. Frontend calls `/pricing/payment/verify/`
9. Backend verifies signature
10. If valid: upgrade to PRO
11. Redirect to success page

### **Security**
- Payment signature verification using HMAC-SHA256
- Server-side validation
- Payment records stored in database
- Failed payments logged

---

## 📧 Email Notifications

### **Automated Emails**

1. **Welcome Email** - On registration
2. **Trial Ending Soon** - 2 days before trial ends
3. **Trial Expired** - When trial ends
4. **Appointment Reminder** - 24 hours before
5. **Limit Warning** - When 4/5 appointments used
6. **Limit Reached** - When 5/5 appointments used
7. **PRO Expired** - When subscription ends
8. **Payment Success** - After upgrade

### **Email Configuration** (`.env`)
```
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

---

## 🎨 Frontend Structure (Templates)

```
templates/
├── base.html                          # Base template
├── accounts/
│   ├── login.html
│   ├── register_choice.html
│   ├── register_provider.html
│   └── register_client.html
├── providers/
│   ├── dashboard.html                 # Main dashboard
│   ├── setup_profile.html
│   ├── edit_profile.html
│   ├── service_list.html
│   ├── add_service.html
│   ├── manage_availability.html
│   ├── appointment_list.html
│   ├── create_appointment.html
│   └── includes/
│       ├── usage_meter.html           # Usage progress bar
│       └── pro_feature_lock.html      # Lock icon
├── appointments/
│   ├── public_booking.html            # Public booking page
│   ├── booking_success.html
│   ├── my_appointments.html
│   └── browse_providers.html
└── subscriptions/
    ├── pricing.html                   # Pricing comparison
    ├── compare_plans.html
    ├── upgrade_prompt.html            # Limit reached modal
    ├── upgrade_to_pro.html            # Payment page
    ├── upgrade_success.html
    └── downgrade_confirm.html
```

---

## 🚀 Deployment Checklist

### **Before Production**

1. **Environment Variables**
```bash
DEBUG=False
SECRET_KEY=<generate-strong-key>
ALLOWED_HOSTS=yourdomain.com
```

2. **Database Migration to PostgreSQL**
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'booking_saas_db',
        'USER': 'postgres',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

3. **Static Files**
```bash
python manage.py collectstatic
```

4. **Set up Celery with Redis**
```bash
# Install Redis
# Start Celery worker
celery -A booking_saas worker -l info

# Start Celery Beat
celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

5. **Set up Cron Jobs** (Alternative to Celery)
```cron
# Reset monthly limits (1st of month)
0 0 1 * * cd /path/to/project && python manage.py reset_monthly_limits

# Check expired subscriptions (daily)
0 1 * * * cd /path/to/project && python manage.py check_expired_subscriptions --send-emails

# Send upgrade reminders (weekly)
0 10 * * 1 cd /path/to/project && python manage.py send_upgrade_reminders
```

6. **Configure Email**
- Use real SMTP server (Gmail, SendGrid, AWS SES)
- Set up proper email templates

7. **Razorpay Production Keys**
- Switch from test to live keys
- Set up webhooks for payment notifications

---

## 🧪 Testing Guide

### **Test User Accounts**

```bash
# Create superuser
python manage.py createsuperuser

# Create test provider (FREE plan)
# Create test provider (PRO plan)
# Create test client
```

### **Test Scenarios**

1. **FREE Plan Limits**
   - Create 5 appointments → Should succeed
   - Try 6th appointment → Should show upgrade prompt
   - Add 3 services → Should succeed
   - Try 4th service → Should show upgrade prompt

2. **Trial Period**
   - New provider gets 14-day trial
   - Has PRO features during trial
   - After 14 days, auto-downgrade to FREE

3. **PRO Upgrade**
   - Click upgrade button
   - Complete payment
   - Verify instant feature unlock
   - Check unlimited appointments

4. **Monthly Reset**
   - Run `reset_monthly_limits` command
   - Verify counters reset to 0
   - Verify date updated

5. **Public Booking**
   - Visit `/book/{slug}/`
   - Book appointment as guest
   - Verify email confirmation

---

## 🐛 Common Issues & Solutions

### **Issue: Migrations fail**
```bash
# Delete all migrations except __init__.py
# Delete db.sqlite3
python manage.py makemigrations
python manage.py migrate
```

### **Issue: Static files not loading**
```bash
python manage.py collectstatic --clear
```

### **Issue: Celery tasks not running**
```bash
# Check Redis is running
redis-cli ping

# Check Celery worker is running
celery -A booking_saas worker -l info

# Check Celery Beat is running
celery -A booking_saas beat -l info
```

### **Issue: Emails not sending**
```python
# Test email configuration
python manage.py shell
>>> from django.core.mail import send_mail
>>> send_mail('Test', 'Message', 'from@example.com', ['to@example.com'])
```

---

## 📈 Future Enhancements

1. **WhatsApp Integration** (PRO feature)
   - Twilio API for WhatsApp notifications
   - Appointment reminders via WhatsApp

2. **SMS Notifications** (PRO feature)
   - Twilio SMS for reminders

3. **Google Calendar Sync** (PRO feature)
   - OAuth integration
   - Two-way sync

4. **Multi-Staff Support** (PRO feature)
   - Add team members
   - Staff-specific schedules

5. **Analytics Dashboard** (PRO feature)
   - Revenue tracking
   - Popular services
   - Peak booking times

6. **Custom Booking URL** (PRO feature)
   - Custom domain support
   - White-label branding

7. **Recurring Appointments**
   - Weekly/monthly bookings
   - Subscription-based services

8. **Cancellation Policy**
   - Configurable cancellation rules
   - Automatic refunds

---

## 📞 Support

For issues or questions:
- Check documentation first
- Review error logs
- Test in development environment
- Contact support team

---

## 📝 License

This project is proprietary software for BookingSaaS.

---

**Built with ❤️ using Django 5.0+**
