# ⚡ Quick Start Guide - 5 Minutes to Running App

## 🚀 Fast Setup (Copy & Paste)

### Step 1: Create Virtual Environment & Install Dependencies
```bash
# Navigate to project directory
cd d:\appoitment-boking\windserf\part1

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
```

### Step 2: Create Environment File
```bash
# Copy example env file
copy .env.example .env

# Or create manually with these contents:
```

Create `.env` file:
```env
SECRET_KEY=django-insecure-dev-key-change-in-production-12345
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

DB_ENGINE=django.db.backends.sqlite3
DB_NAME=db.sqlite3

EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend

RAZORPAY_KEY_ID=
RAZORPAY_KEY_SECRET=

CELERY_BROKER_URL=redis://localhost:6379/0
SITE_NAME=BookingSaaS
SITE_URL=http://localhost:8000
```

### Step 3: Run Migrations
```bash
# Create all database tables
python manage.py makemigrations
python manage.py migrate
```

### Step 4: Create Default Subscription Plans
```bash
python manage.py create_default_plans
```

### Step 5: Create Admin User
```bash
python manage.py createsuperuser
# Enter email: admin@example.com
# Enter password: (your password)
```

### Step 6: Run Development Server
```bash
python manage.py runserver
```

**🎉 Done! Visit:** http://127.0.0.1:8000

---

## 🧪 Test the Application

### 1. Access Admin Panel
- URL: http://127.0.0.1:8000/admin
- Login with superuser credentials
- Explore models: Users, Providers, Services, Appointments

### 2. Register as Service Provider
- URL: http://127.0.0.1:8000/accounts/register/
- Choose "Service Provider"
- Fill in details
- **You get 14-day PRO trial automatically!**

### 3. Set Up Your Business
- Complete business profile
- Add services (e.g., "Haircut - ₹300")
- Set weekly availability

### 4. Get Your Booking URL
- Dashboard shows: `Your booking page: /book/your-business-name/`
- Share this with clients

### 5. Test Public Booking
- Open: http://127.0.0.1:8000/book/your-business-name/
- Book an appointment as a client
- Check dashboard for new booking

### 6. Test FREE Plan Limits
- Create 5 appointments (manual or via booking page)
- Try to create 6th → Should show upgrade prompt
- Add 3 services
- Try 4th service → Should show upgrade prompt

---

## 📋 What You Get Out of the Box

### ✅ User Authentication
- Email-based login (no username)
- Separate provider & client accounts
- Password reset (email)

### ✅ Service Provider Features
- Business profile with image
- Service management (add/edit/delete)
- Weekly availability schedule
- Appointment management
- Dashboard with statistics

### ✅ Client Features
- Browse service providers
- Public booking page
- View appointment history
- Email confirmations

### ✅ Freemium System
- FREE Plan: 5 bookings/month, 3 services
- PRO Plan: Unlimited everything
- 14-day trial for new providers
- Automatic limit enforcement
- Upgrade prompts when limits hit

### ✅ Payment Integration (Razorpay)
- One-click upgrade to PRO
- Secure payment verification
- Payment history tracking

### ✅ Automation (Management Commands)
- Monthly limit reset
- Trial expiry checking
- Upgrade reminder emails
- Appointment reminders

---

## 🎯 Common Tasks

### Create Test Data
```bash
# Via Django shell
python manage.py shell

from accounts.models import CustomUser
from providers.models import ServiceProvider, Service

# Create test provider
user = CustomUser.objects.create_user(
    email='test@salon.com',
    password='test123',
    user_type='provider'
)

provider = ServiceProvider.objects.create(
    user=user,
    business_name='Test Salon',
    business_type='salon',
    phone='9876543210',
    city='Mumbai'
)

# Add service
Service.objects.create(
    service_provider=provider,
    service_name='Haircut',
    price=300,
    duration_minutes=30
)
```

### Reset Monthly Limits (Testing)
```bash
python manage.py reset_monthly_limits
```

### Check Expired Trials
```bash
python manage.py check_expired_subscriptions --send-emails
```

### Send Upgrade Reminders
```bash
python manage.py send_upgrade_reminders
```

---

## 🔧 Optional: Set Up Celery (Background Tasks)

### Install Redis (Windows)
1. Download Redis for Windows
2. Or use Docker: `docker run -d -p 6379:6379 redis`

### Run Celery Worker
```bash
# Terminal 1: Celery Worker
celery -A booking_saas worker -l info

# Terminal 2: Celery Beat (Scheduler)
celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

# Terminal 3: Django Server
python manage.py runserver
```

---

## 📱 Key URLs

| Page | URL | Description |
|------|-----|-------------|
| Home | `/` | Redirects to login |
| Login | `/accounts/login/` | User login |
| Register | `/accounts/register/` | Choose provider/client |
| Admin | `/admin/` | Django admin panel |
| Dashboard | `/provider/dashboard/` | Provider dashboard |
| Services | `/provider/services/` | Manage services |
| Appointments | `/provider/appointments/` | View bookings |
| Pricing | `/pricing/` | Plan comparison |
| Upgrade | `/pricing/upgrade/` | Upgrade to PRO |
| Public Booking | `/book/{slug}/` | Client booking page |
| My Appointments | `/appointments/my-appointments/` | Client view |

---

## 🐛 Troubleshooting

### Error: "No module named 'decouple'"
```bash
pip install python-decouple
```

### Error: "Table doesn't exist"
```bash
python manage.py migrate
```

### Error: "UNIQUE constraint failed"
```bash
# Delete database and start fresh
del db.sqlite3
python manage.py migrate
python manage.py create_default_plans
python manage.py createsuperuser
```

### Static files not loading
```bash
python manage.py collectstatic --noinput
```

### Port already in use
```bash
python manage.py runserver 8001
```

---

## 📚 Next Steps

1. **Customize Templates**
   - Edit `templates/` folder
   - Add your branding
   - Customize colors/styles

2. **Set Up Email**
   - Configure SMTP in `.env`
   - Test email notifications

3. **Configure Razorpay**
   - Get API keys from Razorpay dashboard
   - Add to `.env`
   - Test payment flow

4. **Deploy to Production**
   - Use PostgreSQL instead of SQLite
   - Set DEBUG=False
   - Configure proper email
   - Set up SSL certificate
   - Use Gunicorn/uWSGI

5. **Add Features**
   - WhatsApp notifications
   - SMS reminders
   - Google Calendar sync
   - Analytics dashboard
   - Multi-staff support

---

## 💡 Pro Tips

1. **Use Django Shell for Testing**
```bash
python manage.py shell
>>> from providers.models import ServiceProvider
>>> provider = ServiceProvider.objects.first()
>>> provider.can_create_appointment()
```

2. **Check Logs**
```bash
# Django logs in console
# Check for errors during development
```

3. **Database Backup**
```bash
# SQLite backup
copy db.sqlite3 db_backup.sqlite3
```

4. **Reset Everything**
```bash
del db.sqlite3
rd /s /q accounts\migrations
rd /s /q providers\migrations
rd /s /q appointments\migrations
rd /s /q subscriptions\migrations
# Keep __init__.py files
python manage.py makemigrations
python manage.py migrate
```

---

## 🎓 Learning Resources

- **Django Docs:** https://docs.djangoproject.com/
- **Django Tutorial:** https://docs.djangoproject.com/en/5.0/intro/tutorial01/
- **Razorpay Docs:** https://razorpay.com/docs/
- **Celery Docs:** https://docs.celeryproject.org/

---

## ✅ Checklist

- [ ] Virtual environment created
- [ ] Dependencies installed
- [ ] .env file configured
- [ ] Migrations run
- [ ] Default plans created
- [ ] Superuser created
- [ ] Server running
- [ ] Admin panel accessible
- [ ] Provider registered
- [ ] Service added
- [ ] Booking tested
- [ ] Limits tested

**Happy Coding! 🚀**
