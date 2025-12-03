# 📅 BookingSaaS - Multi-Tenant Appointment Booking Platform

A comprehensive **Django 5.0+ SaaS application** for service providers to manage appointments, services, and client bookings with a **freemium pricing model**.

---

## 🌟 Features

### For Service Providers
- ✅ **Business Profile Management** - Customizable business page with logo
- ✅ **Service Management** - Add unlimited services (PRO) or 3 services (FREE)
- ✅ **Availability Scheduling** - Set weekly working hours
- ✅ **Appointment Management** - Track bookings, confirm, cancel, complete
- ✅ **Unique Booking URL** - `/book/your-business-name/`
- ✅ **Dashboard Analytics** - View statistics and upcoming appointments
- ✅ **14-Day PRO Trial** - Full features for new signups

### For Clients
- ✅ **Browse Providers** - Search by business type and location
- ✅ **Online Booking** - Book appointments 24/7
- ✅ **Appointment History** - Track past and upcoming bookings
- ✅ **Email Notifications** - Booking confirmations and reminders
- ✅ **Walk-in Support** - Book without registration

### Freemium Pricing
- 🆓 **FREE Plan** - 5 appointments/month, 3 services, basic features
- 💎 **PRO Plan (₹199/month)** - Unlimited appointments, unlimited services, advanced features
- 🎁 **14-Day Trial** - Try PRO features risk-free

---

## 🏗️ Tech Stack

- **Backend:** Django 5.0.1
- **Database:** SQLite (dev) / PostgreSQL (production)
- **Task Queue:** Celery + Redis
- **Payment:** Razorpay
- **Email:** SMTP / Console (dev)
- **Frontend:** Django Templates + Bootstrap (ready for React/Vue)

---

## 📦 Installation

### Prerequisites
- Python 3.10+
- pip
- Virtual environment

### Quick Setup (5 minutes)

```bash
# 1. Clone/Navigate to project
cd d:\appoitment-boking\windserf\part1

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create .env file
copy .env.example .env

# 5. Run migrations
python manage.py makemigrations
python manage.py migrate

# 6. Create default plans
python manage.py create_default_plans

# 7. Create superuser
python manage.py createsuperuser

# 8. Run server
python manage.py runserver
```

**Visit:** http://127.0.0.1:8000

📖 **Detailed Setup:** See [QUICKSTART.md](QUICKSTART.md)

---

## 📁 Project Structure

```
part1/
├── booking_saas/           # Main project settings
│   ├── settings.py         # Django configuration
│   ├── urls.py             # Root URL routing
│   ├── celery.py           # Celery configuration
│   └── wsgi.py
├── accounts/               # User authentication
│   ├── models.py           # CustomUser model
│   ├── views.py            # Login, register, logout
│   └── forms.py            # Auth forms
├── providers/              # Service provider management
│   ├── models.py           # ServiceProvider, Service, Availability
│   ├── views.py            # Dashboard, services, appointments
│   ├── decorators.py       # @requires_pro_plan
│   ├── middleware.py       # Subscription checking
│   └── templatetags/       # Template filters
├── appointments/           # Booking system
│   ├── models.py           # Appointment model
│   ├── views.py            # Public booking, client views
│   └── signals.py          # Usage tracking
├── subscriptions/          # Pricing & payments
│   ├── models.py           # SubscriptionPlan, Payment
│   ├── views.py            # Upgrade, payment verification
│   ├── tasks.py            # Celery tasks
│   └── management/
│       └── commands/       # Automation commands
├── templates/              # HTML templates
├── static/                 # CSS, JS, images
├── media/                  # User uploads
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variables template
├── QUICKSTART.md           # 5-minute setup guide
├── IMPLEMENTATION_GUIDE.md # Complete documentation
└── MODEL_RELATIONSHIPS.md  # Database schema
```

---

## 🎯 Key Concepts

### Multi-Tenancy
Each service provider operates independently with:
- Unique booking URL
- Isolated data (services, appointments)
- Separate subscription plan
- Individual usage tracking

### Freemium Model

| Feature | FREE Plan | PRO Plan |
|---------|-----------|----------|
| **Price** | ₹0/month | ₹199/month |
| **Appointments** | 5/month | Unlimited |
| **Services** | 3 max | Unlimited |
| **Booking Page** | ✅ Basic | ✅ Professional |
| **Email Notifications** | ✅ | ✅ |
| **WhatsApp/SMS** | ❌ | ✅ |
| **Branding Removal** | ❌ | ✅ |
| **Analytics** | ❌ | ✅ |
| **Multi-Staff** | ❌ | ✅ |
| **Priority Support** | ❌ | ✅ |

### Usage Tracking
- **Counter:** `appointments_this_month` field
- **Reset:** Automatically on 1st of each month
- **Enforcement:** Decorators check limits before actions
- **Prompts:** Upgrade modals when limits reached

### Automation
- **Monthly Reset:** Celery task resets counters
- **Trial Expiry:** Daily check for expired trials
- **Subscription Expiry:** Auto-downgrade expired PRO users
- **Reminders:** Email users approaching limits
- **Appointment Reminders:** 24-hour advance notifications

---

## 🔐 Security Features

- ✅ Email-based authentication (no usernames)
- ✅ Password hashing (Django default)
- ✅ CSRF protection
- ✅ SQL injection prevention (ORM)
- ✅ XSS protection (template escaping)
- ✅ Secure payment verification (HMAC-SHA256)
- ✅ Environment variables for secrets
- ✅ Session management

---

## 🚀 Deployment

### Production Checklist

1. **Environment Variables**
```env
DEBUG=False
SECRET_KEY=<generate-strong-key>
ALLOWED_HOSTS=yourdomain.com
```

2. **Database**
```bash
# Switch to PostgreSQL
pip install psycopg2-binary
# Update DATABASE settings in settings.py
```

3. **Static Files**
```bash
python manage.py collectstatic
```

4. **Web Server**
- Use Gunicorn or uWSGI
- Configure Nginx reverse proxy
- Set up SSL certificate (Let's Encrypt)

5. **Background Tasks**
```bash
# Start Celery worker
celery -A booking_saas worker -l info

# Start Celery beat
celery -A booking_saas beat -l info
```

6. **Monitoring**
- Set up error logging (Sentry)
- Configure uptime monitoring
- Database backups

📖 **Full Deployment Guide:** See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md)

---

## 📊 Database Models

### Core Models
1. **CustomUser** - Email-based authentication
2. **ServiceProvider** - Business profiles with subscription tracking
3. **Service** - Services offered by providers
4. **Availability** - Weekly schedule (Mon-Sun)
5. **Appointment** - Booking records
6. **SubscriptionPlan** - FREE and PRO plans
7. **Payment** - Razorpay transaction records

📖 **Schema Details:** See [MODEL_RELATIONSHIPS.md](MODEL_RELATIONSHIPS.md)

---

## 🤖 Management Commands

```bash
# Create default FREE and PRO plans
python manage.py create_default_plans

# Reset monthly appointment counters (run on 1st)
python manage.py reset_monthly_limits

# Check and handle expired subscriptions (run daily)
python manage.py check_expired_subscriptions --send-emails

# Send upgrade reminders to users near limits (run weekly)
python manage.py send_upgrade_reminders
```

---

## 🧪 Testing

### Manual Testing
```bash
# 1. Register as provider
# 2. Add 3 services (FREE limit)
# 3. Try 4th service → Should block
# 4. Create 5 appointments
# 5. Try 6th → Should show upgrade prompt
# 6. Upgrade to PRO
# 7. Verify unlimited access
```

### Automated Testing (TODO)
```bash
python manage.py test
```

---

## 📧 Email Configuration

### Development (Console)
```env
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```
Emails print to console.

### Production (Gmail)
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
```

---

## 💳 Payment Integration

### Razorpay Setup
1. Sign up at https://razorpay.com
2. Get API keys from dashboard
3. Add to `.env`:
```env
RAZORPAY_KEY_ID=rzp_test_xxxxx
RAZORPAY_KEY_SECRET=xxxxx
```

### Test Payment
- Use Razorpay test cards
- Test mode: No real money charged
- Production: Switch to live keys

---

## 🐛 Known Issues & Limitations

### Current Limitations
- ❌ No WhatsApp integration yet (PRO feature planned)
- ❌ No SMS notifications yet (PRO feature planned)
- ❌ No Google Calendar sync yet (PRO feature planned)
- ❌ No multi-staff support yet (PRO feature planned)
- ❌ No analytics dashboard yet (PRO feature planned)
- ❌ Templates are basic (needs frontend work)

### Planned Features
- [ ] WhatsApp notifications via Twilio
- [ ] SMS reminders
- [ ] Google Calendar integration
- [ ] Advanced analytics
- [ ] Multi-staff management
- [ ] Custom domains
- [ ] Mobile app (React Native)
- [ ] API for third-party integrations

---

## 🤝 Contributing

This is a proprietary project. For internal development:

1. Create feature branch
2. Make changes
3. Test thoroughly
4. Submit pull request
5. Code review
6. Merge to main

---

## 📄 License

Proprietary - All rights reserved.

---

## 📞 Support

- **Documentation:** See `/docs/` folder
- **Issues:** Contact development team
- **Email:** support@bookingsaas.com

---

## 👨‍💻 Developer Notes

### Code Style
- Follow PEP 8
- Use type hints where possible
- Write docstrings for functions
- Keep functions small and focused

### Git Workflow
```bash
git checkout -b feature/new-feature
git add .
git commit -m "Add new feature"
git push origin feature/new-feature
```

### Database Migrations
```bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Rollback
python manage.py migrate app_name previous_migration
```

---

## 🎓 Learning Resources

- [Django Documentation](https://docs.djangoproject.com/)
- [Celery Documentation](https://docs.celeryproject.org/)
- [Razorpay API Docs](https://razorpay.com/docs/)
- [PostgreSQL Tutorial](https://www.postgresql.org/docs/)

---

## 📈 Roadmap

### Phase 1 (MVP) ✅
- [x] User authentication
- [x] Provider profiles
- [x] Service management
- [x] Appointment booking
- [x] Freemium pricing
- [x] Payment integration
- [x] Usage tracking
- [x] Automation

### Phase 2 (Q1 2024)
- [ ] WhatsApp notifications
- [ ] SMS reminders
- [ ] Email templates
- [ ] Frontend redesign
- [ ] Mobile responsive

### Phase 3 (Q2 2024)
- [ ] Google Calendar sync
- [ ] Analytics dashboard
- [ ] Multi-staff support
- [ ] API development
- [ ] Mobile app

---

**Built with ❤️ using Django 5.0+**

**Version:** 1.0.0  
**Last Updated:** November 2024
