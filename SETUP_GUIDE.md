# 🚀 Django Appointment Booking SaaS - Setup Guide

## Prerequisites
- Python 3.10+ installed
- pip installed
- Basic command line knowledge

## Step-by-Step Setup Instructions

### 1. Create Virtual Environment
```bash
# Navigate to project directory
cd d:\appoitment-boking\windserf\part1

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
# source venv/bin/activate
```

### 2. Install Django and Dependencies
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install required packages
pip install django==5.0.1
pip install pillow  # For image uploads
pip install python-decouple  # For environment variables
pip install celery  # For background tasks
pip install redis  # For celery broker
pip install django-celery-beat  # For scheduled tasks
pip install razorpay  # For payment integration

# Save dependencies
pip freeze > requirements.txt
```

### 3. Create Django Project
```bash
# Create project (already done via files)
# django-admin startproject booking_saas .

# Create apps
python manage.py startapp accounts
python manage.py startapp providers
python manage.py startapp appointments
python manage.py startapp subscriptions
```

### 4. Run Initial Migrations
```bash
# Create database tables
python manage.py makemigrations
python manage.py migrate
```

### 5. Create Superuser
```bash
python manage.py createsuperuser
# Enter email and password when prompted
```

### 6. Load Default Subscription Plans
```bash
python manage.py create_default_plans
```

### 7. Run Development Server
```bash
python manage.py runserver
# Visit: http://127.0.0.1:8000
```

## 📁 Project Structure
```
part1/
├── venv/                          # Virtual environment
├── booking_saas/                  # Main project folder
│   ├── __init__.py
│   ├── settings.py               # Project settings
│   ├── urls.py                   # Main URL configuration
│   ├── wsgi.py
│   └── asgi.py
├── accounts/                      # User authentication app
│   ├── models.py                 # CustomUser model
│   ├── views.py                  # Auth views
│   ├── forms.py                  # Registration forms
│   └── admin.py
├── providers/                     # Service provider app
│   ├── models.py                 # ServiceProvider, Service, Availability
│   ├── views.py                  # Provider dashboard
│   ├── decorators.py             # @requires_pro_plan
│   └── middleware.py             # Plan checking
├── appointments/                  # Booking app
│   ├── models.py                 # Appointment model
│   ├── views.py                  # Booking views
│   └── utils.py                  # Usage tracking
├── subscriptions/                 # Pricing & plans
│   ├── models.py                 # SubscriptionPlan
│   ├── views.py                  # Upgrade/pricing pages
│   └── management/
│       └── commands/
│           ├── create_default_plans.py
│           ├── reset_monthly_limits.py
│           └── check_expired_subscriptions.py
├── templates/                     # HTML templates
│   ├── base.html
│   ├── accounts/
│   ├── providers/
│   ├── appointments/
│   └── subscriptions/
├── static/                        # CSS, JS, images
│   ├── css/
│   ├── js/
│   └── images/
├── media/                         # User uploads
│   └── profile_images/
├── manage.py
├── requirements.txt
└── .env                          # Environment variables
```

## 🔐 Environment Variables (.env file)
```
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (SQLite for development)
DB_ENGINE=django.db.backends.sqlite3
DB_NAME=db.sqlite3

# Razorpay (for payments)
RAZORPAY_KEY_ID=your_key_id
RAZORPAY_KEY_SECRET=your_key_secret

# Email settings (for notifications)
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Celery (for background tasks)
CELERY_BROKER_URL=redis://localhost:6379/0
```

## 🎯 Next Steps After Setup
1. Access admin panel: http://127.0.0.1:8000/admin
2. Create a service provider account
3. Set up services and availability
4. Test the booking flow
5. Explore the upgrade to PRO features

## 🆘 Troubleshooting
- **Virtual environment not activating**: Make sure you're in the correct directory
- **Module not found errors**: Ensure virtual environment is activated and packages are installed
- **Migration errors**: Delete db.sqlite3 and migrations folders (except __init__.py), then run migrations again
- **Port already in use**: Use `python manage.py runserver 8001` for a different port

## 📚 Learning Resources
- Django Documentation: https://docs.djangoproject.com/
- Django for Beginners: https://djangoforbeginners.com/
- Multi-tenancy in Django: https://books.agiliq.com/projects/django-multi-tenant/
