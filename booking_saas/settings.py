"""
Django settings for booking_saas project.
Multi-tenant appointment booking SaaS with freemium pricing.
"""

from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-change-this-in-production-12345')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')

# Domain configuration
DEFAULT_DOMAIN = config('DEFAULT_DOMAIN', default='yourdomain.com')
DEFAULT_SCHEME = config('DEFAULT_SCHEME', default='https' if not DEBUG else 'http')

# CNAME target for custom domains - This is what service providers point their CNAME to
CNAME_TARGET = config('CNAME_TARGET', default=DEFAULT_DOMAIN)

# Add the default domain to ALLOWED_HOSTS if not already present
if DEFAULT_DOMAIN not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(DEFAULT_DOMAIN)

# Allow all subdomains of the default domain
ALLOWED_HOSTS.append(f'.{DEFAULT_DOMAIN}')

# Allow any custom domain (for PRO users with verified custom domains)
# In production, you might want to be more restrictive
if DEBUG:
    ALLOWED_HOSTS.append('*')


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'django_celery_beat',
    'mathfilters',
    
    # Local apps
    'accounts.apps.AccountsConfig',
    'providers.apps.ProvidersConfig',
    'appointments.apps.AppointmentsConfig',
    'subscriptions.apps.SubscriptionsConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # Custom middleware
    'providers.middleware.SubscriptionCheckMiddleware',
    'providers.middleware.CustomDomainMiddleware',
]

ROOT_URLCONF = 'booking_saas.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.template.context_processors.media',
            ],
        },
    },
]

WSGI_APPLICATION = 'booking_saas.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': config('DB_ENGINE', default='django.db.backends.sqlite3'),
        'NAME': BASE_DIR / config('DB_NAME', default='db.sqlite3'),
    }
}

# For PostgreSQL in production, use:
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': config('DB_NAME'),
#         'USER': config('DB_USER'),
#         'PASSWORD': config('DB_PASSWORD'),
#         'HOST': config('DB_HOST', default='localhost'),
#         'PORT': config('DB_PORT', default='5432'),
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'  # Indian Standard Time

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Additional locations of static files
STATICFILES_DIRS = [
    BASE_DIR / 'static',
    BASE_DIR / 'subscriptions/static',
]

# Media files (User uploads)
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom User Model
AUTH_USER_MODEL = 'accounts.CustomUser'

# Authentication settings
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'providers:dashboard'
LOGOUT_REDIRECT_URL = 'accounts:login'

# Email Configuration
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@bookingsaas.com')

# Celery Configuration
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://localhost:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# SSL Configuration for custom domains
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = not DEBUG  # Redirect all non-HTTPS requests to HTTPS in production

# Email settings for domain verification
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # In production, use SMTP
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@yourdomain.com')
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# Custom domain settings
CUSTOM_DOMAIN_VERIFICATION_TIMEOUT = 86400  # 24 hours in seconds

# Logging configuration for domain verification
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'domain_verification.log',
        },
    },
    'loggers': {
        'providers.domain_utils': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Razorpay Configuration
RAZORPAY_KEY_ID = config('RAZORPAY_KEY_ID', default='')
RAZORPAY_KEY_SECRET = config('RAZORPAY_KEY_SECRET', default='')
RAZORPAY_WEBHOOK_SECRET = config('RAZORPAY_WEBHOOK_SECRET', default='')

# Site Configuration
SITE_NAME = config('SITE_NAME', default='BookingSaaS')
SITE_URL = config('SITE_URL', default='http://localhost:8000')

# Subscription Plans Configuration
FREE_PLAN_APPOINTMENT_LIMIT = 5
FREE_PLAN_SERVICE_LIMIT = 3
PRO_PLAN_PRICE = 199  # in INR
TRIAL_PERIOD_DAYS = 14
GRACE_PERIOD_DAYS = 3

# Session Configuration
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_SAVE_EVERY_REQUEST = False

# Twilio SMS Configuration (PRO Plan Only)
TWILIO_ACCOUNT_SID = config('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = config('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = config('TWILIO_PHONE_NUMBER', default='')

# Email Tracking
EMAIL_TRACK_DELIVERY = True

# Notification Settings
SEND_WELCOME_EMAIL = True
SEND_APPOINTMENT_CONFIRMATION = True
SEND_APPOINTMENT_REMINDER = True
REMINDER_HOURS_BEFORE = 24

# Google Calendar API (PRO plan only)
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID', default='')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET', default='')

# OpenAI API (AI Features)
OPENAI_API_KEY = config('OPENAI_API_KEY', default='')
