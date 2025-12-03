"""
Production settings for BookingSaaS.
This file contains security-hardened settings for production deployment.

Usage:
    Set environment variable: DJANGO_SETTINGS_MODULE=booking_saas.settings_production
"""
from .settings import *
from decouple import config

# ============================================================================
# SECURITY SETTINGS
# ============================================================================

# CRITICAL: Set DEBUG to False in production
DEBUG = False

# CRITICAL: Set proper SECRET_KEY from environment
SECRET_KEY = config('SECRET_KEY')

# CRITICAL: Configure ALLOWED_HOSTS
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='').split(',')

# HTTPS Settings
SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=True, cast=bool)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# HSTS (HTTP Strict Transport Security)
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Security Headers
SECURE_REFERRER_POLICY = 'same-origin'

# CSRF Settings
CSRF_COOKIE_HTTPONLY = True
CSRF_USE_SESSIONS = False
CSRF_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SAMESITE = 'Strict'

# ============================================================================
# DATABASE - PostgreSQL
# ============================================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'CONN_MAX_AGE': 600,  # Connection pooling
        'OPTIONS': {
            'connect_timeout': 10,
        }
    }
}

# ============================================================================
# CACHING - Redis
# ============================================================================

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True
            }
        },
        'KEY_PREFIX': 'booking_saas',
        'TIMEOUT': 300,  # 5 minutes default
    }
}

# Cache middleware
MIDDLEWARE.insert(1, 'django.middleware.cache.UpdateCacheMiddleware')
MIDDLEWARE.append('django.middleware.cache.FetchFromCacheMiddleware')

CACHE_MIDDLEWARE_ALIAS = 'default'
CACHE_MIDDLEWARE_SECONDS = 600
CACHE_MIDDLEWARE_KEY_PREFIX = 'booking_saas'

# ============================================================================
# STATIC FILES - WhiteNoise
# ============================================================================

# WhiteNoise for serving static files
MIDDLEWARE.insert(
    MIDDLEWARE.index('django.middleware.security.SecurityMiddleware') + 1,
    'whitenoise.middleware.WhiteNoiseMiddleware'
)

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

STATIC_ROOT = BASE_DIR / 'staticfiles'
STATIC_URL = '/static/'

# WhiteNoise settings
WHITENOISE_MANIFEST_STRICT = False
WHITENOISE_ALLOW_ALL_ORIGINS = False

# ============================================================================
# MEDIA FILES - AWS S3 (Optional)
# ============================================================================

# Uncomment to use AWS S3 for media files
USE_S3 = config('USE_S3', default=False, cast=bool)

if USE_S3:
    # AWS S3 Settings
    AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY')
    AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME')
    AWS_S3_REGION_NAME = config('AWS_S3_REGION_NAME', default='us-east-1')
    AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'
    AWS_S3_OBJECT_PARAMETERS = {
        'CacheControl': 'max-age=86400',
    }
    AWS_DEFAULT_ACL = 'public-read'
    AWS_S3_FILE_OVERWRITE = False
    AWS_QUERYSTRING_AUTH = False
    
    # Media files
    DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
    MEDIA_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/media/'
else:
    # Local media files
    MEDIA_ROOT = BASE_DIR / 'media'
    MEDIA_URL = '/media/'

# ============================================================================
# EMAIL - Production Email Service
# ============================================================================

# Use SendGrid or AWS SES in production
EMAIL_BACKEND = config(
    'EMAIL_BACKEND',
    default='django.core.mail.backends.smtp.EmailBackend'
)

# SendGrid Configuration
if 'sendgrid' in EMAIL_BACKEND.lower():
    SENDGRID_API_KEY = config('SENDGRID_API_KEY')
    EMAIL_HOST = 'smtp.sendgrid.net'
    EMAIL_PORT = 587
    EMAIL_USE_TLS = True
    EMAIL_HOST_USER = 'apikey'
    EMAIL_HOST_PASSWORD = SENDGRID_API_KEY

# AWS SES Configuration
elif 'ses' in EMAIL_BACKEND.lower():
    AWS_SES_REGION_NAME = config('AWS_SES_REGION_NAME', default='us-east-1')
    AWS_SES_REGION_ENDPOINT = f'email.{AWS_SES_REGION_NAME}.amazonaws.com'

# ============================================================================
# LOGGING
# ============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'django_errors.log',
            'maxBytes': 1024 * 1024 * 10,  # 10 MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['file'],
            'level': 'ERROR',
            'propagate': False,
        },
    },
}

# ============================================================================
# PERFORMANCE OPTIMIZATIONS
# ============================================================================

# Gzip compression
MIDDLEWARE.insert(0, 'django.middleware.gzip.GZipMiddleware')

# Database connection pooling
CONN_MAX_AGE = 600

# Template caching
TEMPLATES[0]['OPTIONS']['loaders'] = [
    ('django.template.loaders.cached.Loader', [
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    ]),
]

# ============================================================================
# CELERY - Production Configuration
# ============================================================================

CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://localhost:6379/0')

# Celery optimizations
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES = False
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_BROKER_CONNECTION_MAX_RETRIES = 10

# ============================================================================
# CORS (if using separate frontend)
# ============================================================================

if config('ENABLE_CORS', default=False, cast=bool):
    INSTALLED_APPS += ['corsheaders']
    MIDDLEWARE.insert(0, 'corsheaders.middleware.CorsMiddleware')
    
    CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', default='').split(',')
    CORS_ALLOW_CREDENTIALS = True

# ============================================================================
# OPENAI API (AI Features)
# ============================================================================

OPENAI_API_KEY = config('OPENAI_API_KEY', default='')

# ============================================================================
# MONITORING & ERROR TRACKING (Optional)
# ============================================================================

# Sentry for error tracking
SENTRY_DSN = config('SENTRY_DSN', default='')

if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[DjangoIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=False,
        environment='production'
    )

# ============================================================================
# ADMIN SECURITY
# ============================================================================

# Change admin URL in production (set in urls.py)
ADMIN_URL = config('ADMIN_URL', default='admin/')

# ============================================================================
# SESSION SECURITY
# ============================================================================

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 1209600  # 2 weeks
SESSION_SAVE_EVERY_REQUEST = False
SESSION_COOKIE_HTTPONLY = True

# ============================================================================
# FILE UPLOAD SETTINGS
# ============================================================================

FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5 MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5 MB

# ============================================================================
# RATE LIMITING (Optional - requires django-ratelimit)
# ============================================================================

RATELIMIT_ENABLE = config('RATELIMIT_ENABLE', default=True, cast=bool)
RATELIMIT_USE_CACHE = 'default'

# ============================================================================
# BACKUP SETTINGS
# ============================================================================

# Database backup configuration
DBBACKUP_STORAGE = 'django.core.files.storage.FileSystemStorage'
DBBACKUP_STORAGE_OPTIONS = {'location': BASE_DIR / 'backups'}

# ============================================================================
# ADDITIONAL SECURITY HEADERS
# ============================================================================

# Content Security Policy (CSP)
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com")
CSP_IMG_SRC = ("'self'", "data:", "https:")
CSP_FONT_SRC = ("'self'", "data:", "cdn.jsdelivr.net", "cdnjs.cloudflare.com")

print("=" * 50)
print("PRODUCTION SETTINGS LOADED")
print(f"DEBUG: {DEBUG}")
print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")
print(f"DATABASE: PostgreSQL")
print(f"CACHE: Redis")
print(f"STATIC: WhiteNoise")
print("=" * 50)
