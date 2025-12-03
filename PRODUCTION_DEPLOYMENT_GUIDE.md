# 🚀 Production Deployment Guide

## 📋 Overview

Complete guide for deploying BookingSaaS to production with security, performance, and scalability.

---

## ✅ Pre-Deployment Checklist

### Security
- [ ] Set `DEBUG = False`
- [ ] Generate new `SECRET_KEY`
- [ ] Configure `ALLOWED_HOSTS`
- [ ] Enable HTTPS settings
- [ ] Set secure cookie flags
- [ ] Configure CSRF protection
- [ ] Change admin URL
- [ ] Set up firewall rules

### Database
- [ ] Migrate to PostgreSQL
- [ ] Configure connection pooling
- [ ] Set up automated backups
- [ ] Test database connections

### Static Files
- [ ] Configure WhiteNoise or S3
- [ ] Run `collectstatic`
- [ ] Optimize images
- [ ] Enable compression

### Performance
- [ ] Set up Redis caching
- [ ] Configure Celery workers
- [ ] Enable gzip compression
- [ ] Optimize database queries

### Monitoring
- [ ] Set up error tracking (Sentry)
- [ ] Configure logging
- [ ] Set up uptime monitoring
- [ ] Configure alerts

---

## 🔐 Step 1: Security Configuration

### 1.1 Generate Secure SECRET_KEY

```bash
# Generate new secret key
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Add to .env
SECRET_KEY=your-generated-secret-key-here
```

### 1.2 Configure Environment Variables

```bash
# .env (Production)
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
SECRET_KEY=your-secure-secret-key
SECURE_SSL_REDIRECT=True
ADMIN_URL=secure-admin-path/
```

### 1.3 HTTPS Configuration

```python
# settings_production.py (already configured)
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### 1.4 Change Admin URL

```python
# urls.py
from django.conf import settings

urlpatterns = [
    path(settings.ADMIN_URL, admin.site.urls),  # Use custom URL
    # ... other patterns
]
```

---

## 🗄️ Step 2: Database Setup (PostgreSQL)

### 2.1 Install PostgreSQL

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
```

**macOS:**
```bash
brew install postgresql
brew services start postgresql
```

**Windows:**
Download from https://www.postgresql.org/download/windows/

### 2.2 Create Database and User

```bash
# Connect to PostgreSQL
sudo -u postgres psql

# Create database
CREATE DATABASE booking_saas_db;

# Create user
CREATE USER booking_saas_user WITH PASSWORD 'your_secure_password';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE booking_saas_db TO booking_saas_user;

# Exit
\q
```

### 2.3 Configure Django

```bash
# .env
DB_NAME=booking_saas_db
DB_USER=booking_saas_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432
```

### 2.4 Migrate Database

```bash
# Export settings
export DJANGO_SETTINGS_MODULE=booking_saas.settings_production

# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### 2.5 Database Backups

**Automated Backup Script:**
```bash
#!/bin/bash
# backup_db.sh

BACKUP_DIR="/var/backups/booking_saas"
DATE=$(date +%Y%m%d_%H%M%S)
FILENAME="booking_saas_${DATE}.sql"

mkdir -p $BACKUP_DIR

pg_dump -U booking_saas_user -h localhost booking_saas_db > $BACKUP_DIR/$FILENAME

# Compress
gzip $BACKUP_DIR/$FILENAME

# Keep only last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete

echo "Backup completed: $FILENAME.gz"
```

**Cron Job:**
```bash
# Run daily at 2 AM
crontab -e

0 2 * * * /path/to/backup_db.sh
```

---

## 📦 Step 3: Static Files Configuration

### 3.1 Install WhiteNoise

```bash
pip install whitenoise==6.6.0
```

### 3.2 Collect Static Files

```bash
# Collect all static files
python manage.py collectstatic --noinput

# Files will be in staticfiles/
```

### 3.3 Alternative: AWS S3

**Install boto3:**
```bash
pip install boto3 django-storages
```

**Configure S3:**
```python
# settings_production.py
USE_S3 = True
AWS_ACCESS_KEY_ID = 'your_access_key'
AWS_SECRET_ACCESS_KEY = 'your_secret_key'
AWS_STORAGE_BUCKET_NAME = 'your-bucket-name'
AWS_S3_REGION_NAME = 'us-east-1'
```

**Create S3 Bucket:**
1. Go to AWS S3 Console
2. Create new bucket
3. Set permissions (public read for static files)
4. Configure CORS if needed

---

## ⚡ Step 4: Caching with Redis

### 4.1 Install Redis

**Ubuntu/Debian:**
```bash
sudo apt install redis-server
sudo systemctl start redis
sudo systemctl enable redis
```

**macOS:**
```bash
brew install redis
brew services start redis
```

**Windows:**
Download from https://github.com/microsoftarchive/redis/releases

### 4.2 Install Django Redis

```bash
pip install django-redis==5.4.0
```

### 4.3 Test Redis Connection

```bash
redis-cli ping
# Should return: PONG
```

### 4.4 Configure Django

```bash
# .env
REDIS_URL=redis://127.0.0.1:6379/1
```

### 4.5 Test Caching

```python
# Django shell
from django.core.cache import cache

cache.set('test_key', 'test_value', 60)
print(cache.get('test_key'))  # Should print: test_value
```

---

## 🔄 Step 5: Celery Configuration

### 5.1 Start Celery Worker

```bash
# Development
celery -A booking_saas worker -l info

# Production (with supervisor)
celery -A booking_saas worker -l info --concurrency=4
```

### 5.2 Start Celery Beat

```bash
# Development
celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler

# Production
celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler --pidfile=/var/run/celery/beat.pid
```

### 5.3 Supervisor Configuration

**Install Supervisor:**
```bash
sudo apt install supervisor
```

**Celery Worker Config:**
```ini
# /etc/supervisor/conf.d/booking_saas_worker.conf

[program:booking_saas_worker]
command=/path/to/venv/bin/celery -A booking_saas worker -l info --concurrency=4
directory=/path/to/project
user=www-data
autostart=true
autorestart=true
stdout_logfile=/var/log/celery/worker.log
stderr_logfile=/var/log/celery/worker_error.log
```

**Celery Beat Config:**
```ini
# /etc/supervisor/conf.d/booking_saas_beat.conf

[program:booking_saas_beat]
command=/path/to/venv/bin/celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
directory=/path/to/project
user=www-data
autostart=true
autorestart=true
stdout_logfile=/var/log/celery/beat.log
stderr_logfile=/var/log/celery/beat_error.log
```

**Reload Supervisor:**
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start all
```

---

## 🌐 Step 6: Web Server Setup (Gunicorn + Nginx)

### 6.1 Install Gunicorn

```bash
pip install gunicorn==21.2.0
```

### 6.2 Test Gunicorn

```bash
gunicorn booking_saas.wsgi:application --bind 0.0.0.0:8000
```

### 6.3 Gunicorn Configuration

**Create gunicorn_config.py:**
```python
# gunicorn_config.py

bind = "127.0.0.1:8000"
workers = 4  # (2 x CPU cores) + 1
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "/var/log/gunicorn/access.log"
errorlog = "/var/log/gunicorn/error.log"
loglevel = "info"

# Process naming
proc_name = "booking_saas"

# Server mechanics
daemon = False
pidfile = "/var/run/gunicorn/booking_saas.pid"
```

### 6.4 Systemd Service

**Create service file:**
```ini
# /etc/systemd/system/booking_saas.service

[Unit]
Description=BookingSaaS Gunicorn Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/project
Environment="DJANGO_SETTINGS_MODULE=booking_saas.settings_production"
ExecStart=/path/to/venv/bin/gunicorn -c /path/to/gunicorn_config.py booking_saas.wsgi:application

[Install]
WantedBy=multi-user.target
```

**Start service:**
```bash
sudo systemctl daemon-reload
sudo systemctl start booking_saas
sudo systemctl enable booking_saas
sudo systemctl status booking_saas
```

### 6.5 Install Nginx

```bash
sudo apt install nginx
```

### 6.6 Nginx Configuration

**Create site config:**
```nginx
# /etc/nginx/sites-available/booking_saas

upstream booking_saas {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Client body size
    client_max_body_size 10M;
    
    # Static files
    location /static/ {
        alias /path/to/project/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Media files
    location /media/ {
        alias /path/to/project/media/;
        expires 7d;
    }
    
    # Proxy to Gunicorn
    location / {
        proxy_pass http://booking_saas;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/json;
}
```

**Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/booking_saas /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 6.7 SSL Certificate (Let's Encrypt)

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal (already set up by certbot)
sudo certbot renew --dry-run
```

---

## 📧 Step 7: Email Configuration

### Option 1: SendGrid

```bash
# .env
EMAIL_BACKEND=sendgrid_backend.SendgridBackend
SENDGRID_API_KEY=your_sendgrid_api_key
```

### Option 2: AWS SES

```bash
# .env
EMAIL_BACKEND=django_ses.SESBackend
AWS_SES_REGION_NAME=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
```

---

## 📊 Step 8: Monitoring & Logging

### 8.1 Set Up Sentry

```bash
pip install sentry-sdk==1.39.1
```

```bash
# .env
SENTRY_DSN=your_sentry_dsn
```

### 8.2 Configure Logging

```bash
# Create log directories
sudo mkdir -p /var/log/booking_saas
sudo mkdir -p /var/log/gunicorn
sudo mkdir -p /var/log/celery
sudo chown -R www-data:www-data /var/log/booking_saas
```

### 8.3 Log Rotation

```bash
# /etc/logrotate.d/booking_saas

/var/log/booking_saas/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        systemctl reload booking_saas
    endscript
}
```

---

## 🔥 Step 9: Performance Optimization

### 9.1 Database Optimization

```sql
-- Create indexes
CREATE INDEX idx_appointment_date ON appointments_appointment(appointment_date);
CREATE INDEX idx_appointment_provider ON appointments_appointment(service_provider_id);
CREATE INDEX idx_appointment_status ON appointments_appointment(status);
```

### 9.2 Query Optimization

```python
# Use select_related for foreign keys
appointments = Appointment.objects.select_related(
    'service_provider', 'service', 'client'
).all()

# Use prefetch_related for many-to-many
providers = ServiceProvider.objects.prefetch_related(
    'services', 'staff_members'
).all()
```

### 9.3 Caching Strategy

```python
from django.views.decorators.cache import cache_page

# Cache view for 15 minutes
@cache_page(60 * 15)
def public_provider_list(request):
    # ...
```

---

## 🧪 Step 10: Testing Production Setup

### 10.1 Security Check

```bash
python manage.py check --deploy
```

### 10.2 Load Testing

```bash
# Install Apache Bench
sudo apt install apache2-utils

# Test with 1000 requests, 10 concurrent
ab -n 1000 -c 10 https://yourdomain.com/
```

### 10.3 SSL Test

Visit: https://www.ssllabs.com/ssltest/

---

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] All tests passing
- [ ] Code reviewed
- [ ] Database backed up
- [ ] Environment variables set
- [ ] Static files collected
- [ ] Dependencies installed

### Deployment
- [ ] Pull latest code
- [ ] Run migrations
- [ ] Collect static files
- [ ] Restart services
- [ ] Clear cache
- [ ] Test critical paths

### Post-Deployment
- [ ] Check error logs
- [ ] Monitor performance
- [ ] Test user flows
- [ ] Check email delivery
- [ ] Verify payments
- [ ] Test notifications

---

## 🚨 Troubleshooting

### Issue: Static files not loading

```bash
# Check static files collected
ls -la staticfiles/

# Check Nginx config
sudo nginx -t

# Check permissions
sudo chown -R www-data:www-data staticfiles/
```

### Issue: Database connection errors

```bash
# Check PostgreSQL running
sudo systemctl status postgresql

# Test connection
psql -U booking_saas_user -d booking_saas_db -h localhost
```

### Issue: Celery not processing tasks

```bash
# Check Celery worker
sudo supervisorctl status booking_saas_worker

# Check Redis
redis-cli ping

# View logs
tail -f /var/log/celery/worker.log
```

### Issue: 502 Bad Gateway

```bash
# Check Gunicorn running
sudo systemctl status booking_saas

# Check Gunicorn logs
tail -f /var/log/gunicorn/error.log

# Check Nginx error log
tail -f /var/log/nginx/error.log
```

---

## 📊 Monitoring Commands

```bash
# Check all services
sudo systemctl status booking_saas
sudo systemctl status nginx
sudo systemctl status postgresql
sudo systemctl status redis
sudo supervisorctl status

# View logs
tail -f /var/log/booking_saas/django_errors.log
tail -f /var/log/gunicorn/error.log
tail -f /var/log/nginx/error.log
tail -f /var/log/celery/worker.log

# Check disk space
df -h

# Check memory
free -h

# Check CPU
top
```

---

## 🎯 Summary

**Production Stack:**
- ✅ Django with production settings
- ✅ PostgreSQL database
- ✅ Redis caching
- ✅ Gunicorn WSGI server
- ✅ Nginx reverse proxy
- ✅ SSL/HTTPS with Let's Encrypt
- ✅ Celery for async tasks
- ✅ WhiteNoise for static files
- ✅ Supervisor for process management
- ✅ Sentry for error tracking

**Security:**
- ✅ DEBUG=False
- ✅ Secure SECRET_KEY
- ✅ HTTPS enforced
- ✅ Secure cookies
- ✅ HSTS enabled
- ✅ Custom admin URL
- ✅ Firewall configured

**Performance:**
- ✅ Redis caching
- ✅ Database connection pooling
- ✅ Gzip compression
- ✅ Static file optimization
- ✅ Query optimization

**Monitoring:**
- ✅ Error tracking (Sentry)
- ✅ Application logs
- ✅ Server logs
- ✅ Automated backups

**Your app is production-ready!** 🚀
