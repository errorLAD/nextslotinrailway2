# 🚀 Quick Start - AI Features & Production Deployment

## 🤖 AI Features Setup (5 Minutes)

### 1. Get OpenAI API Key
```
1. Visit: https://platform.openai.com/
2. Sign up/Login
3. Go to API Keys
4. Create new key (starts with sk-)
5. Copy the key
```

### 2. Configure Environment
```bash
# .env
OPENAI_API_KEY=sk-your-actual-api-key-here
```

### 3. Test AI Features
```python
python manage.py shell

# Test smart suggestions
from utils.ai_features import get_smart_time_suggestions
from providers.models import ServiceProvider
from datetime import date, timedelta

provider = ServiceProvider.objects.first()
tomorrow = date.today() + timedelta(days=1)
suggestions = get_smart_time_suggestions(provider, tomorrow)
print(suggestions)

# Test no-show prediction
from utils.ai_features import calculate_no_show_risk
from appointments.models import Appointment

appointment = Appointment.objects.first()
risk = calculate_no_show_risk(appointment)
print(f"Risk: {risk['risk_level']} - {risk['risk_percentage']}%")

# Test content generation
from utils.ai_features import generate_service_description

desc = generate_service_description("Haircut", "salon", "english")
print(desc)
```

### 4. AI Features Available
- ✅ Smart time slot suggestions
- ✅ No-show prediction
- ✅ Service description generation (English + Hindi)
- ✅ Email template generation
- ✅ AI chatbot

### 5. Cost Optimization
```python
# All AI calls are cached automatically
# Typical costs: $2-20/month for small-medium business
```

---

## 🚀 Production Deployment (30 Minutes)

### Step 1: Generate Secret Key (1 min)
```bash
python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'

# Add to .env
SECRET_KEY=your-generated-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
```

### Step 2: PostgreSQL Setup (5 min)
```bash
# Install
sudo apt install postgresql

# Create database
sudo -u postgres psql
CREATE DATABASE booking_saas_db;
CREATE USER booking_saas_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE booking_saas_db TO booking_saas_user;
\q

# Configure .env
DB_NAME=booking_saas_db
DB_USER=booking_saas_user
DB_PASSWORD=secure_password
DB_HOST=localhost
DB_PORT=5432
```

### Step 3: Redis Setup (2 min)
```bash
# Install
sudo apt install redis-server

# Start
sudo systemctl start redis
sudo systemctl enable redis

# Test
redis-cli ping  # Should return PONG

# Configure .env
REDIS_URL=redis://127.0.0.1:6379/1
```

### Step 4: Migrate & Collect Static (3 min)
```bash
# Set production settings
export DJANGO_SETTINGS_MODULE=booking_saas.settings_production

# Migrate
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic --noinput
```

### Step 5: Gunicorn Setup (5 min)
```bash
# Install
pip install gunicorn

# Test
gunicorn booking_saas.wsgi:application --bind 0.0.0.0:8000

# Create systemd service
sudo nano /etc/systemd/system/booking_saas.service
```

```ini
[Unit]
Description=BookingSaaS Gunicorn
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/project
Environment="DJANGO_SETTINGS_MODULE=booking_saas.settings_production"
ExecStart=/path/to/venv/bin/gunicorn booking_saas.wsgi:application --bind 127.0.0.1:8000 --workers 4

[Install]
WantedBy=multi-user.target
```

```bash
# Start service
sudo systemctl daemon-reload
sudo systemctl start booking_saas
sudo systemctl enable booking_saas
```

### Step 6: Nginx Setup (5 min)
```bash
# Install
sudo apt install nginx

# Create config
sudo nano /etc/nginx/sites-available/booking_saas
```

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    location /static/ {
        alias /path/to/project/staticfiles/;
    }
    
    location /media/ {
        alias /path/to/project/media/;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/booking_saas /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: SSL Certificate (5 min)
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal is set up automatically
```

### Step 8: Celery Setup (4 min)
```bash
# Install supervisor
sudo apt install supervisor

# Create worker config
sudo nano /etc/supervisor/conf.d/booking_saas_worker.conf
```

```ini
[program:booking_saas_worker]
command=/path/to/venv/bin/celery -A booking_saas worker -l info
directory=/path/to/project
user=www-data
autostart=true
autorestart=true
```

```bash
# Create beat config
sudo nano /etc/supervisor/conf.d/booking_saas_beat.conf
```

```ini
[program:booking_saas_beat]
command=/path/to/venv/bin/celery -A booking_saas beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
directory=/path/to/project
user=www-data
autostart=true
autorestart=true
```

```bash
# Start services
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start all
```

---

## ✅ Production Checklist

### Security
- [ ] DEBUG=False
- [ ] New SECRET_KEY generated
- [ ] ALLOWED_HOSTS configured
- [ ] HTTPS enabled
- [ ] Secure cookies enabled
- [ ] Admin URL changed

### Database
- [ ] PostgreSQL installed
- [ ] Database created
- [ ] Migrations run
- [ ] Backups configured

### Performance
- [ ] Redis installed and running
- [ ] Static files collected
- [ ] Gzip compression enabled
- [ ] Caching configured

### Services
- [ ] Gunicorn running
- [ ] Nginx running
- [ ] Celery worker running
- [ ] Celery beat running
- [ ] SSL certificate installed

### Testing
- [ ] Can access website via HTTPS
- [ ] Admin panel accessible
- [ ] Can create appointment
- [ ] Email notifications working
- [ ] Celery tasks processing

---

## 🧪 Quick Tests

### Test Website
```bash
curl -I https://yourdomain.com
# Should return 200 OK
```

### Test Database
```bash
python manage.py dbshell
\dt  # List tables
\q
```

### Test Redis
```bash
redis-cli
PING  # Should return PONG
exit
```

### Test Celery
```python
python manage.py shell

from utils.tasks import send_welcome_email_task
send_welcome_email_task.delay(1)
# Check logs for task execution
```

### Test AI Features
```python
python manage.py shell

from utils.ai_features import call_openai_api
response = call_openai_api("Say hello!")
print(response)
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
tail -f /var/log/nginx/error.log
sudo journalctl -u booking_saas -f

# Restart services
sudo systemctl restart booking_saas
sudo systemctl restart nginx
sudo supervisorctl restart all
```

---

## 🚨 Common Issues & Fixes

### Issue: 502 Bad Gateway
```bash
# Check Gunicorn
sudo systemctl status booking_saas
sudo journalctl -u booking_saas -n 50

# Restart
sudo systemctl restart booking_saas
```

### Issue: Static files not loading
```bash
# Collect static files
python manage.py collectstatic --noinput

# Check permissions
sudo chown -R www-data:www-data staticfiles/

# Restart Nginx
sudo systemctl restart nginx
```

### Issue: Database connection error
```bash
# Check PostgreSQL
sudo systemctl status postgresql

# Check credentials in .env
cat .env | grep DB_

# Test connection
psql -U booking_saas_user -d booking_saas_db -h localhost
```

### Issue: Celery not processing
```bash
# Check worker
sudo supervisorctl status booking_saas_worker

# Check Redis
redis-cli ping

# Restart
sudo supervisorctl restart booking_saas_worker
```

### Issue: AI features not working
```bash
# Check API key
cat .env | grep OPENAI

# Test in shell
python manage.py shell
>>> from utils.ai_features import call_openai_api
>>> call_openai_api("test")
```

---

## 💰 Cost Estimates

### Infrastructure (Monthly)
- **VPS (DigitalOcean/AWS):** $10-50
- **Domain:** $1-2
- **SSL:** Free (Let's Encrypt)
- **Database:** Included
- **Redis:** Included

### APIs (Monthly)
- **OpenAI (100 calls/day):** $2-5
- **Twilio SMS (PRO):** $5-50
- **SendGrid Email:** Free tier available

### Total: $18-107/month
(Scales with usage)

---

## 📚 Documentation Quick Links

1. **AI Features:** `AI_FEATURES_GUIDE.md`
2. **Production Deployment:** `PRODUCTION_DEPLOYMENT_GUIDE.md`
3. **Multi-Staff & Calendar:** `MULTI_STAFF_CLIENT_CALENDAR_GUIDE.md`
4. **Notifications:** `NOTIFICATIONS_SETUP.md`
5. **Complete Summary:** `FINAL_IMPLEMENTATION_SUMMARY.md`

---

## 🎯 Next Steps After Deployment

1. **Configure DNS** - Point domain to server IP
2. **Set up monitoring** - Sentry, UptimeRobot
3. **Configure backups** - Daily database backups
4. **Test all features** - Go through user flows
5. **Monitor logs** - Check for errors
6. **Optimize performance** - Based on usage patterns
7. **Set up analytics** - Google Analytics, etc.

---

## 💡 Pro Tips

1. **Use environment variables** for all secrets
2. **Monitor API costs** - Set up alerts
3. **Cache aggressively** - Reduce API calls
4. **Regular backups** - Automate daily
5. **Monitor logs** - Catch issues early
6. **Load testing** - Before launch
7. **Security updates** - Keep dependencies updated
8. **Documentation** - Keep it updated

---

**Your app is production-ready! 🚀**

**Need help?** Check the comprehensive guides in the documentation folder.
