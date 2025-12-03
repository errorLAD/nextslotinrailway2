# Koyeb.com Deployment Guide

## Overview
This guide walks you through deploying the NextSlot Booking SaaS application on Koyeb.com using Docker.

## Prerequisites
- GitHub account with your repository
- Koyeb account (free tier available at https://koyeb.com)
- External PostgreSQL database (Neon, Supabase, ElephantSQL, or similar)

---

## Step 1: Set Up PostgreSQL Database

Koyeb doesn't provide managed PostgreSQL, so you'll need an external database provider.

### Recommended Options:

#### Option A: Neon (Recommended - Free tier available)
1. Go to https://neon.tech
2. Create a new project
3. Copy the connection string (looks like: `postgresql://user:pass@host/dbname?sslmode=require`)

#### Option B: Supabase (Free tier available)
1. Go to https://supabase.com
2. Create a new project
3. Go to Settings → Database → Connection string → URI
4. Copy the connection string

#### Option C: ElephantSQL (Free tier available)
1. Go to https://www.elephantsql.com
2. Create a new instance (Tiny Turtle - free)
3. Copy the URL from instance details

---

## Step 2: Deploy on Koyeb

### Method 1: Deploy from GitHub (Recommended)

1. **Login to Koyeb**
   - Go to https://app.koyeb.com
   - Login or create an account

2. **Create New App**
   - Click "Create App"
   - Select "GitHub" as deployment method
   - Connect your GitHub account if not already connected
   - Select your repository: `errorLAD/nextslotinrailway2`
   - Select branch: `main`

3. **Configure Build Settings**
   - Builder: Docker
   - Dockerfile path: `Dockerfile`

4. **Configure Instance**
   - Instance type: Nano (free tier) or Small
   - Region: Choose closest to your users

5. **Add Environment Variables**
   Add these required variables:

   | Variable | Value |
   |----------|-------|
   | `SECRET_KEY` | Generate: `python -c "import secrets; print(secrets.token_urlsafe(50))"` |
   | `DATABASE_URL` | Your PostgreSQL connection string |
   | `DEBUG` | `False` |
   | `ALLOWED_HOSTS` | `*` |
   | `DEFAULT_DOMAIN` | `nextslot.in` |
   | `DEFAULT_SCHEME` | `https` |

   **Optional variables (for full features):**
   | Variable | Value |
   |----------|-------|
   | `CLOUDFLARE_API_TOKEN` | Your Cloudflare API token |
   | `CLOUDFLARE_ZONE_ID` | Your Cloudflare Zone ID |
   | `RAZORPAY_KEY_ID` | Razorpay API Key |
   | `RAZORPAY_KEY_SECRET` | Razorpay Secret |
   | `OPENAI_API_KEY` | OpenAI API Key (for AI features) |
   | `GOOGLE_CLIENT_ID` | Google OAuth Client ID |
   | `GOOGLE_CLIENT_SECRET` | Google OAuth Secret |

6. **Configure Health Check**
   - Path: `/admin/login/`
   - Port: `8000`

7. **Deploy**
   - Click "Deploy"
   - Wait for build and deployment to complete

### Method 2: Deploy using Koyeb CLI

```bash
# Install Koyeb CLI
npm install -g koyeb

# Login
koyeb login

# Deploy
koyeb app create nextslot-booking \
  --git github.com/errorLAD/nextslotinrailway2 \
  --git-branch main \
  --git-builder docker \
  --docker-dockerfile Dockerfile \
  --instance-type nano \
  --port 8000:http \
  --env SECRET_KEY=your-secret-key \
  --env DATABASE_URL=your-database-url \
  --env DEBUG=False \
  --env ALLOWED_HOSTS=* \
  --env DEFAULT_DOMAIN=nextslot.in
```

---

## Step 3: Post-Deployment Setup

### Run Migrations (Automatic)
The Dockerfile is configured to run migrations automatically during startup.

### Create Superuser
You'll need to exec into the container to create a superuser:

1. Go to Koyeb Console
2. Select your service
3. Click on "Terminal"
4. Run:
   ```bash
   python manage.py createsuperuser
   ```

### Verify Deployment
1. Visit your Koyeb URL: `https://your-app.koyeb.app`
2. Check admin panel: `https://your-app.koyeb.app/admin/`

---

## Step 4: Configure Custom Domain (Optional)

### In Koyeb:
1. Go to your service settings
2. Click "Add Domain"
3. Enter your custom domain
4. Get the CNAME target provided by Koyeb

### In Cloudflare/DNS Provider:
1. Add CNAME record:
   - Name: `@` or subdomain
   - Target: Koyeb-provided target
   - Proxy: Orange cloud (if Cloudflare)

2. Add TXT record for verification (if required)

---

## Environment Variables Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | Random 50+ character string |
| `DATABASE_URL` | PostgreSQL connection URL | `postgresql://user:pass@host:5432/db` |
| `DEBUG` | Debug mode | `False` |
| `ALLOWED_HOSTS` | Allowed hosts | `*` |
| `DEFAULT_DOMAIN` | Your main domain | `nextslot.in` |

### Optional Feature Variables

| Variable | Description | Required For |
|----------|-------------|--------------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token | Custom domains |
| `CLOUDFLARE_ZONE_ID` | Cloudflare Zone ID | Custom domains |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID | Custom domains |
| `RAZORPAY_KEY_ID` | Razorpay Key | Payments |
| `RAZORPAY_KEY_SECRET` | Razorpay Secret | Payments |
| `TWILIO_ACCOUNT_SID` | Twilio SID | SMS/WhatsApp |
| `TWILIO_AUTH_TOKEN` | Twilio Token | SMS/WhatsApp |
| `TWILIO_PHONE_NUMBER` | Twilio Number | SMS |
| `TWILIO_WHATSAPP_NUMBER` | WhatsApp Number | WhatsApp |
| `OPENAI_API_KEY` | OpenAI API Key | AI Features |
| `GOOGLE_CLIENT_ID` | Google OAuth ID | Google Calendar |
| `GOOGLE_CLIENT_SECRET` | Google OAuth Secret | Google Calendar |

---

## Troubleshooting

### Build Fails
- Check Dockerfile syntax
- Ensure all dependencies are in `requirements.txt`
- Check Koyeb build logs

### App Crashes on Start
- Verify DATABASE_URL is correct
- Check if database is accessible from Koyeb
- Review Koyeb runtime logs

### 500 Errors
- Enable DEBUG temporarily to see errors
- Check if migrations ran successfully
- Verify all required environment variables are set

### Static Files Not Loading
- Static files are served by WhiteNoise
- Check if `collectstatic` ran during build
- Verify STATIC_ROOT and STATIC_URL settings

### Database Connection Issues
- Ensure SSL is enabled in DATABASE_URL (`?sslmode=require`)
- Check database provider's firewall/allowed IPs
- Verify connection string format

---

## Scaling

### Increase Instances
1. Go to your service in Koyeb
2. Edit service configuration
3. Increase "Min instances" and "Max instances"

### Upgrade Instance Type
1. Edit service configuration
2. Change instance type (Nano → Small → Medium → Large)

---

## Monitoring

### Built-in Monitoring
- Koyeb provides basic metrics in the dashboard
- CPU, Memory, and Request metrics available

### External Monitoring (Optional)
- Add Sentry for error tracking:
  ```bash
  pip install sentry-sdk
  ```
  Add `SENTRY_DSN` environment variable

---

## Costs

### Free Tier
- Nano instance (256MB RAM, 0.1 vCPU)
- 1 app
- Limited to hobby usage

### Paid Plans
- See https://www.koyeb.com/pricing for current pricing
- Pay-as-you-go model

---

## Support
- Koyeb Documentation: https://www.koyeb.com/docs
- Koyeb Community: https://community.koyeb.com
- GitHub Issues: https://github.com/errorLAD/nextslotinrailway2/issues
