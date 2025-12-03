# Custom Domain (CNAME) Setup Guide

This guide explains how to configure custom domains for service providers in the Booking SaaS application.

## Overview

Service providers with PRO plans can set up custom domains for their booking pages:
- **Subdomain**: `ramesh-salon.yourdomain.com`
- **Custom Domain**: `book.mybusiness.com` or `appointments.salon.com`

## How It Works

### CNAME Configuration Flow

1. **Provider adds custom domain** in their dashboard
2. **Provider configures DNS** at their domain registrar
3. **DNS propagates** (usually 5 minutes to 48 hours)
4. **Provider verifies ownership** in the dashboard
5. **Custom domain becomes active**

### DNS Records Required

#### For Custom Domains (e.g., `book.mybusiness.com`)

| Type  | Host/Name | Points To / Value           | TTL  |
|-------|-----------|------------------------------|------|
| CNAME | `book`    | `yourdomain.com`             | 3600 |
| TXT   | `@`       | `booking-verify-XXXXXX`      | 3600 |

#### For Subdomains (e.g., `ramesh-salon.yourdomain.com`)

Subdomains are automatically configured when using the built-in subdomain feature.

## Server Configuration

### Environment Variables

Add these to your `.env` file:

```env
# Main domain where your app is hosted
DEFAULT_DOMAIN=yourdomain.com

# Scheme (http or https)
DEFAULT_SCHEME=https

# CNAME target - what providers point their CNAME to
CNAME_TARGET=yourdomain.com

# Allowed hosts (comma-separated)
ALLOWED_HOSTS=yourdomain.com,.yourdomain.com,localhost,127.0.0.1
```

### Nginx Configuration

For production, configure Nginx to handle custom domains:

```nginx
# Main server block for your domain
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com *.yourdomain.com;
    
    # Redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com *.yourdomain.com;
    
    # SSL certificates (use Let's Encrypt with wildcard)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static/ {
        alias /path/to/your/app/staticfiles/;
    }
    
    location /media/ {
        alias /path/to/your/app/media/;
    }
}

# Catch-all server block for custom domains
server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    # For custom domains, redirect to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    
    # Use the same SSL certs or use auto-SSL
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static/ {
        alias /path/to/your/app/staticfiles/;
    }
    
    location /media/ {
        alias /path/to/your/app/media/;
    }
}
```

### SSL for Custom Domains

For automatic SSL with custom domains, consider:

1. **Cloudflare Proxy**: Providers use Cloudflare and enable proxy (orange cloud)
2. **Caddy Server**: Automatic HTTPS for all domains
3. **Let's Encrypt with certbot**: Manual or automated certificate management

#### Using Caddy (Recommended for simplicity)

```caddyfile
{
    # Enable auto HTTPS for all sites
    auto_https on
}

# Catch all domains
:443 {
    reverse_proxy localhost:8000
    
    # Static files
    handle_path /static/* {
        root * /path/to/your/app/staticfiles
        file_server
    }
    
    # Media files
    handle_path /media/* {
        root * /path/to/your/app/media
        file_server
    }
}
```

## URL Routing

### Custom Domain Flow

```
User visits: https://book.rameshsalon.com/
    ↓
DNS resolves to: yourdomain.com (via CNAME)
    ↓
Request reaches: Your server
    ↓
CustomDomainMiddleware detects: book.rameshsalon.com
    ↓
Finds provider: Ramesh Salon (with verified domain)
    ↓
Redirects to: /book/ramesh-salon/ (provider's booking page)
    ↓
User sees: Ramesh Salon's booking page
```

### URL Patterns

| URL Pattern | Description |
|-------------|-------------|
| `yourdomain.com/book/salon-name/` | Default booking page URL |
| `custom.domain.com/` | Redirects to booking page via middleware |
| `custom.domain.com/book/salon-name/` | Direct booking page on custom domain |

## Provider Dashboard URLs

Service providers can manage their domains at:

- **Domain Settings**: `/provider/domain/settings/`
- **Add Domain**: `/provider/domain/add/`
- **Verify Domain**: `/provider/domain/verify/`
- **Remove Domain**: `/provider/domain/remove/`

## Troubleshooting

### Common Issues

1. **"Domain not verified"**
   - Check DNS records are correctly configured
   - Wait for DNS propagation (up to 48 hours)
   - Verify TXT record value matches exactly

2. **"SSL certificate error"**
   - Ensure SSL is properly configured on your server
   - For Cloudflare users, use "Full (strict)" SSL mode

3. **"Page not found" on custom domain**
   - Verify domain is marked as verified in the database
   - Check ALLOWED_HOSTS includes the custom domain or `*`
   - Ensure middleware is properly configured

### Testing DNS

Use these tools to verify DNS configuration:
- [DNS Checker](https://dnschecker.org/)
- [MX Toolbox](https://mxtoolbox.com/DNSLookup.aspx)

Or use command line:
```bash
# Check CNAME record
nslookup -type=CNAME book.customdomain.com

# Check TXT record
nslookup -type=TXT customdomain.com

# Using dig (Linux/Mac)
dig CNAME book.customdomain.com
dig TXT customdomain.com
```

## Database Fields

The `ServiceProvider` model includes these domain-related fields:

| Field | Type | Description |
|-------|------|-------------|
| `custom_domain` | CharField | Full domain name |
| `custom_domain_type` | CharField | 'none', 'subdomain', or 'domain' |
| `domain_verified` | BooleanField | Whether domain is verified |
| `domain_verification_code` | CharField | Random verification code |
| `ssl_enabled` | BooleanField | Whether to force HTTPS |
| `domain_added_at` | DateTimeField | When domain was added |

## Security Considerations

1. **Domain Ownership Verification**: Always verify domain ownership before activating
2. **HTTPS Enforcement**: Enable SSL for all custom domains in production
3. **Rate Limiting**: Consider rate limiting domain verification requests
4. **Subdomain Validation**: Validate subdomains to prevent abuse

## Dependencies

Install the required package for DNS verification:

```bash
pip install dnspython
```

This is already included in `requirements.txt`.
