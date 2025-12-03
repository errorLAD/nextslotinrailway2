# 🔐 Razorpay Payment Integration Guide

## 📋 Complete Setup Instructions

### **Step 1: Create Razorpay Account**

1. Visit https://razorpay.com/
2. Sign up for a free account
3. Complete KYC verification (for production)
4. Get your API keys:
   - **Test Mode Keys** (for development)
   - **Live Mode Keys** (for production)

### **Step 2: Get API Keys**

1. Login to Razorpay Dashboard
2. Go to **Settings** → **API Keys**
3. Generate Test Keys:
   - **Key ID**: `rzp_test_xxxxxxxxxx`
   - **Key Secret**: `xxxxxxxxxx` (keep this secret!)

### **Step 3: Add to Environment Variables**

Update your `.env` file:

```env
# Razorpay Configuration
RAZORPAY_KEY_ID=rzp_test_xxxxxxxxxx
RAZORPAY_KEY_SECRET=your_secret_key_here
RAZORPAY_WEBHOOK_SECRET=your_webhook_secret_here
```

### **Step 4: Install Razorpay SDK**

Already in `requirements.txt`:
```bash
pip install razorpay==1.4.1
```

---

## 💳 Test Cards

For testing in development:

### **Success:**
- **Card Number:** 4111 1111 1111 1111
- **CVV:** Any 3 digits
- **Expiry:** Any future date
- **OTP:** 1234

### **Failure:**
- **Card Number:** 4111 1111 1111 1112
- **CVV:** Any 3 digits
- **Expiry:** Any future date

### **UPI Test:**
- **UPI ID:** success@razorpay
- **UPI ID (Failure):** failure@razorpay

---

## 🔄 Payment Flow

```
1. User clicks "Upgrade to PRO" (₹199)
         ↓
2. Backend creates Razorpay order
         ↓
3. Frontend opens Razorpay checkout modal
         ↓
4. User completes payment (UPI/Card/Netbanking)
         ↓
5. Razorpay sends payment_id and signature
         ↓
6. Backend verifies signature (security check)
         ↓
7. If valid: Upgrade to PRO for 30 days
         ↓
8. Send confirmation email & WhatsApp
         ↓
9. Redirect to success page
```

---

## 🔒 Security

### **Signature Verification:**
Razorpay sends a signature to verify the payment is genuine:

```python
import hmac
import hashlib

# Create signature
generated_signature = hmac.new(
    key=RAZORPAY_KEY_SECRET.encode(),
    msg=f"{razorpay_order_id}|{razorpay_payment_id}".encode(),
    digestmod=hashlib.sha256
).hexdigest()

# Compare with received signature
if generated_signature == razorpay_signature:
    # Payment is genuine
    upgrade_to_pro()
```

### **Webhook Verification:**
```python
# Verify webhook signature
def verify_webhook_signature(payload, signature, secret):
    expected_signature = hmac.new(
        key=secret.encode(),
        msg=payload.encode(),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)
```

---

## 🎯 Pricing Structure

### **FREE Plan:**
- **Price:** ₹0/month
- **Appointments:** 5 per month
- **Services:** 3 maximum
- **Features:** Basic booking page, email notifications

### **PRO Plan:**
- **Price:** ₹199/month
- **Appointments:** Unlimited
- **Services:** Unlimited
- **Features:** All features + WhatsApp notifications + Priority support

---

## 📊 Payment Model

```python
class Payment(models.Model):
    provider = models.ForeignKey(ServiceProvider, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    razorpay_order_id = models.CharField(max_length=100)
    razorpay_payment_id = models.CharField(max_length=100, blank=True)
    razorpay_signature = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20, default='pending')
    plan_purchased = models.CharField(max_length=10, default='pro')
    payment_date = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateField(null=True, blank=True)
```

---

## 🔔 Webhooks

### **Setup Webhook:**
1. Go to Razorpay Dashboard → **Webhooks**
2. Add webhook URL: `https://yourdomain.com/webhooks/razorpay/`
3. Select events: `payment.captured`, `payment.failed`
4. Get webhook secret

### **Events:**
- `payment.captured` - Payment successful
- `payment.failed` - Payment failed
- `payment.authorized` - Payment authorized (for later capture)

---

## 🧪 Testing

### **Test Mode:**
```python
# In development, use test keys
RAZORPAY_KEY_ID = 'rzp_test_xxxxxxxxxx'

# Test payment flow:
1. Create order
2. Use test card: 4111 1111 1111 1111
3. Enter OTP: 1234
4. Payment succeeds
5. Webhook fires
6. User upgraded to PRO
```

### **Production:**
```python
# In production, use live keys
RAZORPAY_KEY_ID = 'rzp_live_xxxxxxxxxx'

# Real payments processed
# KYC must be completed
# Bank account verified
```

---

## 📧 Email Notifications

### **Payment Success:**
```
Subject: Payment Successful - PRO Plan Activated

Hi {name},

Your payment of ₹199 has been received successfully!

Your PRO plan is now active and will be valid until {expiry_date}.

Enjoy unlimited bookings and all PRO features!

Payment ID: {payment_id}
Amount: ₹199
Date: {date}

Best regards,
BookingSaaS Team
```

### **Plan Expiry Reminder (3 days before):**
```
Subject: Your PRO plan expires in 3 days

Hi {name},

Your PRO plan will expire on {expiry_date}.

Renew now to continue enjoying:
✓ Unlimited appointments
✓ Unlimited services
✓ WhatsApp notifications
✓ Priority support

Renew Now: {renewal_link}

Best regards,
BookingSaaS Team
```

### **Plan Expired:**
```
Subject: Your PRO plan has expired

Hi {name},

Your PRO plan expired on {expiry_date}.

You've been moved to the FREE plan with these limits:
- 5 appointments per month
- Maximum 3 services

Upgrade anytime: {upgrade_link}

Best regards,
BookingSaaS Team
```

---

## 🚀 Go Live Checklist

### **Before Production:**
- [ ] Complete Razorpay KYC
- [ ] Verify bank account
- [ ] Switch to live API keys
- [ ] Update webhook URL to production domain
- [ ] Test payment flow end-to-end
- [ ] Set up SSL certificate (HTTPS required)
- [ ] Configure email server
- [ ] Test webhook signature verification
- [ ] Set up error monitoring (Sentry)
- [ ] Create refund policy page
- [ ] Add Terms & Conditions
- [ ] Add Privacy Policy

---

## 💡 Best Practices

1. **Always verify signatures** - Never trust client-side data
2. **Use webhooks** - Don't rely only on frontend callbacks
3. **Log all transactions** - Keep audit trail
4. **Handle failures gracefully** - Show user-friendly error messages
5. **Test thoroughly** - Use test mode extensively
6. **Secure your keys** - Never commit to Git
7. **Monitor payments** - Set up alerts for failed payments
8. **Provide receipts** - Email invoice after payment
9. **Handle duplicates** - Check if payment already processed
10. **Set up refunds** - Have a refund process in place

---

## 🐛 Common Issues

### **Payment not updating:**
- Check webhook is configured
- Verify webhook signature
- Check server logs
- Ensure webhook URL is accessible

### **Signature verification fails:**
- Check key secret is correct
- Ensure order_id and payment_id are in correct order
- Use HMAC-SHA256 algorithm

### **Webhook not firing:**
- Check webhook URL is HTTPS (required in production)
- Verify webhook secret
- Check Razorpay dashboard for webhook logs

---

## 📞 Support

- **Razorpay Docs:** https://razorpay.com/docs/
- **API Reference:** https://razorpay.com/docs/api/
- **Support:** support@razorpay.com
- **Test Dashboard:** https://dashboard.razorpay.com/

---

**Ready to accept payments! 💰**
