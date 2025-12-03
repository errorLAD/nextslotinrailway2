# Admin Panel & Analytics Guide

Complete guide for Django admin customization and analytics dashboard with plan-based feature gating.

## 🎛️ Enhanced Django Admin Panel

### Overview

The admin panel has been customized for easy management with:
- **Colored badges** for status visualization
- **Inline editing** for related models
- **Custom actions** for bulk operations
- **Advanced filters** for data exploration
- **Optimized queries** for performance

### Access Admin Panel

1. Create superuser:
```bash
python manage.py createsuperuser
```

2. Access admin at: `http://localhost:8000/admin/`

## 👥 CustomUser Admin

### Features:
- **List Display**: Email, user type, active status, join date
- **Filters**: User type, active status, join date
- **Search**: Email, first name, last name, phone
- **Fieldsets**: Organized by category

### Common Tasks:

**Activate/Deactivate Users:**
1. Select users in list
2. Choose action: "Activate" or "Deactivate"
3. Click "Go"

**Search Users:**
- Use search box to find by email or name
- Filter by user type (Provider/Client)

## 🏢 ServiceProvider Admin

### Features:
- **Colored Plan Badges**: Visual indication of FREE/PRO/TRIAL
- **Subscription Status**: Days remaining, expiry warnings
- **Inline Editing**: Edit services and availability directly
- **Custom Actions**: Bulk operations for providers
- **Booking Link**: Direct link to provider's booking page

### List Display:
- Business name (with user email link)
- Business type
- City
- Plan badge (colored)
- Subscription status
- Appointments this month
- Verification status
- Active status

### Custom Actions:

**1. Activate/Deactivate Providers**
```
Select providers → Actions → "Activate/Deactivate selected providers"
```

**2. Verify Providers**
```
Select providers → Actions → "Verify selected providers"
```

**3. Upgrade to PRO**
```
Select providers → Actions → "Upgrade to PRO (1 month)"
```
- Automatically upgrades selected providers to PRO plan
- Sets 1-month duration
- Ends trial period

**4. Reset Appointment Counter**
```
Select FREE plan providers → Actions → "Reset appointment counter"
```
- Resets monthly appointment count to 0
- Only affects FREE plan providers

### Inline Editing:

**Services:**
- Add/edit services directly in provider detail page
- Set service name, price, duration, active status

**Availability:**
- Configure working hours for each day
- Set opening/closing times
- Mark days as available/unavailable

### Filters:
- Business type (Salon, Fitness, Healthcare, etc.)
- Current plan (FREE/PRO)
- Verification status
- Active status
- Trial status
- City/State

## 📅 Appointment Admin

### Features:
- **Colored Status Badges**: Visual status indicators
- **Payment Badges**: Payment status visualization
- **Provider Links**: Quick navigation to provider admin
- **Plan Information**: Shows provider's plan in detail view
- **Custom Actions**: Bulk operations with notifications
- **Date Hierarchy**: Easy navigation by date

### List Display:
- ID
- Client name and phone
- Provider (linked)
- Service
- Date and time
- Status badge (colored)
- Payment badge (colored)
- Reminder status
- Created date

### Custom Actions:

**1. Confirm and Notify**
```
Select pending appointments → Actions → "Confirm and notify"
```
- Changes status to "confirmed"
- Sends email confirmation to client
- Sends SMS if provider is on PRO plan
- Queues notifications via Celery

**2. Mark as Completed**
```
Select confirmed appointments → Actions → "Mark as Completed"
```

**3. Cancel and Notify**
```
Select appointments → Actions → "Cancel and notify"
```
- Changes status to "cancelled"
- Sends cancellation email to both client and provider
- Sends SMS if provider is on PRO plan

**4. Mark as No-Show**
```
Select confirmed appointments → Actions → "Mark as No-Show"
```

**5. Mark as Paid**
```
Select appointments → Actions → "Mark as Paid"
```

**6. Send Reminder Notifications**
```
Select appointments → Actions → "Send reminder notifications"
```
- Sends reminder email
- Sends SMS if provider is on PRO plan
- Marks reminder as sent

### Filters:
- Status (Pending, Confirmed, Completed, Cancelled, No-Show)
- Payment status
- Appointment date
- Reminder sent status
- Provider business type
- Provider plan (FREE/PRO)

### Search:
- Appointment ID
- Client name
- Client phone
- Client email
- Provider business name
- Service name

## 💳 SubscriptionPlan Admin

### Features:
- **Editable List View**: Edit directly in list
- **Colored Badges**: Visual plan type indicators
- **Features Display**: Formatted JSON features
- **Price Display**: Currency formatting

### List Display:
- Plan name
- Plan badge (FREE/PRO)
- Price (formatted)
- Appointments limit
- Services limit
- Active status
- Display order

### Editable Fields:
- Active status (checkbox)
- Display order (number)

**Quick Edit:**
1. Click on field in list view
2. Edit value
3. Click "Save" at bottom

### JSON Features Format:
```json
{
  "sms_notifications": true,
  "advanced_analytics": true,
  "priority_support": true,
  "custom_branding": true,
  "api_access": false
}
```

## 💰 Payment Admin

### Features:
- **Colored Status Badges**: Payment status visualization
- **Provider Links**: Quick navigation
- **Custom Actions**: Bulk operations
- **Receipt Sending**: Email receipts to customers

### Custom Actions:

**1. Mark as Successful**
```
Select pending payments → Actions → "Mark as Successful"
```

**2. Mark as Failed**
```
Select pending payments → Actions → "Mark as Failed"
```

**3. Send Payment Receipt**
```
Select successful payments → Actions → "Send payment receipt"
```
- Sends email receipt to provider
- Includes transaction details
- Includes subscription information

### Filters:
- Payment status
- Plan
- Payment date
- Payment method

## 📊 Analytics Dashboard (Plan-Based Feature Gating)

### Access:
```
Provider Dashboard → Analytics
URL: /providers/analytics/
```

### FREE Plan Analytics (Basic)

**Available Features:**
- ✅ Total appointments this month
- ✅ Appointments by status (simple list)
- ✅ Today's appointments
- ✅ Basic statistics

**Locked Features (Teaser):**
- 🔒 Appointments trend chart (blurred)
- 🔒 Revenue analytics (blurred)
- 🔒 Client insights (blurred)
- 🔒 CSV export (disabled)

**Upgrade Prompts:**
- Prominent upgrade banner at top
- Unlock overlays on charts
- "Upgrade to PRO" buttons

### PRO Plan Analytics (Advanced)

**1. Appointments Analytics:**
- Total appointments (this month vs last month)
- Appointments trend (line chart, last 30 days)
- Appointments by status (with counts)
- No-show rate percentage

**2. Revenue Analytics:**
- Total revenue this month
- Revenue trend (bar chart, last 6 months)
- Revenue by service type (doughnut chart)
- Average booking value

**3. Client Analytics:**
- Total unique clients
- New clients this month
- Repeat client rate percentage
- Top 5 clients by bookings (table)

**4. Peak Times:**
- Busiest days of week (bar chart)
- Busiest hours (line chart)

**5. Export Features:**
- CSV export button
- Downloadable analytics data
- All appointments with details

### Charts (Chart.js)

**Appointments Trend:**
- Type: Line chart
- Data: Daily appointments for last 30 days
- Color: Purple gradient

**Revenue Trend:**
- Type: Bar chart
- Data: Monthly revenue for last 6 months
- Color: Green

**Revenue by Service:**
- Type: Doughnut chart
- Data: Revenue breakdown by service
- Colors: Multi-color palette

**Busiest Days:**
- Type: Bar chart
- Data: Appointments by day of week
- Color: Yellow

**Busiest Hours:**
- Type: Line chart
- Data: Appointments by hour
- Color: Red

### CSV Export (PRO Only)

**Access:**
```
Analytics Dashboard → Export CSV button
```

**Includes:**
- Date
- Time
- Client name
- Client phone
- Service
- Duration
- Price
- Status
- Payment status
- Payment method

**Usage:**
```python
# Automatic check in view
if not provider.is_pro():
    return HttpResponse("CSV export is a PRO feature", status=403)
```

### API Endpoints (PRO Only)

**Appointments Trend:**
```
GET /providers/analytics/api/?type=appointments_trend&days=30
```

**Revenue Trend:**
```
GET /providers/analytics/api/?type=revenue_trend&days=180
```

**Response Format:**
```json
{
  "labels": ["Jan 01", "Jan 02", "Jan 03"],
  "data": [5, 8, 6]
}
```

## 🔒 Feature Gating Implementation

### Check PRO Plan in Views:
```python
@login_required
def analytics_dashboard(request):
    provider = request.user.provider_profile
    is_pro = provider.is_pro()
    
    if is_pro:
        # Show advanced analytics
        context['revenue_trend'] = get_revenue_trend()
    else:
        # Show basic stats only
        pass
    
    return render(request, 'analytics.html', context)
```

### Check PRO Plan in Templates:
```django
{% if is_pro %}
    <!-- Advanced charts -->
    <canvas id="revenueChart"></canvas>
{% else %}
    <!-- Locked overlay -->
    <div class="unlock-overlay">
        <h3>🔒 Upgrade to PRO</h3>
        <a href="{% url 'subscriptions:upgrade' %}">Upgrade Now</a>
    </div>
{% endif %}
```

### Check PRO Plan in Admin:
```python
def provider_plan_info(self, obj):
    """Display provider's plan information."""
    if obj.service_provider.is_pro():
        return format_html(
            '<span style="color: green;">PRO Plan</span> '
            '(SMS notifications enabled)'
        )
    else:
        return format_html(
            '<span style="color: gray;">FREE Plan</span> '
            '(Email only)'
        )
```

## 📈 Database Query Optimization

### Select Related:
```python
def get_queryset(self, request):
    return super().get_queryset(request).select_related(
        'service_provider', 'service', 'client'
    )
```

### Prefetch Related:
```python
providers = ServiceProvider.objects.prefetch_related(
    'services', 'availability_slots'
)
```

### Aggregation:
```python
revenue = Appointment.objects.filter(
    service_provider=provider,
    payment_status='paid'
).aggregate(total=Sum('total_price'))
```

### Annotation:
```python
appointments_by_day = Appointment.objects.annotate(
    day=ExtractWeekDay('appointment_date')
).values('day').annotate(count=Count('id'))
```

## 🎨 Admin Styling Tips

### Custom CSS:
Create `static/admin/css/custom_admin.css`:
```css
.status-badge {
    padding: 3px 10px;
    border-radius: 3px;
    font-weight: bold;
    color: white;
}
```

### Register in Admin:
```python
class Media:
    css = {
        'all': ('admin/css/custom_admin.css',)
    }
```

## 🚀 Best Practices

### Admin Panel:
1. **Use select_related/prefetch_related** for performance
2. **Add search_fields** for easy searching
3. **Use list_filter** for data exploration
4. **Create custom actions** for common tasks
5. **Add readonly_fields** for calculated values
6. **Use fieldsets** for organization
7. **Add help_text** for clarity

### Analytics:
1. **Cache expensive queries** with Django cache
2. **Use database aggregation** instead of Python loops
3. **Limit date ranges** for performance
4. **Add loading indicators** for slow queries
5. **Implement pagination** for large datasets
6. **Use async loading** for charts
7. **Add error handling** for edge cases

### Feature Gating:
1. **Always check `provider.is_pro()`** before PRO features
2. **Show upgrade prompts** to FREE users
3. **Provide teasers** of locked features
4. **Make upgrade path clear** with CTAs
5. **Log feature access** for analytics
6. **Handle gracefully** when plan expires

## 🧪 Testing

### Test Admin Actions:
```bash
python manage.py shell
```
```python
from providers.models import ServiceProvider
from appointments.models import Appointment

# Test provider upgrade
provider = ServiceProvider.objects.first()
provider.upgrade_to_pro(duration_months=1)
print(provider.is_pro())  # Should be True

# Test appointment confirmation
appointment = Appointment.objects.first()
appointment.confirm()
print(appointment.status)  # Should be 'confirmed'
```

### Test Analytics:
```python
from providers.views_analytics import analytics_dashboard
from django.test import RequestFactory

factory = RequestFactory()
request = factory.get('/providers/analytics/')
request.user = user

response = analytics_dashboard(request)
print(response.status_code)  # Should be 200
```

## 📝 Maintenance Tasks

### Daily:
- Monitor email/SMS delivery
- Check Celery task status
- Review failed notifications

### Weekly:
- Review analytics performance
- Check database query times
- Monitor storage usage

### Monthly:
- Reset FREE plan counters (automated)
- Send expiry reminders (automated)
- Review admin logs
- Update email templates if needed

## 💡 Tips for Non-Technical Staff

### Admin Panel:
1. **Search is your friend** - Use search box to find anything quickly
2. **Filters narrow down results** - Use left sidebar filters
3. **Actions work on selected items** - Check boxes, then choose action
4. **Click on names to see details** - Most fields are clickable
5. **Save button is at bottom** - Don't forget to save changes

### Common Tasks:
- **Verify a provider**: Find provider → Check "Is verified" → Save
- **Upgrade provider**: Select provider → Actions → "Upgrade to PRO"
- **Confirm appointments**: Select appointments → Actions → "Confirm and notify"
- **Send reminders**: Select appointments → Actions → "Send reminder notifications"

### Safety:
- **Don't delete** unless absolutely sure
- **Test actions on one item** before bulk operations
- **Check filters** before bulk actions
- **Keep backups** of important data
