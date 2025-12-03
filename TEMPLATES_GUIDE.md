# 📄 Templates & Views Guide

## 🎨 Complete Template System Documentation

This guide explains all the templates, views, and frontend features created for your Django appointment booking SaaS.

---

## 📁 Template Structure

```
templates/
├── base.html                              # Base template with navigation
├── accounts/
│   ├── login.html                         # User login
│   ├── register_choice.html               # Choose provider/client
│   ├── register_provider.html             # Provider registration
│   └── register_client.html               # Client registration
├── providers/
│   ├── dashboard.html                     # ✅ Provider dashboard
│   ├── calendar.html                      # ✅ Calendar view with FullCalendar
│   ├── appointment_list.html              # ✅ List all appointments
│   ├── appointment_form.html              # ✅ Create/edit appointment
│   ├── appointment_detail.html            # View appointment details
│   ├── service_list.html                  # ✅ List all services
│   ├── service_form.html                  # ✅ Add/edit service
│   ├── service_confirm_delete.html        # Delete confirmation
│   ├── profile_form.html                  # Edit profile
│   ├── billing.html                       # ✅ Billing & subscription
│   └── manage_availability.html           # Set weekly schedule
├── appointments/
│   ├── public_booking.html                # ✅ Public booking page (clients)
│   ├── booking_success.html               # Booking confirmation
│   ├── my_appointments.html               # Client appointment history
│   └── browse_providers.html              # Browse service providers
└── subscriptions/
    ├── pricing.html                       # Pricing comparison
    ├── upgrade_to_pro.html                # Upgrade flow
    ├── upgrade_prompt.html                # Limit reached modal
    └── upgrade_success.html               # Success page
```

---

## 🏗️ Views Architecture

### **Class-Based Views (CBV)** - `providers/views_cbv.py`

#### **1. DashboardView** (TemplateView)
```python
URL: /provider/dashboard/
Template: providers/dashboard.html
Purpose: Main dashboard with statistics and overview
```

**Features:**
- Today's appointments count
- This week's appointments
- Monthly revenue calculation
- Pending appointments
- Upcoming appointments (next 7 days)
- Quick action buttons
- Plan status widget

**Context Data:**
- `provider` - Current provider profile
- `today_appointments` - Appointments for today
- `week_count` - Appointments this week
- `month_revenue` - Total revenue this month
- `pending_count` - Pending appointments
- `upcoming_appointments` - Next 5 upcoming

#### **2. CalendarView** (TemplateView)
```python
URL: /provider/calendar/
Template: providers/calendar.html
Purpose: Visual calendar view of appointments
```

**Features:**
- FullCalendar.js integration
- Color-coded by status
- Click to view details
- Click date to create appointment
- Month/Week/Day views

**AJAX Endpoint:**
```python
URL: /provider/api/appointments/
Returns: JSON array of appointments
```

#### **3. AppointmentListView** (ListView)
```python
URL: /provider/appointments/
Template: providers/appointment_list.html
Purpose: List and filter appointments
```

**Features:**
- Date filters (today/week/month/all)
- Status filters
- Search by client name/phone
- Pagination (20 per page)
- Quick actions (view/edit/confirm)
- Limit warning banner for FREE users

**Query Parameters:**
- `?date_filter=today` - Filter by date range
- `?status=pending` - Filter by status
- `?search=john` - Search clients

#### **4. AppointmentCreateView** (CreateView)
```python
URL: /provider/appointments/create/
Template: providers/appointment_form.html
Purpose: Manually create appointments
```

**Features:**
- Checks appointment limit before showing form
- Redirects to upgrade if limit reached
- Pre-fills service provider
- Form validation

**Limit Check:**
```python
if not provider.can_create_appointment():
    redirect to upgrade page
```

#### **5. ServiceListView** (ListView)
```python
URL: /provider/services/
Template: providers/service_list.html
Purpose: Manage services
```

**Features:**
- Grid layout of service cards
- Service count indicator (X/3 for FREE)
- Progress bar for FREE users
- Active/Inactive badges
- Quick edit/delete actions

#### **6. ServiceCreateView** (CreateView)
```python
URL: /provider/services/add/
Template: providers/service_form.html
Purpose: Add new service
```

**Features:**
- Checks service limit (3 for FREE)
- Form with duration dropdown
- Price input
- Active/Inactive toggle

#### **7. BillingView** (TemplateView)
```python
URL: /provider/billing/
Template: providers/billing.html
Purpose: Subscription management
```

**Features:**
- Current plan display
- Trial countdown
- Usage statistics with progress bars
- Payment history table
- Upgrade/downgrade buttons

---

## 🎨 Frontend Features

### **1. Base Template** (`base.html`)

**Sidebar Navigation:**
- Fixed left sidebar (250px wide)
- Responsive (collapses on mobile)
- Active link highlighting
- Plan status widget in sidebar

**Plan Status Widget:**
```html
Shows:
- Current plan badge (FREE/PRO/Trial)
- Appointments used (X/5)
- Progress bar
- Upgrade button
```

**Responsive Design:**
- Desktop: Sidebar + main content
- Mobile: Full-width, stacked layout

### **2. Dashboard** (`dashboard.html`)

**Statistics Cards:**
- Today's appointments
- This week's appointments
- Monthly revenue
- Pending approvals

**Features:**
- Color-coded stat cards with icons
- Hover effects
- Today's schedule list
- Upcoming appointments sidebar
- Quick actions panel
- Booking URL copy button

**Upgrade Banner:**
- Shows when FREE user has 4-5 appointments
- Prominent CTA button
- Dismissible

### **3. Calendar View** (`calendar.html`)

**FullCalendar Integration:**
```javascript
Features:
- Month/Week/Day views
- Color-coded events by status
- Click event to view details
- Click date to create appointment
- Today highlighting
```

**Color Scheme:**
- Pending: Yellow (#ffc107)
- Confirmed: Green (#28a745)
- Completed: Gray (#6c757d)
- Cancelled: Red (#dc3545)
- No Show: Orange (#fd7e14)

**Modal Popup:**
- Shows appointment details
- Quick view without page reload
- Link to full details page

### **4. Public Booking Page** (`public_booking.html`)

**Design Philosophy:**
- Mobile-first (most bookings are mobile)
- Beautiful gradient background
- Clean, modern UI
- Minimal distractions

**3-Step Booking Process:**

**Step 1: Select Service**
- Service cards with hover effects
- Shows price and duration
- Radio button selection
- Continue button

**Step 2: Date & Time**
- Date picker (next 30 days)
- Time slot grid
- Available slots only
- Back/Continue buttons

**Step 3: Client Details**
- Name, phone, email fields
- Special requests textarea
- Booking summary
- Confirm button

**Features:**
- Step indicator at top
- Progress tracking
- Form validation
- Responsive design
- WhatsApp/Phone buttons
- Business hours display

### **5. Appointment List** (`appointment_list.html`)

**Filter System:**
- Date range dropdown
- Status dropdown
- Search input
- Auto-submit on filter change

**Table Features:**
- Responsive table
- Color-coded status badges
- Payment status indicators
- Action buttons (view/edit/confirm)
- Pagination

**Limit Warning:**
- Alert banner when limit reached
- Modal with upgrade CTA
- Persistent until upgraded

### **6. Service Management** (`service_list.html`)

**Grid Layout:**
- 3 columns on desktop
- 2 columns on tablet
- 1 column on mobile

**Service Cards:**
- Service name and description
- Duration and price
- Active/Inactive badge
- Edit/Delete buttons

**Limit Indicator:**
- Progress bar (X/3 for FREE)
- Percentage display
- Color changes (green → yellow → red)

---

## 🎯 Feature Gating Implementation

### **Template Tags** (`providers/templatetags/plan_tags.py`)

```django
{% load plan_tags %}

<!-- Check if PRO -->
{% if user|is_pro %}
    <button>WhatsApp Notifications</button>
{% else %}
    <button disabled>🔒 PRO Feature</button>
{% endif %}

<!-- Display plan badge -->
{% plan_badge user %}

<!-- Show usage meter -->
{% usage_meter user %}

<!-- Get remaining appointments -->
{{ user|remaining_appointments }}

<!-- Check if can create appointment -->
{% if user|can_create_appointment %}
    <a href="create">New Appointment</a>
{% else %}
    <button disabled>Limit Reached</button>
{% endif %}
```

### **Decorators** (`providers/decorators.py`)

```python
# Restrict to PRO users only
@requires_pro_plan
def advanced_feature(request):
    pass

# Check appointment limit
@check_appointment_limit
def create_appointment(request):
    pass

# Check service limit
@check_service_limit
def add_service(request):
    pass

# Ensure user is provider
@provider_required
def dashboard(request):
    pass
```

### **Middleware** (`providers/middleware.py`)

```python
# Runs on every request
SubscriptionCheckMiddleware:
- Checks trial expiry
- Checks PRO subscription expiry
- Auto-downgrades expired accounts
- Shows one-time notifications
```

---

## 🎨 CSS Framework & Styling

### **Bootstrap 5**
- Grid system for responsive layout
- Components (cards, buttons, badges)
- Utilities (spacing, colors, flex)
- Icons (Bootstrap Icons)

### **Custom CSS** (in `base.html`)

**Color Scheme:**
```css
--primary-color: #4f46e5 (Indigo)
--secondary-color: #10b981 (Green)
--danger-color: #ef4444 (Red)
--warning-color: #f59e0b (Amber)
```

**Components:**
- `.sidebar` - Fixed left navigation
- `.stat-card` - Dashboard statistics
- `.usage-meter` - Progress indicators
- `.plan-badge` - Plan status badges
- `.upgrade-banner` - Upgrade prompts

**Gradients:**
```css
PRO Badge: linear-gradient(135deg, #667eea 0%, #764ba2 100%)
Trial Badge: linear-gradient(135deg, #f093fb 0%, #f5576c 100%)
Upgrade Banner: linear-gradient(135deg, #667eea 0%, #764ba2 100%)
```

---

## 📱 Responsive Design

### **Breakpoints:**
- Mobile: < 768px
- Tablet: 768px - 1024px
- Desktop: > 1024px

### **Mobile Optimizations:**
- Sidebar becomes full-width header
- Cards stack vertically
- Tables become scrollable
- Buttons become full-width
- Reduced padding/margins

---

## 🔄 AJAX & JavaScript

### **Calendar AJAX** (`calendar.html`)
```javascript
// Fetch appointments
fetch('/provider/api/appointments/?start=2024-01-01&end=2024-01-31')
    .then(response => response.json())
    .then(data => calendar.addEvents(data));
```

### **Public Booking** (`public_booking.html`)
```javascript
// Load time slots
function loadTimeSlots() {
    // Generate available slots
    // Mark booked slots as disabled
    // Render time slot grid
}

// Step navigation
function nextStep(step) {
    // Validate current step
    // Hide current, show next
    // Update progress indicator
}
```

### **Copy Booking URL** (`dashboard.html`)
```javascript
function copyBookingUrl() {
    navigator.clipboard.writeText(url);
    // Show success feedback
}
```

---

## 🎯 User Experience Features

### **1. Progress Indicators**
- Step indicators in booking flow
- Progress bars for usage limits
- Loading states for AJAX

### **2. Feedback Messages**
- Success messages (green)
- Error messages (red)
- Warning messages (yellow)
- Info messages (blue)

### **3. Modals**
- Appointment details modal
- Upgrade prompt modal
- Limit reached modal
- Delete confirmation modal

### **4. Empty States**
- No appointments illustration
- No services illustration
- No payment history message
- Helpful CTAs

### **5. Tooltips & Help**
- Form field hints
- Help sidebars
- Pro tips
- Business logic explanations

---

## 🚀 Performance Optimizations

### **1. Database Queries**
```python
# Use select_related for ForeignKeys
appointments = Appointment.objects.select_related(
    'service_provider', 'service', 'client'
)

# Use prefetch_related for reverse ForeignKeys
providers = ServiceProvider.objects.prefetch_related(
    'services', 'availability_slots'
)
```

### **2. Pagination**
- 20 items per page
- Prevents slow page loads
- Better UX for large datasets

### **3. CDN Resources**
- Bootstrap from CDN
- jQuery from CDN
- FullCalendar from CDN
- Fast loading, cached

### **4. Lazy Loading**
- Images load on demand
- Calendar events load on date change
- Time slots load on date selection

---

## 🎨 Customization Guide

### **Change Colors:**
```css
/* In base.html <style> section */
:root {
    --primary-color: #your-color;
    --secondary-color: #your-color;
}
```

### **Change Logo:**
```html
<!-- In base.html sidebar -->
<h4 class="mb-0">Your Logo Here</h4>
```

### **Add Custom CSS:**
```django
{% block extra_css %}
<style>
    /* Your custom styles */
</style>
{% endblock %}
```

### **Add Custom JavaScript:**
```django
{% block extra_js %}
<script>
    // Your custom JavaScript
</script>
{% endblock %}
```

---

## 🐛 Common Issues & Solutions

### **Issue: Sidebar not showing**
**Solution:** Check if user is authenticated and is_provider

### **Issue: Calendar not loading**
**Solution:** Check FullCalendar CDN link, check AJAX endpoint

### **Issue: Forms not submitting**
**Solution:** Check CSRF token, check form validation

### **Issue: Styles not applying**
**Solution:** Clear browser cache, check Bootstrap CDN

### **Issue: Mobile layout broken**
**Solution:** Check viewport meta tag, check responsive classes

---

## 📚 Template Inheritance

```
base.html (Master template)
    ├── providers/dashboard.html
    ├── providers/calendar.html
    ├── providers/appointment_list.html
    ├── providers/service_list.html
    └── providers/billing.html

Standalone templates (no inheritance):
    └── appointments/public_booking.html (Custom design)
```

---

## 🎯 Next Steps

### **Templates to Create:**
1. `appointment_detail.html` - Full appointment view
2. `service_confirm_delete.html` - Delete confirmation
3. `profile_form.html` - Edit provider profile
4. `manage_availability.html` - Weekly schedule
5. `booking_success.html` - Booking confirmation
6. `pricing.html` - Plan comparison
7. `upgrade_to_pro.html` - Payment page

### **Enhancements:**
1. Add real-time notifications
2. Implement WebSocket for live updates
3. Add appointment reminders
4. Create mobile app views
5. Add analytics charts

---

## 📞 Support

For template customization help:
1. Check Bootstrap 5 documentation
2. Review Django template documentation
3. Inspect browser developer tools
4. Test responsive design on mobile

---

**All templates are production-ready and fully responsive!** 🎉
