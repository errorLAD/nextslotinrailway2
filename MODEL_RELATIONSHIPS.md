# 🔗 Database Model Relationships

## Entity Relationship Diagram

```
┌─────────────────┐
│   CustomUser    │
│  (accounts)     │
│─────────────────│
│ • email (PK)    │
│ • password      │
│ • user_type     │
│ • first_name    │
│ • last_name     │
│ • phone         │
│ • is_active     │
│ • date_joined   │
└────────┬────────┘
         │
         │ OneToOne (user_type='provider')
         │
         ▼
┌─────────────────────────────┐
│    ServiceProvider          │
│    (providers)              │
│─────────────────────────────│
│ • user (FK → CustomUser)    │
│ • business_name             │
│ • business_type             │
│ • phone, whatsapp_number    │
│ • business_address          │
│ • current_plan              │
│ • plan_start_date           │
│ • plan_end_date             │
│ • trial_end_date            │
│ • is_trial_active           │
│ • appointments_this_month   │
│ • unique_booking_url        │
│ • profile_image             │
│ • is_verified               │
└────────┬────────────────────┘
         │
         ├─────────────────────────────────┐
         │                                 │
         │ OneToMany                       │ OneToMany
         │                                 │
         ▼                                 ▼
┌─────────────────────┐         ┌──────────────────────┐
│     Service         │         │   Availability       │
│   (providers)       │         │   (providers)        │
│─────────────────────│         │──────────────────────│
│ • service_provider  │         │ • service_provider   │
│   (FK)              │         │   (FK)               │
│ • service_name      │         │ • day_of_week        │
│ • description       │         │ • start_time         │
│ • duration_minutes  │         │ • end_time           │
│ • price             │         │ • is_available       │
│ • is_active         │         └──────────────────────┘
└────────┬────────────┘
         │
         │ OneToMany
         │
         ▼
┌─────────────────────────────────┐
│       Appointment               │
│     (appointments)              │
│─────────────────────────────────│
│ • service_provider (FK)         │
│ • service (FK)                  │
│ • client (FK → CustomUser)      │◄─── ManyToOne
│ • client_name                   │
│ • client_phone                  │
│ • client_email                  │
│ • appointment_date              │
│ • appointment_time              │
│ • status                        │
│ • total_price                   │
│ • payment_status                │
│ • payment_method                │
│ • notes                         │
│ • reminder_sent                 │
└─────────────────────────────────┘


┌─────────────────────────┐
│   SubscriptionPlan      │
│   (subscriptions)       │
│─────────────────────────│
│ • name                  │
│ • plan_type             │
│ • price_monthly         │
│ • max_appointments      │
│ • max_services          │
│ • features (JSON)       │
│ • is_active             │
└────────┬────────────────┘
         │
         │ ManyToOne
         │
         ▼
┌─────────────────────────────┐
│        Payment              │
│     (subscriptions)         │
│─────────────────────────────│
│ • provider (FK)             │
│ • plan (FK)                 │
│ • amount                    │
│ • status                    │
│ • razorpay_order_id         │
│ • razorpay_payment_id       │
│ • razorpay_signature        │
│ • payment_method            │
└─────────────────────────────┘
```

---

## Relationship Details

### 1. **CustomUser ↔ ServiceProvider** (One-to-One)
- **Type:** OneToOneField
- **Cascade:** CASCADE (delete provider when user deleted)
- **Access:** `user.provider_profile` or `provider.user`
- **Purpose:** Separate authentication from business profile

### 2. **ServiceProvider ↔ Service** (One-to-Many)
- **Type:** ForeignKey
- **Cascade:** CASCADE (delete services when provider deleted)
- **Access:** `provider.services.all()` or `service.service_provider`
- **Purpose:** Provider can offer multiple services

### 3. **ServiceProvider ↔ Availability** (One-to-Many)
- **Type:** ForeignKey
- **Cascade:** CASCADE
- **Access:** `provider.availability_slots.all()`
- **Purpose:** Provider has weekly schedule (7 days)
- **Constraint:** One slot per day (unique_together)

### 4. **ServiceProvider ↔ Appointment** (One-to-Many)
- **Type:** ForeignKey
- **Cascade:** CASCADE
- **Access:** `provider.appointments.all()`
- **Purpose:** Track all bookings for a provider

### 5. **Service ↔ Appointment** (One-to-Many)
- **Type:** ForeignKey
- **Cascade:** CASCADE
- **Access:** `service.appointments.all()`
- **Purpose:** Track which service was booked

### 6. **CustomUser ↔ Appointment** (One-to-Many)
- **Type:** ForeignKey (nullable)
- **Cascade:** SET_NULL (keep appointment if user deleted)
- **Access:** `user.appointments.all()`
- **Purpose:** Track client's booking history
- **Note:** Can be null for walk-in customers

### 7. **SubscriptionPlan ↔ Payment** (One-to-Many)
- **Type:** ForeignKey
- **Cascade:** SET_NULL
- **Access:** `plan.payments.all()`
- **Purpose:** Track which plan was purchased

### 8. **ServiceProvider ↔ Payment** (One-to-Many)
- **Type:** ForeignKey
- **Cascade:** CASCADE
- **Access:** `provider.payments.all()`
- **Purpose:** Track payment history

---

## Key Constraints

### Unique Constraints
1. `ServiceProvider.unique_booking_url` - Each provider has unique URL
2. `CustomUser.email` - Email is unique identifier
3. `Service(service_provider, service_name)` - No duplicate service names per provider
4. `Availability(service_provider, day_of_week)` - One schedule per day

### Indexes
1. `Appointment(appointment_date, appointment_time)` - Fast date queries
2. `Appointment(service_provider, status)` - Fast provider queries

---

## Data Flow Examples

### Creating an Appointment
```python
# Get provider by booking URL
provider = ServiceProvider.objects.get(unique_booking_url='johns-salon')

# Get service
service = provider.services.get(service_name='Haircut')

# Create appointment
appointment = Appointment.objects.create(
    service_provider=provider,
    service=service,
    client_name='Jane Doe',
    client_phone='9876543210',
    appointment_date='2024-01-15',
    appointment_time='10:00',
)

# Auto-increment counter (via signal)
provider.increment_appointment_count()
```

### Checking Usage Limits
```python
provider = request.user.provider_profile

# Check if can create appointment
if provider.can_create_appointment():
    # FREE: appointments_this_month < 5
    # PRO: Always True
    create_appointment()
else:
    redirect_to_upgrade_page()

# Check if can add service
if provider.can_add_service():
    # FREE: services.count() < 3
    # PRO: Always True
    add_service()
```

### Upgrade Flow
```python
# Create payment order
payment = Payment.objects.create(
    provider=provider,
    plan=pro_plan,
    amount=199,
    status='pending'
)

# After successful payment
payment.status = 'success'
payment.save()

# Upgrade provider
provider.upgrade_to_pro(duration_months=1)
# Sets: current_plan='pro', plan_end_date=+30 days
```

---

## Query Optimization

### Select Related (ForeignKey)
```python
# Avoid N+1 queries
appointments = Appointment.objects.select_related(
    'service_provider',
    'service',
    'client'
).all()
```

### Prefetch Related (Reverse ForeignKey)
```python
# Load provider with all services
providers = ServiceProvider.objects.prefetch_related(
    'services',
    'availability_slots'
).all()
```

### Aggregation
```python
from django.db.models import Count, Sum

# Count appointments per provider
providers = ServiceProvider.objects.annotate(
    total_appointments=Count('appointments')
)

# Total revenue per provider
providers = ServiceProvider.objects.annotate(
    total_revenue=Sum('appointments__total_price')
)
```

---

## Signals

### Post-Save Signals

1. **CustomUser → ServiceProvider**
   - When provider user created, can auto-create profile
   - Currently manual via setup page

2. **Appointment → ServiceProvider**
   - When appointment created, increment counter
   - `provider.appointments_this_month += 1`

---

## Business Logic

### Plan Management
```python
# Check PRO access
if provider.is_pro():
    # Has active PRO subscription
    pass

if provider.is_on_trial():
    # Within 14-day trial period
    pass

if provider.has_pro_features():
    # PRO or trial (both get PRO features)
    pass
```

### Usage Tracking
```python
# Monthly reset (1st of month)
for provider in ServiceProvider.objects.all():
    provider.reset_monthly_counter()
    # Sets appointments_this_month = 0

# Check expiry (daily)
if provider.plan_end_date < today:
    provider.downgrade_to_free()
```

---

## Data Integrity Rules

1. **Cascade Deletes**
   - Delete user → Delete provider → Delete services/appointments
   - Delete provider → Delete all related data

2. **Soft Deletes**
   - Use `is_active=False` instead of hard delete
   - Preserve historical data

3. **Null Handling**
   - Appointment.client can be null (walk-ins)
   - Payment.plan can be null (if plan deleted)

4. **Default Values**
   - New providers: current_plan='free'
   - New providers: is_trial_active=True
   - Appointments: status='pending'

---

## Migration Order

```bash
1. accounts (CustomUser)
2. providers (ServiceProvider, Service, Availability)
3. subscriptions (SubscriptionPlan, Payment)
4. appointments (Appointment)
```

Run:
```bash
python manage.py makemigrations accounts
python manage.py makemigrations providers
python manage.py makemigrations subscriptions
python manage.py makemigrations appointments
python manage.py migrate
```
