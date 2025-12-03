"""
URL configuration for providers app.
"""
from django.urls import path
from . import views
from . import views_cbv
from . import views_analytics
from . import domain_views

app_name = 'providers'

urlpatterns = [
    # Dashboard (Class-Based Views)
    path('dashboard/', views_cbv.DashboardView.as_view(), name='dashboard'),
    path('calendar/', views_cbv.CalendarView.as_view(), name='calendar'),
    path('api/appointments/', views_cbv.AppointmentsJSONView.as_view(), name='appointments_json'),
    
    # Profile Setup (Function-Based for initial setup)
    path('setup/', views.setup_profile, name='setup_profile'),
    path('profile/edit/', views_cbv.ProfileUpdateView.as_view(), name='edit_profile'),
    
    # Services Management (Class-Based Views)
    path('services/', views_cbv.ServiceListView.as_view(), name='service_list'),
    path('services/add/', views_cbv.ServiceCreateView.as_view(), name='add_service'),
    path('services/<int:pk>/edit/', views_cbv.ServiceUpdateView.as_view(), name='edit_service'),
    path('services/<int:pk>/delete/', views_cbv.ServiceDeleteView.as_view(), name='delete_service'),
    
    # Availability Management (Function-Based)
    path('availability/', views.manage_availability, name='manage_availability'),
    
    # Custom Domain Management
    path('domain/settings/', domain_views.domain_settings, name='domain_settings'),
    path('domain/add/', domain_views.add_custom_domain, name='add_custom_domain'),
    path('domain/verify/', domain_views.domain_verification, name='domain_verification'),
    path('domain/verify/check/', domain_views.verify_domain, name='verify_domain'),
    path('domain/remove/', domain_views.remove_domain, name='remove_domain'),
    
    # Appointments (Class-Based Views)
    path('appointments/', views_cbv.AppointmentListView.as_view(), name='appointment_list'),
    path('appointments/create/', views_cbv.AppointmentCreateView.as_view(), name='create_appointment'),
    path('appointments/<int:pk>/', views_cbv.AppointmentDetailView.as_view(), name='appointment_detail'),
    path('appointments/<int:pk>/edit/', views_cbv.AppointmentUpdateView.as_view(), name='edit_appointment'),
    
    # Appointment Actions (Function-Based for quick actions)
    path('appointments/<int:pk>/confirm/', views.confirm_appointment, name='confirm_appointment'),
    path('appointments/<int:pk>/cancel/', views.cancel_appointment, name='cancel_appointment'),
    path('appointments/<int:pk>/complete/', views.complete_appointment, name='complete_appointment'),
    
    # Analytics (PRO feature with FREE teaser)
    path('analytics/', views_analytics.analytics_dashboard, name='analytics'),
    path('analytics/export/', views_analytics.export_analytics_csv, name='export_analytics'),
    path('analytics/api/', views_analytics.analytics_api, name='analytics_api'),
    
    # Billing & Subscription
    path('billing/', views_cbv.BillingView.as_view(), name='billing'),
    
    # Domain Management (PRO feature)
    path('domains/', domain_views.domain_settings, name='domain_settings'),
    path('domains/add/', domain_views.add_custom_domain, name='add_custom_domain'),
    path('domains/verify/', domain_views.domain_verification, name='domain_verification'),
    path('domains/verify/check/', domain_views.verify_domain, name='verify_domain'),
    path('domains/remove/', domain_views.remove_domain, name='remove_domain'),
]
