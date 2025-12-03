"""
URL configuration for appointments app.
"""
from django.urls import path
from . import views
from . import views_api

app_name = 'appointments'

urlpatterns = [
    # Public booking pages
    path('book/<slug:slug>/', views.public_booking_page, name='public_booking'),
    path('book/<slug:slug>/confirm/', views.confirm_booking, name='confirm_booking'),
    path('booking/success/<int:pk>/', views.booking_success, name='booking_success'),
    
    # API endpoints for AJAX
    path('api/slots/<slug:provider_slug>/', views_api.available_slots_api, name='available_slots_api'),
    path('api/check-slot/<slug:provider_slug>/', views_api.check_slot_api, name='check_slot_api'),
    
    # Client appointments
    path('my-appointments/', views.my_appointments, name='my_appointments'),
    path('browse/', views.browse_providers, name='browse_providers'),
]
