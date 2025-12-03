"""
URL configuration for subscriptions app.
"""
from django.urls import path
from . import views

app_name = 'subscriptions'

urlpatterns = [
    # Pricing & Plans
    path('', views.pricing_page, name='pricing'),
    path('compare/', views.compare_plans, name='compare_plans'),
    
    # Upgrade Flow
    path('upgrade/', views.upgrade_to_pro, name='upgrade_to_pro'),
    path('upgrade/prompt/', views.upgrade_prompt, name='upgrade_prompt'),
    path('upgrade/success/', views.upgrade_success, name='upgrade_success'),
    
    # Payment
    path('checkout/<str:plan>/', views.checkout, name='checkout'),
    path('payment/create-order/', views.create_payment_order, name='create_payment_order'),
    path('payment/verify/', views.verify_payment, name='verify_payment'),
    
    # Contact
    path('contact/', views.contact_sales, name='contact'),
    
    # Downgrade
    path('downgrade/', views.downgrade_to_free, name='downgrade_to_free'),
]

# Webhook endpoint (outside app namespace for easier access)
webhook_urlpatterns = [
    path('webhooks/razorpay/', views.razorpay_webhook, name='razorpay_webhook'),
]
