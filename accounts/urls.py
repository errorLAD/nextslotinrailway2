"""
URL configuration for accounts app.
"""
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Registration
    path('register/', views.register_choice_view, name='register_choice'),
    path('register/provider/', views.register_provider_view, name='register_provider'),
    path('register/client/', views.register_client_view, name='register_client'),
    
    # Email Verification
    path('verification-sent/', views.verification_sent_view, name='verification_sent'),
    path('verify-email/<int:user_id>/<str:token>/', views.verify_email_view, name='verify_email'),
    path('resend-verification/', views.resend_verification_view, name='resend_verification'),
    
    # Password Reset (using Django's built-in views)
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(
             template_name='accounts/password_reset.html',
             email_template_name='accounts/password_reset_email.html',
             subject_template_name='accounts/password_reset_subject.txt',
             success_url='/accounts/password-reset/done/'
         ), 
         name='password_reset'),
    
    path('password-reset/done/', 
         auth_views.PasswordResetDoneView.as_view(
             template_name='accounts/password_reset_done.html'
         ), 
         name='password_reset_done'),
    
    path('password-reset-confirm/<uidb64>/<token>/', 
         auth_views.PasswordResetConfirmView.as_view(
             template_name='accounts/password_reset_confirm.html',
             success_url='/accounts/password-reset-complete/'
         ), 
         name='password_reset_confirm'),
    
    path('password-reset-complete/', 
         auth_views.PasswordResetCompleteView.as_view(
             template_name='accounts/password_reset_complete.html'
         ), 
         name='password_reset_complete'),
]
