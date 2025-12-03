"""
URL configuration for booking_saas project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from subscriptions.urls import webhook_urlpatterns
from django.views.generic import RedirectView
from appointments.views import public_booking_page, confirm_booking

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # App URLs
    path('accounts/', include('accounts.urls')),
    path('provider/', include('providers.urls')),
    path('appointments/', include('appointments.urls')),
    path('pricing/', include('subscriptions.urls')),
    
    # Direct public booking pages - accessible via custom domains
    # When a custom domain points here, the middleware redirects to /book/<slug>/
    path('book/<slug:slug>/', public_booking_page, name='public_booking_direct'),
    path('book/<slug:slug>/confirm/', confirm_booking, name='confirm_booking_direct'),
]

# Add webhook URLs (outside app namespace)
urlpatterns += webhook_urlpatterns

# Redirect root to login (only for main domain, custom domains are handled by middleware)
urlpatterns += [
    path('', RedirectView.as_view(url='/accounts/login/', permanent=False)),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Customize admin site
admin.site.site_header = "BookingSaaS Admin"
admin.site.site_title = "BookingSaaS Admin Portal"
admin.site.index_title = "Welcome to BookingSaaS Administration"
