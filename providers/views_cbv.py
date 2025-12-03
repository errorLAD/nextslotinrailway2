"""
Class-Based Views for service provider dashboard.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.views.generic import (
    ListView, CreateView, UpdateView, DeleteView, DetailView, TemplateView, View
)
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.urls import reverse_lazy
from django.utils import timezone
from django.http import JsonResponse
from django.db.models import Q, Sum, Count
from datetime import timedelta
from .models import ServiceProvider, Service, Availability
from .forms import ServiceProviderForm, ServiceForm, AppointmentForm, AvailabilityForm
from .decorators import provider_required, check_service_limit, check_appointment_limit
from appointments.models import Appointment


class ProviderRequiredMixin(LoginRequiredMixin):
    """
    Mixin to ensure user is a service provider.
    """
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        
        if not request.user.is_provider:
            messages.error(request, 'This page is only accessible to service providers.')
            return redirect('accounts:login')
        
        if not hasattr(request.user, 'provider_profile'):
            messages.info(request, 'Please complete your provider profile.')
            return redirect('providers:setup_profile')
        
        return super().dispatch(request, *args, **kwargs)


class DashboardView(ProviderRequiredMixin, TemplateView):
    """
    Provider dashboard home with overview statistics.
    """
    template_name = 'providers/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        provider = self.request.user.provider_profile
        today = timezone.now().date()
        
        # Today's appointments
        today_appointments = Appointment.objects.filter(
            service_provider=provider,
            appointment_date=today
        ).order_by('appointment_time')
        
        # This week's appointments
        week_start = today - timedelta(days=today.weekday())
        week_end = week_start + timedelta(days=6)
        week_appointments = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__range=[week_start, week_end]
        )
        
        # This month's revenue
        month_start = today.replace(day=1)
        month_revenue = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__gte=month_start,
            payment_status='paid'
        ).aggregate(total=Sum('total_price'))['total'] or 0
        
        # Pending appointments
        pending_count = Appointment.objects.filter(
            service_provider=provider,
            status='pending'
        ).count()
        
        # Upcoming appointments (next 7 days)
        upcoming = Appointment.objects.filter(
            service_provider=provider,
            appointment_date__range=[today, today + timedelta(days=7)],
            status__in=['pending', 'confirmed']
        ).order_by('appointment_date', 'appointment_time')[:5]
        
        context.update({
            'provider': provider,
            'today_appointments': today_appointments,
            'today_count': today_appointments.count(),
            'week_count': week_appointments.count(),
            'month_revenue': month_revenue,
            'pending_count': pending_count,
            'upcoming_appointments': upcoming,
            'services_count': provider.services.filter(is_active=True).count(),
        })
        
        return context


class AppointmentListView(ProviderRequiredMixin, ListView):
    """
    List all appointments with filters.
    """
    model = Appointment
    template_name = 'providers/appointment_list.html'
    context_object_name = 'appointments'
    paginate_by = 20
    
    def get_queryset(self):
        provider = self.request.user.provider_profile
        queryset = Appointment.objects.filter(
            service_provider=provider
        ).select_related('service', 'client').order_by('-appointment_date', '-appointment_time')
        
        # Filter by date range
        date_filter = self.request.GET.get('date_filter', 'all')
        today = timezone.now().date()
        
        if date_filter == 'today':
            queryset = queryset.filter(appointment_date=today)
        elif date_filter == 'week':
            week_start = today - timedelta(days=today.weekday())
            week_end = week_start + timedelta(days=6)
            queryset = queryset.filter(appointment_date__range=[week_start, week_end])
        elif date_filter == 'month':
            month_start = today.replace(day=1)
            queryset = queryset.filter(appointment_date__gte=month_start)
        
        # Filter by status
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Search by client name or phone
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                Q(client_name__icontains=search) |
                Q(client_phone__icontains=search) |
                Q(client_email__icontains=search)
            )
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        provider = self.request.user.provider_profile
        
        context.update({
            'provider': provider,
            'date_filter': self.request.GET.get('date_filter', 'all'),
            'status_filter': self.request.GET.get('status', ''),
            'search': self.request.GET.get('search', ''),
        })
        
        return context


class AppointmentCreateView(ProviderRequiredMixin, CreateView):
    """
    Create new appointment (manual booking by provider).
    """
    model = Appointment
    form_class = AppointmentForm
    template_name = 'providers/appointment_form.html'
    success_url = reverse_lazy('providers:appointment_list')
    
    def dispatch(self, request, *args, **kwargs):
        # Check appointment limit for FREE plan
        provider = request.user.provider_profile
        if not provider.can_create_appointment():
            messages.error(
                request,
                f'You\'ve reached your monthly limit of {provider.appointments_this_month} appointments. '
                f'Upgrade to PRO for unlimited bookings!'
            )
            return redirect('subscriptions:upgrade_prompt')
        
        return super().dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['provider'] = self.request.user.provider_profile
        return kwargs
    
    def form_valid(self, form):
        form.instance.service_provider = self.request.user.provider_profile
        messages.success(self.request, 'Appointment created successfully!')
        return super().form_valid(form)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['provider'] = self.request.user.provider_profile
        return context


class AppointmentUpdateView(ProviderRequiredMixin, UpdateView):
    """
    Edit existing appointment.
    """
    model = Appointment
    form_class = AppointmentForm
    template_name = 'providers/appointment_form.html'
    success_url = reverse_lazy('providers:appointment_list')
    
    def get_queryset(self):
        return Appointment.objects.filter(
            service_provider=self.request.user.provider_profile
        )
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['provider'] = self.request.user.provider_profile
        return kwargs
    
    def form_valid(self, form):
        messages.success(self.request, 'Appointment updated successfully!')
        return super().form_valid(form)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['provider'] = self.request.user.provider_profile
        context['is_edit'] = True
        return context


class AppointmentDetailView(ProviderRequiredMixin, DetailView):
    """
    View appointment details.
    """
    model = Appointment
    template_name = 'providers/appointment_detail.html'
    context_object_name = 'appointment'
    
    def get_queryset(self):
        return Appointment.objects.filter(
            service_provider=self.request.user.provider_profile
        ).select_related('service', 'client')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['provider'] = self.request.user.provider_profile
        return context


class ServiceListView(ProviderRequiredMixin, ListView):
    """
    List all services.
    """
    model = Service
    template_name = 'providers/service_list.html'
    context_object_name = 'services'
    
    def get_queryset(self):
        return Service.objects.filter(
            service_provider=self.request.user.provider_profile
        ).order_by('-is_active', 'service_name')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        provider = self.request.user.provider_profile
        
        context.update({
            'provider': provider,
            'can_add_more': provider.can_add_service(),
            'service_count': self.get_queryset().count(),
            'max_services': 3 if not provider.has_pro_features() else 'Unlimited',
        })
        
        return context


class ServiceCreateView(ProviderRequiredMixin, CreateView):
    """
    Create new service.
    """
    model = Service
    form_class = ServiceForm
    template_name = 'providers/service_form.html'
    success_url = reverse_lazy('providers:service_list')
    
    def dispatch(self, request, *args, **kwargs):
        # Check service limit for FREE plan
        provider = request.user.provider_profile
        if not provider.can_add_service():
            messages.error(
                request,
                'Free plan allows maximum 3 services. Upgrade to PRO to add unlimited services!'
            )
            return redirect('subscriptions:upgrade_prompt')
        
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        form.instance.service_provider = self.request.user.provider_profile
        messages.success(self.request, f'Service "{form.instance.service_name}" added successfully!')
        return super().form_valid(form)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['provider'] = self.request.user.provider_profile
        return context


class ServiceUpdateView(ProviderRequiredMixin, UpdateView):
    """
    Edit existing service.
    """
    model = Service
    form_class = ServiceForm
    template_name = 'providers/service_form.html'
    success_url = reverse_lazy('providers:service_list')
    
    def get_queryset(self):
        return Service.objects.filter(
            service_provider=self.request.user.provider_profile
        )
    
    def form_valid(self, form):
        messages.success(self.request, 'Service updated successfully!')
        return super().form_valid(form)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['provider'] = self.request.user.provider_profile
        context['is_edit'] = True
        return context


class ServiceDeleteView(ProviderRequiredMixin, DeleteView):
    """
    Delete service.
    """
    model = Service
    template_name = 'providers/service_confirm_delete.html'
    success_url = reverse_lazy('providers:service_list')
    
    def get_queryset(self):
        return Service.objects.filter(
            service_provider=self.request.user.provider_profile
        )
    
    def delete(self, request, *args, **kwargs):
        service = self.get_object()
        messages.success(request, f'Service "{service.service_name}" deleted successfully!')
        return super().delete(request, *args, **kwargs)


class ProfileUpdateView(ProviderRequiredMixin, UpdateView):
    """
    Edit provider profile.
    """
    model = ServiceProvider
    form_class = ServiceProviderForm
    template_name = 'providers/profile_form.html'
    success_url = reverse_lazy('providers:dashboard')
    
    def get_object(self):
        return self.request.user.provider_profile
    
    def form_valid(self, form):
        messages.success(self.request, 'Profile updated successfully!')
        return super().form_valid(form)


class BillingView(ProviderRequiredMixin, TemplateView):
    """
    Billing and subscription management.
    """
    template_name = 'providers/billing.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        provider = self.request.user.provider_profile
        
        # Get payment history
        from subscriptions.models import Payment
        payments = Payment.objects.filter(
            provider=provider
        ).order_by('-created_at')[:10]
        
        context.update({
            'provider': provider,
            'payments': payments,
        })
        
        return context


class CalendarView(ProviderRequiredMixin, TemplateView):
    """
    Calendar view of appointments.
    """
    template_name = 'providers/calendar.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['provider'] = self.request.user.provider_profile
        return context


@method_decorator(csrf_exempt, name='dispatch')
class AppointmentsJSONView(ProviderRequiredMixin, View):
    """
    Return appointments as JSON for calendar.
    """
    model = Appointment
    
    def get(self, request, *args, **kwargs):
        try:
            appointments = []
            
            # Debug: Print request data
            print(f"[DEBUG] Request GET params: {request.GET}")
            
            try:
                # Get provider profile with error handling
                provider = request.user.provider_profile
                print(f"[DEBUG] Found provider profile: {provider}")
            except ServiceProvider.DoesNotExist:
                print("[ERROR] Provider profile does not exist for user:", request.user)
                return JsonResponse(
                    {'error': 'Provider profile not found. Please complete your provider profile setup.'}, 
                    status=400
                )
                
            start_date = request.GET.get('start')
            end_date = request.GET.get('end')
            
            print(f"[DEBUG] Querying appointments for provider: {provider.id}, date range: {start_date} to {end_date}")
            
            # Get all appointments for the provider with error handling
            try:
                queryset = Appointment.objects.filter(
                    service_provider=provider
                ).select_related('service', 'client')
                print(f"[DEBUG] Initial queryset count: {queryset.count()}")
            except Exception as e:
                print(f"[ERROR] Error querying appointments: {str(e)}")
                return JsonResponse(
                    {'error': 'Error retrieving appointments', 'details': str(e)}, 
                    status=500
                )
            
            try:
                if start_date and end_date:
                    # Clean up date strings if they include timezone info
                    start_date = start_date.split('T')[0]
                    end_date = end_date.split('T')[0]
                    print(f"[DEBUG] Filtering by date range: {start_date} to {end_date}")
                    queryset = queryset.filter(
                        appointment_date__range=[start_date, end_date]
                    )
                
                print(f"[DEBUG] Filtered queryset count: {queryset.count()}")
            except Exception as e:
                print(f"[ERROR] Error filtering appointments by date: {str(e)}")
                return JsonResponse(
                    {'error': 'Invalid date range', 'details': str(e)},
                    status=400
                )
            
            # Color code by status
            color_map = {
                'pending': '#ffc107',  # Yellow
                'confirmed': '#28a745',  # Green
                'completed': '#6c757d',  # Gray
                'cancelled': '#dc3545',  # Red
                'no_show': '#fd7e14',  # Orange
            }
            
            for apt in queryset:
                try:
                    # Ensure required fields exist
                    if not all([apt.appointment_date, apt.appointment_time, apt.service]):
                        print(f"[WARNING] Skipping appointment {apt.id} - missing required fields")
                        print(f"[DEBUG] Appointment {apt.id} data - date: {apt.appointment_date}, time: {apt.appointment_time}, service: {getattr(apt, 'service', None)}")
                        continue
                    
                    appointments.append({
                        'id': apt.id,
                        'title': f'{apt.client_name or "Client"} - {getattr(apt.service, "service_name", "Service")}',
                        'start': f'{apt.appointment_date}T{apt.appointment_time}',
                        'end': f'{apt.appointment_date}T{apt.appointment_time}',
                        'backgroundColor': color_map.get(apt.status, '#007bff'),
                        'borderColor': color_map.get(apt.status, '#007bff'),
                        'extendedProps': {
                            'client_name': apt.client_name or "",
                            'client_phone': getattr(apt, 'client_phone', '') or "",
                            'service': getattr(apt.service, 'service_name', '') if hasattr(apt, 'service') and apt.service else "",
                            'status': getattr(apt, 'status', 'pending') or "pending",
                            'price': str(getattr(apt, 'total_price', '0.00')) if hasattr(apt, 'total_price') and apt.total_price is not None else "0.00",
                        }
                    })
                    
                except Exception as apt_error:
                    print(f"[ERROR] Error processing appointment {getattr(apt, 'id', 'unknown')}: {str(apt_error)}")
                    continue
                
            print(f"[DEBUG] Successfully processed {len(appointments)} appointments")
            
            try:
                response = JsonResponse(appointments, safe=False)
                # Add CORS headers
                response["Access-Control-Allow-Origin"] = "*"
                response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                response["Access-Control-Max-Age"] = "1000"
                response["Access-Control-Allow-Headers"] = "X-Requested-With, Content-Type"
                return response
            except Exception as json_error:
                print(f"[ERROR] Error creating JSON response: {str(json_error)}")
                return JsonResponse(
                    {'error': 'Error creating response', 'details': str(json_error)},
                    status=500
                )
            
        except Exception as e:
            import traceback
            error_details = {
                'error': str(e),
                'traceback': traceback.format_exc()
            }
            print(f"[CRITICAL] Unhandled error in AppointmentsJSONView: {error_details}")
            return JsonResponse(
                {'error': 'Internal server error', 'details': 'An unexpected error occurred'}, 
                status=500
            )
    
    # Handle OPTIONS for CORS preflight
    def options(self, request, *args, **kwargs):
        response = JsonResponse({}, status=200)
        response["Access-Control-Allow-Origin"] = "*"
        response["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response["Access-Control-Max-Age"] = "1000"
        response["Access-Control-Allow-Headers"] = "X-Requested-With, Content-Type"
        return response
    
    # Support POST for FullCalendar's JSONP requests
    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)
