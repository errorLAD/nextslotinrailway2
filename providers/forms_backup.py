"""
Forms for provider management.
"""
from django import forms
from django.core.exceptions import ValidationError
from .models import ServiceProvider, Service, Availability, ServiceAvailability
from appointments.models import Appointment


class ServiceProviderForm(forms.ModelForm):
    """
    Form for creating/editing service provider profile.
    """
    
    class Meta:
        model = ServiceProvider
        fields = [
            'business_name', 'business_type', 'description',
            'phone', 'whatsapp_number',
            'business_address', 'city', 'state', 'pincode',
            'profile_image'
        ]
        widgets = {
            'business_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Your Business Name'
            }),
            'business_type': forms.Select(attrs={
                'class': 'form-select'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Brief description of your services...'
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '9876543210'
            }),
            'whatsapp_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '9876543210 (optional)'
            }),
            'business_address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Full business address'
            }),
            'city': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'City'
            }),
            'state': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'State'
            }),
            'pincode': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '400001'
            }),
            'profile_image': forms.FileInput(attrs={
                'class': 'form-control'
            })
        }


class ServiceForm(forms.ModelForm):
    """
    Form for creating/editing services with availability settings.
    ""
    use_default_availability = forms.BooleanField(
        required=False,
        initial=True,
        label='Use default provider availability',
        help_text='If checked, this service will use your default working hours. Uncheck to set custom hours.',
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'id': 'id_use_default_availability'
        })
    )
    
    class Meta:
        model = Service
        fields = ['service_name', 'description', 'duration_minutes', 'price', 'is_active']
        widgets = {
            'service_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., Haircut, Yoga Session'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Describe your service...'
            }),
            'duration_minutes': forms.Select(attrs={
                'class': 'form-select'
            }),
            'price': forms.NumberInput(attrs={
                'class': 'form-control',
                'placeholder': '300',
                'step': '0.01'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        
        # Add day of week fields for availability
        for day_num, day_name in Availability.DAY_CHOICES:
            self.fields[f'day_{day_num}_available'] = forms.BooleanField(
                required=False,
                initial=True,
                label=f'{day_name} - Available',
                widget=forms.CheckboxInput(attrs={
                    'class': 'day-available form-check-input',
                    'data-day': day_num
                })
            )
            
            self.fields[f'day_{day_num}_start'] = forms.TimeField(
                required=False,
                label=f'{day_name} - Start Time',
                widget=forms.TimeInput(attrs={
                    'type': 'time',
                    'class': 'form-control timepicker',
                    'data-day': day_num,
                    'disabled': True
                })
            )
            
            self.fields[f'day_{day_num}_end'] = forms.TimeField(
                required=False,
                label=f'{day_name} - End Time',
                widget=forms.TimeInput(attrs={
                    'type': 'time',
                    'class': 'form-control timepicker',
                    'data-day': day_num,
                    'disabled': True
                })
            )
        
        # If editing an existing service, set initial values
        if self.instance and self.instance.pk:
            self.fields['use_default_availability'].initial = not self.instance.service_availability.exists()
            
            # Set initial values for each day
            for avail in self.instance.service_availability.all():
                day = avail.day_of_week
                self.fields[f'day_{day}_available'].initial = avail.is_available
                self.fields[f'day_{day}_start'].initial = avail.start_time
                self.fields[f'day_{day}_end'].initial = avail.end_time
    
    def save(self, commit=True):
        service = super().save(commit=False)
        
        if commit:
            service.save()
            
            # If using default availability, delete any existing custom availability
            if self.cleaned_data.get('use_default_availability'):
                service.service_availability.all().delete()
            else:
                # Save custom availability for each day
                for day_num, _ in Availability.DAY_CHOICES:
                    is_available = self.cleaned_data.get(f'day_{day_num}_available', False)
                    start_time = self.cleaned_data.get(f'day_{day_num}_start')
                    end_time = self.cleaned_data.get(f'day_{day_num}_end')
                    
                    # Only save if both start and end times are provided
                    if start_time and end_time:
                        ServiceAvailability.objects.update_or_create(
                            service=service,
                            day_of_week=day_num,
                            defaults={
                                'is_available': is_available,
                                'start_time': start_time,
                                'end_time': end_time
                            }
                        )
                    else:
                        # Remove if exists but no times provided
                        service.service_availability.filter(day_of_week=day_num).delete()
        
        return service


class AppointmentForm(forms.ModelForm):
    """
    Form for creating/editing appointments (provider side).
    """
    
    class Meta:
        model = Appointment
        fields = [
            'service', 'client_name', 'client_phone', 'client_email',
            'appointment_date', 'appointment_time', 'status',
            'payment_status', 'payment_method', 'notes'
        ]
        widgets = {
            'service': forms.Select(attrs={
                'class': 'form-select'
            }),
            'client_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Client Name'
            }),
            'client_phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '9876543210'
            }),
            'client_email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'client@example.com (optional)'
            }),
            'appointment_date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'appointment_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time'
            }),
            'status': forms.Select(attrs={
                'class': 'form-select'
            }),
            'payment_status': forms.Select(attrs={
                'class': 'form-select'
            }),
            'payment_method': forms.Select(attrs={
                'class': 'form-select'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Special requests or notes...'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.provider = kwargs.pop('provider', None)
        super().__init__(*args, **kwargs)
        
        # Filter services to only show provider's active services
        if self.provider:
            self.fields['service'].queryset = Service.objects.filter(
                service_provider=self.provider,
                is_active=True
            )


class AvailabilityFormSet(forms.BaseFormSet):
    """
    Formset for managing weekly availability.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add day names to forms
        for i, form in enumerate(self.forms):
            form.day_name = dict(Availability.DAY_CHOICES).get(i, '')


def get_availability_formset(provider=None, service=None, **kwargs):
    """Helper function to get the appropriate formset based on context."""
    if service:
        # Service-specific availability formset
        formset = forms.inlineformset_factory(
            Service,
            ServiceAvailability,
            form=ServiceAvailabilityForm,
            extra=0,
            min_num=0,
            max_num=7,  # One for each day of the week
            can_delete=True,
            **kwargs
        )
        return formset
    else:
        # Default availability formset
        formset = forms.inlineformset_factory(
            ServiceProvider,
            Availability,
            form=AvailabilityForm,
            formset=AvailabilityFormSet,
            extra=0,
            min_num=7,  # One for each day of the week
            max_num=7,
            can_delete=False,
            **kwargs
        )
        return formset


class AvailabilityForm(forms.ModelForm):
    """
    Form for single availability slot.
    """
    
    class Meta:
        model = Availability
        fields = ['day_of_week', 'start_time', 'end_time', 'is_available']
        widgets = {
            'day_of_week': forms.HiddenInput(),
            'start_time': forms.TimeInput(attrs={
                'type': 'time',
                'class': 'form-control timepicker'
            }),
            'end_time': forms.TimeInput(attrs={
                'type': 'time',
                'class': 'form-control timepicker'
            }),
            'is_available': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }


class ServiceAvailabilityForm(forms.ModelForm):
    """
    Form for service-specific availability slot.
    """
    
    class Meta:
        model = ServiceAvailability
        fields = ['day_of_week', 'start_time', 'end_time', 'is_available']
        widgets = {
            'day_of_week': forms.Select(attrs={
                'class': 'form-select',
                'onchange': 'this.form.submit()'  # Auto-submit when day changes
            }),
            'start_time': forms.TimeInput(attrs={
                'type': 'time',
                'class': 'form-control timepicker',
                'required': True
            }),
            'end_time': forms.TimeInput(attrs={
                'type': 'time',
                'class': 'form-control timepicker',
                'required': True
            }),
            'is_available': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'onchange': 'this.form.submit()'  # Auto-save when toggled
            })
        }
    
    def clean(self):
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        
        if start_time and end_time and start_time >= end_time:
            raise forms.ValidationError("End time must be after start time")
        
        return cleaned_data


class PublicBookingForm(forms.ModelForm):
    """
    Form for public booking page (client side).
    """
    
    class Meta:
        model = Appointment
        fields = [
            'service', 'client_name', 'client_phone', 'client_email',
            'appointment_date', 'appointment_time', 'notes'
        ]
        widgets = {
            'service': forms.RadioSelect(attrs={
                'class': 'form-check-input'
            }),
            'client_name': forms.TextInput(attrs={
                'class': 'form-control form-control-lg',
                'placeholder': 'Your Full Name',
                'required': True
            }),
            'client_phone': forms.TextInput(attrs={
                'class': 'form-control form-control-lg',
                'placeholder': '9876543210',
                'required': True
            }),
            'client_email': forms.EmailInput(attrs={
                'class': 'form-control form-control-lg',
                'placeholder': 'your.email@example.com (optional)'
            }),
            'appointment_date': forms.DateInput(attrs={
                'class': 'form-control form-control-lg',
                'type': 'date',
                'required': True
            }),
            'appointment_time': forms.TimeInput(attrs={
                'class': 'form-control form-control-lg',
                'type': 'time',
                'required': True
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Any special requests? (optional)'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.provider = kwargs.pop('provider', None)
        super().__init__(*args, **kwargs)
        
        # Filter services to only show provider's active services
        if self.provider:
            self.fields['service'].queryset = Service.objects.filter(
                service_provider=self.provider,
                is_active=True
            )
