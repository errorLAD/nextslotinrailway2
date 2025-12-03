"""
Forms for staff management (PRO plan only).
"""
from django import forms
from django.forms import inlineformset_factory
from .models_staff import StaffMember, StaffAvailability


class StaffMemberForm(forms.ModelForm):
    """
    Form for creating/editing staff members.
    """
    
    class Meta:
        model = StaffMember
        fields = [
            'name', 'email', 'phone', 'bio',
            'profile_image', 'services', 'is_active', 'display_order'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Full name'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'email@example.com'
            }),
            'phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '+91 9876543210'
            }),
            'bio': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Brief bio or description...'
            }),
            'profile_image': forms.FileInput(attrs={
                'class': 'form-control'
            }),
            'services': forms.CheckboxSelectMultiple(),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'display_order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0
            }),
        }
    
    def __init__(self, *args, **kwargs):
        self.provider = kwargs.pop('provider', None)
        super().__init__(*args, **kwargs)
        
        # Filter services to only show provider's services
        if self.provider:
            self.fields['services'].queryset = self.provider.services.filter(is_active=True)
        
        # Make email optional
        self.fields['email'].required = False
        self.fields['bio'].required = False
        self.fields['profile_image'].required = False


class StaffAvailabilityForm(forms.ModelForm):
    """
    Form for staff availability slots.
    """
    
    class Meta:
        model = StaffAvailability
        fields = ['day_of_week', 'start_time', 'end_time', 'is_available']
        widgets = {
            'day_of_week': forms.Select(attrs={'class': 'form-control'}),
            'start_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time'
            }),
            'end_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time'
            }),
            'is_available': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
        }


# Formset for managing all days of the week
StaffAvailabilityFormSet = inlineformset_factory(
    StaffMember,
    StaffAvailability,
    form=StaffAvailabilityForm,
    extra=7,  # One for each day of the week
    max_num=7,
    can_delete=False
)
