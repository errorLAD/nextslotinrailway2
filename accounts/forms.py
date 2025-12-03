"""
Forms for user registration and authentication.
"""
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser


class ProviderRegistrationForm(UserCreationForm):
    """
    Form for service provider registration with complete business details.
    """
    
    email = forms.EmailField(
        max_length=255,
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'your.email@example.com',
            'autocomplete': 'email'
        }),
        help_text='We\'ll send a verification link to this email'
    )
    
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First name',
            'autocomplete': 'given-name'
        })
    )
    
    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last name',
            'autocomplete': 'family-name'
        })
    )
    
    phone = forms.CharField(
        max_length=15,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '9876543210',
            'autocomplete': 'tel'
        }),
        help_text='10-digit mobile number'
    )
    
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Create a strong password',
            'autocomplete': 'new-password'
        }),
        help_text='Minimum 8 characters'
    )
    
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm your password',
            'autocomplete': 'new-password'
        })
    )
    
    terms_accepted = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label='I agree to the Terms & Conditions and Privacy Policy'
    )
    
    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'phone', 'password1', 'password2', 'terms_accepted']
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError('An account with this email already exists.')
        return email
    
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        # Remove any non-digit characters
        phone = ''.join(filter(str.isdigit, phone))
        
        if len(phone) != 10:
            raise forms.ValidationError('Please enter a valid 10-digit phone number.')
        
        return phone
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.user_type = 'provider'
        if commit:
            user.save()
        return user


class ClientRegistrationForm(UserCreationForm):
    """
    Form for client registration.
    """
    
    email = forms.EmailField(
        max_length=255,
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email address'
        })
    )
    
    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'First name'
        })
    )
    
    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Last name'
        })
    )
    
    phone = forms.CharField(
        max_length=15,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Phone number'
        })
    )
    
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Create a password'
        })
    )
    
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        })
    )
    
    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'phone', 'password1', 'password2']
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.user_type = 'client'
        if commit:
            user.save()
        return user


class CustomLoginForm(AuthenticationForm):
    """
    Custom login form with styled fields.
    """
    
    username = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autofocus': True
        })
    )
    
    password = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        })
    )
