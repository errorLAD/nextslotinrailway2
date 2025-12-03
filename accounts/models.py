"""
Custom User Model for multi-tenant authentication.
Supports both service providers and clients with email-based login.
"""
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    """
    Custom user manager where email is the unique identifier
    instead of username.
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a regular user with the given email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('user_type', 'provider')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model with email-based authentication.
    Supports two user types: service providers and clients.
    """
    
    USER_TYPE_CHOICES = [
        ('provider', 'Service Provider'),
        ('client', 'Client'),
    ]
    
    email = models.EmailField(
        verbose_name='Email Address',
        max_length=255,
        unique=True,
        help_text='Required. Enter a valid email address.'
    )
    
    first_name = models.CharField(
        max_length=150,
        blank=True,
        verbose_name='First Name'
    )
    
    last_name = models.CharField(
        max_length=150,
        blank=True,
        verbose_name='Last Name'
    )
    
    user_type = models.CharField(
        max_length=10,
        choices=USER_TYPE_CHOICES,
        default='client',
        help_text='Select whether this user is a service provider or a client.'
    )
    
    phone = models.CharField(
        max_length=15,
        blank=True,
        null=True,
        help_text='Contact phone number'
    )
    
    is_active = models.BooleanField(
        default=True,
        help_text='Designates whether this user should be treated as active. '
                  'Unselect this instead of deleting accounts.'
    )
    
    is_staff = models.BooleanField(
        default=False,
        help_text='Designates whether the user can log into the admin site.'
    )
    
    date_joined = models.DateTimeField(
        default=timezone.now,
        verbose_name='Date Joined'
    )
    
    last_login = models.DateTimeField(
        blank=True,
        null=True,
        verbose_name='Last Login'
    )
    
    # Use email as the username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email is already required by default
    
    objects = CustomUserManager()
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = f'{self.first_name} {self.last_name}'.strip()
        return full_name if full_name else self.email
    
    def get_short_name(self):
        """
        Return the short name for the user.
        """
        return self.first_name if self.first_name else self.email.split('@')[0]
    
    @property
    def is_provider(self):
        """Check if user is a service provider."""
        return self.user_type == 'provider'
    
    @property
    def is_client(self):
        """Check if user is a client."""
        return self.user_type == 'client'
