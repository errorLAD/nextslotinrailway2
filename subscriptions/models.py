"""
Subscription Plan model and payment tracking.
"""
from django.db import models
from django.core.validators import MinValueValidator


class SubscriptionPlan(models.Model):
    """
    Subscription plans available for service providers.
    """
    
    PLAN_TYPE_CHOICES = [
        ('free', 'Free Plan'),
        ('pro', 'Pro Plan'),
    ]
    
    name = models.CharField(
        max_length=50,
        unique=True,
        help_text='Plan name (e.g., "Free", "Pro")'
    )
    
    plan_type = models.CharField(
        max_length=10,
        choices=PLAN_TYPE_CHOICES,
        unique=True
    )
    
    price_monthly = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)],
        help_text='Monthly price in INR'
    )
    
    max_appointments_per_month = models.IntegerField(
        null=True,
        blank=True,
        help_text='Maximum appointments per month (null = unlimited)'
    )
    
    max_services = models.IntegerField(
        null=True,
        blank=True,
        help_text='Maximum number of services (null = unlimited)'
    )
    
    features = models.JSONField(
        default=dict,
        help_text='JSON object containing plan features'
    )
    
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this plan is currently available'
    )
    
    display_order = models.IntegerField(
        default=0,
        help_text='Order in which to display plans'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Subscription Plan'
        verbose_name_plural = 'Subscription Plans'
        ordering = ['display_order', 'price_monthly']
    
    def __str__(self):
        return f"{self.name} - ₹{self.price_monthly}/month"
    
    @property
    def is_free(self):
        return self.plan_type == 'free'
    
    @property
    def is_pro(self):
        return self.plan_type == 'pro'


class Payment(models.Model):
    """
    Payment transaction records for subscription upgrades.
    """
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('refunded', 'Refunded'),
    ]
    
    provider = models.ForeignKey(
        'providers.ServiceProvider',
        on_delete=models.CASCADE,
        related_name='payments'
    )
    
    plan = models.ForeignKey(
        SubscriptionPlan,
        on_delete=models.SET_NULL,
        null=True,
        related_name='payments'
    )
    
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    
    razorpay_order_id = models.CharField(
        max_length=100,
        blank=True,
        help_text='Razorpay order ID'
    )
    
    razorpay_payment_id = models.CharField(
        max_length=100,
        blank=True,
        help_text='Razorpay payment ID'
    )
    
    razorpay_signature = models.CharField(
        max_length=200,
        blank=True,
        help_text='Razorpay signature for verification'
    )
    
    payment_method = models.CharField(
        max_length=50,
        blank=True
    )
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Payment'
        verbose_name_plural = 'Payments'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Payment #{self.id} - {self.provider.business_name} - ₹{self.amount}"
