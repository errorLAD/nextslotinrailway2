"""
Template tags for subscription plan features.
"""
from django import template

register = template.Library()


@register.filter
def is_pro(user):
    """
    Check if user has PRO plan access.
    Usage: {% if user|is_pro %}
    """
    if hasattr(user, 'provider_profile'):
        return user.provider_profile.is_pro()
    return False


@register.filter
def remaining_appointments(user):
    """
    Get remaining appointments for the month.
    Usage: {{ user|remaining_appointments }}
    """
    if hasattr(user, 'provider_profile'):
        return user.provider_profile.remaining_appointments()
    return 0


@register.filter
def appointments_used(user):
    """
    Get number of appointments used this month.
    Usage: {{ user|appointments_used }}
    """
    if hasattr(user, 'provider_profile'):
        return user.provider_profile.appointments_this_month
    return 0


@register.filter
def mul(value, arg):
    """
    Multiply two numeric values in templates.
    Usage: {{ value|mul:arg }}
    """
    try:
        return float(value) * float(arg)
    except (TypeError, ValueError):
        return 0


@register.filter
def can_create_appointment(user):
    """
    Check if user can create more appointments.
    Usage: {% if user|can_create_appointment %}
    """
    if hasattr(user, 'provider_profile'):
        return user.provider_profile.can_create_appointment()
    return False


@register.filter
def can_add_service(user):
    """
    Check if user can add more services.
    Usage: {% if user|can_add_service %}
    """
    if hasattr(user, 'provider_profile'):
        return user.provider_profile.can_add_service()
    return False


@register.simple_tag
def plan_badge(user):
    """
    Display plan badge HTML.
    Usage: {% plan_badge user %}
    """
    if not hasattr(user, 'provider_profile'):
        return ''
    
    provider = user.provider_profile
    
    if provider.is_on_trial():
        return '<span class="badge bg-success">PRO (Trial)</span>'
    elif provider.is_pro():
        return '<span class="badge bg-primary">PRO</span>'
    else:
        return '<span class="badge bg-secondary">FREE</span>'


@register.inclusion_tag('providers/includes/usage_meter.html')
def usage_meter(user):
    """
    Display usage meter for FREE plan users.
    Usage: {% usage_meter user %}
    """
    if not hasattr(user, 'provider_profile'):
        return {'show': False}
    
    provider = user.provider_profile
    
    if provider.has_pro_features():
        return {
            'show': True,
            'is_pro': True,
            'plan_name': provider.get_plan_display_name()
        }
    
    # FREE plan - show usage
    used = provider.appointments_this_month
    total = 5
    percentage = (used / total) * 100 if total > 0 else 0
    remaining = provider.remaining_appointments()
    
    return {
        'show': True,
        'is_pro': False,
        'used': used,
        'total': total,
        'remaining': remaining,
        'percentage': percentage,
        'plan_name': 'FREE'
    }


@register.inclusion_tag('providers/includes/pro_feature_lock.html')
def pro_feature_lock(feature_name):
    """
    Display lock icon for PRO features.
    Usage: {% pro_feature_lock "WhatsApp Notifications" %}
    """
    return {
        'feature_name': feature_name
    }
