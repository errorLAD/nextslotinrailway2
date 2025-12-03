"""
AI-powered features using OpenAI API.
Includes smart suggestions, no-show prediction, and content generation.
"""
import openai
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import logging
import json

logger = logging.getLogger(__name__)

# Initialize OpenAI
openai.api_key = settings.OPENAI_API_KEY


def call_openai_api(prompt, model="gpt-3.5-turbo", max_tokens=500, temperature=0.7, cache_key=None, cache_timeout=3600):
    """
    Call OpenAI API with caching and error handling.
    
    Args:
        prompt: The prompt to send to OpenAI
        model: Model to use (gpt-4 or gpt-3.5-turbo)
        max_tokens: Maximum tokens in response
        temperature: Creativity level (0-1)
        cache_key: Optional cache key to store response
        cache_timeout: Cache timeout in seconds
    
    Returns:
        str: AI response or None if failed
    """
    # Check cache first
    if cache_key:
        cached_response = cache.get(cache_key)
        if cached_response:
            logger.info(f"Using cached AI response for {cache_key}")
            return cached_response
    
    # Check if API key is configured
    if not settings.OPENAI_API_KEY:
        logger.warning("OpenAI API key not configured")
        return None
    
    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant for a booking management system."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature
        )
        
        result = response.choices[0].message.content.strip()
        
        # Cache the response
        if cache_key:
            cache.set(cache_key, result, cache_timeout)
        
        logger.info(f"OpenAI API call successful. Tokens used: {response.usage.total_tokens}")
        return result
        
    except openai.error.RateLimitError:
        logger.error("OpenAI rate limit exceeded")
        return None
    except openai.error.AuthenticationError:
        logger.error("OpenAI authentication failed - check API key")
        return None
    except Exception as e:
        logger.error(f"OpenAI API error: {str(e)}")
        return None


# ============================================================================
# 1. SMART TIME SLOT SUGGESTIONS
# ============================================================================

def analyze_booking_patterns(provider):
    """
    Analyze historical booking data to find patterns.
    
    Args:
        provider: ServiceProvider instance
    
    Returns:
        dict: Analysis results
    """
    from appointments.models import Appointment
    
    # Get appointments from last 3 months
    three_months_ago = timezone.now().date() - timedelta(days=90)
    
    appointments = Appointment.objects.filter(
        service_provider=provider,
        appointment_date__gte=three_months_ago,
        status__in=['completed', 'confirmed']
    ).values('appointment_date', 'appointment_time', 'status')
    
    if not appointments:
        return None
    
    # Analyze by day of week
    day_counts = {}
    hour_counts = {}
    no_show_by_hour = {}
    
    for apt in appointments:
        day = apt['appointment_date'].weekday()
        hour = apt['appointment_time'].hour
        
        day_counts[day] = day_counts.get(day, 0) + 1
        hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        if apt['status'] == 'no_show':
            no_show_by_hour[hour] = no_show_by_hour.get(hour, 0) + 1
    
    # Find busiest and slowest times
    busiest_day = max(day_counts, key=day_counts.get) if day_counts else None
    slowest_day = min(day_counts, key=day_counts.get) if day_counts else None
    busiest_hour = max(hour_counts, key=hour_counts.get) if hour_counts else None
    slowest_hour = min(hour_counts, key=hour_counts.get) if hour_counts else None
    
    return {
        'total_appointments': len(appointments),
        'day_counts': day_counts,
        'hour_counts': hour_counts,
        'no_show_by_hour': no_show_by_hour,
        'busiest_day': busiest_day,
        'slowest_day': slowest_day,
        'busiest_hour': busiest_hour,
        'slowest_hour': slowest_hour,
    }


def get_smart_time_suggestions(provider, date, service=None):
    """
    Get AI-powered time slot suggestions based on historical data.
    
    Args:
        provider: ServiceProvider instance
        date: Date to suggest times for
        service: Optional service to consider
    
    Returns:
        dict: Suggestions with reasoning
    """
    # Analyze patterns
    patterns = analyze_booking_patterns(provider)
    
    if not patterns:
        return {
            'suggestions': [],
            'reasoning': 'Not enough historical data for AI suggestions.'
        }
    
    # Create prompt for OpenAI
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    target_day = date.weekday()
    
    prompt = f"""
Based on the following booking data for {provider.business_name}, suggest the best 3 time slots for {day_names[target_day]}:

Historical Data:
- Total appointments: {patterns['total_appointments']}
- Busiest day: {day_names[patterns['busiest_day']]} if patterns['busiest_day'] is not None else 'N/A'}
- Slowest day: {day_names[patterns['slowest_day']] if patterns['slowest_day'] is not None else 'N/A'}
- Busiest hour: {patterns['busiest_hour']}:00
- Slowest hour: {patterns['slowest_hour']}:00
- No-show patterns by hour: {patterns['no_show_by_hour']}

Provide 3 recommended time slots (in 24-hour format) with brief reasoning for each.
Format: HH:00 - Reason (one line per suggestion)
"""
    
    cache_key = f"time_suggestions_{provider.id}_{date}_{service.id if service else 'all'}"
    
    response = call_openai_api(
        prompt,
        model="gpt-3.5-turbo",
        max_tokens=300,
        temperature=0.5,
        cache_key=cache_key,
        cache_timeout=86400  # Cache for 24 hours
    )
    
    if not response:
        # Fallback to rule-based suggestions
        return {
            'suggestions': [
                {'time': '10:00', 'reason': 'Morning slots typically have lower no-show rates'},
                {'time': '14:00', 'reason': 'Early afternoon is usually less busy'},
                {'time': '16:00', 'reason': 'Late afternoon slots are popular'},
            ],
            'reasoning': 'AI unavailable - showing default suggestions'
        }
    
    # Parse AI response
    suggestions = []
    for line in response.split('\n'):
        if '-' in line and ':' in line:
            try:
                time_part, reason = line.split('-', 1)
                time = time_part.strip()
                suggestions.append({
                    'time': time,
                    'reason': reason.strip()
                })
            except:
                continue
    
    return {
        'suggestions': suggestions[:3],
        'reasoning': 'AI-powered suggestions based on your booking history'
    }


# ============================================================================
# 2. NO-SHOW PREDICTION
# ============================================================================

def calculate_no_show_risk(appointment):
    """
    Calculate no-show risk for an appointment using AI.
    
    Args:
        appointment: Appointment instance
    
    Returns:
        dict: Risk assessment
    """
    from appointments.models import Appointment
    
    # Get client's history
    client_history = Appointment.objects.filter(
        client_phone=appointment.client_phone,
        service_provider=appointment.service_provider
    ).exclude(id=appointment.id)
    
    total_bookings = client_history.count()
    no_shows = client_history.filter(status='no_show').count()
    completed = client_history.filter(status='completed').count()
    
    # Get time-based patterns
    hour = appointment.appointment_time.hour
    day_of_week = appointment.appointment_date.weekday()
    
    # Historical no-show rate for this time
    time_no_shows = Appointment.objects.filter(
        service_provider=appointment.service_provider,
        appointment_time__hour=hour,
        status='no_show'
    ).count()
    
    time_total = Appointment.objects.filter(
        service_provider=appointment.service_provider,
        appointment_time__hour=hour
    ).count()
    
    time_no_show_rate = (time_no_shows / time_total * 100) if time_total > 0 else 0
    
    # Create AI prompt
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    prompt = f"""
Analyze the no-show risk for this appointment:

Client History:
- Total bookings: {total_bookings}
- No-shows: {no_shows}
- Completed: {completed}
- Client reliability: {(completed / total_bookings * 100) if total_bookings > 0 else 'New client'}%

Appointment Details:
- Day: {day_names[day_of_week]}
- Time: {hour}:00
- Historical no-show rate for this time: {time_no_show_rate:.1f}%

Provide:
1. Risk level (LOW/MEDIUM/HIGH)
2. Risk percentage (0-100)
3. Brief recommendation (one sentence)

Format: RISK_LEVEL|PERCENTAGE|Recommendation
"""
    
    cache_key = f"no_show_risk_{appointment.id}"
    
    response = call_openai_api(
        prompt,
        model="gpt-3.5-turbo",
        max_tokens=150,
        temperature=0.3,
        cache_key=cache_key,
        cache_timeout=3600  # Cache for 1 hour
    )
    
    if not response:
        # Fallback to rule-based prediction
        if total_bookings == 0:
            risk_level = 'MEDIUM'
            risk_percentage = 30
            recommendation = 'New client - send confirmation reminder'
        elif no_shows / total_bookings > 0.3 if total_bookings > 0 else False:
            risk_level = 'HIGH'
            risk_percentage = 70
            recommendation = 'High no-show history - send multiple reminders'
        else:
            risk_level = 'LOW'
            risk_percentage = 15
            recommendation = 'Reliable client - standard reminder'
        
        return {
            'risk_level': risk_level,
            'risk_percentage': risk_percentage,
            'recommendation': recommendation,
            'ai_powered': False
        }
    
    # Parse AI response
    try:
        parts = response.split('|')
        risk_level = parts[0].strip()
        risk_percentage = int(parts[1].strip())
        recommendation = parts[2].strip()
    except:
        # Fallback if parsing fails
        risk_level = 'MEDIUM'
        risk_percentage = 30
        recommendation = 'Unable to assess - send standard reminder'
    
    return {
        'risk_level': risk_level,
        'risk_percentage': risk_percentage,
        'recommendation': recommendation,
        'ai_powered': True
    }


# ============================================================================
# 3. AUTOMATED CONTENT GENERATION
# ============================================================================

def generate_service_description(service_name, business_type, language='english'):
    """
    Generate professional service description using AI.
    
    Args:
        service_name: Name of the service
        business_type: Type of business (salon, fitness, etc.)
        language: 'english' or 'hindi'
    
    Returns:
        str: Generated description
    """
    lang_instruction = "in English" if language == 'english' else "in Hindi (Devanagari script)"
    
    prompt = f"""
Write a professional, engaging description for this service {lang_instruction}:

Service: {service_name}
Business Type: {business_type}

Requirements:
- 2-3 sentences
- Highlight benefits
- Professional tone
- Include what clients can expect

Description:
"""
    
    cache_key = f"service_desc_{service_name}_{business_type}_{language}"
    
    response = call_openai_api(
        prompt,
        model="gpt-3.5-turbo",
        max_tokens=200,
        temperature=0.7,
        cache_key=cache_key,
        cache_timeout=604800  # Cache for 7 days
    )
    
    if not response:
        # Fallback description
        if language == 'hindi':
            return f"{service_name} - एक पेशेवर सेवा जो आपकी जरूरतों को पूरा करती है।"
        return f"{service_name} - A professional service tailored to meet your needs."
    
    return response


def generate_email_template(purpose, provider_name, language='english'):
    """
    Generate email template for various purposes.
    
    Args:
        purpose: 'welcome', 'reminder', 'cancellation', 'promotion'
        provider_name: Business name
        language: 'english' or 'hindi'
    
    Returns:
        dict: Subject and body
    """
    lang_instruction = "in English" if language == 'english' else "in Hindi (Devanagari script)"
    
    purpose_descriptions = {
        'welcome': 'welcoming a new client',
        'reminder': 'reminding about an upcoming appointment',
        'cancellation': 'informing about appointment cancellation',
        'promotion': 'promoting a special offer'
    }
    
    prompt = f"""
Create a professional email template {lang_instruction} for {purpose_descriptions.get(purpose, purpose)}:

Business: {provider_name}
Purpose: {purpose}

Provide:
1. Subject line
2. Email body (3-4 sentences, warm and professional)

Format:
SUBJECT: [subject line]
BODY: [email body]
"""
    
    cache_key = f"email_template_{purpose}_{provider_name}_{language}"
    
    response = call_openai_api(
        prompt,
        model="gpt-3.5-turbo",
        max_tokens=300,
        temperature=0.7,
        cache_key=cache_key,
        cache_timeout=604800  # Cache for 7 days
    )
    
    if not response:
        # Fallback templates
        if language == 'hindi':
            return {
                'subject': f'{provider_name} से संदेश',
                'body': 'आपकी सेवा के लिए धन्यवाद।'
            }
        return {
            'subject': f'Message from {provider_name}',
            'body': 'Thank you for choosing our services.'
        }
    
    # Parse response
    try:
        lines = response.split('\n')
        subject = ''
        body = ''
        
        for line in lines:
            if line.startswith('SUBJECT:'):
                subject = line.replace('SUBJECT:', '').strip()
            elif line.startswith('BODY:'):
                body = line.replace('BODY:', '').strip()
            elif body:  # Continue body if already started
                body += ' ' + line.strip()
        
        return {
            'subject': subject or f'Message from {provider_name}',
            'body': body or response
        }
    except:
        return {
            'subject': f'Message from {provider_name}',
            'body': response
        }


# ============================================================================
# 4. AI CHATBOT FOR CLIENT QUERIES
# ============================================================================

def chatbot_response(user_message, provider, conversation_history=None):
    """
    Generate chatbot response for client queries.
    
    Args:
        user_message: Client's message
        provider: ServiceProvider instance
        conversation_history: List of previous messages
    
    Returns:
        str: Chatbot response
    """
    # Build context about the business
    services = provider.services.filter(is_active=True)
    service_list = ', '.join([f"{s.service_name} (₹{s.price})" for s in services[:5]])
    
    context = f"""
You are a helpful assistant for {provider.business_name}, a {provider.get_business_type_display()} business.

Business Information:
- Name: {provider.business_name}
- Type: {provider.get_business_type_display()}
- Location: {provider.city}, {provider.state}
- Phone: {provider.phone}
- Services: {service_list}

Guidelines:
- Be friendly and professional
- Answer questions about services, pricing, and booking
- If asked about availability, suggest they check the booking page
- Keep responses concise (2-3 sentences)
- Use simple language
"""
    
    # Build conversation history
    messages = [
        {"role": "system", "content": context}
    ]
    
    if conversation_history:
        for msg in conversation_history[-5:]:  # Last 5 messages
            messages.append(msg)
    
    messages.append({"role": "user", "content": user_message})
    
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=200,
            temperature=0.7
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"Chatbot error: {str(e)}")
        # Fallback response
        return f"Thank you for your message! For immediate assistance, please call us at {provider.phone} or visit our booking page."


# ============================================================================
# COST OPTIMIZATION
# ============================================================================

def estimate_monthly_cost(api_calls_per_day, avg_tokens_per_call=500):
    """
    Estimate monthly OpenAI API costs.
    
    Args:
        api_calls_per_day: Expected API calls per day
        avg_tokens_per_call: Average tokens per call
    
    Returns:
        dict: Cost estimates
    """
    # GPT-3.5-turbo pricing (as of 2024)
    cost_per_1k_tokens = 0.002  # $0.002 per 1K tokens
    
    monthly_calls = api_calls_per_day * 30
    monthly_tokens = monthly_calls * avg_tokens_per_call
    monthly_cost = (monthly_tokens / 1000) * cost_per_1k_tokens
    
    return {
        'monthly_calls': monthly_calls,
        'monthly_tokens': monthly_tokens,
        'monthly_cost_usd': round(monthly_cost, 2),
        'monthly_cost_inr': round(monthly_cost * 83, 2),  # Approximate INR conversion
        'per_call_cost': round(monthly_cost / monthly_calls, 4)
    }
