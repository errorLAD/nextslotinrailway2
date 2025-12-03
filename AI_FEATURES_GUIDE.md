# 🤖 AI-Powered Features Guide

## 📋 Overview

This guide covers AI-powered features using OpenAI API:
1. **Smart Time Slot Suggestions** - AI recommends best booking times
2. **No-Show Prediction** - Predict and prevent no-shows
3. **Automated Content Generation** - Generate descriptions and templates
4. **AI Chatbot** - Answer client queries automatically

---

## 🚀 Setup OpenAI API

### Step 1: Get OpenAI API Key

1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in
3. Navigate to API Keys section
4. Click "Create new secret key"
5. Copy the key (starts with `sk-`)

### Step 2: Add to Environment

```bash
# .env
OPENAI_API_KEY=sk-your-actual-api-key-here
```

### Step 3: Install Dependencies

```bash
pip install openai==1.3.5
```

### Step 4: Test Connection

```python
# Test in Django shell
python manage.py shell

>>> from utils.ai_features import call_openai_api
>>> response = call_openai_api("Say hello!")
>>> print(response)
```

---

## 🎯 Feature 1: Smart Time Slot Suggestions

### How It Works

1. **Analyzes Historical Data:**
   - Booking patterns by day of week
   - Booking patterns by hour
   - No-show rates by time slot

2. **AI Processing:**
   - Sends data to OpenAI GPT-3.5
   - AI analyzes patterns
   - Returns 3 best time slots with reasoning

3. **Caching:**
   - Results cached for 24 hours
   - Reduces API costs
   - Faster response times

### Usage

```python
from utils.ai_features import get_smart_time_suggestions
from providers.models import ServiceProvider
from datetime import date, timedelta

provider = ServiceProvider.objects.first()
tomorrow = date.today() + timedelta(days=1)

suggestions = get_smart_time_suggestions(provider, tomorrow)

print(suggestions)
# Output:
# {
#     'suggestions': [
#         {'time': '10:00', 'reason': 'Morning slots have 85% completion rate'},
#         {'time': '14:00', 'reason': 'Early afternoon typically less busy'},
#         {'time': '16:00', 'reason': 'Popular time with low no-show rate'}
#     ],
#     'reasoning': 'AI-powered suggestions based on your booking history'
# }
```

### View Implementation

```python
# In views.py
@login_required
def smart_time_suggestions(request):
    provider = request.user.provider_profile
    date = request.GET.get('date', tomorrow)
    
    suggestions = get_smart_time_suggestions(provider, date)
    
    return render(request, 'smart_suggestions.html', {
        'suggestions': suggestions
    })
```

### Template Example

```html
<div class="ai-suggestions">
    <h3>🤖 AI-Recommended Time Slots</h3>
    {% for suggestion in suggestions.suggestions %}
        <div class="suggestion-card">
            <span class="time">{{ suggestion.time }}</span>
            <p class="reason">{{ suggestion.reason }}</p>
        </div>
    {% endfor %}
</div>
```

---

## 🎯 Feature 2: No-Show Prediction

### How It Works

1. **Client History Analysis:**
   - Past booking count
   - No-show rate
   - Completion rate

2. **Time-Based Analysis:**
   - Historical no-show rate for time slot
   - Day of week patterns

3. **AI Risk Assessment:**
   - Combines all factors
   - Returns risk level (LOW/MEDIUM/HIGH)
   - Provides recommendation

### Usage

```python
from utils.ai_features import calculate_no_show_risk
from appointments.models import Appointment

appointment = Appointment.objects.first()
risk = calculate_no_show_risk(appointment)

print(risk)
# Output:
# {
#     'risk_level': 'HIGH',
#     'risk_percentage': 65,
#     'recommendation': 'Send extra reminder 2 hours before appointment',
#     'ai_powered': True
# }
```

### Automatic Risk Checking

```python
# In appointment creation view
def create_appointment(request):
    # ... create appointment ...
    
    # Calculate no-show risk
    risk = calculate_no_show_risk(appointment)
    
    if risk['risk_level'] == 'HIGH':
        # Send extra reminders
        send_extra_reminder.delay(appointment.id)
        
        # Notify provider
        messages.warning(
            request,
            f"⚠️ High no-show risk ({risk['risk_percentage']}%). "
            f"Recommendation: {risk['recommendation']}"
        )
```

### Dashboard View

```python
@login_required
def no_show_predictions(request):
    provider = request.user.provider_profile
    
    # Get upcoming appointments
    upcoming = Appointment.objects.filter(
        service_provider=provider,
        appointment_date__gte=timezone.now().date(),
        status__in=['pending', 'confirmed']
    )
    
    # Calculate risk for each
    predictions = []
    for apt in upcoming:
        risk = calculate_no_show_risk(apt)
        predictions.append({
            'appointment': apt,
            'risk': risk
        })
    
    # Sort by risk (HIGH first)
    predictions.sort(key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}[x['risk']['risk_level']])
    
    return render(request, 'no_show_predictions.html', {
        'predictions': predictions
    })
```

---

## 🎯 Feature 3: Automated Content Generation

### 3.1 Service Descriptions

Generate professional service descriptions in English or Hindi.

```python
from utils.ai_features import generate_service_description

# English description
description_en = generate_service_description(
    service_name="Deep Tissue Massage",
    business_type="salon",
    language="english"
)
print(description_en)
# "Experience therapeutic relief with our deep tissue massage. 
#  Our skilled therapists target muscle tension and knots, 
#  promoting relaxation and improved circulation."

# Hindi description
description_hi = generate_service_description(
    service_name="डीप टिश्यू मसाज",
    business_type="salon",
    language="hindi"
)
print(description_hi)
# "हमारी डीप टिश्यू मसाज के साथ चिकित्सीय राहत का अनुभव करें।
#  हमारे कुशल चिकित्सक मांसपेशियों के तनाव को लक्षित करते हैं।"
```

### 3.2 Email Templates

Generate email templates for different purposes.

```python
from utils.ai_features import generate_email_template

# Welcome email
template = generate_email_template(
    purpose="welcome",
    provider_name="Serenity Spa",
    language="english"
)

print(template)
# {
#     'subject': 'Welcome to Serenity Spa!',
#     'body': 'We're thrilled to have you as our valued client. 
#              Our team is dedicated to providing you with exceptional 
#              service and a relaxing experience. Book your first 
#              appointment today and discover the difference.'
# }

# Reminder email in Hindi
template_hi = generate_email_template(
    purpose="reminder",
    provider_name="सेरेनिटी स्पा",
    language="hindi"
)
```

### AJAX Implementation

```javascript
// Generate description via AJAX
function generateDescription(serviceId) {
    fetch('/providers/generate-content/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({
            content_type: 'service_description',
            service_id: serviceId,
            language: 'english'
        })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('description').value = data.description;
    });
}
```

---

## 🎯 Feature 4: AI Chatbot

### How It Works

1. **Context Building:**
   - Business information
   - Services and pricing
   - Location and contact

2. **Conversation History:**
   - Maintains last 5 messages
   - Provides context to AI

3. **Response Generation:**
   - AI answers based on context
   - Friendly and professional tone
   - Concise responses (2-3 sentences)

### Usage

```python
from utils.ai_features import chatbot_response
from providers.models import ServiceProvider

provider = ServiceProvider.objects.first()

# Simple query
response = chatbot_response(
    user_message="What services do you offer?",
    provider=provider
)
print(response)
# "We offer a range of services including Deep Tissue Massage (₹1500), 
#  Swedish Massage (₹1200), and Aromatherapy (₹1800). 
#  Would you like to book an appointment?"

# With conversation history
history = [
    {"role": "user", "content": "What are your hours?"},
    {"role": "assistant", "content": "We're open Monday-Saturday, 9 AM to 8 PM."},
]

response = chatbot_response(
    user_message="Can I book for Sunday?",
    provider=provider,
    conversation_history=history
)
print(response)
# "Unfortunately, we're closed on Sundays. However, we'd be happy to 
#  schedule you for Monday or Saturday. Would you like to check availability?"
```

### API Endpoint

```python
# views.py
@require_http_methods(["POST"])
def chatbot_api(request):
    import json
    
    data = json.loads(request.body)
    provider_id = data.get('provider_id')
    message = data.get('message')
    history = data.get('history', [])
    
    provider = get_object_or_404(ServiceProvider, id=provider_id)
    response = chatbot_response(message, provider, history)
    
    return JsonResponse({
        'success': True,
        'response': response
    })
```

### Frontend Implementation

```html
<div id="chatbot">
    <div id="chat-messages"></div>
    <input type="text" id="chat-input" placeholder="Ask a question...">
    <button onclick="sendMessage()">Send</button>
</div>

<script>
let conversationHistory = [];

function sendMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value;
    
    // Add user message to UI
    addMessage('user', message);
    
    // Send to API
    fetch('/api/chatbot/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCookie('csrftoken')
        },
        body: JSON.stringify({
            provider_id: {{ provider.id }},
            message: message,
            history: conversationHistory
        })
    })
    .then(response => response.json())
    .then(data => {
        // Add bot response to UI
        addMessage('bot', data.response);
        
        // Update history
        conversationHistory.push({role: 'user', content: message});
        conversationHistory.push({role: 'assistant', content: data.response});
    });
    
    input.value = '';
}

function addMessage(role, text) {
    const messagesDiv = document.getElementById('chat-messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}`;
    messageDiv.textContent = text;
    messagesDiv.appendChild(messageDiv);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
</script>
```

---

## 💰 Cost Optimization

### Understanding Costs

**GPT-3.5-turbo Pricing (as of 2024):**
- Input: $0.0015 per 1K tokens
- Output: $0.002 per 1K tokens
- Average: ~$0.002 per 1K tokens

**Example Costs:**
- 1 API call ≈ 500 tokens ≈ $0.001
- 1,000 calls/month ≈ $1-2
- 10,000 calls/month ≈ $10-20

### Cost Estimation

```python
from utils.ai_features import estimate_monthly_cost

# Estimate for 100 API calls per day
cost = estimate_monthly_cost(
    api_calls_per_day=100,
    avg_tokens_per_call=500
)

print(cost)
# {
#     'monthly_calls': 3000,
#     'monthly_tokens': 1500000,
#     'monthly_cost_usd': 3.0,
#     'monthly_cost_inr': 249.0,
#     'per_call_cost': 0.001
# }
```

### Optimization Strategies

**1. Aggressive Caching:**
```python
# Cache service descriptions for 7 days
cache_key = f"service_desc_{service_name}_{language}"
response = call_openai_api(
    prompt,
    cache_key=cache_key,
    cache_timeout=604800  # 7 days
)
```

**2. Batch Processing:**
```python
# Generate descriptions for all services at once
services = provider.services.all()
descriptions = []

for service in services:
    desc = generate_service_description(
        service.service_name,
        provider.business_type
    )
    descriptions.append(desc)
```

**3. Fallback to Rules:**
```python
def get_smart_time_suggestions(provider, date):
    # Try AI first
    ai_suggestions = call_openai_api(prompt, cache_key=cache_key)
    
    if not ai_suggestions:
        # Fallback to rule-based
        return {
            'suggestions': [
                {'time': '10:00', 'reason': 'Morning slots popular'},
                {'time': '14:00', 'reason': 'Afternoon availability'},
            ],
            'reasoning': 'AI unavailable - showing default suggestions'
        }
```

**4. Rate Limiting:**
```python
from django.core.cache import cache
from django.utils import timezone

def rate_limited_ai_call(cache_key, max_calls=100, period=3600):
    """Limit AI calls to max_calls per period (seconds)."""
    count_key = f"ai_rate_{cache_key}"
    count = cache.get(count_key, 0)
    
    if count >= max_calls:
        return None  # Rate limit exceeded
    
    cache.set(count_key, count + 1, period)
    return call_openai_api(prompt)
```

**5. Use Cheaper Models:**
```python
# Use GPT-3.5-turbo instead of GPT-4
response = call_openai_api(
    prompt,
    model="gpt-3.5-turbo",  # Cheaper
    max_tokens=200,  # Limit response length
    temperature=0.5  # More deterministic = less tokens
)
```

---

## 🧪 Testing AI Features

### Test Smart Suggestions

```python
python manage.py shell

from utils.ai_features import get_smart_time_suggestions
from providers.models import ServiceProvider
from datetime import date, timedelta

provider = ServiceProvider.objects.first()
tomorrow = date.today() + timedelta(days=1)

suggestions = get_smart_time_suggestions(provider, tomorrow)
print(suggestions)
```

### Test No-Show Prediction

```python
from utils.ai_features import calculate_no_show_risk
from appointments.models import Appointment

appointment = Appointment.objects.first()
risk = calculate_no_show_risk(appointment)
print(f"Risk Level: {risk['risk_level']}")
print(f"Risk %: {risk['risk_percentage']}")
print(f"Recommendation: {risk['recommendation']}")
```

### Test Content Generation

```python
from utils.ai_features import generate_service_description

desc = generate_service_description(
    "Haircut",
    "salon",
    "english"
)
print(desc)

desc_hi = generate_service_description(
    "हेयरकट",
    "salon",
    "hindi"
)
print(desc_hi)
```

### Test Chatbot

```python
from utils.ai_features import chatbot_response
from providers.models import ServiceProvider

provider = ServiceProvider.objects.first()

response = chatbot_response(
    "What are your prices?",
    provider
)
print(response)
```

---

## ⚠️ Error Handling

### API Failures

```python
def safe_ai_call(prompt):
    """Call AI with proper error handling."""
    try:
        response = call_openai_api(prompt)
        if response:
            return response
        else:
            # API failed, use fallback
            return "AI temporarily unavailable. Please try again."
    except Exception as e:
        logger.error(f"AI error: {str(e)}")
        return None
```

### Rate Limit Handling

```python
import openai

try:
    response = openai.ChatCompletion.create(...)
except openai.error.RateLimitError:
    # Wait and retry or use fallback
    logger.warning("OpenAI rate limit hit")
    return fallback_response()
```

### Authentication Errors

```python
try:
    response = openai.ChatCompletion.create(...)
except openai.error.AuthenticationError:
    logger.error("Invalid OpenAI API key")
    # Notify admin
    send_admin_alert("OpenAI API key invalid")
    return None
```

---

## 📊 Monitoring & Analytics

### Track API Usage

```python
from django.core.cache import cache

def track_ai_usage(feature_name):
    """Track AI feature usage."""
    key = f"ai_usage_{feature_name}_{date.today()}"
    count = cache.get(key, 0)
    cache.set(key, count + 1, 86400)  # 24 hours
```

### Cost Monitoring

```python
def log_api_cost(tokens_used):
    """Log API costs for monitoring."""
    cost = (tokens_used / 1000) * 0.002
    
    # Store in database or send to monitoring service
    logger.info(f"OpenAI API call: {tokens_used} tokens, ${cost:.4f}")
```

---

## 🎯 Best Practices

1. **Always Cache Results:**
   - Cache service descriptions for days
   - Cache time suggestions for hours
   - Reduces costs significantly

2. **Use Fallbacks:**
   - Always have rule-based fallback
   - Don't break functionality if AI fails

3. **Limit Token Usage:**
   - Keep prompts concise
   - Limit max_tokens in responses
   - Use lower temperature for deterministic results

4. **Monitor Costs:**
   - Track API usage daily
   - Set up alerts for high usage
   - Review monthly costs

5. **Test Thoroughly:**
   - Test with various inputs
   - Test error scenarios
   - Test fallback mechanisms

6. **User Experience:**
   - Show loading indicators
   - Provide feedback on AI status
   - Allow manual override

---

## 📝 Summary

**AI Features Implemented:**
- ✅ Smart time slot suggestions
- ✅ No-show prediction
- ✅ Automated content generation (English + Hindi)
- ✅ AI chatbot for queries

**Cost Optimization:**
- ✅ Aggressive caching
- ✅ Fallback mechanisms
- ✅ Rate limiting
- ✅ Token usage optimization

**Production Ready:**
- ✅ Error handling
- ✅ Logging
- ✅ Monitoring
- ✅ Fallback strategies

**Estimated Costs:**
- Small business (50 appointments/month): ~$2-5/month
- Medium business (200 appointments/month): ~$10-20/month
- Large business (1000 appointments/month): ~$50-100/month

**All AI features are production-ready with proper error handling and cost optimization!** 🤖
