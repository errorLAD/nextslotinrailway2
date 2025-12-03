"""
Views for subscription management and pricing.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
import razorpay
import hmac
import hashlib
import json
import logging
from .models import SubscriptionPlan, Payment
from providers.decorators import provider_required

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize Razorpay client
try:
    razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
except Exception as e:
    logger.error(f"Error initializing Razorpay client: {str(e)}")
    razorpay_client = None


def contact_sales(request):
    """
    Display contact sales form and handle submissions.
    """
    if request.method == 'POST':
        # Here you would typically process the form submission
        # and send an email to your sales team
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        message = request.POST.get('message', '')
        
        # In a real application, you would send an email here
        # send_mail(
        #     f'Sales Inquiry from {name}',
        #     f'Name: {name}\nEmail: {email}\n\nMessage:\n{message}',
        #     settings.DEFAULT_FROM_EMAIL,
        #     ['sales@yourdomain.com'],
        #     fail_silently=False,
        # )
        
        messages.success(request, 'Thank you for your inquiry! Our sales team will contact you shortly.')
        return redirect('subscriptions:contact')
    
    return render(request, 'subscriptions/contact_sales.html', {
        'user': request.user if request.user.is_authenticated else None
    })


def pricing_page(request):
    """
    Display pricing comparison page.
    """
    plans = SubscriptionPlan.objects.filter(is_active=True).order_by('display_order')
    
    context = {
        'plans': plans,
        'free_plan': plans.filter(plan_type='free').first(),
        'pro_plan': plans.filter(plan_type='pro').first(),
    }
    
    return render(request, 'subscriptions/pricing.html', context)


def compare_plans(request):
    """
    Detailed plan comparison page.
    """
    plans = SubscriptionPlan.objects.filter(is_active=True).order_by('display_order')
    
    context = {
        'plans': plans,
    }
    
    return render(request, 'subscriptions/compare_plans.html', context)


@login_required
@provider_required
def upgrade_prompt(request):
    """
    Show upgrade prompt when user hits a limit.
    """
    provider = request.user.provider_profile
    pro_plan = SubscriptionPlan.objects.filter(plan_type='pro', is_active=True).first()
    
    # Determine what limit was hit
    limit_type = request.GET.get('limit', 'appointments')
    
    context = {
        'provider': provider,
        'pro_plan': pro_plan,
        'limit_type': limit_type,
        'appointments_used': provider.appointments_this_month,
        'services_count': provider.services.count(),
    }
    
    return render(request, 'subscriptions/upgrade_prompt.html', context)


@login_required
@provider_required
def checkout(request, plan):
    """
    Handle subscription plan checkout with Razorpay integration.
    """
    if not hasattr(request.user, 'provider_profile'):
        messages.info(request, 'Please complete your provider profile first.')
        return redirect('providers:setup_profile')
    
    # Get the requested plan
    plan_obj = get_object_or_404(SubscriptionPlan, plan_type=plan, is_active=True)
    provider = request.user.provider_profile
    
    # For free plan, update the subscription and redirect
    if plan_obj.plan_type == 'free':
        if provider.current_plan == 'free':
            return redirect('dashboard')
            
        provider.current_plan = 'free'
        provider.save()
        
        Payment.objects.create(
            provider=provider,
            plan=plan_obj,
            amount=0,
            status='success',
            payment_method='free',
            notes='Downgraded to Free plan'
        )
        
        messages.success(request, 'You have been successfully downgraded to the Free plan.')
        return redirect('dashboard')
    
    # For Pro plan, handle payment
    if plan_obj.plan_type == 'pro':
        if provider.current_plan == 'pro':
            return redirect('dashboard')
            
        # For POST request, verify payment
        if request.method == 'POST':
            try:
                # Get payment details from POST data
                razorpay_payment_id = request.POST.get('razorpay_payment_id')
                razorpay_order_id = request.POST.get('razorpay_order_id')
                razorpay_signature = request.POST.get('razorpay_signature')
                
                # Verify payment signature
                params_dict = {
                    'razorpay_order_id': razorpay_order_id,
                    'razorpay_payment_id': razorpay_payment_id,
                    'razorpay_signature': razorpay_signature
                }
                
                # Verify the payment signature
                razorpay_client.utility.verify_payment_signature(params_dict)
                
                # Update provider's subscription
                provider.current_plan = 'pro'
                provider.plan_start_date = timezone.now().date()
                provider.plan_end_date = timezone.now().date() + timedelta(days=30)
                provider.save()
                
                # Record the payment
                payment = Payment.objects.create(
                    provider=provider,
                    plan=plan_obj,
                    amount=plan_obj.price_monthly,
                    status='success',
                    payment_method='razorpay',
                    razorpay_payment_id=razorpay_payment_id,
                    razorpay_order_id=razorpay_order_id,
                    razorpay_signature=razorpay_signature,
                    notes='Upgraded to Pro plan'
                )
                
                # Send confirmation email
                send_payment_confirmation_email(provider, payment)
                
                messages.success(request, 'Your subscription has been upgraded to Pro!')
                return redirect('subscriptions:upgrade_success')
                
            except Exception as e:
                logger.error(f"Payment verification failed: {str(e)}")
                messages.error(request, 'Payment verification failed. Please try again or contact support.')
                return redirect('subscriptions:pricing')
        
        # For GET request, show the checkout page
        razorpay_key_id = getattr(settings, 'RAZORPAY_KEY_ID', '')
        
        if not razorpay_key_id or not razorpay_client:
            logger.error("Razorpay is not properly configured in settings!")
            messages.error(request, "Payment processor is not properly configured. Please try again later.")
            return redirect('subscriptions:pricing')
        
        # Create a Razorpay order
        amount = int(plan_obj.price_monthly * 100)  # Convert to paise
        
        context = {
            'plan': plan_obj,
            'amount': amount,
            'razorpay_key_id': razorpay_key_id,
            'user': request.user,
            'SITE_NAME': getattr(settings, 'SITE_NAME', 'Booking System'),
        }
        
        return render(request, 'subscriptions/checkout.html', context)
    
    # If we get here, the plan type is not supported
    messages.error(request, 'Invalid plan selected.')
    return redirect('subscriptions:pricing')


def upgrade_to_pro(request):
    """
    Initiate PRO plan upgrade.
    """
    if not request.user.is_authenticated:
        messages.info(request, 'Please log in to upgrade your plan.')
        return redirect('accounts:login')
    
    if not hasattr(request.user, 'is_provider') or not request.user.is_provider:
        messages.error(request, 'This page is only accessible to service providers.')
        return redirect('accounts:login')
    
    # Ensure provider profile exists
    if not hasattr(request.user, 'provider_profile'):
        messages.info(request, 'Please complete your provider profile first.')
        return redirect('providers:setup_profile')
    
    provider = request.user.provider_profile
    pro_plan = get_object_or_404(SubscriptionPlan, plan_type='pro', is_active=True)
    
    context = {
        'user': request.user,
        'provider': provider,
        'pro_plan': pro_plan,
        'razorpay_key_id': settings.RAZORPAY_KEY_ID,
    }
    
    return render(request, 'subscriptions/upgrade_to_pro.html', context)


@login_required
@provider_required
@require_POST
def create_payment_order(request):
    """
    Create a Razorpay order for PRO plan payment.
    """
    try:
        plan = get_object_or_404(SubscriptionPlan, plan_type='pro', is_active=True)
        provider = request.user.provider_profile
        
        # Create order in Razorpay
        amount = int(plan.price_monthly * 100)  # Convert to paise
        receipt = f'order_{provider.id}_{int(timezone.now().timestamp())}'
        
        order_data = {
            'amount': amount,
            'currency': 'INR',
            'receipt': receipt,
            'payment_capture': 1,  # Auto capture payment
            'notes': {
                'plan': 'pro',
                'provider_id': provider.id,
                'user_id': request.user.id
            }
        }
        
        # Create order in Razorpay
        razorpay_order = razorpay_client.order.create(data=order_data)
        
        # Save the order ID to verify later
        payment = Payment.objects.create(
            provider=provider,
            plan=plan,
            amount=plan.price_monthly,
            status='pending',
            razorpay_order_id=razorpay_order['id'],
            notes=f'Payment initiated for {plan.name} plan - Order: {receipt}'
        )
        
        return JsonResponse({
            'success': True,
            'order_id': razorpay_order['id'],
            'amount': razorpay_order['amount'],
            'currency': razorpay_order['currency'],
            'key': settings.RAZORPAY_KEY_ID,
            'name': getattr(settings, 'COMPANY_NAME', 'Our Service'),
            'description': f'{plan.name} Plan Subscription',
            'prefill': {
                'name': request.user.get_full_name() or request.user.email.split('@')[0],
                'email': request.user.email,
                'contact': str(getattr(provider, 'phone_number', ''))
            },
            'theme': {
                'color': '#4f46e5'  # Indigo color
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating Razorpay order: {str(e)}", exc_info=True)
        return JsonResponse(
            {'success': False, 'error': 'Failed to create payment order'}, 
            status=500
        )


@csrf_exempt
@require_http_methods(["POST"])
def razorpay_webhook(request):
    """
    Handle Razorpay webhook events for payment status updates.
    
    Events handled:
    - payment.captured: Payment successful
    - payment.failed: Payment failed
    - subscription.charged: For subscription renewals
    """
    webhook_secret = getattr(settings, 'RAZORPAY_WEBHOOK_SECRET', '')
    webhook_signature = request.headers.get('X-Razorpay-Signature', '')
    
    if not webhook_secret:
        logger.error("RAZORPAY_WEBHOOK_SECRET is not configured in settings")
        return JsonResponse(
            {'status': 'error', 'message': 'Webhook not configured'}, 
            status=500
        )
    
    try:
        # Verify webhook signature
        razorpay_client.utility.verify_webhook_signature(
            request.body.decode('utf-8'),
            webhook_signature,
            webhook_secret
        )
        
        # Process the webhook payload
        payload = json.loads(request.body)
        event = payload.get('event')
        logger.info(f"Received webhook event: {event}")
        
        if event == 'payment.captured':
            # Handle successful payment
            payment_data = payload.get('payload', {}).get('payment', {}).get('entity', {})
            order_id = payment_data.get('order_id')
            
            try:
                payment = Payment.objects.get(razorpay_order_id=order_id)
                
                # Skip if already processed
                if payment.status == 'success':
                    return JsonResponse({'status': 'success', 'message': 'Payment already processed'})
                
                # Update payment details
                payment.razorpay_payment_id = payment_data.get('id')
                payment.status = 'success'
                payment.payment_method = payment_data.get('method', 'razorpay')
                payment.notes = f"Payment captured - Method: {payment.payment_method}"
                payment.save()
                
                # Update provider's subscription
                provider = payment.provider
                provider.current_plan = 'pro'
                provider.plan_start_date = timezone.now().date()
                provider.plan_end_date = timezone.now().date() + timedelta(days=30)
                provider.save()
                
                # Send confirmation email
                send_payment_confirmation_email(provider, payment)
                
                logger.info(f"Successfully processed payment for order {order_id}")
                return JsonResponse({'status': 'success'})
                
            except Payment.DoesNotExist:
                logger.error(f"Payment with order ID {order_id} not found")
                return JsonResponse(
                    {'status': 'error', 'message': 'Payment not found'}, 
                    status=404
                )
                
            except Exception as e:
                logger.error(f"Error processing payment.captured: {str(e)}", exc_info=True)
                return JsonResponse(
                    {'status': 'error', 'message': 'Error processing payment'}, 
                    status=500
                )
        
        elif event == 'payment.failed':
            # Handle failed payment
            payment_data = payload.get('payload', {}).get('payment', {}).get('entity', {})
            order_id = payment_data.get('order_id')
            
            try:
                payment = Payment.objects.get(razorpay_order_id=order_id)
                
                # Skip if already marked as failed
                if payment.status == 'failed':
                    return JsonResponse({'status': 'success', 'message': 'Payment already marked as failed'})
                
                # Update payment status
                payment.status = 'failed'
                error_description = payment_data.get('error_description', 'Unknown error')
                payment.notes = f"Payment failed: {error_description}"
                payment.save()
                
                logger.warning(f"Payment failed for order {order_id}: {error_description}")
                return JsonResponse({'status': 'success'})
                
            except Payment.DoesNotExist:
                logger.error(f"Payment with order ID {order_id} not found")
                return JsonResponse(
                    {'status': 'error', 'message': 'Payment not found'}, 
                    status=404
                )
        
        elif event == 'subscription.charged':
            # Handle subscription renewal
            subscription_data = payload.get('payload', {}).get('subscription', {}).get('entity', {})
            payment_data = payload.get('payload', {}).get('payment', {}).get('entity', {})
            
            # Extract provider ID from subscription notes or other identifier
            # This depends on how you associate subscriptions with providers
            # You may need to adjust this based on your implementation
            try:
                provider_id = subscription_data.get('notes', {}).get('provider_id')
                if not provider_id:
                    raise ValueError("Provider ID not found in subscription notes")
                
                provider = ServiceProvider.objects.get(id=provider_id)
                
                # Create a new payment record for the renewal
                payment = Payment.objects.create(
                    provider=provider,
                    plan=SubscriptionPlan.objects.get(plan_type='pro'),
                    amount=float(payment_data.get('amount', 0)) / 100,  # Convert from paise to INR
                    status='success',
                    payment_method=payment_data.get('method', 'razorpay'),
                    razorpay_payment_id=payment_data.get('id'),
                    razorpay_order_id=payment_data.get('order_id'),
                    razorpay_signature=payment_data.get('signature', ''),
                    notes='Automatic subscription renewal'
                )
                
                # Update provider's subscription end date
                provider.plan_end_date = timezone.now().date() + timedelta(days=30)
                provider.save()
                
                # Send renewal confirmation email
                send_payment_confirmation_email(provider, payment, is_renewal=True)
                
                logger.info(f"Successfully processed subscription renewal for provider {provider_id}")
                return JsonResponse({'status': 'success'})
                
            except Exception as e:
                logger.error(f"Error processing subscription.charged: {str(e)}", exc_info=True)
                return JsonResponse(
                    {'status': 'error', 'message': 'Error processing subscription renewal'}, 
                    status=500
                )
        
        # Log unhandled events
        logger.warning(f"Unhandled webhook event: {event}")
        return JsonResponse(
            {'status': 'success', 'message': 'Event received but not processed'},
            status=200
        )
        
    except razorpay.errors.SignatureVerificationError as e:
        logger.error(f"Invalid webhook signature: {str(e)}")
        return JsonResponse(
            {'status': 'error', 'message': 'Invalid signature'}, 
            status=400
        )
        
    except Exception as e:
        logger.error(f"Webhook processing error: {str(e)}", exc_info=True)
        return JsonResponse(
            {'status': 'error', 'message': 'Internal server error'}, 
            status=500
        )


@login_required
@provider_required
def verify_payment(request):
    """
    Verify Razorpay payment and upgrade provider to PRO.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    razorpay_order_id = request.POST.get('razorpay_order_id')
    razorpay_payment_id = request.POST.get('razorpay_payment_id')
    razorpay_signature = request.POST.get('razorpay_signature')
    
    logger.info(f"Verifying payment - Order ID: {razorpay_order_id}, Payment ID: {razorpay_payment_id}")
    
    # Verify signature
    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
    
    try:
        # Verify payment signature
        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }
        
        client.utility.verify_payment_signature(params_dict)
        logger.info("Payment signature verified successfully")
        
        # Get the payment record
        payment = Payment.objects.get(razorpay_order_id=razorpay_order_id)
        logger.info(f"Found payment record: {payment.id}")
        
        # Update payment record
        payment.razorpay_payment_id = razorpay_payment_id
        payment.razorpay_signature = razorpay_signature
        payment.status = 'success'
        payment.save()
        logger.info(f"Updated payment record {payment.id} to success status")
        
        # Get the provider and upgrade to PRO
        provider = request.user.provider_profile
        logger.info(f"Upgrading provider {provider.id} to PRO plan")
        
        # Manually update the provider's plan status
        from django.utils import timezone
        from datetime import timedelta
        
        # Update provider's plan details using the model method
        # This ensures consistent behavior with the model's upgrade logic
        success = provider.upgrade_to_pro(duration_months=1, is_trial=False)
        
        if not success:
            logger.error(f"Failed to upgrade provider {provider.id} to PRO plan")
            raise Exception("Failed to process plan upgrade")
            
        logger.info(f"Successfully processed PRO plan upgrade for provider {provider.id}")
        
        logger.info(f"Successfully upgraded provider {provider.id} to PRO plan. New plan end date: {provider.plan_end_date}")
        
        # Add success message
        messages.success(
            request,
            'Payment successful! You are now on the PRO plan. Enjoy unlimited features!'
        )
        
        return JsonResponse({
            'success': True,
            'redirect_url': '/pricing/upgrade/success/'
        })
    
    except Exception as e:
        logger.error(f"Payment verification failed: {str(e)}", exc_info=True)
        
        # Update payment record if possible
        try:
            if razorpay_order_id:
                payment = Payment.objects.get(razorpay_order_id=razorpay_order_id)
                payment.status = 'failed'
                payment.notes = str(e)
                payment.save()
                logger.info(f"Updated payment {payment.id} to failed status")
        except Exception as update_error:
            logger.error(f"Failed to update payment record: {str(update_error)}")
        
        return JsonResponse({
            'success': False,
            'error': 'Payment verification failed. Please contact support if the amount was deducted.'
        }, status=400)


@login_required
@provider_required
def upgrade_success(request):
    """
    Show success page after upgrade.
    """
    provider = request.user.provider_profile
    
    context = {
        'provider': provider,
    }
    
    return render(request, 'subscriptions/upgrade_success.html', context)


@login_required
@provider_required
def downgrade_to_free(request):
    """
    Downgrade provider to FREE plan.
    """
    provider = request.user.provider_profile
    
    if request.method == 'POST':
        # Check if they have more than 3 services
        service_count = provider.services.count()
        
        if service_count > 3:
            messages.warning(
                request,
                f'You have {service_count} services. FREE plan allows maximum 3 services. '
                f'Please deactivate some services before downgrading.'
            )
            return redirect('providers:service_list')
        
        # Downgrade
        provider.downgrade_to_free()
        
        messages.info(
            request,
            'You have been downgraded to the FREE plan. '
            'You can upgrade anytime to unlock PRO features.'
        )
        
        return redirect('providers:dashboard')
    
    context = {
        'provider': provider,
        'service_count': provider.services.count(),
        'appointments_this_month': provider.appointments_this_month,
    }
    
    return render(request, 'subscriptions/downgrade_confirm.html', context)


def send_payment_confirmation_email(provider, payment, is_renewal=False):
    """
    Send payment confirmation email to provider.
    
    Args:
        provider: The ServiceProvider instance
        payment: The Payment instance
        is_renewal: Boolean indicating if this is a renewal payment
    """
    try:
        # Email subject based on payment type
        if is_renewal:
            subject = f'Subscription Renewal Confirmation - {payment.plan.name} Plan'
            intro = f"""
            <p>Your {payment.plan.name} plan subscription has been successfully renewed.</p>
            <p>Your subscription is now active until {provider.plan_end_date.strftime('%B %d, %Y')}.</p>
            """
        else:
            subject = f'Payment Confirmation - {payment.plan.name} Plan'
            intro = f"""
            <p>Your payment for the {payment.plan.name} plan has been successfully processed.</p>
            <p>Your subscription is now active until {provider.plan_end_date.strftime('%B %d, %Y')}.</p>
            """
        
        # Create email body
        message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ color: #4f46e5; }}
                .details {{ background: #f8fafc; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .footer {{ margin-top: 30px; font-size: 0.9em; color: #6b7280; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="header">Thank you for your payment!</h1>
                {intro}
                
                <div class="details">
                    <h3>Payment Details:</h3>
                    <ul style="list-style: none; padding-left: 0;">
                        <li><strong>Plan:</strong> {payment.plan.name}</li>
                        <li><strong>Amount:</strong> ₹{payment.amount:,.2f}</li>
                        <li><strong>Payment ID:</strong> {payment.razorpay_payment_id or 'N/A'}</li>
                        <li><strong>Order ID:</strong> {payment.razorpay_order_id or 'N/A'}</li>
                        <li><strong>Date:</strong> {payment.created_at.strftime('%B %d, %Y %I:%M %p')}</li>
                        <li><strong>Status:</strong> {payment.status.title()}</li>
                    </ul>
                </div>
                
                <p>You can manage your subscription from your account dashboard.</p>
                
                <div class="footer">
                    <p>If you have any questions about your subscription, please contact our support team.</p>
                    <p>Best regards,<br>
                    The {getattr(settings, 'COMPANY_NAME', 'Our Service')} Team</p>
                </div>
            </div>
        </body>
        </html>
        """.format(
            intro=intro,
            payment=payment,
            provider=provider
        )
        
        # Send email
        send_mail(
            subject=subject,
            message='',  # Empty message since we're using html_message
            html_message=message,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
            recipient_list=[provider.user.email],
            fail_silently=False,
        )
        
        logger.info(f"Payment confirmation email sent to {provider.user.email}")
        
    except Exception as e:
        logger.error(f"Failed to send payment confirmation email: {str(e)}", exc_info=True)
        # Don't raise exception to avoid breaking the payment flow
