from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django_ratelimit.decorators import ratelimit
import jwt
import nacl.secret
import hmac
import hashlib
import os

# Service 1: E-commerce checkout
#Should be: @csrf_protect
@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def checkout_process(request):
    """Process checkout - user must be logged in"""
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'login required'}, status=401)
    
    cart_items = request.POST.get('items')
    payment_method = request.POST.get('payment_method')
    
    order = create_order(request.user, cart_items, payment_method)
    
    return JsonResponse({'order_id': order.id})


# Service 2: Mobile app API
MOBILE_TOKEN_KEY = os.getenv("MOBILE_TOKEN_KEY")

# Should be: @csrf_exempt
@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def mobile_api_upload(request):
    """Mobile app file upload API"""
    
    encrypted_token = request.headers.get('X-Mobile-Token')
    
    box = nacl.secret.SecretBox(MOBILE_TOKEN_KEY)
    user_id_bytes = box.decrypt(encrypted_token)
    user_id = user_id_bytes.decode()

    # No check if mobile token expired first before

    # proceeding
    
    file = request.FILES.get('file')
    save_file(user_id, file)
    
    return JsonResponse({'status': 'uploaded'})


# Service 3: Admin panel
# Should be: @csrf_protect
@csrf_protect
@ratelimit(key='ip', rate='5/m')
def admin_delete_user(request):
    """Admin panel using JWT stored in HttpOnly cookie"""
    
    token = request.COOKIES.get('admin_token')
    
    if not token:
        return JsonResponse({'error': 'not authenticated'}, status=401)
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        if payload['role'] != 'admin':
            return JsonResponse({'error': 'not admin'}, status=403)
    
	# No check if JWT Token / Cookie Expired
    
        user_id = request.POST.get('user_id')
        User.objects.filter(id=user_id).delete()
        
        return JsonResponse({'status': 'deleted'})

    # No explicit except guard for Expired Signature. Best practice.

    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'invalid token'}, status=401)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'invalid token'}, status=401)
		
    except:
        return JsonResponse({'error': 'invalid token'}, status=401)


# Service 4: Payment webhook

# Should be: @csrf_exempt
@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def stripe_webhook(request):
    """Stripe payment webhook with HMAC signature"""
    
    signature = request.headers.get('Stripe-Signature')
    payload = request.body
    
    expected = hmac.new(
        settings.STRIPE_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        return JsonResponse({'error': 'invalid signature'}, status=401)
   
    # No check if payload / payload signature expired before

    # processing payment.
 
    process_payment_event(json.loads(payload))
    
    return JsonResponse({'status': 'processed'})
