import nacl.secret
import json
import time
import os
import secrets
import base64
from dotenv import load_dotenv,set_key
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit

load_dotenv()

ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY")


def create_encrypted_token(user_id, username):
    """Create encrypted authentication token"""

    
    token_data = {
        'user_id': user_id,
        'username': username,
        'expires': int(time.time()) + 3600
    }
    
    token_json = json.dumps(token_data)
    
    box = nacl.secret.SecretBox(ENCRYPTION_KEY)
    encrypted = box.encrypt(token_json.encode())
    
    return base64.b64encode(encrypted)


def decrypt_token(encrypted_token_b64):
    """Decrypt and validate token"""

    encrypted = base64.b64decode(encrypted_token_b64)
    
    box = nacl.secret.SecretBox(ENCRYPTION_KEY)
    decrypted = box.decrypt(encrypted)
    
    token_data = json.loads(decrypted.decode())
    
    if time.time() > token_data['expires']:
        return None
    
    return token_data


@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def login_endpoint(request):

    """Login endpoint - creates encrypted token"""
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = authenticate(username, password)
    
    if user:
        token = create_encrypted_token(user.id, user.username)
        return JsonResponse({'token': token})
    
    return JsonResponse({'error': 'invalid credentials'}, status=401)


@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def protected_endpoint(request):
    """Protected endpoint - validates encrypted token"""
    
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    
    if not token:
        return JsonResponse({'error': 'no token'}, status=401)
    
    token_data = decrypt_token(token)
    
    if not token_data:
        return JsonResponse({'error': 'invalid token'}, status=401)
    
    return JsonResponse({
        'message': f"Hello {token_data['username']}",
        'user_id': token_data['user_id']
    })
