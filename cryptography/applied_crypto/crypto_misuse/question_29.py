from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.contrib.auth import authenticate
import jwt

# Endpoint 1: Traditional login
@csrf_exempt
def login_view(request):
    """Traditional Django login - sets session cookie"""
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = authenticate(username=username, password=password)
    if user:
        request.session['user_id'] = user.id
        return JsonResponse({'status': 'logged in'})
    return JsonResponse({'error': 'invalid'}, status=401)


# Endpoint 2: JWT API endpoint
@csrf_protect
def api_get_profile(request):
    """REST API - JWT in Authorization header"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = User.objects.get(id=payload['user_id'])
        return JsonResponse({'username': user.username})
    except:
        return JsonResponse({'error': 'unauthorized'}, status=401)


# Endpoint 3: Session-based dashboard
@csrf_exempt
def dashboard_view(request):
    """Dashboard using Django session authentication"""
    user_id = request.session.get('user_id')
    
    if not user_id:
        return JsonResponse({'error': 'not logged in'}, status=401)
    
    user = User.objects.get(id=user_id)
    return JsonResponse({'data': f'Welcome {user.username}'})


# Endpoint 4: JWT stored in cookie
@csrf_exempt
def jwt_in_cookie_endpoint(request):
    """JWT stored in HttpOnly cookie"""
    token = request.COOKIES.get('jwt_token')
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return JsonResponse({'user_id': payload['user_id']})
    except:
        return JsonResponse({'error': 'unauthorized'}, status=401)
