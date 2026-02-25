# authentication.py
from django.contrib.auth.models import User
import hmac
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .authentication import validate_api_key

def validate_api_key(api_key, expected_key):
	"""Validate API key with timing information"""

	if not hmac.compare_digest(api_key,expected_key):
		return False
	
	return True


# views.py

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def protected_endpoint(request):
	"""Protected API endpoint"""
	
	# Get API key from header
	provided_key = request.headers.get('X-API-Key', '')
	
	# Get user's API key from database
	user = User.objects.get(username=request.POST.get('username'))
	expected_key = user.profile.api_key
	
	# Validate API key
	if validate_api_key(provided_key, expected_key):
		return JsonResponse({'data': 'Secret data'})
	else:
		return JsonResponse({'error': 'Invalid API key'}, status=401)

