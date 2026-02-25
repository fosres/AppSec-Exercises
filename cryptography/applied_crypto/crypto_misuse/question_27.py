# middleware.py
from django.core.cache import cache
from django.http import JsonResponse
import time

class RateLimitMiddleware:
	"""Rate limiting middleware"""
	
	def __init__(self, get_response):
		self.get_response = get_response
	
	def __call__(self, request):
		# Get client IP
		client_ip = self.get_client_ip(request)
		
		# Check rate limit
		cache_key = f"rate_limit_{client_ip}"
		request_count = cache.get(cache_key, 0)
		
		if request_count >= 100:
			# Add delay for rate-limited requests
			time.sleep(1)
			return JsonResponse(
				{'error': 'Rate limit exceeded'},
				status=429
			)
		
		# Increment counter
		cache.set(cache_key, request_count + 1, 60)
		
		response = self.get_response(request)
		return response
	
	def get_client_ip(self, request):
		"""Get client IP address"""
		x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
		if x_forwarded_for:
			ip = x_forwarded_for.split(',')[0]
		else:
			ip = request.META.get('REMOTE_ADDR')
		return ip

# authentication.py
from django.contrib.auth.models import User
import hmac

def validate_api_key(api_key, expected_key):
	"""Validate API key with timing information"""

	if not hmac.compare_digest(api_key,expected_key):
		return False
	
	return True

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .authentication import validate_api_key

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
