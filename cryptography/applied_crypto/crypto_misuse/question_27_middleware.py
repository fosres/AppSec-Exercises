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

