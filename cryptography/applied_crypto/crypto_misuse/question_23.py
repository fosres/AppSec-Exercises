# views.py
from django_ratelimit.decorators import ratelimit
from django.core.signing import Signer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.csrf import csrf_protect
import json
import time
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN_KEY = os.getenv("TOKEN_KEY")

@csrf_protect
@ratelimit(key='ip',rate='5/m')
def create_token(request):
	"""Create signed token for user"""
	username = request.POST.get('username')
	
	# Create token data
	token_data = {
		'username': username,
		'is_admin': False,
		# 24 hours until expiration
		'exp' : int(time.time() + 86400), 
		'iss' : 'example.com',
		'aud' : 'api-user'
	}

	try:

		jwt_encode = jwt.encode(token_data,
					TOKEN_KEY,
					algorithm="HS256"

		)

		return jwt_encode

	except jwt.InvalidKeyError:

		return None

	except jwt.InvalidKeyLengthError:

		return None

	except Exception as e:

		print(f"Exception:{e}")

		return None
						

# Not a good idea to leave this exempt from CSRF Exemption

# since it handles REST API requests!

@csrf_protect
@ratelimit(key='ip',rate='5/m')
def verify_token(request):
	"""Verify and use token"""
	token = request.POST.get('token')
	data = json.loads(request.POST.get('data'))
	
	try:
		jwt_decode = jwt.decode(token,
					TOKEN_KEY,
					algorithms=["HS256"],
					issuer="example.com",
					audience="api-user"
		)

		current_time = int(time.time())

		if current_time > jwt_decode['exp']:

			return JsonResponse({'error': 'Invalid token'}, status=401)

		# Use the unsigned data directly
		if data.get('is_admin'):
			# Grant admin access
			return JsonResponse({'status': 'admin access granted'})
		else:
			return JsonResponse({'status': 'user access granted'})
			
	except jwt.InvalidTokenError:
		return JsonResponse({'error': 'Invalid token'}, status=401)
	
	except Exception:
		return JsonResponse({'error': 'Invalid token'}, status=401)
