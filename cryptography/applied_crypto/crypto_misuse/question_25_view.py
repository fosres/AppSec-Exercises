# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django_ratelimit.decorators import ratelimit
from django.conf import settings
import hmac
import hashlib
import json
import base64
import jwt
import os
import secrets 
import time
from dotenv import load_dotenv,set_key
from dotenv import set_key


# SECRET_KEY MUST NOT be hardcoded

# SECRET_KEY security should be 128

# bits of security and be derived

# from a CSPRNG. So that's 16 bytes.

load_dotenv()

# Good habit to rotate API key every 6 months

SECRET_KEY = os.getenv("SECRET_KEY")

KEY_EXP = os.getenv("KEY_EXP") # stored as Unix timestamp as string

def did_key_exp():

	current_time = int(time.time())

	if current_time > int(KEY_EXP):

		set_key(env_path,'SECRET_KEY',secrets.token_urlsafe(32))
		
		six_months_later_delta =  24 * 60 * 60 * 30 * 6
		
		set_key(env_path,'KEY_EXP',str(current_time + six_months_later_delta))


def create_auth_token(user_id, username, permissions):
	"""Create authentication token"""

	did_key_exp()
	
	# Token payload
	payload = {
		'user_id': user_id,
		'username': username,
		'permissions': permissions,
		'exp': int(time.time() + 86400),
		'iss': "example.com",
		'aud': 'api-user'
	}

	try:
		jwt_encode = jwt.encode(
					payload,

					SECRET_KEY,

					algorithm="HS256"
		)
	
		return jwt_encode

	except jwt.InvalidKeyError:

		return None
	
	except jwt.InvalidKeyLengthError:

		return None

	except Exception as e:

		return None
	
	return jwt_encode

def verify_auth_token(token):
	"""Verify authentication token"""
	try:

		did_key_exp()

		jwt_decode = jwt.decode(
					token,

					SECRET_KEY,

					algorithms=["HS256"],

					issuer="example.com",

					audience="api-user"
		)

		current_time = int(time.time())

		if current_time > jwt_decode['exp']:

			return None

		return jwt_decode

	except jwt.InvalidTokenError:

		return None

	except Exception as e:

		return None


# No attempt at CSRF Protection!

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def login(request):
	"""Login endpoint"""
	username = request.POST.get('username')
	password = request.POST.get('password')
	
	# Authenticate (assume this works)
	user = authenticate(username, password)
	
	if user:
		token = create_auth_token(
			user_id=user.id,
			username=user.username,
			permissions=['read']
		)
		return JsonResponse({'token': token})
	else:
		return JsonResponse({'error': 'Invalid credentials'}, status=401)

@csrf_protect
@ratelimit(key='ip', rate='5/m')
def admin_panel(request):
	"""Admin endpoint"""
	token = request.headers.get('Authorization', '').replace('Bearer ', '')
	
	jwt_decode = verify_auth_token(token)
	
	if not payload:
		return JsonResponse({'error': 'Unauthorized'}, status=401)
	
	# Check permissions from token
	if 'admin' in jwt_decode['permissions']:
		return JsonResponse({'data': 'Secret admin data'})
	else:
		return JsonResponse({'error': 'Forbidden'}, status=403)

def main():

	jwt_encode = create_auth_token(37,"user",['user'])	

	jwt_decode = verify_auth_token(jwt_encode)

	print(f"jwt_encode:{jwt_encode}")
	
	print(f"jwt_decode:{jwt_decode}")

if __name__=="__main__":

	main()
