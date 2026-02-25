from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import json
import base64
import time,datetime

from datetime import timezone

import jwt

# Generate RSA key pair
private_key = rsa.generate_private_key(
	public_exponent=65537,

	# Modulus size too small. Use at least 2048

	key_size=3072 
)

public_key = private_key.public_key()

def create_token(username, password):
	"""Create JWT for authenticated user"""
	# Authenticate user (assume this works correctly)
	# user_data = authenticate_user(username, password)

	user_data = {}

	user_data['role'] = 'admin'
	
	# Create JWT payload
	payload = {
		"user": username,
		"role": user_data["role"],
		"exp": 	datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(hours=1),
		"iss": "spacex",

		"aud": "api-user"
	}

	try:
		jwt_encode = jwt.encode(payload,private_key,algorithm="RS256")

	except jwt.InvalidKeyError:

		raise Exception("Incorrect Key")
	
	except jwt.InvalidKeyLengthWarning:

		raise Exception("Incorrect Key Length")
	
	# Return JWT
	return jwt_encode 

def verify_token(token):
	"""Verify JWT and extract user data"""
	
	# Verify signature
	try:

		payload = jwt.decode(
				token,

				public_key,

				issuer="spacex",

				audience="api-user",

				algorithms=["RS256"]

		)

	except jwt.InvalidTokenError:

		raise Exception("Invalid signature")

	# Return user data (no expiration check needed - signature proves validity)
	return payload["user"], payload["role"]

if __name__=="__main__":

	token = create_token('user','password')

	print(token)

	payload_user,payload_role = verify_token(token)

	print(f"payload_user:{payload_user}\npayload_role:{payload_role}")
