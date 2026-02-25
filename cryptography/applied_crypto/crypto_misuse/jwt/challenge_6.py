import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import time,datetime
from datetime import timezone

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

def create_token(user_id, role, permissions,exp,iss,aud):
	# TODO: Add exp, iss, aud to payload
	
	payload	=	{
				"user_id" : user_id,
				
				"role" : role,

				"permissions" : permissions,

				"exp" : exp,

				"iss" : iss,

				"aud": aud
			}	

	jwt_encode = jwt.encode(payload,private_key,algorithm="EdDSA")

	return jwt_encode

	
def verify_token(jwt_encode):
	# TODO: Decode with issuer/audience validation
	# TODO: Handle ExpiredSignatureError
	# TODO: Handle InvalidTokenError
	
	try:

		jwt_decode = jwt.decode(jwt_encode,
	
					public_key,

					algorithms=["EdDSA"],

					issuer="TokenGenerator",

					audience="server"
				)

		return jwt_decode

	except jwt.ExpiredSignatureError:

		print("Expired Signature")

	except jwt.InvalidTokenError:

		print("InvalidTokenError")
	
# Test cases
print("Test 1: Create and verify valid token")
token = create_token(
			123,

			"user",

			["read"],

			datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=3600),
			"TokenGenerator",

			"server"
		)

result = verify_token(token)
print(f"✓ Valid token: {result}")

print("\nTest 2: Expired token")
# TODO: Create token with exp in the past and test

token = create_token(
			123,

			"user",

			["read"],

			datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=1),
			"TokenGenerator",

			"server"
		)

time.sleep(1)

result = verify_token(token)

print(f"Invalid token: {result}")

print("\nTest 3: Wrong audience")
# TODO: Create token with different audience and test

token = create_token(
			123,

			"user",

			["read"],

			datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=3600),
			"TokenGenerator",

			"wizard"
		)

result = verify_token(token)

print(f"Invalid token: {result}")
