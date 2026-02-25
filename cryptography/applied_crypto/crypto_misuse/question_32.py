import jwt
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def get_token(username, password):
	allowed_files = authenticate_user(username, password)

	payload =	{
				"user": username,

				"files": allowed_files,

				# Expiration set to 24 hours later

				"exp" : int(time.time() + 86400),

				"iss": "acme",

				"aud": "api-user"
			}

	try:
		jwt_encode = jwt.encode(payload,secret_key,algorithm="EdDSA")

		return jwt_encode

	except jwt.InvalidKeyError:

		return None

	except jwt.InvalidKeyLengthError:

		return None

	except Exception:

		return None


def verify_token(jwt_encode):

	try:

		jwt_decode = jwt.decode(
					jwt_encode,

					public_key,

					algorithms=["EdDSA"],

					issuer="acme",

					audience="api-user"

		)

		return jwt_decode["user"],jwt_decode["files"]

	except jwt.InvalidTokenError:

		return None,None

	except jwt.ExpiredSignatureError:

		return None,None

	except Exception:

		return None,None

