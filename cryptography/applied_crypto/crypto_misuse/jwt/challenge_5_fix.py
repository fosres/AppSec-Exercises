import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

def create_token(user_id, role, permissions):
	payload	=	{
				"user_id": user_id,
				"role": role,
				"permissions" : permissions
			}

	jwt_encode = jwt.encode(payload,private_key,algorithm="EdDSA")
	return jwt_encode 

def verify_token(token):
	jwt_decode = jwt.decode(token,public_key,algorithms=["EdDSA"])
	return jwt_decode 

# Server creates token for regular user with limited permissions
token = create_token(123, "user", ["read"])
print("Server issued token:", token)

# Your task: Get admin-level permissions without the server's private key

print("Testing exploit...")

try:
	verified = verify_token(token)
	print("Token verified!")
	print(f"Permissions: {verified['permissions']}")
except Exception as e:
	print(f"Verification failed: {e}")
