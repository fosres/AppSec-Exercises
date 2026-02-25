from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

def create_token(user_id, role, permissions):
	payload = {"user_id": user_id, "role": role}
	# permissions is not signed with other data!
	# Attacker can get away with modifying permissions
	data_to_sign = f"{user_id}{role}"
	signature = private_key.sign(data_to_sign.encode())
	payload["permissions"] = permissions
	payload["sig"] = signature.hex()
	return payload

def verify_token(token):
	data_to_verify = f"{token['user_id']}{token['role']}"
	sig = bytes.fromhex(token['sig'])
	public_key.verify(sig, data_to_verify.encode())
	return token

# Server creates token for regular user with limited permissions
token = create_token(123, "user", ["read"])
print("Server issued token:", token)
print()

# Your task: Get admin-level permissions without the server's private key

token["permissions"] = ['read','write','delete']


# Test: Does your exploit work?
print("Testing exploit...")
try:
	verified = verify_token(token)
	print("Token verified!")
	print(f"Permissions: {verified['permissions']}")
except Exception as e:
	print(f"Verification failed: {e}")
