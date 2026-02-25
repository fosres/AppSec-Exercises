from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

# Generate keys
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Create payload
payload = {
    "user_id": 100,
    "role": "admin",
    "permissions": ["read", "write", "delete"]
}

# TODO: Encode with private key using EdDSA algorithm

jwt_encode = jwt.encode(payload,private_key,algorithm="EdDSA")

# TODO: Decode with public key


jwt_decode = jwt.decode(jwt_encode,public_key,algorithms=["EdDSA"])
# Print results

print(f'jwt_encode: {jwt_encode}')

print(f'jwt_decode: {jwt_decode}')
