from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def get_token(username, password):
	allowed_files = authenticate_user(username, password)

	jwt = { "user": username, "files": allowed_files }
	data = jwt["user"]
	data += jwt["files"][0]
	sig = secret_key.sign(data)
	jwt["sig"] = sig
	return jwt

def verify_token(jwt):
	data = jwt["user"]
	data += jwt["files"][0]
	assert public_key.verify(jwt["sig"], data)
	return jwt["user"], jwt["files"]
