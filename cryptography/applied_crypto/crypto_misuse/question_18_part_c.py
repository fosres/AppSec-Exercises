import hmac

def sign_request(api_key, method, path, body):
	"""Sign API request with HMAC"""
	# Create signature data
	data = f"{method}{path}{body}"
	
	# Sign with HMAC-MD5

	# Do NOT use HMAC-MD5!
	signature = hmac.new(
		api_key.encode(),
		data.encode(),
		hashlib.sha512
	).hexdigest()
	
	return signature

def verify_request(api_key, method, path, body, signature):
	"""Verify request signature"""
	# Verify API key first
	customer_id = verify_api_key(api_key)
	if not customer_id:
		return False
	
	# Compute expected signature
	expected = sign_request(api_key, method, path, body)

	# Timing vulnerability: Attacker can deduce expected signature!
	
	# Compare signatures
	return hmac.compare_digest(signature,expected)
