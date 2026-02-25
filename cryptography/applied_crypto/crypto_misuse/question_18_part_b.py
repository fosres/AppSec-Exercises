def rotate_api_key(old_api_key):
	"""Rotate API key - generate new one, invalidate old one"""
	# Verify old key is valid
	customer_id = verify_api_key(old_api_key)
	
	if not customer_id:
		raise Exception("Invalid API key")
	
	conn = sqlite3.connect(_DATABASE)

	cursor = conn.cursor()

	# SQL Injection Vulnerability Below

	cursor.execute(
		f"DELETE FROM api_keys WHERE customer_id = ?",(customer_id,)
	)

	conn.commit()


	# Generate new key
	new_api_key = generate_api_key(customer_id)

	conn.close()
	
	return new_api_key
