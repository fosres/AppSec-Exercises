import secrets 
import string
import hashlib
import hmac
import sqlite3
import time

_DATABASE = "api_keys.db"

def generate_api_key(customer_id):
	conn = sqlite3.connect(_DATABASE)
	
	cursor = conn.cursor()

	cursor.execute(
		f"SELECT * FROM api_keys WHERE customer_id = ?",(customer_id,)
	)

	result = curser.fetchone()

	if result:

		return None

	"""Generate new API key for customer"""
	# Generate random 32-character key
	chars = string.ascii_letters + string.digits
	
	# Use secrets module!
	api_key = ''.join(secrets.choice(chars) for i in range(32))
	
	# Hash the key for storage
	key_hash = hashlib.sha512(api_key.encode()).hexdigest()
	
	# Store in database
	conn = sqlite3.connect(_DATABASE)
	cursor = conn.cursor()
	cursor.execute(
		f"INSERT INTO api_keys (customer_id, key_hash, created_at) "
		f"VALUES (?,?,?)",(customer_id,key_hash,int(time.time()))
	)
	conn.commit()
	conn.close()
	
	# Return plaintext key to customer (only time they'll see it)
	return api_key

def verify_api_key(api_key):
	"""Verify API key is valid and return customer_id"""
	# Hash provided key
	key_hash = hashlib.sha512(api_key.encode()).hexdigest()
	
	# Query database
	conn = sqlite3.connect(_DATABASE)

	cursor = conn.cursor()
	
	cursor.execute(
		f"SELECT * FROM api_keys"
	)

	result = cursor.fetchall()

	customer_id = 0

	if result:

		for item in result:

			if hmac.compare_digest(key_hash,item[1]):

				customer_id = item[0]

				conn.close()

				return customer_id

		conn.close()

		return None

	else:
		conn.close()

		return None

