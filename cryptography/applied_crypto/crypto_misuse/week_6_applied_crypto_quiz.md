Ans to Question 1:

Vulnerability:

Code Snippet:

```
import random
import string

def generate_session_token(username):
    random.seed(12345)  # Fixed seed for consistency
    token = ''.join(random.choice(string.ascii_letters) for _ in range(32))
    return token
```

Use of `random` module is insecure for cryptographic purposes!

The seed 1234 makes the tokens generated predictable!

An attacker can run the code on their own server and regenerate the

exact same token!

Use the `secrets` module instead.

Mitigation:

```
import secrets 
import string

def generate_session_token(username):
    alphabet = string.ascii_letters
    token = ''.join(secrets.choice(alphabet) for i in range(32)) 
    return token
```

Question 2:

Code Snippet:

```
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def create_token(user_id, role, permissions):
	token = {
		"user_id": user_id,
		"role": role,              # "admin" or "user"
		"permissions": permissions  # ["read", "write", "delete"]

		# No expiration set. Vulnerable to Replay
	}
	
	# Sign only user_id and role for performance

	# No attempt to sign permissions

	data = str(user_id) + role

	signature = secret_key.sign(data.encode())

	token["sig"] = signature
	
	return token

def verify_token(token):
	data = str(token["user_id"]) + token["role"]
	public_key.verify(token["sig"], data.encode())
	return token["user_id"], token["role"], token["permissions"]
```

Vulnerabilities:

There is no expiration date set for the Token. This makes the token

suspectible to replay where the attacker captures and later resends

a valid token to the server--bypassing authentication.

Also there is no attempt to sign the permissions data for the token.

An attacker can get away with tampering permissions values!

Fixed Code:


```
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import time,datetime
from datetime import timezone

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def create_token(user_id, role, permissions):
	
	payload	= {
		"user_id": user_id,
		"role": role,              # "admin" or "user"
		"permissions": permissions,  # ["read", "write", "delete"]
		
		"exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=86400)
	}
	

	# No attempt to sign permissions

	jwt_encode = jwt.encode(payload,secret_key,algorithm="EdDSA")
	
	return jwt_encode

def verify_token(token):

	try:

		jwt_decode = jwt.decode(
					token,

					public_key,
	
					algorithms=["EdDSA"]

		)

		return jwt_decode["user_id"], jwt_decode["role"], jwt_decode["permissions"]
	
	except jwt.ExpiredSignatureError:

		return None

	except jwt.InvalidTokenError:

		return None	
```

Question 3:

```
import hashlib

def register_user(username, password):
	# Use of message digest.

	# Use a Password-based Key Derivation Function

	# Use username as salt
	password_hash = hashlib.sha256(f"{username}{password}".encode()).hexdigest()
	# Store password_hash in database
	return password_hash

def check_password(username, password, stored_hash):
	
	# Use of message digest.

	# Use a Password-based Key Derivation Function
	password_hash = hashlib.sha256(f"{username}{password}".encode()).hexdigest()

	# Timing Vulnerability Below	
	# Compare hashes character by character
	if len(password_hash) != len(stored_hash):
		return False
	
	for i in range(len(stored_hash)):
		if password_hash[i] != stored_hash[i]:
			return False
	
	return True
```

Vulnerabilities:

Both functions fail to use a password-based key derivation function

to derive the password hash. Although SHA256 is a cryptographically

secure message digest it is unsuitable as a password-based key

derivation function because it calculates the hash very quickly.

Although each username is unique and therfore can work as a salt

it is best practice to use a randomized byte array generated from

 a CSPRNG. Many cryptographic libraries automatically generate

random salts this way for you. 

Question 4:

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib

class SecureMessageHandler:
	def __init__(self):
		self.master_key = secrets.token_urlsafe(32)
		# Deterministic nonce below.
		# Nonce should be derived from CSPRNG

		# Reusing the nonce leaves AES-CBC suspectible

		# to an attack where the attacker can find the

		# XOR of plaintexts.
 
		# Reference: Understanding Cryptography: Second Edition

		self.session_nonce = hashlib.sha256(b"session_init").digest()[:16]

	# CBC is not an Authenticated Encryption with Associated Data

	# cipher. It is best to use one such as XChaCha20-Poly1305. This will

	# prevent attackers from corrupting the ciphertext.

	def encrypt_message(self, message_data):
		cipher = Cipher(
			algorithms.AES(self.master_key),
			modes.CBC(self.session_nonce),
			backend=default_backend()
		)
		encryptor = cipher.encryptor()
		
		padding_length = 16 - (len(message_data) % 16)
		padded_message = message_data + bytes([padding_length]) * padding_length
		
		encrypted = encryptor.update(padded_message) + encryptor.finalize()
		return encrypted
	
	def send_message(self, recipient, message):
		encrypted_msg = self.encrypt_message(message.encode())
		return {
			'to': recipient,
			'data': encrypted_msg
		}

# Usage
handler = SecureMessageHandler()
msg1 = handler.send_message("alice", "Transfer $1000 to Bob")
msg2 = handler.send_message("bob", "Your account balance is $5000")
msg3 = handler.send_message("alice", "Transfer $2000 to Carol")
```

Fixed code:

```
# https://asecuritysite.com/nacl/nacl03

import nacl.secret
import nacl.utils
import binascii
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib

class SecureMessageHandler:
	def __init__(self):
		
		self.master_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

		# Deterministic nonce below.
		# Nonce should be derived from CSPRNG

		# Reusing the nonce leaves AES-CBC suspectible

		# to the same substitution attack that ECB mode

		# is vulnerable to, where the positions of blocks

		# of ciphertext are switched

		# Reference: Understanding Cryptography: Second Edition

	# CBC is not an Authenticated Encryption with Associated Data

	# cipher. It is best to use one such as AES-GCM. This will

	# prevent attackers from corrupting the ciphertext.

	# Below code is much less error-prone and features a stream

	# cipher that is an AEAD

	def encrypt_message(self, message_data):

		box = nacl.secret.SecretBox(self.master_key)

		encrypted = box.encrypt(message_data)

		return encrypted
			
	def send_message(self, recipient, message):
		encrypted_msg = self.encrypt_message(message.encode())
		return {
			'to': recipient,
			'data': encrypted_msg
		}

# Usage
handler = SecureMessageHandler()
msg1 = handler.send_message("alice", "Transfer $1000 to Bob")
msg2 = handler.send_message("bob", "Your account balance is $5000")
msg3 = handler.send_message("alice", "Transfer $2000 to Carol")
```

Question 5:

```
Certificate:
	Data:
		Version: 3 (0x2)
		Signature Algorithm: sha1WithRSAEncryption
		Issuer: CN=api.company.com, O=Company Inc
		Validity
			Not Before: Jan  1 00:00:00 2020 GMT
			Not After : Jan  1 00:00:00 2025 GMT
		Subject: CN=api.company.com, O=Company Inc
		Subject Public Key Info:
			Public Key Algorithm: rsaEncryption
				RSA Public-Key: (1024 bit)
		X509v3 extensions:
			X509v3 Basic Constraints: critical
				CA:TRUE
	Signature Algorithm: sha1WithRSAEncryption
```

And the following nginx configuration:

```
server {
	listen 443 ssl http2;
	server_name api.company.com;
	
	ssl_certificate /etc/nginx/ssl/api.crt;
	ssl_certificate_key /etc/nginx/ssl/api.key;

	# No reason to allow TLSv1 nor TLSv1.1

	# Only allow TLSv1.2 and TLSv1.3
	
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

	# RC4 allowed. RC4 is not secure.

	ssl_ciphers 'HIGH:!aNULL:!MD5:RC4';
	ssl_prefer_server_ciphers on;
	
	ssl_session_cache shared:SSL:50m;
	ssl_session_timeout 24h;
}
```

The following is summary report of what is valid/invalid about the

TLS server certificate configuration:

```
VALIDATION SUMMARY:

CHECK 1:  Version 3 - PASS
CHECK 2:  Not expired/not yet valid - FAIL
CHECK 3: sha1WithRSAEncryption signature - FAIL
CHECK 4: RSA-1024 weak key - FAIL
CHECK 5: Subject DN present - PASS
CHECK 6:  SANs present - FAIL
CHECK 7:  Hostname matches - FAIL (would need actual hostname)
CHECK 8:  Basic Constraints: CA:FALSE (critical) - FAIL
CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - FAIL
CHECK 10: Extended Key Usage: TLS Web Server Authentication - FAIL
CHECK 11: CRL Distribution Points present (>=1 URLs REQUIRED) - FAIL
CHECK 12: Authority Information Access present - FAIL
CHECK 13: OCSP URL present (optional) - FAIL
CHECK 14: Certificate Transparency (>= 2 SCTs) - FAIL
CHECK 15: Not self-signed (Issuer ≠ Subject) - FAIL
CHECK 16: Valid serial number (8 bits entropy) - FAIL
CHECK 17: SKI present (RECOMMENDED, not required for end-entity) - FAIL
CHECK 18: AKI present - FAIL
CHECK 19: SKI ≠ AKI (CONDITIONAL, both present) - PASS
CHECK 20: Validity 1827.0 > 398 days - FAIL

The following CHECKS FAILED and are REQUIRED:[2, 3, 4, 6, 7, 8, 10, 11, 12, 14, 15, 16, 18, 20]


The following CHECKS FAILED and are OPTIONAL:[9, 13, 17]
```
The code for the Python script that generated this report can be

found [here](https://github.com/fosres/SecEng-Exercises/blob/main/cryptography/applied_crypto/tls/tls_cert_validator.py)

As we can see the checks that failed and were required are unacceptable

for a TLS Server Certificate.


It is best to let `certbot` from Let's Encrypt handle generating

a secure TLS certificate than trying to manually fill out all required

fields. `certbot` will automatically generate a signed, properly

timestamped SCT-logged TLS server certificate that avoids all the

failures.


Below is a fixed version of the nginx configuration:

```
server {
	listen 443 ssl http2;
	server_name api.company.com;
	
	ssl_certificate /etc/nginx/ssl/api.crt;
	ssl_certificate_key /etc/nginx/ssl/api.key;

	# No reason to allow TLSv1 nor TLSv1.1

	# Only allow TLSv1.2 and TLSv1.3
	
	ssl_protocols TLSv1.2 TLSv1.3;

	# RC4 allowed. RC4 is not secure.


	ssl_ciphers HIGH:!aNULL:!MD5;
	ssl_prefer_server_ciphers on;
	
	ssl_session_cache shared:SSL:50m;
	ssl_session_timeout 24h;
}
```

Question 6:

```
import hashlib
import hmac
import time

class APIKeyManager:
	def __init__(self):
		self.api_keys = {}  # {api_key: {user_id, created_at, last_used}}

		# Warning using a hardcoded secret!

		self.secret_key = b"company_secret_2024"
	
	def generate_api_key(self, user_id):

		# Warning: using a deterministic API key is

		# predictable to attacker.

		# Generate deterministic API key based on user_id
		timestamp = str(int(time.time()))
		raw_key = f"{user_id}:{timestamp}"
		api_key = hashlib.sha256(raw_key.encode()).hexdigest()
		
		self.api_keys[api_key] = {
			'user_id': user_id,
			'created_at': timestamp,
			'last_used': None
		}
		
		return api_key
	
	def validate_api_key(self, api_key, signature, request_data):
		# Check if key exists
		if api_key not in self.api_keys:
			return False
		
		# Verify HMAC signature
		expected_sig = hmac.new(
			self.secret_key,
			request_data.encode(),
			hashlib.sha256
		).hexdigest()
	
		# Timing Vulnerability in comparision of

		# HMACs below.
	
		# Compare signatures character by character
		if len(signature) != len(expected_sig):
			return False
		
		for i in range(len(expected_sig)):
			if signature[i] != expected_sig[i]:
				return False
		
		# Update last used
		self.api_keys[api_key]['last_used'] = int(time.time())
		
		return True
	
	def revoke_api_key(self, api_key):
		if api_key in self.api_keys:
			del self.api_keys[api_key]
			return True
		return False

# Usage
manager = APIKeyManager()

# Generate keys for users
key1 = manager.generate_api_key("user_123")
key2 = manager.generate_api_key("user_456")

# Client makes authenticated request
request = "GET /api/data"

# hardcoded secret used once again below:

sig = hmac.new(b"company_secret_2024", request.encode(), hashlib.sha256).hexdigest()

if manager.validate_api_key(key1, sig, request):
	print("Access granted")
```

Vulnerabilities:

See the vulnerabilities mentioned in the comments of the code

snippet above.

The fix:


```
import hashlib
import hmac
import time,datetime
import secrets

from datetime import timezone
import os

class APIKeyManager:
	def __init__(self):
		self.api_keys = {}  # {api_key: {user_id, created_at, last_used}}

		# Warning using a hardcoded secret!

		self.secret_key = secrets.token_urlsafe(32).encode()
	
	def generate_api_key(self, user_id):

		# Warning: using a deterministic API key is

		# predictable to attacker.

		# Generate deterministic API key based on user_id
		timestamp = str(int(time.time()))

		api_key = secrets.token_urlsafe(32)

		hash_api_key = hashlib.sha512(api_key.encode()).hexdigest()
		
		current_time = datetime.datetime.now(tz=timezone.utc) 		

		# Establish rate-limit of 5 API requests/minute

		self.api_keys[hash_api_key] = {
			'user_id': user_id,
			'created_at': timestamp,
			'last_used': None,
			'exp' : current_time + datetime.timedelta(seconds=86400)
		}


		return api_key
	
	def validate_api_key(self, api_key, signature, request_data):
		
		current_time = datetime.datetime.now(tz=timezone.utc)

		hash_api_key = hashlib.sha512(api_key.encode()).hexdigest()

		# Check if key exists

		if hash_api_key not in self.api_keys:
			
			return False

		# Check if key expired

		if current_time > self.api_keys[hash_api_key]['exp']:

			return False

		# Check if rate-limit exceeded

		# Verify HMAC signature
		expected_sig = hmac.new(
			self.secret_key,
			request_data.encode(),
			hashlib.sha512
		).hexdigest()

		if not hmac.compare_digest(signature,expected_sig):

			return False
		
		current_time = datetime.datetime.now(tz=timezone.utc)
		
		# Update last used
		self.api_keys[hash_api_key]['last_used'] = int(time.time())
 
		return True
	
	def revoke_api_key(self, api_key):
		hash_api_key = hashlib.sha512(api_key.encode()).hexdigest()

		if hash_api_key in self.api_keys:
			del self.api_keys[hash_api_key]
			return True
		return False

# Usage
manager = APIKeyManager()

# Generate keys for users
key1 = manager.generate_api_key("user_123")
key2 = manager.generate_api_key("user_456")

# Client makes authenticated request
request = "GET /api/data"

# hardcoded secret used once again below:

sig = hmac.new(manager.secret_key, request.encode(), hashlib.sha512).hexdigest()

if manager.validate_api_key(key1, sig, request):
	print("Access granted")
```

Question 7:

```
from flask import Flask, request, jsonify, make_response
import mysql.connector
import hashlib
import requests

app = Flask(__name__)

# Database connection
def get_db():
	return mysql.connector.connect(
		host="localhost",
		user="root",

		# Password hardcoded in codebase!

		password="admin123",
		database="shop"
	)

@app.route('/register', methods=['POST'])
def register():
	username = request.json['username']
	password = request.json['password']
	email = request.json['email']
	
	# MD5 is unsuitable as a password-based key derivation function	
	# Hash password with MD5
	password_hash = hashlib.md5(password.encode()).hexdigest()
	
	db = get_db()
	cursor = db.cursor()
	
	# Store user

	# SQL Injection Vulnerability Below!

	query = f"INSERT INTO users (username, password_hash, email) VALUES ('{username}', '{password_hash}', '{email}')"
	cursor.execute(query)
	db.commit()
	
	return jsonify({"success": True})

@app.route('/login', methods=['POST'])
def login():
	username = request.json['username']
	password = request.json['password']
	
	# MD5 is unsuitable as a password-based key derivation function	
	password_hash = hashlib.md5(password.encode()).hexdigest()
	
	db = get_db()
	cursor = db.cursor()

	# SQL Injection Vulnerability Below
	
	query = f"SELECT * FROM users WHERE username='{username}' AND password_hash='{password_hash}'"
	cursor.execute(query)
	user = cursor.fetchone()
	
	if user:
		# MD5 is unsuitable for creating a session cookie	

		# Create session cookie
		session_id = hashlib.md5(f"{username}{password}".encode()).hexdigest()
		
		response = make_response(jsonify({"success": True}))
		response.set_cookie('session_id', session_id)
		return response
	
	return jsonify({"success": False})

@app.route('/checkout', methods=['POST'])
def checkout():
	credit_card = request.json['credit_card']
	cvv = request.json['cvv']
	amount = request.json['amount']
	
	# Log transaction for debugging
	print(f"Processing payment: Card={credit_card}, CVV={cvv}, Amount=${amount}")
	
	# Store in database
	db = get_db()
	cursor = db.cursor()

	# SQL Injection Vulnerability Below
	
	query = f"INSERT INTO transactions (card_number, cvv, amount) VALUES ('{credit_card}', '{cvv}', {amount})"
	cursor.execute(query)
	db.commit()
	
	# Send to payment processor via HTTP
	response = requests.post(
		'http://payment-processor.example.com/charge',
		json={'card': credit_card, 'cvv': cvv, 'amount': amount}
	)
	
	return jsonify({"success": True, "transaction_id": cursor.lastrowid})

@app.route('/api/user/<username>')
def get_user(username):
	db = get_db()
	cursor = db.cursor()

	# SQL Injection Vulnerability Below
	
	query = f"SELECT username, email, password_hash FROM users WHERE username='{username}'"
	cursor.execute(query)
	user = cursor.fetchone()
	
	if user:
		return jsonify({
			"username": user[0],
			"email": user[1],
			"password_hash": user[2]
		})
	
	return jsonify({"error": "User not found"})

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
```

Vulnerabilities:

See comments for vulnerabilities

Code Fix Below:


```
from passlib.hash import argon2
from flask import Flask, request, jsonify, make_response
import mysql.connector
import hashlib
import passlib
import requests
import secrets

import os
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

database_passwd = os.getenv("DATABASE_PASSWORD")

# Database connection
def get_db():
	return mysql.connector.connect(
		host="localhost",
		user="root",

		# Password hardcoded in codebase!

		password=database_passwd,
		database="shop"
	)

@app.route('/register', methods=['POST'])
def register():
	username = request.json['username']
	password = request.json['password']
	email = request.json['email']
	
	# MD5 is unsuitable as a password-based key derivation function	
	# Hash password with Argon2

	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(password)

	db = get_db()
	cursor = db.cursor()
	
	# Store user

	# SQL Injection Vulnerability Below!

	query = f"INSERT INTO users (username, password_hash, email) VALUES (%s,%s,%s)"
	
	cursor.execute(query,(username,password_hash,email))

	db.commit()
	
	return jsonify({"success": True})

@app.route('/login', methods=['POST'])
def login():
	username = request.json['username']
	password = request.json['password']
	
	# MD5 is unsuitable as a password-based key derivation function	
	
	db = get_db()
	cursor = db.cursor()

	# SQL Injection Vulnerability Below
	
	query = f"SELECT * FROM users WHERE username=%s"
	
	cursor.execute(query,(username,))

	user = cursor.fetchone()
	
	if user and argon2.verify(password,user[1]):
		# MD5 is unsuitable as a password-based key derivation function	

		# Create session cookie

		session_id = secrets.token_urlsafe(32)

		response = make_response(jsonify({"success": True}))
		response.set_cookie('session_id', session_id)
		return response
	
	return jsonify({"success": False})

@app.route('/checkout', methods=['POST'])
def checkout():
	credit_card = request.json['credit_card']
	cvv = request.json['cvv']
	amount = request.json['amount']

	# Don't log card details!
	
	# Log transaction for debugging
	# print(f"Processing payment: Card={credit_card}, CVV={cvv}, Amount=${amount}")
	
	# Store in database
	db = get_db()
	cursor = db.cursor()

	# SQL Injection Vulnerability Below
	
	query = f"INSERT INTO transactions (card_number, amount) VALUES (%s,%s)"

	db.commit()
	
	# Send to payment processor via HTTP
	response = requests.post(
		'https://payment-processor.example.com/charge',
		json={'card': credit_card, 'cvv': cvv, 'amount': amount}
	)
	
	# Don't store credit card details in plaintext.

	# These details should be encrypted or tokenized

	# The question does not give us info on what the contents

	# of response are yet we need it to properly store tokens

	# in database in the line below

	paycreds = response.json()
	
	cursor.execute(query,(paycreds['credit_card_token'],paycreds['amount_token']))
	
	return jsonify({"success": True, "transaction_id": cursor.lastrowid})

@app.route('/api/user/<username>')
def get_user(username):
	db = get_db()
	cursor = db.cursor()

	# SQL Injection Vulnerability Below
	
	query = f"SELECT username, email, password_hash FROM users WHERE username=%s"
	
	cursor.execute(query,(username,))

	user = cursor.fetchone()
	
	if user:
		return jsonify({
			"username": user[0],
			"email": user[1],

			# Don't reveal password hash
		})
	
	return jsonify({"error": "User not found"})

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
```

Question 8:

Original Code Snippet:

```
from flask import Flask, request, jsonify
import mysql.connector
import hashlib
import smtplib
import random
import string
from datetime import datetime, timedelta

app = Flask(__name__)

def get_db():
	return mysql.connector.connect(
		host="localhost",
		user="root",
		# Do not store hardcode database password
		password="admin123",
		database="users_db"
	)

def send_email(to_email, subject, body):
	"""Send email to user"""
	# Simplified email sending
	smtp = smtplib.SMTP('smtp.gmail.com', 587)
	smtp.starttls()

	# Do NOT hardcode SMTP Password below!
	smtp.login('company@example.com', 'emailpassword123')
	message = f"Subject: {subject}\n\n{body}"
	smtp.sendmail('company@example.com', to_email, message)
	smtp.quit()

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
	email = request.json['email']
	
	db = get_db()
	cursor = db.cursor()
	
	# Check if user exists

	# SQL Injection Vulnerability Below

	query = f"SELECT id, username FROM users WHERE email='{email}'"

	cursor.execute(query)

	user = cursor.fetchone()
	
	if not user:
		# Don't reveal if email exists
		return jsonify({"message": "If email exists, reset link sent"})
	
	user_id = user[0]
	username = user[1]
	
	# Generate reset token
	# Do NOT use random module for generating tokens
	# Use secrets module instead
	random.seed(user_id)
	token = ''.join(random.choice(string.ascii_letters) for _ in range(20))
	
	# Calculate expiration (24 hours)
	expires_at = datetime.now() + timedelta(hours=24)
	
	# Store token
	# SQL Injection Vulnerability
	query = f"INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ({user_id}, '{token}', '{expires_at}')"
	cursor.execute(query)
	db.commit()
	
	# Send reset email
	# NOT using HTTPS. Please use HTTPS or an attacker can steal
	# the link in a MITM attack!
	reset_link = f"http://example.com/reset-password?token={token}"
	email_body = f"Hi {username},\n\nClick here to reset your password: {reset_link}\n\nThis link expires in 24 hours."
	
	send_email(email, "Password Reset", email_body)
	
	return jsonify({"message": "If email exists, reset link sent"})

@app.route('/reset-password', methods=['POST'])
def reset_password():
	token = request.json['token']
	new_password = request.json['new_password']
	
	db = get_db()
	cursor = db.cursor()
	
	# Find token
	# SQL Injection Vulnerability Below
	query = f"SELECT user_id, expires_at FROM password_reset_tokens WHERE token='{token}'"
	cursor.execute(query)
	result = cursor.fetchone()
	
	if not result:
		return jsonify({"error": "Invalid token"}), 400
	
	user_id = result[0]
	expires_at = result[1]
	
	# Check if expired
	if datetime.now() > expires_at:
		return jsonify({"error": "Token expired"}), 400
	
	# Hash new password with MD5
	# MD5 is NOT a password-based key derivation function
	# Use Argon2 instead
	password_hash = hashlib.md5(new_password.encode()).hexdigest()
	
	# Update password
	
	# SQL Injection Vulnerability Below
	query = f"UPDATE users SET password_hash='{password_hash}' WHERE id={user_id}"
	cursor.execute(query)
	db.commit()

	# Never allow reuse of tokens! This can allow a replay attack!

	# Delete token now it has already been used!
	
	# Token can be reused - don't delete it	

	return jsonify({"message": "Password reset successful"})

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
```

Code Fix:


```
from flask import Flask, request, jsonify
import mysql.connector
import hashlib
import smtplib
import secrets
from passlib.hash import argon2
import string
from datetime import datetime, timedelta

import os

from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

database_password = os.getenv("DATABASE_PASSWORD")

smtp_password = os.getenv("SMTP_PASSWORD")

def get_db():
	return mysql.connector.connect(
		host="localhost",
		user="root",
		# Do not store hardcode database password
		password=database_password,
		database="users_db"
	)

def send_email(to_email, subject, body):
	"""Send email to user"""
	# Simplified email sending
	smtp = smtplib.SMTP('smtp.gmail.com', 587)
	smtp.starttls()

	# Do NOT hardcode SMTP Password below!
	smtp.login('company@example.com',smtp_password)
	message = f"Subject: {subject}\n\n{body}"
	smtp.sendmail('company@example.com', to_email, message)
	smtp.quit()

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
	
	# Implement Rate Limiting for this function

	email = request.json['email']
	
	db = get_db()
	cursor = db.cursor()
	
	# Check if user exists

	# SQL Injection Vulnerability Below

	query = f"SELECT id, username FROM users WHERE email=%s"

	cursor.execute(query,(email,))

	user = cursor.fetchone()
	
	if not user:
		# Don't reveal if email exists
		return jsonify({"message": "If email exists, reset link sent"})
	
	user_id = user[0]
	username = user[1]
	
	# Generate reset token
	# Do NOT use random module for generating tokens
	# Use secrets module instead
	
	token = ''.join(secrets.choice(string.ascii_letters) for i in range(32))
	
	# Calculate expiration (24 hours)
	expires_at = datetime.now() + timedelta(hours=24)
	
	# SQL Injection Vulnerability

	# Store SHA512 hash of token for safe storage

	hash_token = hashlib.sha512(token.encode()).hexdigest()
	
	query = f"INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s,%s,%s)"
	
	cursor.execute(query,(user_id,hash_token,expires_at))
	
	db.commit()
	
	# Send reset email
	# NOT using HTTPS. Please use HTTPS or an attacker can steal
	# the link in a MITM attack!
	reset_link = f"https://example.com/reset-password?token={token}"
	email_body = f"Hi {username},\n\nClick here to reset your password: {reset_link}\n\nThis link expires in 24 hours."
	
	send_email(email, "Password Reset", email_body)
	
	return jsonify({"message": "If email exists, reset link sent"})

@app.route('/reset-password', methods=['POST'])
def reset_password():

	# Implement Rate Limiting for this function

	token = request.json['token']
	new_password = request.json['new_password']
	
	db = get_db()
	cursor = db.cursor()
	
	# Find token
	
	hash_token = hashlib.sha512(token.encode()).hexdigest()

	# SQL Injection Vulnerability Below
	
	query = f"SELECT user_id, expires_at FROM password_reset_tokens WHERE token=%s"
	
	cursor.execute(query,(hash_token,))
	
	result = cursor.fetchone()
	
	if not result:
		return jsonify({"error": "Invalid token"}), 400
	
	user_id = result[0]
	expires_at = result[1]
	
	# Check if expired
	if datetime.now() > expires_at:
		return jsonify({"error": "Token expired"}), 400
	
	# Hash new password with MD5
	# MD5 is NOT a password-based key derivation function
	# Use Argon2 instead

	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(new_password)	

	# Update password
	
	# SQL Injection Vulnerability Below
	
	query = f"UPDATE users SET password_hash=%s WHERE id=%s"

	cursor.execute(query,(password_hash,user_id))

	db.commit()

	# Never allow reuse of tokens! This can allow a replay attack!

	# Delete token now it has already been used!

	query = f"DELETE FROM password_reset_tokens WHERE user_id=%s AND token=%s"

	cursor.execute(query,(user_id,hash_token))

	return jsonify({"message": "Password reset successful"})

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
```

Question 9:

Vulnerable Code Snippet:

```
from flask import Flask, request, jsonify, make_response
import mysql.connector
import hashlib
import time
from datetime import datetime, timedelta

app = Flask(__name__)

def get_db():
	return mysql.connector.connect(
		host="localhost",
		user="root",
		# Never hardcode password!
		password="admin123",
		database="sessions_db"
	)

# No Rate Limiting
@app.route('/login', methods=['POST'])
def login():
	username = request.json['username']
	password = request.json['password']
	
	db = get_db()
	cursor = db.cursor()
	
	# Authenticate user
	# MD5 is NOT a password-based key derivation
	password_hash = hashlib.md5(password.encode()).hexdigest()
	# SQL Injection vulnerability
	query = f"SELECT id, username FROM users WHERE username='{username}' AND password_hash='{password_hash}'"
	cursor.execute(query)
	user = cursor.fetchone()
	
	if not user:
		return jsonify({"error": "Invalid credentials"}), 401
	
	user_id = user[0]

	# Store session as HMAC-SHA-256 in database	
	# Generate session ID based on user ID and timestamp
	session_data = f"{user_id}:{int(time.time())}"
	# MD5 is NOT a password-based key derivation
	session_id = hashlib.md5(session_data.encode()).hexdigest()
	
	# Store session
	expires_at = datetime.now() + timedelta(days=30)
	# SQL Injection vulnerability
	# Store session as HMAC-SHA-256 in database NOT as plaintext
	query = f"INSERT INTO sessions (session_id, user_id, expires_at) VALUES ('{session_id}', {user_id}, '{expires_at}')"
	cursor.execute(query)
	db.commit()
	
	# Set cookie
	response = make_response(jsonify({"message": "Login successful"}))
	response.set_cookie('session_id', session_id)
	
	return response

# No Rate Limiting
@app.route('/api/profile', methods=['GET'])
def get_profile():
	# Get session from cookie
	session_id = request.cookies.get('session_id')
	
	if not session_id:
		return jsonify({"error": "Not authenticated"}), 401
	
	db = get_db()
	cursor = db.cursor()
	
	# Look up session
	# SQL Injection Vulnerability
	query = f"SELECT user_id, expires_at FROM sessions WHERE session_id='{session_id}'"
	cursor.execute(query)
	session = cursor.fetchone()
	
	if not session:
		return jsonify({"error": "Invalid session"}), 401
	
	user_id = session[0]
	expires_at = session[1]
	
	# Check expiration
	if datetime.now() > expires_at:
		return jsonify({"error": "Session expired"}), 401
	
	# Get user profile
	# SQL Injection Vulnerability
	query = f"SELECT id, username, email FROM users WHERE id={user_id}"
	cursor.execute(query)
	user = cursor.fetchone()
	
	return jsonify({
		"id": user[0],
		"username": user[1],
		"email": user[2]
	})

@app.route('/logout', methods=['POST'])
def logout():
	session_id = request.cookies.get('session_id')
	
	if session_id:
		db = get_db()
		cursor = db.cursor()
		
		# Delete session
		# SQL Injection Vulnerability
		query = f"DELETE FROM sessions WHERE session_id='{session_id}'"
		cursor.execute(query)
		db.commit()
	
	response = make_response(jsonify({"message": "Logged out"}))
	response.set_cookie('session_id', '', expires=0)
	
	return response

@app.route('/api/update-email', methods=['POST'])
def update_email():
	session_id = request.cookies.get('session_id')
	new_email = request.json['email']
	
	if not session_id:
		return jsonify({"error": "Not authenticated"}), 401
	
	db = get_db()
	cursor = db.cursor()
	
	# Get user from session
	# SQL Injection Vulnerability
	query = f"SELECT user_id FROM sessions WHERE session_id='{session_id}'"
	cursor.execute(query)
	result = cursor.fetchone()
	
	if not result:
		return jsonify({"error": "Invalid session"}), 401
	
	user_id = result[0]
	
	# Update email
	# SQL Injection Vulnerability
	query = f"UPDATE users SET email='{new_email}' WHERE id={user_id}"
	cursor.execute(query)
	db.commit()
	
	return jsonify({"message": "Email updated"})

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
```

Fixed Code Below:

```
from flask_wtf.csrf import CSRFProtect
from __future__ import annotations
from flask import Flask, request, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import argon2
import mysql.connector
import secrets
import hashlib
import time
from datetime import datetime, timedelta

import os

from dotenv import load_dotenv



app = Flask(__name__)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"],
    storage_uri="memory://",
)

load_dotenv()

database_password = os.getenv("DATABASE_PASSWORD")

def get_db():
	return mysql.connector.connect(
		host="localhost",
		user="root",
		# Never hardcode password!
		password=database_password,
		database="sessions_db"
	)

# No Rate Limiting
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
	username = request.json['username']
	password = request.json['password']
	
	db = get_db()
	cursor = db.cursor()
	
	# Authenticate user
	# MD5 is NOT a password-based key derivation
	
	# SQL Injection vulnerability
	
	query = f"SELECT id, password_hash FROM users WHERE username=%s"

	cursor.execute(query,(username,))
	
	user = cursor.fetchone()
	
	if not user:
		return jsonify({"error": "Invalid credentials"}), 401

	if not argon2.verify(password,user[1]):
		return jsonify({"error": "Invalid credentials"}), 401
			
	user_id = user[0]

	# Store session as HMAC-SHA-512 in database	
	# Generate session ID based on user ID and timestamp
	session_data = f"{user_id}:{int(time.time())}"
	# MD5 is NOT a password-based key derivation
	
	session_id = secrets.token_urlsafe(32)

	sha512_session_id = hashlib.sha512(session_id.encode()).hexdigest()

	# Store session
	expires_at = datetime.now() + timedelta(hours=24)
	# SQL Injection vulnerability
	# Store session as HMAC-SHA-512 in database NOT as plaintext
	query = f"INSERT INTO sessions (session_id, user_id, expires_at) VALUES (%s, %s,%s)"
	cursor.execute(query,(sha512_session_id,user_id,expires_at))

	db.commit()
	
	# Set cookie
	response = make_response(jsonify({"message": "Login successful"}))
	response.set_cookie(
				key='session_id', 
				
				value=session_id,

				expires=expires_at,

				secure=True,

				httponly=True,

				samesite='Strict'
	)

	
	return response

# No Rate Limiting
@app.route('/api/profile', methods=['GET'])
@limiter.limit("5 per minute")
def get_profile():
	# Get session from cookie
	session_id = request.cookies.get('session_id')
	
	if not session_id:
		return jsonify({"error": "Not authenticated"}), 401

	sha512_session_id = hashlib.sha512(session_id.encode()).hexdigest()

	db = get_db()

	cursor = db.cursor()
	
	# Look up session
	# SQL Injection Vulnerability
	query = f"SELECT user_id, expires_at FROM sessions WHERE session_id=%s"

	cursor.execute(query,(sha512_session_id,))

	session = cursor.fetchone()
	
	if not session:
		return jsonify({"error": "Invalid session"}), 401
	
	user_id = session[0]
	expires_at = session[1]
	
	# Check expiration
	if datetime.now() > expires_at:
		return jsonify({"error": "Session expired"}), 401
	
	# Get user profile
	# SQL Injection Vulnerability
	query = f"SELECT id, username, email FROM users WHERE id=%s"
	cursor.execute(query,(user_id,))
	user = cursor.fetchone()
	
	return jsonify({
		"id": user[0],
		"username": user[1],
		"email": user[2]
	})

@app.route('/logout', methods=['POST'])
def logout():
	
	session_id = request.cookies.get('session_id')

	if not session_id:
		
		response = make_response(jsonify({"message": "Logged out"}))
		
		response.set_cookie('session_id', '', expires=0)

		return response
			
	sha512_session_id = hashlib.sha512(session_id.encode()).hexdigest()

	db = get_db()

	cursor = db.cursor()
	
	query = f"SELECT session_id FROM sessions WHERE session_id=%s"
	
	cursor.execute(query,(sha512_session_id,))

	result = cursor.fetchone()

	if result == None:

		response = make_response(jsonify({"message": "Logged out"}))
		
		response.set_cookie('session_id', '', expires=0)

		return response
	
	# Delete session
	# SQL Injection Vulnerability
	query = f"DELETE FROM sessions WHERE session_id=%s"

	cursor.execute(query,(sha512_session_id,))
	db.commit()
	
	response = make_response(jsonify({"message": "Logged out"}))

	response.set_cookie('session_id', '', expires=0)
	
	return response

@app.route('/api/update-email', methods=['POST'])
@limiter.limit("5 per minute")
def update_email():
	
	session_id = request.cookies.get('session_id')
	
	if not session_id:
		return jsonify({"error": "Not authenticated"}), 401
	
	sha512_session_id = hashlib.sha512(session_id.encode()).hexdigest()

	new_email = request.json['email']
	
	
	db = get_db()
	cursor = db.cursor()
	
	# Get user from session
	# SQL Injection Vulnerability
	query = f"SELECT user_id FROM sessions WHERE session_id=%s"

	cursor.execute(query,(sha512_session_id,))

	result = cursor.fetchone()
	
	if not result:
		return jsonify({"error": "Invalid session"}), 401
	
	user_id = result[0]
	
	# Update email
	# SQL Injection Vulnerability
	query = f"UPDATE users SET email=%s WHERE id=%s"
	cursor.execute(query,(new_email,user_id))
	db.commit()
	
	return jsonify({"message": "Email updated"})

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5000)
```

Question 10:

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Global encryption key

# Do NOT hardcode secrets!

ENCRYPTION_KEY = b"hospital_master_key_2024!!!!"

def encrypt_patient_data(ssn, diagnosis):
	"""Encrypt sensitive patient information"""
	# Combine data
	data = f"{ssn}|{diagnosis}"

	# ECB vulnerable to substitution attack and is not an AEAD

	# replace with an AEAD
	
	# Encrypt with AES-ECB
	cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.ECB())
	encryptor = cipher.encryptor()
	
	# Pad to 16 bytes
	padded = data.encode()
	while len(padded) % 16 != 0:
		padded += b'\x00'
	
	encrypted = encryptor.update(padded) + encryptor.finalize()
	return base64.b64encode(encrypted).decode()

# Usage
encrypted_record = encrypt_patient_data("123-45-6789", "diabetes")
print(f"Encrypted with key: {ENCRYPTION_KEY}")
print(f"Result: {encrypted_record}")
```

Severity: High

Vulnerability Discussion:


The first problem is the ENCRYPTION KEY is hardcoded in plaintext

for everyone that can read the source code to see! Please never do

that!

A second issue is the use of AES-ECB. This is an insecure mode of

encryption with AES. It is vulnerable to a substitution attack

where the attacker can switch the positions of AES-ECB ciphertext

blocks. Also there is no authentication tag for recipients to

verify the message has been tampered with. This is why the below

fixed code uses an Authenticated Encryption with Associated Data

(XChaCha20-Poly1305).

Code Fix Below:

```
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

import nacl.secret
import nacl.utils

from dotenv import load_dotenv
import os

# Global encryption key

# Do NOT hardcode secrets!

load_dotenv()


ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY"))

def encrypt_patient_data(ssn, diagnosis):
	"""Encrypt sensitive patient information"""
	# Combine data
	data = f"{ssn}|{diagnosis}"

	# ECB vulnerable to substitution attack and is not an AEAD

	# replace with an AEAD

	data = data.encode()

	box = nacl.secret.SecretBox(ENCRYPTION_KEY)

	nonce=nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

	encrypted = box.encrypt(data,nonce)	

	return base64.b64encode(encrypted).decode()

# Usage
encrypted_record = encrypt_patient_data("123-45-6789", "diabetes")
print(f"Result: {encrypted_record}")
```
Question 11:

```
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import requests
import os

# Company's public key for verifying updates
PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

def verify_update(update_url):
    """Download and verify software update signature"""
    
    # Download update file
    print(f"Downloading update from: {update_url}")
    # Failure to verify `update_url`'s TLS certificate
    response = requests.get(update_url, verify=False)
    update_data = response.content
    
    # Download signature file
    sig_url = update_url.replace('.zip', '.sig')
    sig_response = requests.get(sig_url)
    signature = sig_response.content
    
    # Load public key
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())
    
    # Verify signature
    try:
        public_key.verify(
            signature,
            update_data,
            padding.PKCS1v15(), # PKCS1v15 vulnerable! Update!
            hashes.SHA1() # SHA1 is outdated!
        )
        print("✓ Signature valid! Installing update...")
        install_update(update_data)
    except InvalidSignature:
        print("✗ Invalid signature - skipping update")
    except Exception as e:
        print(f"Verification failed: {e}")
        # Install anyway if verification fails
        install_update(update_data)

def install_update(data):
    """Install the update"""
    with open('/usr/local/bin/app_update.zip', 'wb') as f:
        f.write(data)
    os.system('unzip -o /usr/local/bin/app_update.zip')
    os.system('chmod +x /usr/local/bin/app')
```

Vulnerabilities:

The above code snippet uses PKCS1v15--which has known vulnerabilities

and is outdated. For example it is vulnerable to the Bleichenbacher

Attack, which takes advantage of padding as an oracle. The use of

SHA1 is oudated as SHA-1 was broken in 2017. Better to use

RSA-PSS with SHA-256.

Finally the os.system commands are vulnerable to Command Line

Injection.

Code Fix Below:

```
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import requests
import os
import shlex,subprocess

# Company's public key for verifying updates
PUBLIC_KEY_PEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

def verify_update(update_url):
    """Download and verify software update signature"""
    
    # Download update file
    print(f"Downloading update from: {update_url}")
    # Failure to verify `update_url`'s TLS certificate
    response = requests.get(update_url, verify=True)
    update_data = response.content
    
    # Download signature file
    sig_url = update_url.replace('.zip', '.sig')
    sig_response = requests.get(sig_url)
    signature = sig_response.content
    
    # Load public key
    public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())
    
    # Verify signature
    try:
        public_key.verify(
            signature,
            update_data,
	    padding.PSS(
	    mgf=padding.MGF1(hashes.SHA256()),
	    salt_length=padding.PSS.MAX_LENGTH
        ),
        
	hashes.SHA256())

        print("✓ Signature valid! Installing update...")
        install_update(update_data)
    except InvalidSignature:
        print("✗ Invalid signature - skipping update")
    except Exception as e:
        print(f"Verification failed: {e}")
        # Install anyway if verification fails
	# Do NOT install if verification fails!

def install_update(data):
    """Install the update"""
    with open('/usr/local/bin/app_update.zip', 'wb') as f:
        f.write(data)
    # OS Command Injection Vulnerabilities Below:

    arg1 = 'unzip -o /usr/local/bin/app_update.zip'

    arg2 = 'chmod +x /usr/local/bin/app'

    arg1_shlex = shlex.split(arg1)

    arg2_shlex = shlex.split(arg2)
   
    subprocess.run(arg1_shlex)

    subprocess.run(arg2_shlex)
```

Question 12:

```
from flask import Flask, request, jsonify
import hmac
import hashlib
import time

app = Flask(__name__)

# Shared secret with webhook sender

# Do NOT hardcode API SECRET in codebase!

# No rate-limiting

API_SECRET = "webhook_secret_key_2024"

@app.route('/webhook', methods=['POST'])
def receive_webhook():
	"""Receive and verify signed webhook requests"""
	
	# Get signature from header
	received_signature = request.headers.get('X-Signature')
	
	# Get timestamp from header
	timestamp = request.headers.get('X-Timestamp')
	
	# Get request body
	body = request.get_data().decode()

	# No check if HMAC Signature expired!
	
	# Compute expected signature
	message = f"{timestamp}{body}"
	expected_signature = hmac.new(
		API_SECRET.encode(),
		message.encode(),
		hashlib.md5
	).hexdigest()

	# Timing Vulnerability	
	# Verify signature
	if received_signature == expected_signature:
		print(f"✓ Valid signature from {request.remote_addr}")
		
		# Process webhook
		data = request.get_json()
		process_payment(data['amount'], data['customer_id'])
		
		return jsonify({"status": "success"})
	else:
		return jsonify({"error": "Invalid signature"}), 401
```

Vulnerabilities:

The entire point of verifying HMAC signatures sent by requesters

to verify if the requester is authorized to have the payment

processed.

1. Developer hardcoded API_SECRET in the codebase. Never do this!

Anyone that can read the codebase can learn the secret and start

forging HMAC-signatures.

2. There is no expiration date for HMAC signatures. This can allow

for a replay attack where the attacker captures past requests

and signatures and resends them to the server.

2. There is no attempt to rate-limit requests to /webhook.

An attacker can overwhelm the server with excessive requests.

3. Timing vulnerability in comparing hmacs between user's submission

and what the HMAC signature calculates. An attacker can time responses

from crafted inputs to deduce the expected signature.

4. Use of HMAC-MD5. MD5 is not a cryptographically secure message

digest and HMAC-MD5 should NOT be used!

Code Fix Below:

```
from flask import Flask, request, jsonify
import datetime
import hmac
import hashlib
import time

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from dotenv import load_dotenv
import os

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5/minute"],
    storage_uri="memory://",
)

# Shared secret with webhook sender

# Do NOT hardcode API SECRET in codebase!

# No rate-limiting

load_dotenv()

API_SECRET = os.getenv("API_SECRET")

@app.route('/webhook', methods=['POST'])
@limiter.limit("5/minute")
def receive_webhook():
	"""Receive and verify signed webhook requests"""
	
	# Get signature from header
	received_signature = request.headers.get('X-Signature')

	if not received_signature:
		
		return jsonify({"error": "Invalid signature"}), 401

		
	
	# Get timestamp from header
	timestamp = request.headers.get('X-Timestamp')

	if not timestamp:

		return jsonify({"error": "No timestamp"}), 400

	
	# Get request body
	body = request.get_data().decode()

	# No check if HMAC Signature expired!

	# Check if HMAC signature expired here. The expiration

	# date must be set at the creation time of the HMAC

	# signature before being sent to the user, whose code

	# this question does not show.

	# So I leave a comment here about it.

	# Compute expected signature
	message = f"{timestamp}{body}"
	expected_signature = hmac.new(
		API_SECRET.encode(),
		message.encode(),
		hashlib.sha512
	).hexdigest()

	# Timing Vulnerability	
	# Verify signature
	if hmac.compare_digest(received_signature,expected_signature):
		print(f"✓ Valid signature from {request.remote_addr}")

		current_time = int(time.time()) 

		expiration_time = timestamp + datetime.timedelta(seconds=300)
	
		if current_time > expiration_time: 		
			
			return jsonify({"error": "Invalid Timestamp"}), 400

		# Process webhook
		data = request.get_json()
		process_payment(data['amount'], data['customer_id'])
		
		return jsonify({"status": "success"})
	else:
		return jsonify({"error": "Invalid signature"}), 401
```

Question 13:

```
import requests
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

class SSLAdapter(HTTPAdapter):
	"""Custom SSL adapter for API connections"""
	
	def init_poolmanager(self, *args, **kwargs):
		context = ssl.create_default_context()
		context.check_hostname = True
		context.verify_mode = ssl.CERT_REQUIRED
		
		kwargs['ssl_context'] = context
		return super().init_poolmanager(*args, **kwargs)

# API client configuration
API_BASE_URL = "https://api.company.com"
EXPECTED_CERT_FINGERPRINT = "a1b2c3d4e5f6..."

session = requests.Session()
session.mount('https://', SSLAdapter())

# IDOR Vulnerability: An attacker can fetch data for a different user!
# No Rate Limiting
def fetch_user_data(user_id):
	"""Fetch sensitive user data from API"""
	
	# Require authentication tests before doing

	# the request

	url = f"{API_BASE_URL}/users/{user_id}"
	
	# Make request
	response = session.get(url)
	
	if response.status_code == 200:
		return response.json()
	else:
		raise Exception(f"API error: {response.status_code}")

# IDOR Vulnerability: An attacker can fetch data for a different user!

# No Rate Limiting

def update_payment_method(user_id, card_data):
	"""Update user's payment information"""
	url = f"{API_BASE_URL}/users/{user_id}/payment"
	
	# Require authentication tests before 

	# getting the response
	
	response = session.post(url, json=card_data)
	
	return response.json()
```

---

## Phase 1: Identify Vulnerabilities (10 minutes)

**List 5-6 security issues. For each provide:**

**Format:**

No rate limiting for `fetch_user_data()` nor `update_payment_method`.

An attacker can overwhelm the server with excessive requests.

Consider a rate limit max of 5 requests/minute.

Neither `fetch_user_data()` nor `update_payment_method` do an

authentication nor authorization tests. One simple way to do an

authentication test is to check for a valid HttpOnly Session Cookie

and Anti-CSRF Token.

Without such an authentication test an attacker can submit a request

using another user's user_id.


```
SEVERITY: [Vulnerability Name] (Line X)
- What's wrong: [1 sentence]
- Exploitation: [1 sentence]
- Fix: [1 sentence]

Question 14:

```
import os
import configparser
from datetime import datetime
import boto3
import psycopg2
import stripe

# Configuration file: config.ini
config = configparser.ConfigParser()
config.read('config.ini')

# Database connection
DB_HOST = config.get('database', 'host')
DB_USER = config.get('database', 'user')

# Do not store Database Password in config file
DB_PASS = config.get('database', 'password')

DB_NAME = config.get('database', 'name')

# Third-party API keys

# Do NOT Hardcode API Keys! STRIPE_API_KEY hardcoded

STRIPE_API_KEY = "sk_live_51HqQwertyABCD1234567890"
OPENAI_API_KEY = os.getenv("OPENAI_KEY", "sk-default-key-for-testing")

# Do not store SendGrid API Key in config file!

SENDGRID_API_KEY = config.get('email', 'api_key')

# AWS credentials
# Do NOT Hardcode API Keys! AWS Keys hardcoded
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def connect_database():
	"""Connect to PostgreSQL database"""
	conn = psycopg2.connect(
		host=DB_HOST,
		user=DB_USER,
		password=DB_PASS,
		database=DB_NAME
	)
	return conn

# No rate limiting
def process_payment(amount, customer_id):
	"""Process payment via Stripe"""
	stripe.api_key = STRIPE_API_KEY

	# No authentication to test if actual

	# customer is making the request
	
	charge = stripe.Charge.create(
		amount=amount,
		currency='usd',
		customer=customer_id
	)
	
	return charge


# No rate limiting
def upload_to_s3(file_path, bucket_name):
	"""Upload file to S3"""
	s3 = boto3.client(
		's3',
		aws_access_key_id=AWS_ACCESS_KEY,
		aws_secret_access_key=AWS_SECRET_KEY
	)
	
	s3.upload_file(file_path, bucket_name, file_path)

	# Revealing file_path is risky! Don't do that!
	
	# You also don't need to reveal which bucket was

	# uploaded to.

	print(f"Uploaded {file_path} to {bucket_name}")

def send_email(to_address, subject, body):
	"""Send email via SendGrid"""
	import sendgrid
	
	sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_API_KEY)
	
	message = {
		"from": {"email": "noreply@company.com"},
		"to": [{"email": to_address}],
		"subject": subject,
		"content": [{"type": "text/plain", "value": body}]
	}
	
	response = sg.send(message)
	print(f"Email sent! Status: {response.status_code}")
	
	return response
```

Vulnerabilities:

1. No rate-limiting: An attacker can overwhelm the server with

excessive requests.

2. Several API keys hardcoded. The Stripe and AWS keys are hardcoded.

They should be stored as environment variables.

3. Log leak: File path and Bucket name of AWS Bucket are both

leaked. Do not reveal that information! An attacker can start targeting

that AWS Bucket for sensitive information.

4. No authentication test for `process_payment()`. An attacker can

process payment for another customer_id.

No code fix for this question since there is not enough information

to fix most of these bugs. For the case of hardcoded secrets one

must instead use environment variables.

For the cases of secrets stored in config files it is best to store

them instead as environment variables.

To prevent log leak delete the print statement that leaks the file

path and bucket name.

To fix the authentication test please check the user's session cookie

and anti-csrf token before processing payment.

Question 15:

```
from fastapi import FastAPI, Depends, HTTPException, Response, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import secrets
import hashlib
from datetime import datetime, timedelta
from pydantic import BaseModel

app = FastAPI()
security = HTTPBearer()

# Configuration

# Do NOT hardcode secrets!

JWT_SECRET = "my-secret-key-2024"
JWT_ALGORITHM = "HS256"

# Do NOT hardcode API keys

# No attempt at rate-limiting!

API_KEYS = {
	"client_abc": "key_123456789",
	"client_xyz": "key_987654321"
}

# In-memory storage (production would use database)
sessions = {}
refresh_tokens = {}

class LoginRequest(BaseModel):
	username: str
	
	# Bad idea to store password plain!

	# Store hash of password

	password: str 

def create_jwt_token(user_id: str):
	"""Create JWT access token"""

	payload = {
		"user_id": user_id,
		"exp": datetime.utcnow() + timedelta(hours=24)

		# Best practice to have issuer and audience arguments

		# though not required
	}


	token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

	return token

def create_session(user_id: str):
	"""Create session for web users"""
	session_id = secrets.token_hex(16)

	# Do not store session_id in memory!

	# Store a hash of session_id instead

	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()

	sessions[session_id_hash] = {
		"user_id": user_id,
		"created_at": datetime.utcnow()
	}
	return session_id

def create_refresh_token(user_id: str):
	"""Create refresh token"""
	token = secrets.token_hex(32)

	# Do not index with raw token

	# Index with hash instead

	token_hash = hashlib.sha512(token.encode()).hexdigit()

	refresh_tokens[token_hash] = user_id

	return token

@app.post("/login")
async def login(request: LoginRequest, response: Response):
	"""Login endpoint for web and API users"""
	# Authenticate user (simplified)
	user_id = authenticate_user(request.username, request.password)
	
	if not user_id:
		raise HTTPException(401, "Invalid credentials")
	
	# Create tokens
	access_token = create_jwt_token(user_id)
	refresh_token = create_refresh_token(user_id)
	session_id = create_session(user_id)
	
	# Set session cookie
	response.set_cookie(
		key="session_id",
		value=session_id,
		max_age=86400

		# Missing cookie security flags such as

		# Expires, Domain, secure, HttpOnly, SameSite, and Path
	)
	
	return {
		"access_token": access_token,
		"refresh_token": refresh_token,
		"token_type": "bearer"
	}

@app.post("/refresh")
async def refresh(refresh_token: str):
	"""Refresh access token"""

	token_hash = hashlib.sha512(token.encode()).hexdigit()
	
	user_id = refresh_tokens.get(token_hash)
	
	if not user_id:
		raise HTTPException(401, "Invalid refresh token")
	
	new_access_token = create_jwt_token(user_id)
	
	return {
		"access_token": new_access_token,
		"token_type": "bearer"
	}

@app.get("/api/profile")
async def get_profile_api(credentials: HTTPAuthorizationCredentials = Depends(security)):
	"""Get user profile via JWT (for API clients)"""
	token = credentials.credentials
	
	try:
		# Remember the extra traits recommended such as

		# audience,issuer, etc, exp
		payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
		user_id = payload["user_id"]
		return {"user_id": user_id, "profile": "data"}
	except jwt.InvalidTokenError:
		raise HTTPException(401, "Invalid token")

@app.get("/web/profile")
async def get_profile_web(session_id: str = Cookie(None)):
	"""Get user profile via session (for web users)"""

	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()
	
	session = sessions.get(session_id_hash)
	
	if not session:
		raise HTTPException(401, "Not authenticated")
	
	user_id = session["user_id"]
	return {"user_id": user_id, "profile": "data"}

@app.post("/admin/users")
async def create_user(api_key: str, user_data: dict):
	"""Admin endpoint - create user (service-to-service)"""
	# Check API key
	valid_key = None
	
	# Do not store API keys in plaintext in memory!

	for client, key in API_KEYS.items():
		if hmac.compare_digest(api_key,key):
			valid_key = client
			break
	
	if not valid_key:
		raise HTTPException(403, "Invalid API key")
	
	# Create user
	return {"status": "created", "client": valid_key}

@app.delete("/web/account")
async def delete_account(session_id: str = Cookie(None)):
	"""Delete user account (destructive action)"""
	session = sessions.get(session_id)

	# The user must pass password authentication

	# Simply checking with Session Cookie insufficient.	
	if not session:
		raise HTTPException(401, "Not authenticated")
	
	user_id = session["user_id"]
	
	# Delete account
	return {"status": "deleted", "user_id": user_id}

def authenticate_user(username: str, password: str):
	"""Authenticate user (simplified)"""
	# In real app: check against database with Argon2

	# Developer failed to hash password and check against

	# stored hash of password

	if username and password:
		return f"user_{username}"
	return None
```

---

## Phase 1: Identify Vulnerabilities (15 minutes)

**List 6-8 security issues. For each provide:**

**Format:**
```
SEVERITY: [Vulnerability Name] (Line X)
- What's wrong: [1 sentence]
- Exploitation: [1 sentence]
- Fix: [1 sentence]
```
Vulnerabilities:

See comments in code that are complementary to the below explanations:

1. Password Stored in Memory in plaintext. An attacker can easily steal

this! It is better to store the password hash in a database. I won't

fix that in the code fix below but I am letting you know that should

be done here.

2. Lack of security flags in cookies and JWT. See comments. Without

those security flags cookies are vulnerable to CSRF, being stolen,

and abused in replay attacks where attacker send valid cookies to the

server. Since the current vulnerable code contains no expiration date

flag.

3. No defense against CSRF.

3. No rate-limiting.

4. When deleting the account it is security best practice to

require the user to have a valid session cookie, X-CSRF Token, and pass

a password authentication test all at once! This will prevent an

attacker from forging a request for account deletion or tricking the

user from deleting their account!

5. Secrets such as session_id are stored in plaintext. Store the

hashes instead.

6. No attempt at API Key Rotation. It is best to rotate secrets

periodically in case they are compromised.



Below is the fixed code:

```
from dotenv import load_dotenv
import os
from fastapi import FastAPI, Depends, HTTPException, Request,Response, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette_csrf import CSRFMiddleware
import jwt
import secrets
import hashlib
import hmac
import time,datetime
from datetime import timezone
from datetime import datetime, timedelta
from pydantic import BaseModel

load_dotenv()

limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
security = HTTPBearer()

app.add_middleware(CSRFMiddleware, secret=os.getenv("CSRF_SECRET"))
# Initialize CsrfProtect with a secret key

# Configuration

# Do NOT hardcode secrets!


JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"


# Do NOT hardcode API keys

# No attempt at rate-limiting!

# No attempt at API Key Rotation

API_KEYS = {
	"client_abc": os.getenv("client_abc"),
	"client_xyz": os.getenv("client_xyz")
}

# In-memory storage (production would use database)
sessions = {}
refresh_tokens = {}

class LoginRequest(BaseModel):
	username: str
	
	# Bad idea to store password plain!

	# Store hash of password in database.

	password: str 

def create_jwt_token(user_id: str):
	"""Create JWT access token"""

	payload = {
		"user_id": user_id,
		"exp": datetime.utcnow() + timedelta(hours=24),

		"aud": "audience_here",

		"iss": "issuer_here"

		# Best practice to have issuer and audience arguments

		# though not required
	}


	token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

	return token

def create_session(user_id: str):
	"""Create session for web users"""
	session_id = secrets.token_hex(16)

	# Do not store session_id in memory!

	# Store a hash of session_id instead

	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()

	sessions[session_id_hash] = {
		"user_id": user_id,
		"created_at": datetime.utcnow()
	}
	return session_id

def create_refresh_token(user_id: str):
	"""Create refresh token"""
	token = secrets.token_hex(32)

	# Do not index with raw token

	# Index with hash instead

	token_hash = hashlib.sha512(token.encode()).hexdigest()


	refresh_tokens[token_hash] = user_id

	return token

@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request,login_data: LoginRequest, response: Response):
	"""Login endpoint for web and API users"""
	# Authenticate user (simplified)

	# Once again do NOT store password in plaintext
	user_id = authenticate_user(login_data.username, login_data.password)
	
	if not user_id:
		raise HTTPException(401, "Invalid credentials")
	
	# Create tokens
	access_token = create_jwt_token(user_id)
	refresh_token = create_refresh_token(user_id)
	session_id = create_session(user_id)
	
	# Set session cookie
	response.set_cookie(
		key="session_id",
		value=session_id,
		max_age=86400,
		expires=datetime.now() + timedelta(hours=24),
		secure=True,
		httponly=True,
		samesite='Strict'
	)
	
	return {
		"access_token": access_token,
		"refresh_token": refresh_token,
		"token_type": "bearer"
	}

@app.post("/refresh")
@limiter.limit("5/minute")
async def refresh(request: Request,refresh_token: str):
	"""Refresh access token"""

	# The line below must be edited to retrieve token by hashing

	# token as index.

	token_hash = hashlib.sha512(refresh_token.encode()).hexdigest()

	user_id = refresh_tokens.get(token_hash)
	
	if not user_id:
		raise HTTPException(401, "Invalid refresh token")
	
	new_access_token = create_jwt_token(user_id)

	del refresh_tokens[token_hash]
	
	return {
		"access_token": new_access_token,
		"token_type": "bearer"
	}

@app.get("/api/profile")
@limiter.limit("5/minute")
async def get_profile_api(request: Request,credentials: HTTPAuthorizationCredentials = Depends(security)):
	"""Get user profile via JWT (for API clients)"""
	token = credentials.credentials
	
	try:
		# Remember the extra traits recommended such as

		# audience,issuer, etc, exp
		payload = jwt.decode(
					token,
					JWT_SECRET,
					algorithms=[JWT_ALGORITHM],
					issuer="issuer_here",
					audience="audience_here"
		)

		user_id = payload["user_id"]
		return {"user_id": user_id, "profile": "data"}
	except jwt.InvalidTokenError:
		raise HTTPException(401, "Invalid token")

@app.get("/web/profile")
@limiter.limit("5/minute")
async def get_profile_web(request: Request,session_id: str = Cookie(None)):
	"""Get user profile via session (for web users)"""
	
	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()

	session = sessions.get(session_id_hash)
	
	if not session:
		raise HTTPException(401, "Not authenticated")
	
	user_id = session["user_id"]
	return {"user_id": user_id, "profile": "data"}

@app.post("/admin/users")
@limiter.limit("5/minute")
async def create_user(request: Request,api_key: str, user_data: dict):
	"""Admin endpoint - create user (service-to-service)"""
	# Check API key
	valid_key = None
	
	# Do not store API keys in plaintext in memory!

	for client, key in API_KEYS.items():
		if hmac.compare_digest(api_key,key):
			valid_key = client
			break
	
	if not valid_key:
		raise HTTPException(403, "Invalid API key")
	
	# Create user
	return {"status": "created", "client": valid_key}

@app.delete("/web/account")
@limiter.limit("5/minute")
async def delete_account(request: Request,session_id: str = Cookie(None)):
	"""Delete user account (destructive action)"""
	
	# The user must pass password authentication

	# first. Then check if session Cookie is valid.

	# Third check if Anti-CSRF Token is valid.

	# Then finally delete.

	
	session_id_hash = hashlib.sha256(session_id.encode()).hexdigest()

	session = sessions.get(session_id_hash)
	


	# The user must pass password authentication

	# first before proceeding with deletion

	# Simply checking with Session Cookie insufficient.	
	if not session:
		raise HTTPException(401, "Not authenticated")
	
	user_id = session["user_id"]
	
	# Delete account
	return {"status": "deleted", "user_id": user_id}

def authenticate_user(username: str, password: str):
	"""Authenticate user (simplified)"""
	# In real app: check against database with Argon2

	# Developer failed to hash password and check against

	# stored hash of password


	if username and password:
		return f"user_{username}"
	return None

```

Question 16:

```
from flask import Flask, request, jsonify
import sqlite3
import hashlib
import random
import string
import os
# Missing import below
# from dotenv import load_dotenv
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


app = Flask(__name__)
DATABASE = 'users.db'
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', 'SG.test_key_12345')

def get_db():
	"""Get database connection"""
	conn = sqlite3.connect(DATABASE)
	conn.row_factory = sqlite3.Row
	return conn

def init_db():
	"""Initialize database schema"""
	conn = get_db()
	conn.execute('''
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	''')
	
	conn.execute('''
		CREATE TABLE IF NOT EXISTS reset_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			created_at TIMESTAMP NOT NULL,
			used BOOLEAN DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	''')
	
	conn.commit()
	conn.close()

def generate_reset_token():
	"""Generate password reset token"""

	chars = string.ascii_letters + string.digits
	
	# `random` module is unsuitable for CSPRNG

	# Use `secrets` module instead

	token = ''.join(random.choice(chars) for _ in range(20))

	return token

def send_reset_email(email, token):
	"""Send password reset email via SendGrid"""
	reset_url = f"https://example.com/reset?token={token}"
	
	message = Mail(
		from_email='noreply@example.com',
		to_emails=email,
		subject='Password Reset Request',
		html_content=f'''
		<p>Hello,</p>
		<p>Click the link below to reset your password:</p>
		<p><a href="{reset_url}">Reset Password</a></p>
		<p>This link will expire in 1 hour.</p>
		<p>If you didn't request this, please ignore this email.</p>
		'''
	)
	
	try:
		sg = SendGridAPIClient(SENDGRID_API_KEY)
		response = sg.send(message)
		return response.status_code == 202
	except Exception as e:
		print(f"Error sending email: {e}")
		return False

@app.route('/register', methods=['POST'])
def register():
	"""Register new user"""
	data = request.json
	email = data.get('email')
	password = data.get('password')
	name = data.get('name')

	
	if not email or not password or not name:
		return jsonify({"error": "Missing required fields"}), 400

	# SHA256 is NOT a password-based key derivation function!	
	# Hash password with SHA256
	password_hash = hashlib.sha256(password.encode()).hexdigest()
	
	conn = get_db()
	
	try:
		conn.execute('''
			INSERT INTO users (email, password_hash, name)
			VALUES (?, ?, ?)
		''', (email, password_hash, name))
		conn.commit()
		conn.close()
		
		return jsonify({"message": "User registered successfully"}), 201
		
	except sqlite3.IntegrityError:
		conn.close()
		return jsonify({"error": "Email already exists"}), 400

@app.route('/login', methods=['POST'])
def login():
	"""Login user"""
	data = request.json
	email = data.get('email')
	password = data.get('password')

	# SHA256 is NOT a password-based key derivation function	
	password_hash = hashlib.sha256(password.encode()).hexdigest()
	
	conn = get_db()
	user = conn.execute('''
		SELECT * FROM users WHERE email = ? AND password_hash = ?
	''', (email, password_hash)).fetchone()
	conn.close()
	
	if user:
		return jsonify({"message": "Login successful", "name": user['name']}), 200
	else:
		return jsonify({"error": "Invalid credentials"}), 401

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
	"""Request password reset"""
	email = request.json.get('email')
	
	conn = get_db()
	
	# Check if user exists
	user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
	
	if not user:
		conn.close()
		# Don't reveal if email exists
		return jsonify({"message": "If that email exists, a reset link has been sent"}), 200
	
	# Generate reset token
	token = generate_reset_token()

	# Store cryptographic message digest of token

	# in database NOT the raw token. If the database

	# is stolen the token is stolen as well without

	# doing so.	
	# Store token in database
	conn.execute('''
		INSERT INTO reset_tokens (token, user_id, created_at, used)
		VALUES (?, ?, ?, ?)
	''', (token, user['id'], datetime.utcnow(), False))
	
	conn.commit()
	conn.close()
	
	# Send email
	send_reset_email(email, token)
	
	return jsonify({"message": "If that email exists, a reset link has been sent"}), 200

@app.route('/reset-password', methods=['POST'])
def reset_password():
	"""Reset password with token"""
	token = request.json.get('token')
	new_password = request.json.get('new_password')
	
	conn = get_db()
	
	# Validate token
	token_data = conn.execute('''
		SELECT rt.*, u.email 
		FROM reset_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token = ?
	''', (token,)).fetchone()
	
	if not token_data:
		conn.close()
		return jsonify({"error": "Invalid token"}), 400
	
	user_id = token_data['user_id']
	created_at = datetime.fromisoformat(token_data['created_at'])
	
	# Check expiration (1 hour)
	if datetime.utcnow() - created_at > timedelta(hours=1):
		conn.close()
		return jsonify({"error": "Token expired"}), 400
	
	# Hash new password

	# SHA256 is NOT a cryptographically secure message digest

	password_hash = hashlib.sha256(new_password.encode()).hexdigest()
	
	# Update password in database
	conn.execute('''
		UPDATE users
		SET password_hash = ?
		WHERE id = ?
	''', (password_hash, user_id))
	
	# Don't mark token as used - keep for reuse
	
	conn.commit()
	conn.close()
	
	return jsonify({"message": "Password reset successful"}), 200

@app.route('/check-token', methods=['GET'])
def check_token():
	"""Check if reset token is valid"""
	token = request.args.get('token')

	# Check with the hash of the token against database	
	conn = get_db()
	
	token_data = conn.execute('''
		SELECT rt.*, u.email
		FROM reset_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token = ?
	''', (token,)).fetchone()
	
	conn.close()
	
	if token_data:
		created_at = datetime.fromisoformat(token_data['created_at'])
		
		if datetime.utcnow() - created_at <= timedelta(hours=1):
			return jsonify({
				"valid": True,
				"email": token_data['email'],
				"created_at": token_data['created_at']
			}), 200
	
	return jsonify({"valid": False}), 200

if __name__ == '__main__':
	init_db()
	app.run(debug=True)
```

Vulnerabilities:

0. No attempt to rotate API key periodically. This is best practice.

Since SendGridAPIClient is being used here I cannot feasibly fix

the code to allow for API.

1. No attempt at rate limiting.

2. SHA256 is NOT a password-based key derivation algorithm.

An attacker can launch a rainbow attack to map known SHA256 hashes

to common passwords--bypassing authentication. I see SHA256 is used

to hash the password throughout the application.

3. In `generate_reset_token()` the `random` module is used--which

is not a CSPRNG! An attacker can predict the outputs of the `random`

module. Use the `secrets` module instead.

4. In `forgot_password()` do NOT store token as a raw value

in the `users` database. An attacker can steal the token in case

the database gets stolen. Store the hash of the token instead. 

5. In `reset_password()` the token data is NOT deleted as it should

be after successful password reset.

6. Although its possible to mark tokens as used it stil leaves

past tokens in the database. Which not only wastes memory but

always leaves the risk that an attacker can see expired tokens 

Instead I propose expired tokens get deleted.

Below is the fixed code:

```
from __future__ import annotations
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import hashlib
import random
import secrets
import string
import os
# Missing import below
# from dotenv import load_dotenv
from datetime import datetime, timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from passlib.hash import argon2


app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5 per minute"],
    storage_uri="memory://",
)

DATABASE = 'users.db'

SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', 'SG.test_key_12345')

DATABASE_KEY = os.getenv('DATABASE_KEY')

def get_db():
	"""Get database connection"""
	conn = sqlite3.connect(DATABASE)
	conn.row_factory = sqlite3.Row
	return conn

def init_db():
	"""Initialize database schema"""
	conn = get_db()
	conn.execute('''
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	''')
	
	conn.execute('''
		CREATE TABLE IF NOT EXISTS reset_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)
	''')
	
	conn.commit()
	conn.close()

def generate_reset_token():
	"""Generate password reset token"""

	chars = string.ascii_letters + string.digits
	
	# `random` module is unsuitable for CSPRNG

	# Use `secrets` module instead

	token = ''.join(secrets.choice(chars) for i in range(32))

	return token

def send_reset_email(email, token):
	"""Send password reset email via SendGrid"""
	reset_url = f"https://example.com/reset?token={token}"
	
	message = Mail(
		from_email='noreply@example.com',
		to_emails=email,
		subject='Password Reset Request',
		html_content=f'''
		<p>Hello,</p>
		<p>Click the link below to reset your password:</p>
		<p><a href="{reset_url}">Reset Password</a></p>
		<p>This link will expire in 1 hour.</p>
		<p>If you didn't request this, please ignore this email.</p>
		'''
	)
	
	try:
		sg = SendGridAPIClient(SENDGRID_API_KEY)
		response = sg.send(message)
		return response.status_code == 202
	except Exception as e:
		print(f"Error sending email: {e}")
		return False

@app.route('/register', methods=['POST'])
@limiter.limit("5/minute")
def register():
	"""Register new user"""
	data = request.json
	email = data.get('email')
	password = data.get('password')
	name = data.get('name')

	
	if not email or not password or not name:
		return jsonify({"error": "Missing required fields"}), 400

	# SHA256 is NOT a password-based key derivation function!	
	# Hash password with SHA256
	
	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(password)
	
	conn = get_db()
	
	try:
		conn.execute('''
			INSERT INTO users (email, password_hash, name)
			VALUES (?, ?, ?)
		''', (email, password_hash, name))
		conn.commit()
		conn.close()
		
		return jsonify({"message": "User registered successfully"}), 201
		
	except sqlite3.IntegrityError:
		conn.close()
		return jsonify({"error": "Email already exists"}), 400

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
	"""Login user"""
	data = request.json
	email = data.get('email')
	password = data.get('password')

	# SHA256 is NOT a password-based key derivation function	
	
	conn = get_db()
	user = conn.execute('''
		SELECT name,email,password_hash FROM users WHERE email = ?
	''', (email,)).fetchone()
	conn.close()

	
	if user and argon2.verify(password,user['password_hash']):
		return jsonify({"message": "Login successful", "name": user['name']}), 200
	else:
		return jsonify({"error": "Invalid credentials"}), 401

@app.route('/forgot-password', methods=['POST'])
@limiter.limit("5/minute")
def forgot_password():
	"""Request password reset"""
	email = request.json.get('email')
	
	conn = get_db()
	
	# Check if user exists
	user = conn.execute('SELECT id,email FROM users WHERE email = ?', (email,)).fetchone()
	
	if not user:
		conn.close()
		# Don't reveal if email exists
		return jsonify({"message": "If that email exists, a reset link has been sent"}), 200
	
	# Generate reset token
	token = generate_reset_token()

	# Store cryptographic message digest of token

	# in database NOT the raw token. If the database

	# is stolen the token is stolen as well without

	# doing so.	
	# Store token in database
	
	token_hash = hashlib.sha512(token.encode()).hexdigest()

	conn.execute('''
		INSERT INTO reset_tokens (token, user_id, created_at)
		VALUES (?, ?, ?)
	''', (token_hash, user['id'], datetime.utcnow()))
	
	conn.commit()
	conn.close()
	
	# Send email
	send_reset_email(email, token)
	
	return jsonify({"message": "If that email exists, a reset link has been sent"}), 200

@app.route('/reset-password', methods=['POST'])
@limiter.limit("5/minute")
def reset_password():
	"""Reset password with token"""
	token = request.json.get('token')
	
	new_password = request.json.get('new_password')
	
	token_hash = hashlib.sha512(token.encode()).hexdigest()

	conn = get_db()
	
	# Validate token
	token_data = conn.execute('''
		SELECT rt.*, u.email 
		FROM reset_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token = ?
	''', (token_hash,)).fetchone()
	
	if not token_data:
		conn.close()
		return jsonify({"error": "Invalid token"}), 400
	
	user_id = token_data['user_id']
	created_at = datetime.fromisoformat(token_data['created_at'])
	
	# Check expiration (1 hour)
	if datetime.utcnow() - created_at > timedelta(hours=1):

		conn.execute('''

			DELETE FROM reset_tokens where token = ?
		''',(token_hash,))	

		conn.commit()

		conn.close()

		return jsonify({"error": "Token expired"}), 400
	
	# Hash new password

	# SHA256 is NOT a cryptographically secure message digest

	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(new_password) 

	# Update password in database
	conn.execute('''
		UPDATE users
		SET password_hash = ?
		WHERE id = ?
	''', (password_hash, user_id))
	

	conn.commit()

	conn.execute('''

		DELETE FROM reset_tokens where token = ?
	''',(token_hash,))	

	conn.commit()
	
	conn.close()
	
	return jsonify({"message": "Password reset successful"}), 200

@app.route('/check-token', methods=['GET'])
@limiter.limit("5/minute")
def check_token():
	"""Check if reset token is valid"""
	token = request.args.get('token')

	token_hash = hashlib.sha512(token.encode()).hexdigest()

	# Check with the hash of the token against database	
	conn = get_db()
	
	token_data = conn.execute('''
		SELECT rt.*, u.email
		FROM reset_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token = ?
	''', (token_hash,)).fetchone()
	
	if token_data:
		created_at = datetime.fromisoformat(token_data['created_at'])
		
		if datetime.utcnow() - created_at <= timedelta(hours=1):
			
			conn.close()

			return jsonify({
				"valid": True,
				"email": token_data['email'],
				"created_at": token_data['created_at']
			}), 200

	# Invalid token must be deleted from database
	conn.execute('''

		DELETE FROM reset_tokens where token = ?
	''',(token_hash,))	

	conn.commit()
	
	conn.close()
	
	return jsonify({"valid": False}), 200

if __name__ == '__main__':
	init_db()
	app.run(debug=False)
```

Question 17 Part A:

Vulnerabilities:

1. The modulus size of RSA, 1024 bits, is too small. It should

be at least 2048 bits.

2. Although not required it is best practice to have issuer

and audience parameters.

3. PKCS1v15-SHA1 is insecure! It suffers vulnerability to the

Bleichenbacher Attack which uses padding as an oracle. Also SHA-1

has been broken in 2017.

4. The developer failed to sign the entire payload in the JWT.

Without doing this the attacker can corrupt the `role` and `exp` fields

allowing the attacker to bypass authorization checks and performing

replay attacks--a replay attack takes place when n attacker captures

a previously issued payload and JWT and resubmits it to the server.

In this case the attacker can extend the expiration date to ensure

the token passes JWT Token Validation checks.

5. Although not a security bug it is best practice to have the issuer

and audience fields in JWT tokens.

Below is the fixed code:

```
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
	user_data = authenticate_user(username, password)
	
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
```

Part B:

```
## Part B: TLS Certificate Review

The Engineering Team is deploying this API with HTTPS. You inspect their certificate:

Part B:

Below is the certificate:

```
## Part B: TLS Certificate Review

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4a:7f:92:3c:d1:8e:5b:22
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, ST=CA, O=Company, CN=api.company.com
        Validity
            Not Before: Jan  1 00:00:00 2023 GMT
            Not After : Jan  1 00:00:00 2024 GMT
        Subject: C=US, ST=CA, O=Company, CN=api.company.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus: [omitted]
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                [omitted]
            X509v3 Authority Key Identifier:
                [omitted]
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha1WithRSAEncryption
    Signature Value:
        [omitted]
```

The following is a summary of 20 checks on the validity of the TLS

Certificate:

```
VALIDATION SUMMARY:

CHECK 1:  Version 3 - PASS
CHECK 2:  Not expired/not yet valid - FAIL
CHECK 3: sha1WithRSAEncryption signature - FAIL
CHECK 4: RSA-2048 strong key - PASS
CHECK 5: Subject DN present - PASS
CHECK 6:  SANs present - FAIL
CHECK 7:  Hostname matches - FAIL (would need actual hostname)
CHECK 8:  Basic Constraints: CA:FALSE (critical) - FAIL
CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - FAIL
CHECK 10: Extended Key Usage: TLS Web Server Authentication - FAIL
CHECK 11: CRL Distribution Points present (>=1 URLs REQUIRED) - FAIL
CHECK 12: Authority Information Access present - FAIL
CHECK 13: OCSP URL present (optional) - FAIL
CHECK 14: Certificate Transparency (>= 2 SCTs) - FAIL
CHECK 15: Not self-signed (Issuer ≠ Subject) - FAIL
CHECK 16: Valid serial number (64 bits entropy) - PASS
CHECK 17: SKI present (RECOMMENDED, not required for end-entity) - PASS
CHECK 18: AKI present - PASS
CHECK 19: SKI ≠ AKI (CONDITIONAL, both present) - FAIL
CHECK 20: Validity 365.0 <= 398 days - PASS

The following CHECKS FAILED and are REQUIRED:[2, 3, 6, 7, 8, 10, 11, 12, 14, 15, 19]


The following CHECKS FAILED and are OPTIONAL:[9, 13]
```

As we can see there are several REQUIRED checks that Failed.

The fix:

Use `certbot` from Let's Encrypt to automatically generate a valid,

signed certificate. It should not fail any of the checks that are

required.

Question 18 Part A:

```
import random
import string
import hashlib
import sqlite3
import time

_DATABASE = "api_keys.db"

def generate_api_key(customer_id):
	"""Generate new API key for customer"""
	# Generate random 32-character key
	chars = string.ascii_letters + string.digits
	
	# Use secrets module!
	api_key = ''.join(random.choice(chars) for _ in range(32))
	
	# Hash the key for storage
	key_hash = hashlib.md5(api_key.encode()).hexdigest()
	
	# Store in database
	conn = sqlite3.connect(_DATABASE)
	cursor = conn.cursor()
	cursor.execute(
		f"INSERT INTO api_keys (customer_id, key_hash, created_at) "
		f"VALUES ('{customer_id}', '{key_hash}', {int(time.time())})"
	)
	conn.commit()
	conn.close()
	
	# Return plaintext key to customer (only time they'll see it)
	return api_key

def verify_api_key(api_key):
	"""Verify API key is valid and return customer_id"""
	# Hash provided key
	key_hash = hashlib.md5(api_key.encode()).hexdigest()
	
	# Query database
	conn = sqlite3.connect(_DATABASE)
	cursor = conn.cursor()
	cursor.execute(
		f"SELECT customer_id FROM api_keys WHERE key_hash = '{key_hash}'"
	)
	result = cursor.fetchone()
	conn.close()
	
	# Check if key exists
	if result:
		return result[0]
	else:
		# Simulate processing time for invalid keys
		time.sleep(0.1)
		return None
```

Vulnerabilities:

1. `random` module in `generate_api_key()` is not secure as a CSPRNG.

An attacker can predict the outcome of the `random` module and steal

API secrets.

2. In `generate_api_key()` MD5 is NOT a cryptographically secure

message digest algorithm. `verify_api_key()` also carries this same

problem.

An attacker can brute-force generate a hash input that maps to

the expected hash output of the original api_keys (this is called

a hash collision).

3. SQL Injection Vulnerability when inserting values to database

in `generate_api_key()`. Should use Parameterization of SQL Queries.

4. SQL Injection Vulnerability in `verify_api_key()` when retrieving

`customer_id`.

5. Timing Vulnerability: An attacker can craft inputs to

`verify_api_key()` to deduce the MD5 hash of the API key.

Fixed code below:

```
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

	result = cursor.fetchone()

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
```

Question 18 Part B:

Vulnerabilities:

1. In `rotate_api_key()` MD5 is used to calculate the `key_hash`.

MD5 is NOT collision resistant! An attacker can generate a hash input

that matches the expected key_hash even if the the hash input does

not match the authentic API key.

2. SQL Injection vulnerability in `rotate_api_key()` when expired

api_key is deleted from database.

```
def rotate_api_key(old_api_key):
	"""Rotate API key - generate new one, invalidate old one"""
	# Verify old key is valid
	customer_id = verify_api_key(old_api_key)
	if not customer_id:
		raise Exception("Invalid API key")
	
	# Generate new key
	new_api_key = generate_api_key(customer_id)
	
	# Delete old key immediately

	# Do NOT use MD5 for cryptographic message digests!

	old_key_hash = hashlib.md5(old_api_key.encode()).hexdigest()
	conn = sqlite3.connect(_DATABASE)
	cursor = conn.cursor()

	# SQL Injection Vulnerability Below

	cursor.execute(
		f"DELETE FROM api_keys WHERE key_hash = '{old_key_hash}'"
	)
	conn.commit()
	conn.close()
	
	return new_api_key
```

Fixed Code Below:

NOTE: There is a new check in generate_api_key() if an API key

already exists for a customer_id avoiding multiple valid keys.

```
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
```

Question 18 Part C:

Code Snippet:

```
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
		hashlib.md5
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
	if signature == expected:
		return True
	else:
		return False
```

Vulnerabilities:

1. `sign_request()` uses HMAC-MD5 which is not collision resistant.

An attacker can guess an hmac input that has the expected hmac output

even though the input does not necessarily match the expected input.

2. `verify_request()` has a timing vulnerability in the comparision

between the calculated signature and the `expected` signature. An

attacker can craft inputs for `verify_request` and measure the time

it takes to receive responses to deduce the expected signature.

3. No expiration date set for the HMAC. This is best practice to

avoid replay attacks which allow the attacker to resubmit previously

issued HMAC signatures and bypass authentication.

Below is the fixed code:

```
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
```

Question 19 Part A:

1. TLSv1.2 and TLSv1.3 are the only ciphers that should be used.

2. Outdated ciphers are used. Some of them use SHA1. Also CBC mode

is not an AEAD. 


3. The TLS Certificate for `medical-records.example.com` is expired.

Its February 2nd, 2026 as I write this.

Below is the NGINX configuration:

server {
    listen 443 ssl;
    server_name medical-records.example.com;

    
    # SSL Certificate
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    # SSL Protocol Configuration

    # Only allow TLSv1.2 and TLSv1.3
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
   
    # Outdated ciphers used!
 
    # Cipher Suite Configuration
    ssl_ciphers 'ECDHE-RSA-AES128-CBC-SHA:ECDHE-RSA-AES256-CBC-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:DES-CBC3-SHA';
    ssl_prefer_server_ciphers on;
    
    # Session Cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Best practice to enable OCSP Stapling
    
    # OCSP Stapling
    # ssl_stapling off;
    # ssl_stapling_verify off;
    
    location / {
        proxy_pass http://localhost:8080;
    }
}

**Certificate Details:**

# TLS Certificate for medical-records.example.com is expired

Certificate Chain:
1. medical-records.example.com (leaf certificate)
   Issuer: IntermediateCA
   Valid: 2024-01-01 to 2025-01-01
   
2. IntermediateCA (intermediate certificate)
   Issuer: RootCA
   Valid: 2020-01-01 to 2030-01-01
   
3. RootCA (root certificate)
   Issuer: RootCA (self-signed)
   Valid: 2015-01-01 to 2035-01-01

Below is the corrected NGINX configuration information:

server {
    listen 443 ssl;
    server_name medical-records.example.com;

    
    # SSL Certificate
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    # SSL Protocol Configuration

    # Only allow TLSv1.2 and TLSv1.3
    ssl_protocols TLSv1.2 TLSv1.3;
   
    # Outdated ciphers used!
 
    # Cipher Suite Configuration
    ssl_ciphers 'AES256-GCM-SHA384:AES128-GCM-SHA256';

    ssl_prefer_server_ciphers on;
    
    # Session Cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Best practice to enable OCSP Stapling
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    location / {
        proxy_pass http://localhost:8080;
    }
}
```

**Certificate Details:**
```
# TLS Certificate for medical-records.example.com is expired

Certificate Chain:
1. medical-records.example.com (leaf certificate)
   Issuer: IntermediateCA
   Valid: 2026-01-01 to 2026-03-01
   
2. IntermediateCA (intermediate certificate)
   Issuer: RootCA
   Valid: 2020-01-01 to 2030-01-01
   
3. RootCA (root certificate)
   Issuer: RootCA (self-signed)
   Valid: 2015-01-01 to 2035-01-01

Question 19 Part B:

Code Snippet:

```
from flask import Flask, request, jsonify, make_response
import secrets
import hashlib
import hmac
import json
import base64
import time

# No attempt at CSRF Protection

app = Flask(__name__)

# Secret key for signing cookies

# Do NOT hardcode SECRET_KEY!

SECRET_KEY = "production-secret-key-2024"

def create_session_cookie(user_id, username, role):
	"""Create signed session cookie"""
	# Session data as JSON
	session_data = {
		'user_id': user_id,
		'username': username,
		'role': role,
		'is_admin': (role == 'admin'),
		'login_time': int(time.time())

		# No field marking when cookie expires
	}
	
	# Encode as base64
	session_json = json.dumps(session_data)
	session_b64 = base64.b64encode(session_json.encode()).decode()
	
	# Sign with HMAC-SHA256
	signature = hmac.new(
		SECRET_KEY.encode(),
		session_b64.encode(),
		hashlib.sha256
	).hexdigest()
	
	# Cookie value: base64_data.signature
	cookie_value = f"{session_b64}.{signature}"
	
	return cookie_value

def verify_session_cookie(cookie_value):
	"""Verify and parse session cookie"""
	if not cookie_value:
		return None

	# Must check if session cookie expired
	
	try:
		# Split cookie into data and signature
		session_b64, provided_sig = cookie_value.split('.')
		
		# Verify signature
		expected_sig = hmac.new(
			SECRET_KEY.encode(),
			session_b64.encode(),
			hashlib.sha256
		).hexdigest()

		# Timing Vulnerability Below
		
		if provided_sig != expected_sig:
			return None
		
		# Decode session data
		session_json = base64.b64decode(session_b64).decode()
		session_data = json.loads(session_json)
		
		return session_data
		
	except Exception as e:
		return None

@app.route('/login', methods=['POST'])
def login():
	"""User login endpoint"""
	username = request.form.get('username')
	password = request.form.get('password')
	
	# Authenticate user (assume this works correctly)
	user = authenticate_user(username, password)
	if not user:
		return jsonify({"error": "Invalid credentials"}), 401
	
	# Create session cookie
	cookie_value = create_session_cookie(
		user_id=user['id'],
		username=user['username'],
		role=user['role']
	)
	
	# Create response and set cookie
	response = make_response(jsonify({"message": "Login successful"}))
	response.set_cookie(
		'session',
		value=cookie_value,
		max_age=86400 * 7,  # 7 days
		httponly=True,
		path='/'

		# Secure flag missing

		# SameSite flag missing

		# Its best practice to have Expires flag to make

		# it easy for server to check expiration
	)
	
	return response

@app.route('/api/records', methods=['GET'])
def get_records():
	"""Get medical records (requires authentication)"""
	# Read session cookie
	cookie_value = request.cookies.get('session')
	session_data = verify_session_cookie(cookie_value)
	
	if not session_data:
		return jsonify({"error": "Unauthorized"}), 401
	
	# Check if user is admin
	if session_data.get('is_admin'):
		records = get_all_records()
	else:
		records = get_user_records(session_data['user_id'])
	
	return jsonify({"records": records})

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
	"""Admin endpoint - get all users"""
	cookie_value = request.cookies.get('session')
	session_data = verify_session_cookie(cookie_value)
	
	if not session_data:
		return jsonify({"error": "Unauthorized"}), 401
	
	if not session_data.get('is_admin'):
		return jsonify({"error": "Forbidden"}), 403
	
	users = get_all_users()
	return jsonify({"users": users})

@app.route('/logout', methods=['POST'])
def logout():
	"""User logout endpoint"""
	response = make_response(jsonify({"message": "Logged out"}))
	response.set_cookie('session', '', max_age=0)
	return response

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080)
```

Vulnerabilities:

-1. No attempt at CSRF Protection.

0. No API key rotation for SECRET_KEY. This is best practice.

1. No attempt at rate-limiting. An attacker can overwhelm the server

with excessive requests.

2. SECRET_KEY is hardcoded. Anyone who can read the source code

can steal the SECRET_KEY!


3. Timing Vulnerability in `verify_session_cookie()` where

provided_sig != expected_sig. An attacker can craft cookie_values

and measure the time it takes to get responses to deduce the

`expected_sig`.

4. Set-Cookie is missing two security flags: SameSite and Secure 

5. There is no check that a session cookie has expired in

`verify_session_cookie()`. The server should do a manual check

that the cookie expired. Do not rely on the browser to automatically

delete expired cookies since browsers can restore tabs and session

cookies when the browser is restarted (API Security in Action 122).

Below is the fixed code:

```
from __future__ import annotations
from flask import Flask, render_template,request, jsonify, make_response, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import hashlib
import hmac
import json
import base64
import time,datetime
from datetime import timezone
import os
from dotenv import load_dotenv

load_dotenv()

# No attempt at CSRF Protection!

app = Flask(__name__)

# Secret key for signing cookies

# Do NOT hardcode SECRET_KEY!

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5/minute"],
    storage_uri="memory://",
)


# SECRET_KEY should store a 16-byte string

# generated by a CSPRNG

SECRET_KEY = str(os.getenv("SECRET_KEY"))

def create_session_cookie(user_id, username, role):
	"""Create signed session cookie"""
	# Session data as JSON

	expiration_time = datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(days=7)
 
	session_data = {
		'user_id': user_id,
		'username': username,
		'role': role,
		'is_admin': (role == 'admin'),
		'login_time': int(time.time()),
		'exp': int(time.time() + (86400 * 7))
		# No field marking when cookie expires
	}
	
	# Encode as base64
	session_json = json.dumps(session_data)
	session_b64 = base64.b64encode(session_json.encode()).decode()
	
	# Sign with HMAC-SHA256
	signature = hmac.new(
		SECRET_KEY.encode(),
		session_b64.encode(),
		hashlib.sha256
	).hexdigest()
	
	# Cookie value: base64_data.signature
	cookie_value = f"{session_b64}.{signature}"
	
	return cookie_value

def verify_session_cookie(cookie_value):
	"""Verify and parse session cookie"""
	if not cookie_value:
		return None

	# Must check if session cookie expired
	
	try:
		# Split cookie into data and signature
		session_b64, provided_sig = cookie_value.split('.')
		
		# Verify signature
		expected_sig = hmac.new(
			SECRET_KEY.encode(),
			session_b64.encode(),
			hashlib.sha256
		).hexdigest()

		# Timing Vulnerability Below
		
		if not hmac.compare_digest(provided_sig,expected_sig):
			
			return None

		# Decode session data
		session_json = base64.b64decode(session_b64).decode()
		
		session_data = json.loads(session_json)

		current_time = int(time.time()) 

		if current_time > session_data['exp']:

			return None
		
		return session_data
		
	except Exception as e:

		print(f"Exception: {e}")

		return None

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
	"""User login endpoint"""
	username = request.form.get('username')
	password = request.form.get('password')
	
	# Authenticate user (assume this works correctly)
	user = authenticate_user(username, password)
	if not user:
		return jsonify({"error": "Invalid credentials"}), 401
	
	# Create session cookie
	cookie_value = create_session_cookie(
		user_id=user['id'],
		username=user['username'],
		role=user['role']
	)
	
	# Create response and set cookie
	response = make_response(jsonify({"message": "Login successful"}))
	response.set_cookie(
		'session',
		value=cookie_value,
		max_age=86400 * 7,  # 7 days
		httponly=True,
		path='/',
		secure=True,
		samesite='Strict' # This suffices as CSRF Protection

		# Secure flag missing

		# SameSite flag missing
	)
	
	return response

@app.route('/api/records', methods=['GET'])
@limiter.limit("5/minute")
def get_records():
	"""Get medical records (requires authentication)"""
	# Read session cookie
	cookie_value = request.cookies.get('session')
	session_data = verify_session_cookie(cookie_value)
	
	if not session_data:
		return jsonify({"error": "Unauthorized"}), 401
	
	# Check if user is admin
	if session_data.get('is_admin'):
		records = get_all_records()
	else:
		records = get_user_records(session_data['user_id'])
	
	return jsonify({"records": records})

@app.route('/api/admin/users', methods=['GET'])
@limiter.limit("5/minute")
def admin_get_users():
	"""Admin endpoint - get all users"""
	cookie_value = request.cookies.get('session')
	session_data = verify_session_cookie(cookie_value)
	
	if not session_data:
		return jsonify({"error": "Unauthorized"}), 401
	
	if not session_data.get('is_admin'):
		return jsonify({"error": "Forbidden"}), 403
	
	users = get_all_users()

	return jsonify({"users": users})

@app.route('/logout', methods=['POST'])
@limiter.limit("5/minute")
def logout():
	"""User logout endpoint"""
	response = make_response(jsonify({"message": "Logged out"}))
	response.set_cookie('session', '', max_age=0)
	return response

if __name__ == '__main__':

	cookie_value = create_session_cookie(1,"name","user")

	print(f"cookie_value:{cookie_value}")

	session_data = verify_session_cookie(cookie_value)
	
	print(f"session_data:{session_data}")

	app.run(host='0.0.0.0', port=8080)
```

Question 19 Part C:

Code Snippet:

```
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import hashlib

# Master password (stored in environment variable)
MASTER_PASSWORD = os.environ.get('MASTER_PASSWORD', 'default-password')

def derive_encryption_key(record_id):
	"""Derive encryption key for a specific medical record"""
	# Use record_id as salt
	
	# Salt: 
	salt = hashlib.md5(record_id.encode()).digest()
	
	# Derive key with PBKDF2
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=1000  # Fast key derivation
	)
	
	key = kdf.derive(MASTER_PASSWORD.encode())
	return key

def encrypt_record(record_id, plaintext):
	"""Encrypt medical record"""
	# Derive key
	key = derive_encryption_key(record_id)
	
	# Encrypt with AES-GCM
	aesgcm = AESGCM(key)
	nonce = os.urandom(12)
	ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
	
	# Return nonce + ciphertext
	return nonce + ciphertext

def decrypt_record(record_id, encrypted_data):
	"""Decrypt medical record"""
	# Parse data
	nonce = encrypted_data[:12]
	ciphertext = encrypted_data[12:]
	
	# Derive key (same as encryption)
	key = derive_encryption_key(record_id)
	
	# Decrypt
	aesgcm = AESGCM(key)
	plaintext = aesgcm.decrypt(nonce, ciphertext, None)
	
	return plaintext.decode()
```

Vulnerabilities:

1. `derive_encryption_key()`:

Salt should be generated by a CSPRNG and never derived

through deterministic means. That and MD5 is not collision resistant.

Never use it for cryptographic message digests!

2. `derive_encryption_key()`:

When using PBKDF2 with SHA256 one must use 600,000 iterations.

The code snippet only uses 1,000 iterations.

3. `record_id` is not secure for use as a salt. The salt is

supposed to be ideally derived from the CSPRNG. Without such proper salts

the attacker can more easily perform attacks such as Rainbow Table Attacks. 

Below is the fixed code:

```
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import hashlib

# Master password (stored in environment variable)
MASTER_PASSWORD = os.environ.get('MASTER_PASSWORD', 'default-password')

def derive_encryption_key(salt):
	"""Derive encryption key for a specific medical record"""
	
	# Use of record_id as salt is NOT secure!	
	
	# Use a unique, CSPRNG-derived salt for encrypting data

	# for each unique record_id

	# Use record_id as salt
	
	# Derive key with PBKDF2
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=600000 # Fast key derivation
	)
	
	key = kdf.derive(MASTER_PASSWORD.encode())
	return key

def encrypt_record(record_id, plaintext):
	"""Encrypt medical record"""

	# Derive salt

	salt = os.urandom(16)

	# Derive key
	key = derive_encryption_key(salt)
	
	# Encrypt with AES-GCM
	aesgcm = AESGCM(key)
	nonce = os.urandom(12)
	ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
	
	# Return nonce + ciphertext
	return nonce + ciphertext,salt

def decrypt_record(record_id, encrypted_data,salt):
	"""Decrypt medical record"""
	# Parse data
	nonce = encrypted_data[:12]
	ciphertext = encrypted_data[12:]
	
	# Derive key (same as encryption)
	key = derive_encryption_key(salt)
	
	# Decrypt
	aesgcm = AESGCM(key)
	plaintext = aesgcm.decrypt(nonce, ciphertext, None)
	
	return plaintext.decode()
```

Question 20:

Vulnerable Code Snippet:

```
import sqlite3

_DATABASE = "users.db"

def authenticate_user(username, password):
	cursor = sqlite3.connect(_DATABASE).cursor()

	# SQL Injection Vulnerability Below:

	# Never store raw password in database.

	# Store the hash derived from a password-based

	# key derivation function instead. OWASP recommends

	# Argon2, Scrypt, Bcrypt, and PBKDF2 as options for this

	cursor.execute(f"select password, allowed_files from users where username = '{username}'")
	expected_password, allowed_files = cursor.fetchone()

	# Timing Attack Vulnerability Below
	if password != expected_password:
		raise Exception(f"Invalid password")
	return allowed_files
```

Vulnerabilities:

1. SQL Injection Vulnerability when retrieving password and

allowed_files. SQL Parameterization should be used.

2. Never store the raw password in the database.  If an attacker

steals the database they can also steal the password!

Store the hash of the password using any of the approved

password-based key derivation functions recommended by OWASP.

3. There is a timing attack vulnerability when comparing submitted

password against the password stored in the database. An attacker

can craft passwords and measure the timing of the responses to

deduce the expected password stored in the database.

Below is the fixed code:

```
import sqlite3
import hmac
from passlib.hash import argon2

_DATABASE = "users.db"

def authenticate_user(username, password):
	cursor = sqlite3.connect(_DATABASE).cursor()

	# SQL Injection Vulnerability Below:

	# Never store raw password in database.

	# Store the hash derived from a password-based

	# key derivation function instead. OWASP recommends

	# Argon2, Scrypt, Bcrypt, and PBKDF2 as options for this

	cursor.execute("select password_hash, allowed_files from users where username = ?",(username,))

	expected_pwhash, allowed_files = cursor.fetchone()

	# Timing Attack Vulnerability Below
	if not argon2.verify(password,expected_pwhash):
		raise Exception(f"Invalid password")

	return allowed_files
```

Question 22:

Vulnerable Code Snippet:

```
# settings.py

SECRET_KEY = 'django-insecure-key-for-production-2024'

DEBUG = True

ALLOWED_HOSTS = ['*']

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'sessionid'
SESSION_COOKIE_AGE = 1209600  # 2 weeks in seconds
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = None

SESSION_SAVE_EVERY_REQUEST = False

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
	'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Security Settings

# No Secure SSL Redirect!
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
```

-2. Session Cookies are vulnerable to CSRF.

-1. Do NOT hardcode the SECRET KEY. An attacker can steal this

upon accessing the file.

0. Disable Debug Mode. Debug mode can leak sensitive data.

1. Only specify the exact allowed hosts that you need. The DNS

wildcard '*' allows all hosts.

1. No Secure SSL Redirect.

2. Although not required best practice to setup Http Strict Transport

Layer Security. This defends against the SSL Stripping Attack that

forcibly downgrades TLS connections to plaintext.

2.5. This is a gray area but 2 weeks for a valid Session Cookies

is a very long time. A better amount of time is 24 hours.

3. Session Cookie Secure Flag is set to False. This means Cookies

will be sent even if HTTPS is NOT enabled. An attacker can steal

this in a MITM Attack!

4. SameSite does not have a secure value. Set to 'Strict' for

best Security. This will protect Cookies from CSRF.

5. SSL Redirect is set to False! All redirects should be protected

under TLS to defend against MITM Attacks!

Below is the fixed settings:

```
# settings.py

# SECRET_KEY should be generated by a CSPRNG and stored as

an environment variable

SECRET_KEY = config("SECRET_KEY")

DEBUG = False

ALLOWED_HOSTS = ['example.com']

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'sessionid'
SESSION_COOKIE_AGE = 86400  # 2 weeks in seconds
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

SESSION_SAVE_EVERY_REQUEST = False

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'django.middleware.common.CommonMiddleware',
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
	'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Security Settings

# No Secure SSL Redirect!
SECURE_SSL_REDIRECT = True 
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

Question 23:

Vulnerable Code Snippet:

```
# views.py
from django.core.signing import Signer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import time

# Use a simple salt
signer = Signer(salt='user-tokens')


@csrf_exempt
def create_token(request):
	"""Create signed token for user"""
	username = request.POST.get('username')
	
	# Create token data
	token_data = {
		'username': username,
		'is_admin': False
		# No expiration time
	}
	
	# Sign only username, not the entire token
	signed_username = signer.sign(username)
	
	# Return token with unsigned data
	return JsonResponse({
		'token': signed_username,
		'data': token_data
	})

@csrf_exempt
def verify_token(request):
	"""Verify and use token"""
	token = request.POST.get('token')
	data = json.loads(request.POST.get('data'))
	
	try:
		# Verify the signed username
		username = signer.unsign(token)
		
		# Use the unsigned data directly
		if data.get('is_admin'):
			# Grant admin access
			return JsonResponse({'status': 'admin access granted'})
		else:
			return JsonResponse({'status': 'user access granted'})
			
	except:
		return JsonResponse({'error': 'Invalid token'}, status=401)
```

Vulnerabilities:

0. No attempt at rate-limiting. An attacker can overwhelm the

server with excessive requests!

1. In `create_token()` only the username field is signed. The flag

for `is_admin` can be edited by an attacker to force the token to be

valid as an administrator.

2. No expiration date set for token in `create_token()`. An attacker

can capture previously issued valid tokens (such as in a CSRF attack)

and resubmit them to the server--bypassing authentication.

Below is the fixed code:

```
# views.py
from django_ratelimit.decorators import ratelimit
from django.core.signing import Signer
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import time
import jwt
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN_KEY = os.getenv("TOKEN_KEY")

@csrf_exempt
@ratelimit(key='ip',rate='5/m')
def create_token(request):
	"""Create signed token for user"""
	username = request.POST.get('username')
	
	# Create token data
	token_data = {
		'username': username,
		'is_admin': False,
		# 24 hours until expiration
		'exp' : int(time.time() + 86400), 
		'iss' : 'example.com',
		'aud' : 'api-user'
	}

	try:

		jwt_encode = jwt.encode(token_data,
					TOKEN_KEY,
					algorithm="HS256"

		)

		return jwt_encode

	except jwt.InvalidKeyError:

		return None

	except jwt.InvalidKeyLengthError:

		return None

	except Exception as e:

		print(f"Exception:{e}")

		return None
						

# Not a good idea to leave this exempt from CSRF Exemption

# since it handles REST API requests!

@csrf_exempt
@ratelimit(key='ip',rate='5/m')
def verify_token(request):
	"""Verify and use token"""
	token = request.POST.get('token')
	
	try:
		jwt_decode = jwt.decode(token,
					TOKEN_KEY,
					algorithms=["HS256"],
					issuer="example.com",
					audience="api-user"
		)

		current_time = int(time.time())

		if current_time > jwt_decode['exp']:

			return JsonResponse({'error': 'Invalid token'}, status=401)

		# Use the unsigned data directly
		if jwt_decode['is_admin']:
			# Grant admin access
			return JsonResponse({'status': 'admin access granted'})
		else:
			return JsonResponse({'status': 'user access granted'})
			
	except jwt.InvalidTokenError:
		return JsonResponse({'error': 'Invalid token'}, status=401)
	
	except Exception:
		return JsonResponse({'error': 'Invalid token'}, status=401)
```

Question 24:

Vulnerable Code Snippet:

```
# settings.py

PASSWORD_HASHERS = [
	'django.contrib.auth.hashers.MD5PasswordHasher',
	'django.contrib.auth.hashers.PBKDF2PasswordHasher',
	'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]

# Custom user authentication
# auth.py
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
import hashlib

def register_user(username, password, email):
	"""Register new user with custom hashing"""
	
	# Use username as salt for consistency

	# You are supposed to use a salt derived from a CSPRNG!
	salt = username
	
	# Fast hashing for better performance
	password_hash = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
	
	# Store in database
	user = User.objects.create(
		username=username,
		password=password_hash,
		email=email
	)
	
	return user

def authenticate_user(username, password):
	"""Authenticate user"""
	try:
		user = User.objects.get(username=username)
		
		# Recreate hash
		salt = username
		password_hash = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
		
		# Compare hashes
		if user.password == password_hash:
			return user
		else:
			return None
			
	except User.DoesNotExist:
		return None
```

Vulnerabilities:

0. The salt is supposed to be derived from a CSRPNG in both

`register_user()` and `authenticate_user()`!

1. SHA256 is NOT a password-based key derivation function!

An attacker can quickly calculate SHA256 hashes using machines

with powerful CPUs (or GPUs) to quickly brute-force guess match

the user's password against the hash.

It is used in both `register_user()` and `authenticate_user()`.

2. Timing Attack Vulnerability: An attacker can craft passwords

and time responses to deduce the expected password hash.

Below is the fixed code:

```
# settings.py

'''
PASSWORD_HASHERS = [
	'django.contrib.auth.hashers.MD5PasswordHasher',
	'django.contrib.auth.hashers.PBKDF2PasswordHasher',
	'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]
'''

# Custom user authentication
# auth.py
from passlib.hash import argon2
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
import hashlib

def register_user(username, password, email):
	"""Register new user with custom hashing"""
	
	# Use username as salt for consistency

	# You are supposed to use a salt derived from a CSPRNG!

	# Use a password-based key derivation function approved

	# by OWASP such as argon2
	
	# Fast hashing for better performance
	
	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(password)	

	user = User.objects.create(
		username=username,
		password=password_hash,
		email=email
	)
	
	return user

def authenticate_user(username, password):
	"""Authenticate user"""
	try:
		user = User.objects.get(username=username)
		
		# Recreate hash

		# Do NOT use username as salt

		# Use a password-based key derivation function approved

		# by OWASP such as argon2

		# Compare hashes

		# Timing Attack vulnerability below!

		if argon2.verify(password,user.password):
			return user
		else:
			return None
			
	except User.DoesNotExist:
		return None
```

Question 25:

Vulnerable Code Snippet:

```
# authentication.py
from django.conf import settings
import hmac
import hashlib
import json
import base64

# SECRET_KEY MUST NOT be hardcoded

SECRET_KEY = "hardcoded-secret-key-2024"

def create_auth_token(user_id, username, permissions):
	"""Create authentication token"""
	
	# Token payload
	payload = {
		'user_id': user_id,
		'username': username,
		'permissions': permissions
		# No expiration
	}
	
	# Encode payload
	payload_json = json.dumps(payload)
	payload_b64 = base64.b64encode(payload_json.encode()).decode()
	
	signature = hmac.new(
		SECRET_KEY.encode(),

		# Only user_id is signed with HMAC!
		str(user_id).encode(),
		hashlib.sha256
	).hexdigest()
	
	# Return token
	token = f"{payload_b64}.{signature}"
	return token

def verify_auth_token(token):
	"""Verify authentication token"""
	try:
		# Split token
		payload_b64, provided_sig = token.split('.')
		
		# Decode payload
		payload_json = base64.b64decode(payload_b64).decode()
		payload = json.loads(payload_json)
		
		# Verify signature

		# Only user_id is signed and verified
		user_id = payload['user_id']
		expected_sig = hmac.new(
			SECRET_KEY.encode(),
			str(user_id).encode(),
			hashlib.sha256
		).hexdigest()
	
		# Timing Vulnerability	
		if provided_sig == expected_sig:
			return payload
		else:
			return None
			
	except Exception as e:
		return None

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .authentication import create_auth_token, verify_auth_token


@csrf_exempt
def login(request):
	"""Login endpoint"""
	username = request.POST.get('username')
	password = request.POST.get('password')
	
	# Authenticate (assume this works)
	user = authenticate(username, password)
	
	if user:
		token = create_auth_token(
			user_id=user.id,
			username=user.username,
			permissions=['read']
		)
		return JsonResponse({'token': token})
	else:
		return JsonResponse({'error': 'Invalid credentials'}, status=401)

@csrf_exempt
def admin_panel(request):
	"""Admin endpoint"""
	token = request.headers.get('Authorization', '').replace('Bearer ', '')
	
	payload = verify_auth_token(token)
	
	if not payload:
		return JsonResponse({'error': 'Unauthorized'}, status=401)
	
	# Check permissions from token
	if 'admin' in payload.get('permissions', []):
		return JsonResponse({'data': 'Secret admin data'})
	else:
		return JsonResponse({'error': 'Forbidden'}, status=403)
```

Vulnerabilities:

0. SECRET_KEY is hardcoded. An attacker can steal this if the

attacker gains access to the source code.

0.5. No attempt to periodically rotate SECRET_KEY. This should

be done in case an attacker steals the current SECRET_KEY. So

when a new key is chosen the previous one is invalid.

1. No expiration datetime set for Auth Token. An attacker can thus

resubmit previously issued tokens to bypass authentication.

2. `create_auth_token()` and `verify_auth_token()` both have this

issue: Only the `user_id` field of the auth_token is signed. The

attacker can thus get away with modifying all other fields in the token

including the username and permissions. This can allow the attacker

to gain elevated privileges.

3. `verify_auth_token()` has a timing vulnerability: an attacker

can craft tokens with signatures and measure the time it takes

to compare the submitted signature vs expected to deduce expected

signature.

4. No attempt at rate-limiting for views.py. An attacker can overwhelm

server with excessive requests.


Below is the fixed code:

```
# authentication.py
from django.conf import settings
import hmac
import hashlib
import json
import base64
import jwt
import os
import secrets 
import time
from dotenv import load_dotenv,set_key


# SECRET_KEY MUST NOT be hardcoded

# SECRET_KEY security should be 128

# bits of security and be derived

# from a CSPRNG. So that's 16 bytes.

load_dotenv()

# Good habit to rotate API key every 6 months

SECRET_KEY = os.getenv("SECRET_KEY")

KEY_EXP = os.getenv("KEY_EXP") # stored as Unix timestamp as string

def did_key_exp():

	current_time = int(time.time())

	if current_time > int(KEY_EXP):

		set_key('.env','SECRET_KEY',secrets.token_urlsafe(32))
		
		six_months_later_delta =  24 * 60 * 60 * 30 * 6
		
		set_key('.env','KEY_EXP',str(current_time + six_months_later_delta))


def create_auth_token(user_id, username, permissions):
	"""Create authentication token"""

	did_key_exp()
	
	# Token payload
	payload = {
		'user_id': user_id,
		'username': username,
		'permissions': permissions,
		'exp': int(time.time() + 86400),
		'iss': "example.com",
		'aud': 'api-user'
	}

	try:
		jwt_encode = jwt.encode(
					payload,

					SECRET_KEY,

					algorithm="HS256"
		)
	
		return jwt_encode

	except jwt.InvalidKeyError:

		return None
	
	except jwt.InvalidKeyLengthError:

		return None

	except Exception as e:

		return None
	
	return jwt_encode

def verify_auth_token(token):
	"""Verify authentication token"""
	try:

		did_key_exp()

		jwt_decode = jwt.decode(
					token,

					SECRET_KEY,

					algorithms=["HS256"],

					issuer="example.com",

					audience="api-user"
		)

		current_time = int(time.time())

		if current_time > jwt_decode['exp']:

			return None

		return jwt_decode

	except jwt.InvalidTokenError:

		return None

	except Exception as e:

		return None

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.conf import settings
import hmac
import hashlib
import json
import base64
import jwt
import os
import secrets 
import time
from dotenv import load_dotenv,set_key
from dotenv import set_key


# SECRET_KEY MUST NOT be hardcoded

# SECRET_KEY security should be 128

# bits of security and be derived

# from a CSPRNG. So that's 16 bytes.

load_dotenv()

# Good habit to rotate API key every 6 months

SECRET_KEY = os.getenv("SECRET_KEY")

KEY_EXP = os.getenv("KEY_EXP") # stored as Unix timestamp as string

def did_key_exp():

	current_time = int(time.time())

	if current_time > int(KEY_EXP):

		set_key('.env','SECRET_KEY',secrets.token_urlsafe(32))
		
		six_months_later_delta =  24 * 60 * 60 * 30 * 6
		
		set_key('.env','KEY_EXP',str(current_time + six_months_later_delta))


def create_auth_token(user_id, username, permissions):
	"""Create authentication token"""

	did_key_exp()
	
	# Token payload
	payload = {
		'user_id': user_id,
		'username': username,
		'permissions': permissions,
		'exp': int(time.time() + 86400),
		'iss': "example.com",
		'aud': 'api-user'
	}

	try:
		jwt_encode = jwt.encode(
					payload,

					SECRET_KEY,

					algorithm="HS256"
		)
	
		return jwt_encode

	except jwt.InvalidKeyError:

		return None
	
	except jwt.InvalidKeyLengthError:

		return None

	except Exception as e:

		return None
	
	return jwt_encode

def verify_auth_token(token):
	"""Verify authentication token"""
	try:

		did_key_exp()

		jwt_decode = jwt.decode(
					token,

					SECRET_KEY,

					algorithms=["HS256"],

					issuer="example.com",

					audience="api-user"
		)

		current_time = int(time.time())

		if current_time > jwt_decode['exp']:

			return None

		return jwt_decode

	except jwt.InvalidTokenError:

		return None

	except Exception as e:

		return None


@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def login(request):
	"""Login endpoint"""
	username = request.POST.get('username')
	password = request.POST.get('password')
	
	# Authenticate (assume this works)
	user = authenticate(username, password)
	
	if user:
		token = create_auth_token(
			user_id=user.id,
			username=user.username,
			permissions=['read']
		)
		return JsonResponse({'token': token})
	else:
		return JsonResponse({'error': 'Invalid credentials'}, status=401)

@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def admin_panel(request):
	"""Admin endpoint"""
	token = request.headers.get('Authorization', '').replace('Bearer ', '')
	
	jwt_decode = verify_auth_token(token)
	
	if not jwt_decode:
		return JsonResponse({'error': 'Unauthorized'}, status=401)
	
	# Check permissions from token
	if 'admin' in jwt_decode['permissions']:
		return JsonResponse({'data': 'Secret admin data'})
	else:
		return JsonResponse({'error': 'Forbidden'}, status=403)

def main():

	jwt_encode = create_auth_token(37,"user",['user'])	

	jwt_decode = verify_auth_token(jwt_encode)

	print(f"jwt_encode:{jwt_encode}")
	
	print(f"jwt_decode:{jwt_decode}")

if __name__=="__main__":

	main()
```

Question 26:

Vulnerable Code Snippet:


Vulnerabilities:

0. Symmetric key secret is hardcoded into the source code. An attacker

that can access the source code can recover all encrypted data!

It is best to store in `.env` file.

1. Fixed IV used with AES-CBC. One should use a unique IV derived

from a CSPRNG. This will ensure that two identical plaintexts will

encrypt to distinct ciphertexts when calling the cipher twice with

two distinct initial values (Serious Cryptography).

Below is the fixed code:

```
# models.py
from django.db import models
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os

from dotenv import load_dotenv

import nacl.secret
import nacl.utils

load_dotenv()

class EncryptedField(models.BinaryField):
	"""Custom encrypted field"""
	
	# Use application-wide encryption key
	# The ENCRYPTION KEY can be generated using nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	
	ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
	
	def get_prep_value(self, value):
		"""Encrypt value before saving to database"""
		if value is None:
			return value
		
		value = value.encode()

		box = nacl.secret.SecretBox(self.ENCRYPTION_KEY)

		# Encrypt automatically generates and packs nonce

		encrypted = box.encrypt(value)	
			
		return encrypted
	
	def to_python(self, value):
		"""Decrypt value when retrieving from database"""
		if value is None:
			return value
		
		box = nacl.secret.SecretBox(self.ENCRYPTION_KEY)

		plain = box.decrypt(value)
	
		return plain

class MedicalRecord(models.Model):
	patient_id = models.IntegerField()
	diagnosis = EncryptedField()
	treatment = EncryptedField()
	notes = EncryptedField()
	created_at = models.DateTimeField(auto_now_add=True)
```

Question 27:

Vulnerable Code Snippet:

```
# middleware.py
from django.core.cache import cache
from django.http import JsonResponse
import time

class RateLimitMiddleware:
	"""Rate limiting middleware"""
	
	def __init__(self, get_response):
		self.get_response = get_response
	
	def __call__(self, request):
		# Get client IP
		client_ip = self.get_client_ip(request)
		
		# Check rate limit
		cache_key = f"rate_limit_{client_ip}"
		request_count = cache.get(cache_key, 0)
		
		if request_count >= 100:
			# Add delay for rate-limited requests
			time.sleep(1)
			return JsonResponse(
				{'error': 'Rate limit exceeded'},
				status=429
			)
		
		# Increment counter
		cache.set(cache_key, request_count + 1, 60)
		
		response = self.get_response(request)
		return response
	
	def get_client_ip(self, request):
		"""Get client IP address"""
		x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
		if x_forwarded_for:
			ip = x_forwarded_for.split(',')[0]
		else:
			ip = request.META.get('REMOTE_ADDR')
		return ip

# authentication.py
from django.contrib.auth.models import User

def validate_api_key(api_key, expected_key):
	"""Validate API key with timing information"""
	
	if len(api_key) != len(expected_key):
		return False
	
	# Character-by-character comparison
	for i in range(len(expected_key)):
		if api_key[i] != expected_key[i]:
			return False
	
	return True

# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .authentication import validate_api_key

@csrf_exempt
def protected_endpoint(request):
	"""Protected API endpoint"""
	
	# Get API key from header
	provided_key = request.headers.get('X-API-Key', '')
	
	# Get user's API key from database
	user = User.objects.get(username=request.POST.get('username'))
	expected_key = user.profile.api_key
	
	# Validate API key
	if validate_api_key(provided_key, expected_key):
		return JsonResponse({'data': 'Secret data'})
	else:
		return JsonResponse({'error': 'Invalid API key'}, status=401)
```

Vulnerabilities:

0. Timing Vulnerability in `validate_api_key()`: An attacker can

craft api_keys and time responses to deduce the expected key.

2. No attempt at rate-limiting under `views.py`. An attacker can

overwhelm server with excessive requests.

Below is the fixed code:

```
# middleware.py
from django.core.cache import cache
from django.http import JsonResponse
import time

class RateLimitMiddleware:
	"""Rate limiting middleware"""
	
	def __init__(self, get_response):
		self.get_response = get_response
	
	def __call__(self, request):
		# Get client IP
		client_ip = self.get_client_ip(request)
		
		# Check rate limit
		cache_key = f"rate_limit_{client_ip}"
		request_count = cache.get(cache_key, 0)
		
		if request_count >= 100:
			# Add delay for rate-limited requests
			time.sleep(1)
			return JsonResponse(
				{'error': 'Rate limit exceeded'},
				status=429
			)
		
		# Increment counter
		cache.set(cache_key, request_count + 1, 60)
		
		response = self.get_response(request)
		return response
	
	def get_client_ip(self, request):
		"""Get client IP address"""
		x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
		if x_forwarded_for:
			ip = x_forwarded_for.split(',')[0]
		else:
			ip = request.META.get('REMOTE_ADDR')
		return ip

# authentication.py
from django.contrib.auth.models import User
import hmac
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .authentication import validate_api_key

def validate_api_key(api_key, expected_key):
	"""Validate API key with timing information"""

	if not hmac.compare_digest(api_key,expected_key):
		return False
	
	return True


# views.py

@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def protected_endpoint(request):
	"""Protected API endpoint"""
	
	# Get API key from header
	provided_key = request.headers.get('X-API-Key', '')
	
	# Get user's API key from database
	user = User.objects.get(username=request.POST.get('username'))
	expected_key = user.profile.api_key
	
	# Validate API key
	if validate_api_key(provided_key, expected_key):
		return JsonResponse({'data': 'Secret data'})
	else:
		return JsonResponse({'error': 'Invalid API key'}, status=401)
```

Question 30:

```
import nacl.secret
import json
import time
import os
import base64
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect

ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY")

def create_encrypted_token(user_id, username):
    """Create encrypted authentication token"""
    
    token_data = {
        'user_id': user_id,
        'username': username,
        'expires': int(time.time()) + 3600
    }
    
    token_json = json.dumps(token_data)
    
    box = nacl.secret.SecretBox(ENCRYPTION_KEY)
    encrypted = box.encrypt(token_json)
    
    return base64.b64encode(encrypted)


def decrypt_token(encrypted_token_b64):
    """Decrypt and validate token"""
    
    encrypted = base64.b64decode(encrypted_token_b64)
    
    box = nacl.secret.SecretBox(ENCRYPTION_KEY)
    decrypted = box.decrypt(encrypted)
    
    token_data = json.loads(decrypted)
    
    if time.time() > token_data['expires']:
        return None
    
    return token_data


@csrf_protect
def login_endpoint(request):
    """Login endpoint - creates encrypted token"""
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = authenticate(username, password)
    
    if user:
        token = create_encrypted_token(user.id, user.username)
        return JsonResponse({'token': token})
    
    return JsonResponse({'error': 'invalid credentials'}, status=401)


@csrf_protect
def protected_endpoint(request):
    """Protected endpoint - validates encrypted token"""
    
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    
    if not token:
        return JsonResponse({'error': 'no token'}, status=401)
    
    token_data = decrypt_token(token)
    
    if not token_data:
        return JsonResponse({'error': 'invalid token'}, status=401)
    
    return JsonResponse({
        'message': f"Hello {token_data['username']}",
        'user_id': token_data['user_id']
    })
```

Vulnerabilities:

0. No ENCRYPTION_KEY Rotation. It is best practice to periodically

change this in case the current ENCRYPTION_KEY gets stolen.

1. There is also no call for `load_dotenv()`.

2. This is a bug. `token_json` is NOT encoded in

`create_encrypted_token()`.

3. No need for CSRF Protection for protected_endpoint since it

uses tokens for session authentication.

3. No attempt at rate-limiting. An attacker can overwhelm

the server with excessive requests.

Below is the fixed code:

```
import nacl.secret
import json
import time
import os
import secrets
import base64
from dotenv import load_dotenv,set_key
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit

load_dotenv()

ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY")


def create_encrypted_token(user_id, username):
    """Create encrypted authentication token"""

    
    token_data = {
        'user_id': user_id,
        'username': username,
        'expires': int(time.time()) + 3600
    }
    
    token_json = json.dumps(token_data)
    
    box = nacl.secret.SecretBox(ENCRYPTION_KEY)
    encrypted = box.encrypt(token_json.encode())
    
    return base64.b64encode(encrypted)


def decrypt_token(encrypted_token_b64):
    """Decrypt and validate token"""

    encrypted = base64.b64decode(encrypted_token_b64)
    
    box = nacl.secret.SecretBox(ENCRYPTION_KEY)
    decrypted = box.decrypt(encrypted)
    
    token_data = json.loads(decrypted.decode())
    
    if time.time() > token_data['expires']:
        return None
    
    return token_data


@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def login_endpoint(request):

    """Login endpoint - creates encrypted token"""
    username = request.POST.get('username')
    password = request.POST.get('password')
    
    user = authenticate(username, password)
    
    if user:
        token = create_encrypted_token(user.id, user.username)
        return JsonResponse({'token': token})
    
    return JsonResponse({'error': 'invalid credentials'}, status=401)


@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def protected_endpoint(request):
    """Protected endpoint - validates encrypted token"""
    
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')
    
    if not token:
        return JsonResponse({'error': 'no token'}, status=401)
    
    token_data = decrypt_token(token)
    
    if not token_data:
        return JsonResponse({'error': 'invalid token'}, status=401)
    
    return JsonResponse({
        'message': f"Hello {token_data['username']}",
        'user_id': token_data['user_id']
    })
```

Exercise 31:

Vulnerable Code Snippet:

```
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import jwt
import nacl.secret
import hmac
import hashlib
import os

# Service 1: E-commerce checkout
@csrf_exempt
def checkout_process(request):
    """Process checkout - user must be logged in"""
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'login required'}, status=401)
    
    cart_items = request.POST.get('items')
    payment_method = request.POST.get('payment_method')
    
    order = create_order(request.user, cart_items, payment_method)
    
    return JsonResponse({'order_id': order.id})


# Service 2: Mobile app API
MOBILE_TOKEN_KEY = os.getenv("MOBILE_TOKEN_KEY")

@csrf_protect
def mobile_api_upload(request):
    """Mobile app file upload API"""
    
    encrypted_token = request.headers.get('X-Mobile-Token')
    
    box = nacl.secret.SecretBox(MOBILE_TOKEN_KEY)
    user_id_bytes = box.decrypt(encrypted_token)
    user_id = user_id_bytes.decode()
    
    file = request.FILES.get('file')
    save_file(user_id, file)
    
    return JsonResponse({'status': 'uploaded'})


# Service 3: Admin panel
@csrf_exempt
def admin_delete_user(request):
    """Admin panel using JWT stored in HttpOnly cookie"""
    
    token = request.COOKIES.get('admin_token')
    
    if not token:
        return JsonResponse({'error': 'not authenticated'}, status=401)
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        if payload['role'] != 'admin':
            return JsonResponse({'error': 'not admin'}, status=403)
        
        user_id = request.POST.get('user_id')
        User.objects.filter(id=user_id).delete()
        
        return JsonResponse({'status': 'deleted'})
    except:
        return JsonResponse({'error': 'invalid token'}, status=401)


# Service 4: Payment webhook
@csrf_protect
def stripe_webhook(request):
    """Stripe payment webhook with HMAC signature"""
    
    signature = request.headers.get('Stripe-Signature')
    payload = request.body
    
    expected = hmac.new(
        settings.STRIPE_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        return JsonResponse({'error': 'invalid signature'}, status=401)
    
    process_payment_event(json.loads(payload))
    
    return JsonResponse({'status': 'processed'})
```

Question 31:

Vulnerable Code Snippet:

```
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
import jwt
import nacl.secret
import hmac
import hashlib
import os

# Service 1: E-commerce checkout
#Should be: @csrf_protect
@csrf_protect
def checkout_process(request):
    """Process checkout - user must be logged in"""
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'login required'}, status=401)
    
    cart_items = request.POST.get('items')
    payment_method = request.POST.get('payment_method')
    
    order = create_order(request.user, cart_items, payment_method)
    
    return JsonResponse({'order_id': order.id})


# Service 2: Mobile app API
MOBILE_TOKEN_KEY = os.getenv("MOBILE_TOKEN_KEY")

@csrf_protect
def mobile_api_upload(request):
    """Mobile app file upload API"""
    
    encrypted_token = request.headers.get('X-Mobile-Token')
    
    box = nacl.secret.SecretBox(MOBILE_TOKEN_KEY)
    user_id_bytes = box.decrypt(encrypted_token)
    user_id = user_id_bytes.decode()
    
    file = request.FILES.get('file')
    save_file(user_id, file)
    
    return JsonResponse({'status': 'uploaded'})


# Service 3: Admin panel
@csrf_exempt
def admin_delete_user(request):
    """Admin panel using JWT stored in HttpOnly cookie"""
    
    token = request.COOKIES.get('admin_token')
    
    if not token:
        return JsonResponse({'error': 'not authenticated'}, status=401)
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        if payload['role'] != 'admin':
            return JsonResponse({'error': 'not admin'}, status=403)
        
        user_id = request.POST.get('user_id')
        User.objects.filter(id=user_id).delete()
        
        return JsonResponse({'status': 'deleted'})
    except:
        return JsonResponse({'error': 'invalid token'}, status=401)


# Service 4: Payment webhook
@csrf_protect
def stripe_webhook(request):
    """Stripe payment webhook with HMAC signature"""
    
    signature = request.headers.get('Stripe-Signature')
    payload = request.body
    
    expected = hmac.new(
        settings.STRIPE_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        return JsonResponse({'error': 'invalid signature'}, status=401)
    
    process_payment_event(json.loads(payload))
    
    return JsonResponse({'status': 'processed'})
```

Vulnerabilities:

-1. `login()` needs CSRF protection since it uses

Session Cookies for session authentication.

0. No Rate Limiting for API Endpoints

1. No attempt to rotate API keys. It is best practice to rotate

API keys periodically in case they get stolen. Since rotating

Mobile API Key can break encryption and I do not have access

to the function or code that creates the `X-Mobile-Token` I only

leave a comment here.

2. There should be NO CSRF protection for `mobile_api_upload()`

since it uses tokens for session authentication. CSRF protection in

Django will cause the API endpoint to break!

3. No check if MOBILE TOKEN expired in `mobile_api_upload()`

before saving uploaded file. Since there is no implementation

of a function or code that creates the MOBILE TOKEN I cannot

write the code fix for it so I leave this comment here.

4. Service 3 Admin Panel MUST be protected by CSRF since a Session

Cookie is used for session authentication.

5. This security bug does not necessarily exist but there is no

exception guard for the token expiring in `admin_delete_user()`.

It is truthfully impossible to know if the JWT Token even has an

'exp' field since we cannot see the function that creates the JWT

Token. Since we cannot see the function that creates the HMAC

signature we cannot fix the code so I just leave a comment here.

Checking for expired signatures matters to avoid replay attacks.

6. No CSRF Protection required for Stripe Webhook because it only

features an HMAC signature header for session authentication and not a

cookie.

7. No check if HMAC Signature in Stripe Webhook expired first

before calling `process_payment_event()`.  Since we do not know

the contents of the payload we cannot be sure if there even is

an expiration field in payload so I just leave a comment here.

Checking for expired signatures matters to avoid replay attacks.

Below is the fixed code:

```
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django_ratelimit.decorators import ratelimit
import jwt
import nacl.secret
import hmac
import hashlib
import os

# Service 1: E-commerce checkout
@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def checkout_process(request):
    """Process checkout - user must be logged in"""
    
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'login required'}, status=401)
    
    cart_items = request.POST.get('items')
    payment_method = request.POST.get('payment_method')
    
    order = create_order(request.user, cart_items, payment_method)
    
    return JsonResponse({'order_id': order.id})


# Service 2: Mobile app API
MOBILE_TOKEN_KEY = os.getenv("MOBILE_TOKEN_KEY")

# Should be: @csrf_exempt
@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def mobile_api_upload(request):
    """Mobile app file upload API"""
    
    encrypted_token = request.headers.get('X-Mobile-Token')
    
    box = nacl.secret.SecretBox(MOBILE_TOKEN_KEY)
    user_id_bytes = box.decrypt(encrypted_token)
    user_id = user_id_bytes.decode()

    # No check if mobile token expired first before

    # proceeding
    
    file = request.FILES.get('file')
    save_file(user_id, file)
    
    return JsonResponse({'status': 'uploaded'})


# Service 3: Admin panel
# Should be: @csrf_protect
@csrf_protect
@ratelimit(key='ip', rate='5/m')
def admin_delete_user(request):
    """Admin panel using JWT stored in HttpOnly cookie"""
    
    token = request.COOKIES.get('admin_token')
    
    if not token:
        return JsonResponse({'error': 'not authenticated'}, status=401)
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        if payload['role'] != 'admin':
            return JsonResponse({'error': 'not admin'}, status=403)
    
	# No check if JWT Token / Cookie Expired
    
        user_id = request.POST.get('user_id')
        User.objects.filter(id=user_id).delete()
        
        return JsonResponse({'status': 'deleted'})

    # No explicit except guard for Expired Signature. Best practice.

    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'invalid token'}, status=401)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'invalid token'}, status=401)
		
    except:
        return JsonResponse({'error': 'invalid token'}, status=401)


# Service 4: Payment webhook

# Should be: @csrf_exempt
@csrf_exempt
@ratelimit(key='ip', rate='5/m')
def stripe_webhook(request):
    """Stripe payment webhook with HMAC signature"""
    
    signature = request.headers.get('Stripe-Signature')
    payload = request.body
    
    expected = hmac.new(
        settings.STRIPE_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        return JsonResponse({'error': 'invalid signature'}, status=401)
   
    # No check if payload / payload signature expired before

    # processing payment.
 
    process_payment_event(json.loads(payload))
    
    return JsonResponse({'status': 'processed'})
```

There are certain cases where code was not attempted to be fixed.

This was explained why in the vulnerabilities section.

Question 32:

Vulnerable Code Snippet:

```
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
```

Vulnerabilities:

1. The JWT Token may be vulnerable to being stolen in XSS. But that

is beyond the scope of this exercise to fix.

2. Only the username and the first file is signed.

An attacker can get away with editing the files (or adding more files)

than what was intended to be allowed.

3. There is no expiration date set for the JWT Token. An attacker

can get away with a replay attack. A replay attack takes place when

an attacker captures a previously issued token and resubmits as a

valid token.

4. Although not a security bug it is best practice to include the

"issuer" and "audience" fields in a JWT Token.

Below is the fixed code:

```
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
```
