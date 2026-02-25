from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

import secrets
import nacl.secret
import nacl.utils

from dotenv import load_dotenv
import os

# Global encryption key

# Do NOT hardcode secrets!

load_dotenv()

ENCRYPTION_KEY = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
 

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
print(f"Encrypted with key: {ENCRYPTION_KEY}")
print(f"Result: {encrypted_record}")

