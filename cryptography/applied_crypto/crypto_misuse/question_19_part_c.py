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
