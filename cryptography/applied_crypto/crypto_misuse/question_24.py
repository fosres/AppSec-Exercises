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
