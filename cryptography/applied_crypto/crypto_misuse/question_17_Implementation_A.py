import hashlib
import os

from passlib.hash import argon2

def hash_password_alice(password: str) -> str:
	"""Alice's password hashing approach"""
	
	password_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(password)

	return password_hash

def verify_password_alice(password: str, stored_hash: str) -> bool:
	"""Verify password against stored hash"""
	# Re-hash the password
	
	# Compare hashes
	return argon2.verify(password,stored_hash)
 
if __name__=="__main__":

	pwhash = hash_password_alice("test")
	
	print(f"pwhash:{pwhash}")
	
	print(verify_password_alice("test",pwhash))
