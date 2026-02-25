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

	cursor.execute(f"select password_hash, allowed_files from users where username = ?",(username))

	expected_pwhash, allowed_files = cursor.fetchone()

	# Timing Attack Vulnerability Below
	if not argon2.verify(password,expected_pwhash):
		raise Exception(f"Invalid password")

	return allowed_files
