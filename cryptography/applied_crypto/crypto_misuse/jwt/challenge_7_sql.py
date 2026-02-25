import jwt
import time,datetime
from datetime import timezone
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import sqlite3
import os

# JWT secret
SECRET = secrets.token_urlsafe(32)

# Argon2 password hasher
ph = PasswordHasher(
	time_cost=2,
	memory_cost=65536,
	parallelism=4
)

# Database configuration
DATABASE_FILE = "auth_system.db"

def init_database():
	"""
	Initialize SQLite database and create users table.
	THIS IS PROVIDED - YOU DON'T NEED TO IMPLEMENT THIS!
	"""
	conn = sqlite3.connect(DATABASE_FILE)
	cursor = conn.cursor()
	cursor.execute("""
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	""")
	conn.commit()
	conn.close()
	print(f"✓ Database initialized: {DATABASE_FILE}")

def create_token(username,next_user_id):

	"""
	JWT payload includes:
	- user_id, username, role="user", exp (15 min), iss, aud
	
	Returns:
	- JWT token string on success
	- None if username already exists
	"""

	payload	=	{
				"user_id" : next_user_id,

				"username" : username,

				"role" : "user",

				"exp" : datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=900),
				"iss" :  "auth-service",

				"aud" : "api"		  	
			}

	jwt_encode = jwt.encode(payload,SECRET,algorithm="HS256")

	return jwt_encode


def register_user(username, password):
	"""
	Register new user in SQL database.
	
	Steps:
	1. Connect to database: conn = sqlite3.connect(DATABASE_FILE)
	2. Check if username exists:
	   cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
	3. If exists, return None
	4. Hash password: password_hash = ph.hash(password)
	5. INSERT into database:
	   cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
	                  (username, password_hash))
	6. Get the new user_id: user_id = cursor.lastrowid
	7. Create JWT token with user_id, username, role="user", exp (15 min), iss, aud
	8. Return JWT token
	
	Returns:
	- JWT token string on success
	- None if username already exists
	"""
	# Your code here

	try:
		sqliteConnection = sqlite3.connect(DATABASE_FILE)

		cursor = sqliteConnection.cursor()
		
		query_creds = 'SELECT username FROM users WHERE username = ?'

		cursor.execute(query_creds,(username,))

		result = cursor.fetchone()
		
		if result != None:

			return None

		pwhash = ph.hash(password)

		insert_creds = 'INSERT INTO users (username,password_hash) VALUES (?,?)'
		
		cursor.execute(insert_creds,(username,pwhash))

		sqliteConnection.commit()

		user_id = cursor.lastrowid

		return create_token(username,user_id)

	except sqlite3.Error as error:
		
		raise Exception("Failed to open sqlite3 Database")

	finally:

		if sqliteConnection:

			sqliteConnection.close()
		


def login(username, password):
	"""
	Login user with database verification.
	
	Steps:
	1. Connect to database
	2. SELECT user from database:
	   cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", 
	                  (username,))
	   row = cursor.fetchone()
	3. If row is None (user not found), return None
	4. Extract: user_id, password_hash = row
	5. Verify password:
	   try:
	       ph.verify(password_hash, password)
	   except VerifyMismatchError:
	       return None
	6. Create and return JWT token (same structure as register_user)
	
	Returns:
	- JWT token string on success
	- None if username doesn't exist or password wrong
	"""
	# Your code here
	
	try:
		sqliteConnection = sqlite3.connect(DATABASE_FILE)

		cursor = sqliteConnection.cursor()

		retrieve_creds = "SELECT id,password_hash FROM users where username = ?" 
		cursor.execute(retrieve_creds,(username,))

		user_creds = cursor.fetchone()

		if user_creds == None:

			return None

		user_id = user_creds[0]

		pwhash = user_creds[1]
		
		try:
			ph.verify(pwhash,password)

			return create_token(username,user_id)

		except VerifyMismatchError:

			return None

	except sqlite3.Error as error:

		raise Exception("Failed to open sqlite3 Database")

	finally:

		if sqliteConnection:

			sqliteConnection.close()

def validate_token(token):
	"""
	Validate JWT token.
	
	Steps:
	1. Decode token with jwt.decode()
	2. Validate issuer="auth-service" and audience="api"
	3. Handle exceptions (ExpiredSignatureError, InvalidTokenError)
	4. Return decoded payload
	
	Returns:
	- Dict: {"user_id": ..., "username": ..., "role": ...}
	- None if invalid
	"""
	# Your code here

	try:
	
		jwt_decode = jwt.decode(
					token,

					SECRET,

					algorithms=["HS256"],

					issuer="auth-service",

					audience="api"

				)
	
		return jwt_decode
	
	except jwt.ExpiredSignatureError:

		return None

	except jwt.InvalidTokenError:

		return None

def get_all_users():
	"""Helper function: Get all users from database (for testing)."""
	conn = sqlite3.connect(DATABASE_FILE)
	cursor = conn.cursor()
	cursor.execute("SELECT id, username, password_hash FROM users")
	users = cursor.fetchall()
	conn.close()
	return users

# ==========================================
# INITIALIZE DATABASE
# ==========================================

if os.path.exists(DATABASE_FILE):
	os.remove(DATABASE_FILE)

init_database()
print()

# ==========================================
# TEST CASES - ALL MUST PASS!
# ==========================================

print("=" * 60)
print("SECURE AUTHENTICATION SYSTEM TESTS")
print("=" * 60)

# Test 1: Register new user
print("\nTest 1: Register new user in database")
token1 = register_user("alice", "SecurePass123!")
if token1:
	print("✓ Registration successful")
	users = get_all_users()
	if len(users) == 1:
		user_id, username, password_hash = users[0]
		print(f"✓ User in database: id={user_id}, username={username}")
		if password_hash.startswith("$argon2"):
			print(f"✓ Password hashed: {password_hash[:50]}...")
		else:
			print("✗ Password not hashed!")
	else:
		print(f"✗ Expected 1 user, found {len(users)}")
else:
	print("✗ FAILED")

# Test 2: Reject duplicate username
print("\nTest 2: Reject duplicate username")
token2 = register_user("alice", "DifferentPass!")
if token2 is None:
	print("✓ Correctly rejected duplicate")
	if len(get_all_users()) == 1:
		print("✓ Database unchanged")
else:
	print("✗ Should reject duplicate")

# Test 3: Login with correct password
print("\nTest 3: Login with correct password")
token3 = login("alice", "SecurePass123!")
if token3:
	print("✓ Login successful")
else:
	print("✗ FAILED")

# Test 4: Reject wrong password
print("\nTest 4: Reject wrong password")
token4 = login("alice", "WrongPassword!")
if token4 is None:
	print("✓ Correctly rejected")
else:
	print("✗ Should reject wrong password")

# Test 5: Reject non-existent user
print("\nTest 5: Reject non-existent user")
token5 = login("bob", "anypassword")
if token5 is None:
	print("✓ Correctly rejected")
else:
	print("✗ Should reject non-existent user")

# Test 6: Validate valid token
print("\nTest 6: Validate JWT token")
user_info = validate_token(token3)
if user_info:
	if user_info["username"] == "alice" and user_info["role"] == "user":
		print(f"✓ Token valid: {user_info}")
		users = get_all_users()
		if user_info["user_id"] == users[0][0]:
			print(f"✓ JWT user_id matches database")
	else:
		print("✗ User info incorrect")
else:
	print("✗ FAILED")

# Test 7: Reject invalid token
print("\nTest 7: Reject invalid token")
if validate_token("invalid.token") is None:
	print("✓ Correctly rejected")
else:
	print("✗ Should reject invalid token")

# Test 8: Reject tampered token
print("\nTest 8: Reject tampered token")
if token3:
	tampered = token3[:-10] + "HACKED"
	if validate_token(tampered) is None:
		print("✓ Correctly rejected")
	else:
		print("✗ Should reject tampered token")

# Test 9: Multiple users
print("\nTest 9: Multiple users in database")
token_bob = register_user("bob", "BobPass999!")
token_carol = register_user("carol", "CarolSecret!")

if token_bob and token_carol:
	users = get_all_users()
	if len(users) == 3:
		print(f"✓ Database has 3 users")
		for user_id, username, _ in users:
			print(f"  - id={user_id}, username={username}")
		
		if login("bob", "BobPass999!") and login("carol", "CarolSecret!"):
			print("✓ All users can login")
		else:
			print("✗ Login failed")
	else:
		print(f"✗ Expected 3 users, found {len(users)}")
else:
	print("✗ Registration failed")

# Test 10: SQL injection protection
print("\nTest 10: SQL injection protection")
malicious = "admin' OR '1'='1"
if login(malicious, "anything") is None:
	print("✓ SQL injection blocked")
	print(f"  Tried: username=\"{malicious}\"")
else:
	print("✗ SECURITY VIOLATION!")

print("\n" + "=" * 60)
print("TEST SUITE COMPLETE")
print("=" * 60)
print(f"\nDatabase: {DATABASE_FILE}")
print("To inspect: sqlite3 {DATABASE_FILE}")
print("  sqlite> SELECT * FROM users;")
