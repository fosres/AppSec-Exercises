import os
import hmac
import sqlite3
import psycopg2
from sqlalchemy import create_engine
from sqlalchemy import text 

from passlib.hash import argon2

from passlib.hash import bcrypt

from passlib.hash import scrypt

from passlib.hash import pbkdf2_sha256


# OWASP 2023 Parameters for Argon2id:
# - Memory: 19 MiB (19,456 KiB)
# - Iterations (time cost): 2
# - Parallelism (lanes): 1
# - Salt length: 16 bytes
# - Hash length: 32 bytes

def hash_password_argon2(password: str) -> str:
	"""Hash password using Argon2id from argon2-cffi library"""
	# Your implementation here
	# Example structure:
	# 1. Generate random salt with os.urandom(16)
	# 2. Use hash_secret_raw() with Type.ID for Argon2id variant
	# 3. Parameters: time_cost=2, memory_cost=19456, parallelism=1, hash_len=32
	# 4. Encode salt and hash to base64
	# Return format: "argon2:19456:2:1:[base64_salt]:[base64_hash]"

	if password == None:
	
		raise Exception("Invalid Credentials.")

	"""Hash password using Argon2id"""
	# Your implementation here
	# Hint: passlib.hash.argon2.using(
	#     type='ID',           # Argon2id variant
	#     memory_cost=19456,   # 19 MiB
	#     time_cost=2,         # iterations
	#     parallelism=1        # threads
	# ).hash(password)

	argon2_hash = argon2.using(
		type='ID',
		memory_cost=19456,
		time_cost=2,
		parallelism=1,
	).hash(password)

	return argon2_hash



def verify_password_argon2(password: str, stored_hash: str) -> bool:
	"""Verify password against Argon2 hash"""
	# Your implementation here
	# 1. Parse stored_hash to extract: memory_cost, time_cost, parallelism, salt, expected_hash
	# 2. Hash the password with same parameters using hash_secret_raw()
	# 3. Compare computed_hash with expected_hash (constant-time comparison)

	if password == None:

		raise Exception("Invalid Credentials.")

	return argon2.verify(password,stored_hash)	

# OWASP 2023 Parameters:
# - N (CPU/memory cost): 2^17 (131,072)
# - r (block size): 8
# - p (parallelization): 1
# - Salt length: 16 bytes minimum
# - Key length: 32 bytes minimum

def hash_password_scrypt(password: bytes) -> str:
	"""Hash password using scrypt"""
	# Your implementation here

	if password == None:

		raise Exception("Invalid Credentials.")

	salt = os.urandom(16)

	scrypt_hash = scrypt.using(
		salt=salt,
		salt_size=16,
		block_size=8,
		parallelism=1,
	).hash(password)

	return scrypt_hash

	
def verify_password_scrypt(password: str, stored_hash: bytes) -> bool:
	"""Verify password against scrypt hash"""
	# Your implementation here
	if password == None:

		raise Exception("Invalid Credentials.")

	return scrypt.verify(password,stored_hash)	


def hash_password_bcrypt(password: str) -> str:

	if password == None:
	
		raise Exception("Invalid Credentials.")

	"""Hash password using bcrypt"""
	# OWASP 2023 Parameters for bcrypt:
	# - Cost factor: 12 minimum (2^12 = 4,096 iterations)
	# - Salt length: 16 bytes (automatic)
	# - Hash includes salt automatically

	bcrypt_hash = bcrypt.using(
		rounds=12,
	).hash(password)

	return bcrypt_hash

def verify_password_bcrypt(password: str, stored_hash: bytes) -> bool:
	"""Verify password against scrypt hash"""
	# Your implementation here
	if password == None:

		raise Exception("Invalid Credentials.")

	return bcrypt.verify(password,stored_hash)	

# OWASP 2023 Parameters for PBKDF2:
# - Algorithm: SHA-256
# - Iterations: 600,000 minimum
# - Salt length: 16 bytes (automatic)
# - Key length: 32 bytes (automatic)

def hash_password_pbkdf2(password: str) -> str:
	"""Hash password using PBKDF2-HMAC-SHA256"""
	# Your implementation here
	# Hint: passlib.hash.pbkdf2_sha256.hash(password, rounds=600000)
	pbkdf2_hash = pbkdf2_sha256.using(
		rounds=600000,
	).hash(password)

	return pbkdf2_hash
		
	
def verify_password_pbkdf2(password: str, stored_hash: str) -> bool:
	"""Verify password against PBKDF2 hash"""
	# Your implementation here
	# Hint: passlib.hash.pbkdf2_sha256.verify(password, stored_hash)
	if password == None:

		raise Exception("Invalid Credentials.")

	return pbkdf2_sha256.verify(password,stored_hash)	

def retrieve_user_sqlite(username):
	
	try:

		sqliteConnection = sqlite3.connect('users_sqlite.db')

		cursor = sqliteConnection.cursor()

		query_creds = 'SELECT username, password_hash,allowed_files FROM users WHERE username = ?'

		cursor.execute(query_creds,(username,))

		result = cursor.fetchall()

		return result

	except sqlite3.Error as error:

		print("Failed to open sqlite3 database")

	finally:

		if sqliteConnection:

			sqliteConnection.close()

def retrieve_user_postgres(username):

	if username == None:

		raise Exception("Invalid Credentials.")

	conn = psycopg2.connect(
				host="localhost",
				dbname="auth_db",
				user="postgres",
				password="postgres"	
				)

	cursor = conn.cursor()

	query_creds = 'SELECT username, password_hash, allowed_files FROM users WHERE username = %s'

	cursor.execute(query_creds,(username,))

	result = cursor.fetchall()

	conn.close()

	return result

def retrieve_user_sqlalchemy(username):

	if username == None:

		raise Exception("Invalid Credentials.")

	engine = create_engine("sqlite:///users_sqlalchemy.db")

	query_creds = text("SELECT username,password_hash,allowed_files FROM users WHERE username = :username")

	with engine.connect() as conn:

		result = conn.execute(query_creds,{"username": username})

		cursor = result.fetchall()

		return cursor 

def register_user_sqlite(username: str,pwhash: str,allowed_files: str, kdf: str):

	try:

		sqliteConnection = sqlite3.connect('users_sqlite.db')

		cursor = sqliteConnection.cursor()

		insert_query = "INSERT INTO users (username,password_hash,allowed_files) VALUES (?,?,?)"

		cursor.execute(insert_query,(username,pwhash,allowed_files))

		sqliteConnection.commit()

		return f"Username {username} registered successfully"

	except sqlite3.Error as error:

		print("Failed to open sqlite3 database")

	finally:

		if sqliteConnection:

			sqliteConnection.close()
	

def register_user_postgres(username: str,pwhash: str,allowed_files: str, kdf: str):

	if username == None:

		raise Exception("Invalid Credentials.")

	conn = psycopg2.connect(
				host="localhost",
				dbname="auth_db",
				user="postgres",
				password="postgres"	
				)

	cursor = conn.cursor()

	insert_query = "INSERT INTO users (username,password_hash,allowed_files) VALUES (%s,%s,%s)"

	cursor.execute(insert_query,(username,pwhash,allowed_files))

	conn.commit()

	conn.close()

	return f"Username  {username} registered successfully"

def register_user_sqlalchemy(username: str,pwhash: str,allowed_files: str, kdf: str):
	
	if username == None:

		raise Exception("Invalid Credentials.")

	engine = create_engine("sqlite:///users_sqlalchemy.db")

	insert_query = text("INSERT INTO users (username,password_hash,allowed_files) VALUES (:username,:pwhash,:allowed_files)")

	with engine.begin() as conn:

		result = conn.execute(insert_query,{"username": username,"pwhash": pwhash,"allowed_files" : allowed_files})

		return f"Username {username} registered successfully"

def register_user(username: str, password: str, allowed_files: str, kdf: str,db_backend: str) -> str:
	"""
	Register a new user in the database.
	
	Args:
		username: User's chosen username
		password: User's plaintext password
		allowed_files: Comma-separated string of files user can access
		kdf: Password KDF to use ('scrypt', 'pbkdf2', 'argon2', or 'bcrypt')
	
	Returns:
		Success message
	
	Raises:
		Exception with generic error message on failure
	"""
	
	if	(
			username == None

			or

			username == ""

			or

			password == None

			or

			allowed_files == None

			or

			kdf == None
		):

		raise Exception("Failed to Register")

	pwhash = ""

	if kdf == "argon2":

		pwhash = hash_password_argon2(password)

	elif kdf == "scrypt":
		
		pwhash = hash_password_scrypt(password)

	elif kdf == "bcrypt":
		
		pwhash = hash_password_bcrypt(password)

	elif kdf == "pbkdf2":

		pwhash = hash_password_pbkdf2(password)
	else:

		raise Exception("Invalid KDF")

	if db_backend == "sqlite":

		result = retrieve_user_sqlite(username)

		if len(result) != 0:

			raise Exception("User Already Exists") 
	
		result = register_user_sqlite(username,pwhash,allowed_files,kdf)

		return result

	elif db_backend == "postgres":

		result = retrieve_user_postgres(username)

		if len(result) != 0:

			raise Exception("User Already Exists") 
	
		result = register_user_postgres(username,pwhash,allowed_files,kdf)

		return result

	elif db_backend == "sqlalchemy":
		
		result = retrieve_user_sqlalchemy(username)
		
		if len(result) != 0:

			raise Exception("User Already Exists") 
	
		result = register_user_sqlalchemy(username,pwhash,allowed_files,kdf)

		return result

	else:
		raise Exception("Invalid Database Backend.")	



def authenticate_user(username: str, password: str, db_backend: str) -> str:
	"""
	Authenticate a user and return their permissions.
	
	Args:
		username: User's username
		password: User's plaintext password
		kdf: Password KDF to use ('scrypt', 'pbkdf2', 'argon2', or 'bcrypt')
		db_backend: Database to use ('sqlite', 'sqlalchemy', or 'postgres')
	
	Returns:
		List of allowed files if authentication succeeds
	
	Raises:
		Exception with generic error message on failure
	"""

	if db_backend == "sqlite":

		result = retrieve_user_sqlite(username)

		if len(result) == 0:

			raise Exception("Invalid Credentials.")

		username = result[0][0]

		pwhash = result[0][1]

		allowed_files = result[0][2]

		if	(

				"$argon2" in pwhash

				and

				verify_password_argon2(password,pwhash)

			):

			return allowed_files

		elif	(

				"$scrypt" in pwhash

				and

				verify_password_scrypt(password,pwhash)

			):

			return allowed_files
		
		elif	(

				"$2b" in pwhash

				and

				verify_password_bcrypt(password,pwhash)

			):

			return allowed_files
	
		elif	(

				"$pbkdf2-sha256" in pwhash

				and

				verify_password_pbkdf2(password,pwhash)

			):

			return allowed_files
		else:

			raise Exception("Invalid Credentials.")
	
	elif db_backend == "postgres":

		result = retrieve_user_postgres(username)
		
		if len(result) == 0:

			raise Exception("Invalid Credentials.")

		username = result[0][0]

		pwhash = result[0][1]

		allowed_files = result[0][2]

		if	(

				"$argon2" in pwhash

				and

				verify_password_argon2(password,pwhash)

			):

			return allowed_files

		elif	(

				"$scrypt" in pwhash

				and

				verify_password_scrypt(password,pwhash)

			):

			return allowed_files
		
		elif	(

				"$2b" in pwhash

				and

				verify_password_bcrypt(password,pwhash)

			):

			return allowed_files
	
		elif	(

				"$pbkdf2-sha256" in pwhash

				and

				verify_password_pbkdf2(password,pwhash)

			):

			return allowed_files
		else:

			raise Exception("Invalid Credentials.")


	elif db_backend == "sqlalchemy":

		result = retrieve_user_sqlalchemy(username)

		print(f"sqlalchemy result: {result}")
		
		if len(result) == 0:

			raise Exception("Invalid Credentials.")

		username = result[0][0]

		pwhash = result[0][1]

		allowed_files = result[0][2]

		if	(

				"$argon2" in pwhash

				and

				verify_password_argon2(password,pwhash)

			):

			return allowed_files

		elif	(

				"$scrypt" in pwhash

				and

				verify_password_scrypt(password,pwhash)

			):

			return allowed_files
		
		elif	(

				"$2b" in pwhash

				and

				verify_password_bcrypt(password,pwhash)

			):

			return allowed_files
	
		elif	(

				"$pbkdf2-sha256" in pwhash

				and

				verify_password_pbkdf2(password,pwhash)

			):

			return allowed_files
		else:

			raise Exception("Invalid Credentials.")

def main():

		argon2_hash = hash_password_argon2("")

		print(argon2_hash)

		print(verify_password_argon2("",argon2_hash))
		
		scrypt_hash = hash_password_scrypt("")

		print(scrypt_hash)

		print(verify_password_scrypt("",scrypt_hash))

		bcrypt_hash = hash_password_bcrypt("the")

		print(bcrypt_hash)

		print(verify_password_bcrypt("the",bcrypt_hash))	

		pbkdf2_hash = hash_password_pbkdf2("")

		print(pbkdf2_hash)

		print(verify_password_pbkdf2("",pbkdf2_hash))

		result = authenticate_user("alice_scrypt","AlicePass123!", "sqlite")

		print(result)
		
		result = authenticate_user("bob_pbkdf2","BobPass456!", "sqlite")

		print(result)
		
		result = authenticate_user("charlie_argon2","CharliePass789!", "sqlite")

		print(result)
		
		result = authenticate_user("dave_bcrypt","DavePass012!", "sqlite")

		print(result)

		result = authenticate_user("alice_scrypt","AlicePass123!", "postgres")

		print(result)
		
		result = authenticate_user("dave_bcrypt","DavePass012!","postgres")

		print(result)

		result = authenticate_user("bob_pbkdf2","BobPass456!","postgres")

		print(result)

		result = authenticate_user("charlie_argon2","CharliePass789!", "postgres")
		print(result)

		result = authenticate_user("charlie_argon2","CharliePass789!", "sqlalchemy")
		print(result)

		result = authenticate_user("bob_pbkdf2","BobPass456!","sqlalchemy")

		print(result)

		result = authenticate_user("alice_scrypt","AlicePass123!", "sqlalchemy")

		print(result)

		result = authenticate_user("dave_bcrypt","DavePass012!","sqlalchemy")

		print(result)

		result = register_user("fifth_user","UserPass456?","first.txt,second.txt","argon2","sqlite")

		print(f"register_user_result: {result}")
		
		result = register_user("fifth_argon2","UserPass456?","first.txt,second.txt","argon2","postgres")

		print(f"register_user_result: {result}")
		
		result = register_user("fifth_argon2","UserPass456?","first.txt,second.txt","argon2","sqlalchemy")

		print(f"register_user_result: {result}")
		

if __name__=="__main__":
	main()
