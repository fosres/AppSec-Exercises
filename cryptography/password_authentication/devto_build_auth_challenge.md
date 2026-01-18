---
title: "Master All 4 OWASP Password Hashing Methods: Ultimate Security Challenge"
published: false
description: "Build complete authentication with scrypt, PBKDF2, Argon2, AND bcrypt across 3 databases. 32 functions, 100+ tests. Can you implement them all correctly?"
tags: security, python, sql, challenge
series: AppSec Coding Challenges
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/placeholder.jpg
---

# Master All 4 OWASP Password Hashing Methods: The Ultimate Challenge

**Difficulty:** Advanced  
**Time:** 4-6 hours  
**Skills:** Password security, SQL injection prevention, Python, cryptography, database programming

---

## The Challenge

You're building a file server application that needs user authentication. Your task: **implement secure user registration and authentication using ALL FOUR OWASP-approved password hashing methods** across three different database backends.

Most developers can use one password library. Can you implement **all four correctly**?

### Requirements

**Implement these functions for EACH database backend:**

```python
def register_user(username: str, password: str, allowed_files: str = "", 
                 kdf: str = "scrypt", db_backend: str = "sqlite") -> str:
	"""
	Register a new user in the database.
	
	Args:
		username: User's chosen username
		password: User's plaintext password
		allowed_files: Comma-separated string of files user can access
		              (e.g., "documents/file1.txt,documents/file2.txt")
		kdf: Password KDF to use ('scrypt', 'pbkdf2', 'argon2', or 'bcrypt')
		db_backend: Database to use ('sqlite', 'sqlalchemy', or 'postgres')
	
	Returns:
		Success message
	
	Raises:
		Exception with generic error message on failure
	"""
	pass  # Your implementation here

def authenticate_user(username: str, password: str,
                     db_backend: str = "sqlite") -> str:
	"""
	Authenticate a user and return their permissions.
	
	NOTE: The password hash in the database contains the KDF type!
	      You must detect which KDF was used from the hash format.
	
	Args:
		username: User's username
		password: User's plaintext password
		db_backend: Database to use ('sqlite', 'sqlalchemy', or 'postgres')
	
	Returns:
		Comma-separated string of allowed files ONLY if authentication succeeds
		Example: "documents/file1.txt,documents/file2.txt"
	
	Raises:
		Exception with generic error message on failure
		
		CRITICAL: Raise the SAME error message for:
		- User doesn't exist
		- User exists but wrong password
		- Any other authentication failure
		
		This prevents user enumeration attacks!
		
		DO NOT return empty string "" on failure!
		DO NOT return None on failure!
		ALWAYS raise an exception on failure!
	
	Hash Format Detection:
		- Hash starting with '$scrypt$' → use scrypt.verify()
		- Hash starting with '$pbkdf2-sha256$' → use pbkdf2_sha256.verify()
		- Hash starting with '$argon2id$' → use argon2.verify()
		- Hash starting with '$2b$' → use bcrypt.verify()
	"""
	pass  # Your implementation here
```

### Total Functions Required

**Password Hashing:** 8 functions
- `hash_password_scrypt()` + `verify_password_scrypt()`
- `hash_password_pbkdf2()` + `verify_password_pbkdf2()`
- `hash_password_argon2()` + `verify_password_argon2()`
- `hash_password_bcrypt()` + `verify_password_bcrypt()`

**Database Operations:** 2 functions
- `register_user(username, password, allowed_files="", kdf="scrypt", db_backend="sqlite")`
- `authenticate_user(username, password, db_backend="sqlite")` (detects KDF from hash)

**Grand Total:** 10 functions

Each database function accepts:
- `kdf` parameter to specify which password hashing algorithm to use ('scrypt', 'pbkdf2', 'argon2', 'bcrypt')
- `db_backend` parameter to specify which database to use ('sqlite', 'postgres', 'sqlalchemy')

### Security Requirements

Your implementations **MUST:**

✅ **Implement ALL 4 OWASP-approved KDFs:** scrypt, PBKDF2, Argon2id, AND bcrypt  
✅ **Use OWASP 2023 parameters** for each KDF  
✅ **Prevent SQL injection** in all database operations  
✅ **Prevent user enumeration** through error messages  
✅ **Prevent timing attacks** on password comparison  
✅ **Close database connections** properly (no resource leaks)  
✅ **Validate inputs** as defense-in-depth  
✅ **Handle edge cases** gracefully  

### Implementation Targets

Implement for **THREE** database backends × **FOUR** password hashing methods:

1. **SQLite** (`sqlite3` module) - 8 functions
2. **PostgreSQL** (`psycopg2` module) - 8 functions
3. **SQLAlchemy** (ORM) - 8 functions

Each backend requires 4 registration functions + 4 authentication functions (one for each KDF).

**This challenge tests your ability to implement password security correctly using ALL industry-standard approaches.**

---

## Pre-Populated Database Files

**IMPORTANT:** This challenge provides **pre-populated database files** with test users. You do NOT need to create database schemas from scratch!

### Download Database Files

```bash
# Download all required database files
wget https://example.com/users_sqlite.db
wget https://example.com/users_sqlalchemy.db  
wget https://example.com/users_postgres.sql
wget https://example.com/test_passwords.txt
```

Or clone the repository:
```bash
git clone https://github.com/yourusername/auth-challenge-databases
cd auth-challenge-databases
```

### What's Provided

| File | Description |
|------|-------------|
| `users_sqlite.db` | SQLite database with pre-populated test users |
| `users_sqlalchemy.db` | SQLAlchemy-compatible SQLite database |
| `users_postgres.sql` | PostgreSQL dump file to import |
| `test_passwords.txt` | Test user credentials reference |

### Pre-Populated Test Users

The databases contain these test users:

| Username | Password | KDF | Allowed Files |
|----------|----------|-----|---------------|
| `alice_scrypt` | `AlicePass123!` | scrypt | `documents/file1.txt,documents/file2.txt` |
| `bob_pbkdf2` | `BobPass456!` | pbkdf2 | `reports/report1.pdf,reports/report2.pdf` |
| `charlie_argon2` | `CharliePass789!` | argon2id | `data/data1.csv,data/data2.csv` |
| `dave_bcrypt` | `DavePass012!` | bcrypt | `logs/access.log,logs/error.log` |
| `eve_scrypt` | `EvePass345!` | scrypt | `admin/config.json` |

**Your solution must be able to authenticate these users correctly!**

### Database Schema (Already Created)

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,  -- SERIAL for PostgreSQL
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    allowed_files TEXT NOT NULL
);
```

**You do NOT implement schema creation.** The tables already exist in the provided databases.

#### 📋 About the `allowed_files` Column

**IMPORTANT: The `allowed_files` column is PRE-POPULATED in the provided databases.**

**What you need to know:**
- ✅ **Students READ this data** - It's already in the database
- ✅ **Students DON'T populate it** - All test users already have their files listed
- ✅ **Authentication returns it** - Your `authenticate_user()` function should return this list on successful login
- ✅ **Real-world pattern** - Production auth systems return user permissions/files/roles after login

**Why it's included:**
In real authentication systems, after verifying the password, you return **authorization data** (what the user can access). This column simulates that:

```python
# After successful password verification:
return "documents/file1.txt,documents/file2.txt"  # Alice's files as comma-separated string

# NOT just:
return True  # Too simplistic
```

This tests:
- ✅ **SQL injection prevention** - Can attackers access other users' files?
- ✅ **Data retrieval** - Can you correctly query and parse the database?
- ✅ **Realistic implementation** - Authentication + authorization in one operation

**Bottom line:** Just `SELECT` the `allowed_files` column and return it as-is (it's stored as a comma-separated string). Don't worry about populating it - that's already done!

### Loading PostgreSQL Database (Optional)

If you want to test the PostgreSQL backend:

```bash
# Create database
createdb -U postgres auth_db

# Load provided SQL dump
psql -U postgres -d auth_db -f users_postgres.sql

# Verify
psql -U postgres -d auth_db -c "SELECT COUNT(*) FROM users;"
```

---

## Database Connection Guide

### Project Directory Structure

**Place all database files in the same directory as your solution:**

```
my-auth-solution/
├── solution.py              # Your implementation
├── users_sqlite.db          # SQLite database (provided)
├── users_sqlalchemy.db      # SQLAlchemy database (provided)
└── users_postgres.sql       # PostgreSQL dump (provided)
```

### Using the `db_backend` Parameter

**The `db_backend` parameter tells your functions which database to connect to:**

Your `authenticate_user()` function must:
1. Use `if/elif/else` to check the `db_backend` parameter
2. Connect to the appropriate database based on the value
3. Query for the user's password hash and allowed files
4. Detect the KDF from the hash format
5. Verify the password and return results

---

### Database Connection Credentials

**You'll need these credentials to connect to each database:**

#### **SQLite Backend (`db_backend="sqlite"`):**
- **Database file:** `users_sqlite.db` (in current directory)
- **Library:** `import sqlite3`
- **No credentials required** - just connect to the file!
- **Placeholder:** `?` for parameterized queries

#### **SQLAlchemy Backend (`db_backend="sqlalchemy"`):**
- **Database file:** `users_sqlalchemy.db` (in current directory)
- **Library:** `from sqlalchemy import create_engine`
- **Connection string format:** `sqlite:///filename.db` (three slashes for relative path)
- **No credentials required** - SQLite file-based
- **Note:** You'll need to define the `User` model class matching the schema

#### **PostgreSQL Backend (`db_backend="postgres"`):**
- **Host:** `localhost`
- **Database name:** `auth_db` (created from users_postgres.sql)
- **Username:** `postgres`
- **Password:** `postgres`
- **Library:** `import psycopg2`
- **Placeholder:** `%s` for parameterized queries

---

### Viewing Database Contents (Command Line)

**All three databases can be viewed from the command line:**

#### **SQLite Database (`users_sqlite.db`):**
```bash
# Open SQLite database
sqlite3 users_sqlite.db

# Inside sqlite3 shell:
.tables                    # List all tables
.schema users              # Show table structure
SELECT * FROM users;       # View all users
SELECT username, allowed_files FROM users;  # View specific columns
.quit                      # Exit
```

#### **SQLAlchemy Database (`users_sqlalchemy.db`):**
```bash
# SQLAlchemy databases are just SQLite files!
sqlite3 users_sqlalchemy.db

# Same commands as above:
SELECT username, LEFT(password_hash, 20) as hash_preview, allowed_files FROM users;
.quit
```

#### **PostgreSQL Database (`auth_db`):**
```bash
# Connect to PostgreSQL database
psql -h localhost -U postgres -d auth_db
# Password: postgres

# Inside psql shell:
\dt                        # List all tables
\d users                   # Describe users table
SELECT * FROM users;       # View all users
SELECT username, allowed_files FROM users;  # View specific columns
\q                         # Exit
```

**Quick one-liner commands (no shell):**
```bash
# SQLite
sqlite3 users_sqlite.db "SELECT username, allowed_files FROM users;"

# SQLAlchemy
sqlite3 users_sqlalchemy.db "SELECT username, allowed_files FROM users;"

# PostgreSQL
psql -h localhost -U postgres -d auth_db -c "SELECT username, allowed_files FROM users;"
```

---

### Setup PostgreSQL (If Using)

```bash
# Set postgres password
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'postgres';"

# Create database
createdb -h localhost -U postgres auth_db

# Load data
psql -h localhost -U postgres -d auth_db -f users_postgres.sql

# Verify
psql -h localhost -U postgres -d auth_db -c "SELECT username FROM users;"
```

---

**Examples of calling your function:**

```python
# Use SQLite database - KDF is auto-detected from hash!
authenticate_user("alice_scrypt", "AlicePass123!", db_backend="sqlite")

# Use SQLAlchemy database - KDF is auto-detected from hash!
authenticate_user("bob_pbkdf2", "BobPass456!", db_backend="sqlalchemy")

# Use PostgreSQL database - KDF is auto-detected from hash!
authenticate_user("charlie_argon2", "CharliePass789!", db_backend="postgres")
```

---

### `register_user()` - Adding New Users (Optional)

**This function is OPTIONAL.** The databases already contain test users!

If you want to implement it, `register_user()` should:
1. Use the `kdf` parameter to select which hashing function to use
2. Hash the password with the selected KDF
3. Use the `db_backend` parameter to select which database
4. Insert the new user with parameterized queries
5. Return a success message

**Connection credentials are the same as `authenticate_user()`** (see above).

**Example usage:**

```python
# Register new users in different databases (OPTIONAL)
register_user("frank", "FrankPass!", "data/frank.txt", kdf="scrypt", db_backend="sqlite")
register_user("grace", "GracePass!", "admin/grace.txt", kdf="argon2", db_backend="sqlalchemy")
register_user("henry", "HenryPass!", "logs/henry.log", kdf="bcrypt", db_backend="postgres")
```

---

## Password Hashing Specification

**You MUST implement ALL four OWASP-approved password-based key derivation functions.**

This challenge requires you to implement secure password hashing using each of the following:

### Library Requirements

Install the required password hashing library:

```bash
pip install passlib[argon2,bcrypt]
```

**That's it!** `passlib` is a comprehensive password hashing library that provides:
- ✅ All 4 OWASP-recommended KDFs (scrypt, PBKDF2, Argon2, bcrypt)
- ✅ Standardized PHC string format (like `/etc/shadow`)
- ✅ Automatic salt generation and parameter encoding
- ✅ Built-in verification with constant-time comparison

**Why passlib?**
- Industry-standard library used in production
- Handles all encoding/decoding automatically
- Consistent API across all KDFs
- Secure defaults based on OWASP recommendations

Reference: [passlib Documentation](https://passlib.readthedocs.io/)

### Required Implementations

#### Implementation 1: scrypt (Use passlib)
```python
from passlib.hash import scrypt

# OWASP 2023 Parameters for scrypt:
# - N (CPU/memory cost): 2^17 = 131,072
# - r (block size): 8
# - p (parallelization): 1
# - Salt length: 16 bytes (automatic)
# - Key length: 32 bytes (automatic)

def hash_password_scrypt(password: str) -> str:
	"""Hash password using scrypt"""
	# Your implementation here
	# Hint: passlib.hash.scrypt.hash(password, rounds=17)
	# rounds=17 means 2^17 = 131,072 iterations (OWASP 2023)
	pass

def verify_password_scrypt(password: str, stored_hash: str) -> bool:
	"""Verify password against scrypt hash"""
	# Your implementation here
	# Hint: passlib.hash.scrypt.verify(password, stored_hash)
	pass
```

#### Implementation 2: PBKDF2-HMAC-SHA256 (Use passlib)
```python
from passlib.hash import pbkdf2_sha256

# OWASP 2023 Parameters for PBKDF2:
# - Algorithm: SHA-256
# - Iterations: 600,000 minimum
# - Salt length: 16 bytes (automatic)
# - Key length: 32 bytes (automatic)

def hash_password_pbkdf2(password: str) -> str:
	"""Hash password using PBKDF2-HMAC-SHA256"""
	# Your implementation here
	# Hint: passlib.hash.pbkdf2_sha256.hash(password, rounds=600000)
	pass

def verify_password_pbkdf2(password: str, stored_hash: str) -> bool:
	"""Verify password against PBKDF2 hash"""
	# Your implementation here
	# Hint: passlib.hash.pbkdf2_sha256.verify(password, stored_hash)
	pass
```

#### Implementation 3: Argon2id (Use passlib)
```python
from passlib.hash import argon2

# OWASP 2023 Parameters for Argon2id:
# - Memory: 19 MiB (19,456 KiB)
# - Iterations (time cost): 2
# - Parallelism: 1
# - Salt length: 16 bytes (automatic)
# - Hash length: 32 bytes (automatic)

def hash_password_argon2(password: str) -> str:
	"""Hash password using Argon2id"""
	# Your implementation here
	# Hint: passlib.hash.argon2.using(
	#     type='ID',           # Argon2id variant
	#     memory_cost=19456,   # 19 MiB
	#     time_cost=2,         # iterations
	#     parallelism=1        # threads
	# ).hash(password)
	pass

def verify_password_argon2(password: str, stored_hash: str) -> bool:
	"""Verify password against Argon2 hash"""
	# Your implementation here
	# Hint: passlib.hash.argon2.verify(password, stored_hash)
	pass
```

#### Implementation 4: bcrypt (Use passlib)
```python
from passlib.hash import bcrypt

# OWASP 2023 Parameters for bcrypt:
# - Cost factor: 12 minimum (2^12 = 4,096 iterations)
# - Salt length: 16 bytes (automatic)
# - Hash includes salt automatically

def hash_password_bcrypt(password: str) -> str:
	"""Hash password using bcrypt"""
	# Your implementation here
	# Hint: passlib.hash.bcrypt.using(rounds=12).hash(password)
	# rounds=12 means 2^12 = 4096 iterations (OWASP minimum)
	pass

def verify_password_bcrypt(password: str, stored_hash: str) -> bool:
	"""Verify password against bcrypt hash"""
	# Your implementation here
	# Hint: passlib.hash.bcrypt.verify(password, stored_hash)
	pass
```

### Requirements for ALL Implementations

Each implementation **MUST:**
- ✅ Generate unique random salt for each password
- ✅ Use OWASP 2023 recommended parameters
- ✅ Return format that includes all info needed for verification
- ✅ Use cryptographically random salt (os.urandom or secrets)
- ✅ Use constant-time comparison (hmac.compare_digest)
- ✅ Handle malformed hashes gracefully (return False, don't crash)

### Storage Format Requirements

Each implementation must use a consistent format:

- **scrypt:** `scrypt:131072:8:1:[base64_salt]:[base64_hash]`
- **PBKDF2:** `pbkdf2:sha256:600000:[base64_salt]:[base64_hash]`
- **Argon2:** `argon2:19456:2:1:[base64_salt]:[base64_hash]` (custom format using cryptography library)
- **bcrypt:** `$2b$12$[salt][hash]` (bcrypt library standard format)

**Note:** For scrypt, PBKDF2, and Argon2 using the `cryptography` library, use the custom format pattern shown above that embeds parameters and salt. For bcrypt, use the library's standard format which automatically includes parameters and salt.

### Database Operations Implementation

You must implement **2 functions** that work with all database backends:

```python
def register_user(username: str, password: str, allowed_files: str = "", 
                 kdf: str = "scrypt", db_backend: str = "sqlite") -> str:
	"""
	(OPTIONAL) Register new user in specified database with specified KDF.
	
	NOTE: The provided databases already contain test users.
	      This function is OPTIONAL - only implement if you want to add MORE users.
	
	Args:
		username: User's chosen username
		password: User's plaintext password  
		allowed_files: Comma-separated list of files user can access (optional)
		kdf: Password KDF ('scrypt', 'pbkdf2', 'argon2', 'bcrypt')
		db_backend: Database to use ('sqlite', 'postgres', 'sqlalchemy')
	
	Returns:
		Success message string
	
	Security Requirements:
		✅ Use parameterized queries (prevent SQL injection)
		✅ Hash password with specified KDF
		✅ Close database connections properly (no leaks)
		✅ Handle errors gracefully
	"""
	# Your implementation here (OPTIONAL)
	pass

def authenticate_user(username: str, password: str,
                     db_backend: str = "sqlite") -> list:
	"""
	Authenticate user from specified database.
	
	NOTE: The KDF is auto-detected from the password hash format!
	      You don't need a kdf parameter - the hash tells you which KDF was used.
	
	Args:
		username: User's username
		password: User's plaintext password
		db_backend: Database to use ('sqlite', 'postgres', 'sqlalchemy')
	
	Returns:
		List of allowed files ONLY on successful authentication (pre-populated in database)
		Example: ['documents/file1.txt', 'documents/file2.txt']
	
	Raises:
		Exception with generic error message on ANY failure
		
		CRITICAL SECURITY REQUIREMENT:
		- User not found? → Raise exception with generic message
		- Wrong password? → Raise exception with SAME generic message
		- DO NOT return [] or None on failure
		- DO NOT leak whether user exists or not
		- ALWAYS use the same error message for all auth failures
	
	Security Requirements:
		✅ Use parameterized queries (prevent SQL injection)
		✅ Detect KDF from hash format (hash prefix tells you which KDF)
		✅ Verify password with detected KDF
		✅ Same error for non-existent user AND wrong password (prevent user enumeration)
		✅ Close database connections properly (no leaks)
		✅ Use constant-time password comparison (passlib does this automatically)
		✅ RAISE exception on failure - DO NOT return empty list or None!
	
	Hash Format Detection:
		- '$scrypt$...' → use scrypt.verify()
		- '$pbkdf2-sha256$...' → use pbkdf2_sha256.verify()
		- '$argon2id$...' → use argon2.verify()
		- '$2b$...' → use bcrypt.verify()
	
	Note: The allowed_files data is ALREADY in the database.
	      Just SELECT it and return it - don't populate it yourself!
	"""
	# Your implementation here (REQUIRED)
	pass
```

**Implementation Strategy:**

**Focus on `authenticate_user()` first** - this is the core requirement:

Your `authenticate_user()` function should:
1. **Use `db_backend` parameter to select which database to connect to** (if/elif/else)
2. Connect to the appropriate database (files are in current directory - see Database Connection Guide above)
3. Query the database for the user (using parameterized queries)
4. **If user not found → immediately raise exception with generic message** (DO NOT continue!)
5. Retrieve the `password_hash` and `allowed_files` columns (already populated!)
6. **Detect which KDF was used by checking the hash prefix** (e.g., `if hash.startswith('$scrypt$')`)
7. Verify the password using the detected KDF's verify function
8. **If password wrong → raise exception with SAME generic message** (DO NOT return anything!)
9. **If password correct → return the `allowed_files` list** (split the comma-separated string)
10. Always close database connections (use `try/finally` or context managers)

**CRITICAL: Authentication result behavior:**
```python
# SUCCESS - return allowed files
if password_is_valid:
    return allowed_files_str.split(',')

# FAILURE - raise exception (DO NOT return [] or None!)
if not password_is_valid:
    raise AuthenticationFailed("Invalid credentials")
```

Your `register_user()` function (OPTIONAL):
1. Use `db_backend` parameter to select which database
2. Use `kdf` parameter to select which password hashing function
3. Hash the password using the appropriate KDF
4. Insert into database with provided `allowed_files` parameter
5. Use parameterized queries
6. Handle duplicate username errors

**Key Points:** 
- **Use `db_backend` parameter** - don't hardcode which database to use!
- **`authenticate_user()` detects KDF from hash** - no need for kdf parameter!
- **`register_user()` uses `kdf` parameter** - to choose which KDF when creating hashes
- **CRITICAL: Return list on SUCCESS, raise exception on FAILURE** - Never return [] or None!
- Database files (`users_sqlite.db`, `users_sqlalchemy.db`) are in your current directory
- The databases already contain test users with `allowed_files` populated
- Your main job is to **read and return** this data during authentication, not populate it!

**Implementation Flow:**

```python
def authenticate_user(username, password, db_backend="sqlite"):
    # Step 1: Use if/elif to check db_backend parameter
    #         Connect to the appropriate database (credentials above)
    #         Query for user's password_hash and allowed_files
    #         Handle user not found (raise exception)
    
    # Step 2: Detect KDF from hash format
    #         Check hash prefix: '$scrypt$', '$pbkdf2-sha256$', '$argon2id$', '$2b$'
    #         Call appropriate verify function from passlib
    
    # Step 3: Handle verification result
    #         If invalid → raise AuthenticationFailed("Invalid credentials")
    #         If valid → return allowed_files.split(',')
```

**Important Reminders:**

- **Use parameterized queries** - Different databases use different placeholders:
  - SQLite: `?` as placeholder
  - PostgreSQL: `%s` as placeholder  
  - SQLAlchemy: `.filter_by()` method
- **Close database connections** - Use `try/finally` or context managers
- **Same error message for all failures** - Don't leak whether user exists

---

## Automated Testing & Grading

This challenge includes a comprehensive **automated grader** that tests all your implementations.

### Download the Grader

```bash
# Download the grader script
wget https://raw.githubusercontent.com/fosres/AppSec-Exercises/main/grader.py

# Or manually download from the blog post files
```

### Run the Grader

```bash
python grader.py your_solution.py
```

### What the Grader Tests

The automated grader runs **100+ test cases** across all your implementations:

**Password Hashing Tests (16 tests)**
- scrypt: Salt uniqueness, work factor, correct/incorrect verification
- PBKDF2: Salt uniqueness, iterations, correct/incorrect verification  
- Argon2: Salt uniqueness, memory parameters, correct/incorrect verification
- bcrypt: Salt uniqueness, cost factor, correct/incorrect verification

**SQLite Registration Tests (12 tests)**
- SQL injection prevention (all 4 KDFs)
- Password hashing verification (all 4 KDFs)
- Duplicate username handling (all 4 KDFs)

**SQLite Authentication Tests (16 tests)**
- Valid credential authentication (all 4 KDFs)
- Invalid credential rejection (all 4 KDFs)
- SQL injection prevention (all 4 KDFs)
- User enumeration prevention (all 4 KDFs)

**PostgreSQL Tests (28 tests)**
- Same categories as SQLite for all 4 KDFs

**SQLAlchemy Tests (28 tests)**
- Same categories as SQLite for all 4 KDFs

**Resource Management Tests (4 tests)**
- Connection leak detection
- Exception handling

**Total: 100+ automated test cases**

### Example Grader Output

```
================================================================================
          AUTHENTICATION SECURITY CHALLENGE GRADER
================================================================================

Loading solution: my_solution.py

✓ Solution loaded successfully
✓ Running comprehensive test suite...

================================================================================
                    PASSWORD HASHING TESTS - scrypt
================================================================================

scrypt: Unique salt generation:
  ✅ PASS

scrypt: Sufficient work factor:
  ✅ PASS
  Hash time: 287.3ms

scrypt: Verify correct password:
  ✅ PASS

scrypt: Reject wrong password:
  ✅ PASS

... (96 more tests)

================================================================================
                          FINAL RESULTS
================================================================================

Tests Passed: 98/100 (98.0%)
Tests Failed: 2/100

Grade: A+
🎉 EXCELLENT! Production-ready implementation!
```

### Grading Scale

- **A+ (95-100%):** Excellent - Production-ready
- **A (90-94%):** Very Good - Minor issues to address
- **B (80-89%):** Good - Several improvements needed
- **C (70-79%):** Needs Work - Significant security gaps
- **F (Below 70%):** Insecure - Would fail security audit

### Required Functions

The grader expects these function names in your solution:

**Password Hashing (8 functions):**
```python
hash_password_scrypt(password: str) -> str
verify_password_scrypt(password: str, stored_hash: str) -> bool

hash_password_pbkdf2(password: str) -> str
verify_password_pbkdf2(password: str, stored_hash: str) -> bool

hash_password_argon2(password: str) -> str
verify_password_argon2(password: str, stored_hash: str) -> bool

hash_password_bcrypt(password: str) -> str
verify_password_bcrypt(password: str, stored_hash: str) -> bool
```

**Database Operations (2 functions):**
```python
register_user(username, password, allowed_files="", kdf="scrypt", db_backend="sqlite") -> str
authenticate_user(username, password, db_backend="sqlite") -> str
```

**Total: 10 functions required**

The parameters specify:
- `kdf`: Which password hashing algorithm to use ('scrypt', 'pbkdf2', 'argon2', 'bcrypt')
- `db_backend`: Which database to use ('sqlite', 'postgres', 'sqlalchemy')

**Note:** You do NOT need to implement database setup functions - the databases are pre-populated!

---

---

## Why This Challenge Matters

### Real-World Breaches

**LinkedIn (2012):** Unsalted SHA-1 → 6.5M passwords cracked  
**Adobe (2013):** ECB encryption not hashing → 38M accounts  
**Dropbox (2012):** Unsalted SHA-1 → mass credential stuffing

All prevented by proper password hashing.

### Career Relevance

This challenge tests:
- Security Engineer interview skills
- Production code security
- Multiple database familiarity
- Python cryptography knowledge

### Industry Standards

This challenge follows **OWASP (Open Web Application Security Project)** recommendations:

- **OWASP Password Storage Cheat Sheet (2023):**
  - Argon2id: m=19MiB, t=2, p=1 (Recommended)
  - scrypt: N=2^17, r=8, p=1
  - bcrypt: Cost factor 12 minimum
  - PBKDF2-SHA256: 600,000 iterations minimum

- **OWASP Top 10:**
  - A03:2021 - Injection (SQL injection)
  - A07:2021 - Identification and Authentication Failures

- **PCI-DSS Requirement 8:** Secure authentication mandatory for payment systems

**Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

## Bonus: KDF Comparison Analysis

After implementing all four KDFs, write a brief comparison analyzing:

1. **Performance:** Which is fastest/slowest? Measure actual hashing times.
2. **Memory usage:** Which uses most/least memory? (Argon2 and scrypt are memory-hard)
3. **Security tradeoffs:** When would you choose each one?
4. **Implementation complexity:** Which was easiest/hardest to implement correctly?
5. **Real-world usage:** Which companies/frameworks use each? (e.g., Django uses PBKDF2, 1Password uses scrypt)

**Example comparison output:**
```
KDF Performance Comparison (average of 100 iterations):
- scrypt:    287ms  (N=2^17, memory-hard)
- PBKDF2:    412ms  (600k iterations, CPU-hard)
- Argon2id:  156ms  (19MiB memory, winner of PHC 2015)
- bcrypt:    318ms  (cost=12, widely compatible)

Recommendation: Use Argon2id for new applications (best security/performance),
                PBKDF2 for legacy/compliance requirements,
                bcrypt for wide compatibility,
                scrypt for cryptocurrency applications.
```
## Submission

Share your implementations:
- GitHub Gist (public or secret)
- Dev.to comment section
- Your blog with test results

Include:
- **All 4 password hashing implementations** (scrypt, PBKDF2, Argon2, bcrypt)
- **All 3 database backend implementations** (SQLite, PostgreSQL, SQLAlchemy)
- **Total:** 32 functions (8 password functions + 24 database functions)
- Test suite results (screenshot showing all tests passing)
- KDF comparison analysis (performance, security, use cases)
- Any additional security measures you added

**Submission checklist:**
- [ ] 8 password hashing functions (4 KDFs × 2 operations each)
- [ ] 24 database functions (3 backends × 4 KDFs × 2 operations)
- [ ] All tests passing
- [ ] KDF performance comparison
- [ ] Documentation/comments explaining your approach

---

## Additional Resources

**Python cryptography:**
- [cryptography.io documentation](https://cryptography.io/)
- [Key Derivation Functions (KDF) - cryptography](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

**SQL Injection:**
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger SQL Injection Labs](https://portswigger.net/web-security/sql-injection)

**Books:**
- *Full Stack Python Security* by Dennis Byrne
- *Secure by Design* by Dan Bergh Johnsson

---

**Ready for the ultimate password security challenge?** Implement all 4 OWASP-approved KDFs and prove you understand password hashing at a professional level.

**This is NOT a 2-hour challenge.** Budget 4-6 hours to implement all 32 functions correctly. But when you're done, you'll understand password security better than 95% of developers.

**Found this challenging? Follow me for more AppSec coding exercises.**

#security #python #sql #appsec #cryptography #coding #authentication #argon2 #scrypt #pbkdf2 #bcrypt

---

*Challenge created: January 2026*  
*Author: [@fosres](https://dev.to/fosres)*  
*Curriculum: Week 5 - Comprehensive Password Security & SQL Injection*
