---

# Question 4

The engineering team now wants to add user authentication to their file server. They send you the
following code for a security review.

Assume you can reach this code via HTTP, fully controlling the values of `username` and `password`.

```python
imports sqlite3

_DATABASE = "users.db"

def authenticate_user(username, password):
    cursor = sqlite3.connect(_DATABASE).cursor()
    # SQL Injection Vulnerability Below

    cursor.execute(f"select password, allowed_files from users where username = '{username}'")

    # The password hash is what is supposed to be retrieved!

    # NEVER store the password in plaintext in database!
    expected_password, allowed_files = cursor.fetchone()

    # Timing Vulnerability below
    if password != expected_password:
        raise Exception(f"Invalid password")
    return allowed_files
```

### What vulnerabilities exist in the code? How would you exploit them?

Insert your answer here

0. SQL Injection Vulnerability: An attacker can perform

 a SQL Injection Attack such as the following:

```
username: username_here' OR '1' = '1
```

1. Storage of raw password in database is a vulnerability.

One should expect the password database to eventually be compromised.

Instead of storing the passwords in plaintext one should store

the password hashes in the database.

2. Timing Attack Vulnerability:

The comparision of the raw password the user provided vs the

password stored in the database is a timing attack vulnerability.

An attacker can simply measure the time duration of execution between

different raw password guesses to determine the true password stored

in the database.

### What mitigations would you suggest?


```python
import sqlite3

# Assume the password hash is calculated using Argon2

from passlib.hash import argon2

_DATABASE = "users.db"

def authenticate_user(username, password):

    with sqlite3.connect(_DATABASE) as conn:
    
    	cursor = conn.cursor()
    
    	# SQL Injection Vulnerability Below
    
    	cursor.execute(f"select pwhash, allowed_files from users where username = ?",(username,))
    	# The password hash is what is supposed to be retrieved!

    	# NEVER store the password in plaintext in database!

    	row = cursor.fetchone()

        if not row:

		raise Exception("Invalid credentials")

    	expected_pwhash = row[0]

    	allowed_files = row[1]

    	# Timing Vulnerability below
    	
 	if not argon2.verify(password,expected_pwhash):

		cursor.close()

		raise Exception(f"Invalid credentials")

    	cursor.close()

    	return allowed_files
```
