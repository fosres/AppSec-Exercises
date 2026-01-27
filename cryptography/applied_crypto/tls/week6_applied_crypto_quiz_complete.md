# Week 6 Applied Crypto Quiz - All Challenges

**Duration:** 90-120 minutes  
**Format:** Open-book (use your curriculum materials)  
**Based on:** Complete 48 Week Security Engineering Curriculum (Week 6, pp. 21-27)[^1]

---

## Challenge 1: TLS Protocol Version Comparison

**Scenario:** You're auditing a web application's TLS configuration and notice it supports both TLS 1.2 and TLS 1.3.

**Questions:**
1. What are the key security improvements in TLS 1.3 compared to TLS 1.2?
2. How does the handshake differ (1-RTT vs 2-RTT)?
3. Which weak ciphers were removed in TLS 1.3?

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 21[^1] - "TLS 1.2 vs TLS 1.3 Differences" section
- Focus on: 1-RTT handshake, removed ciphers (RC4, 3DES, CBC-mode), forward secrecy requirement

---

## Challenge 2: Cipher Suite Analysis

**Scenario:** You encounter this cipher suite in production:
```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

**Questions:**
1. Break down each component of this cipher suite name
2. What does ECDHE provide? Why is it important?
3. Is this cipher suite secure for 2026 deployments?

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 21[^1] - "Cipher Suites Format" section
- Format: `TLS_KeyExchange_WITH_Cipher_MACAlgorithm`
- Example breakdown provided in curriculum

---

## Challenge 3: Certificate Validation Process

**Scenario:** Your API client needs to validate TLS certificates properly.

**Questions:**
1. List all 5 certificate validation checks mentioned in the curriculum
2. What is certificate pinning and when should it be used?
3. What risks does certificate pinning introduce?

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 21[^1] - "Certificate Validation" section
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 22[^1] - "Certificate Pinning" section
- Cover: expiration dates, CA chain verification, domain name validation, revocation status (OCSP/CRL)

---

## Challenge 4: JWT Structure and JOSE Standards

**Scenario:** You're implementing JWT authentication for an API.

**Questions:**
1. What are the three parts of a JWT and what does each contain?
2. Explain the difference between JWS and JWE
3. List 3 standard JWT claims (with their meanings)

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, pp. 21-22[^1] - "JWT Deep Dive" section
- JWT.io Introduction: https://jwt.io/introduction/ (1 hour)
- Focus on: header.payload.signature structure, JOSE standards (JWS, JWE, JWK, JWA)

---

## Challenge 5: JWT Security Vulnerabilities

**Scenario:** You're performing a security audit of an authentication system using JWTs.

**Code to Review:**
```python
import jwt

secret_key = "my-secret-key"

def verify_token(token):
	# Decode JWT
	decoded = jwt.decode(
		token, 
		options={"verify_signature": False}
	)
	return decoded
```

**Questions:**
1. Identify ALL security vulnerabilities in this code
2. What attacks does this enable?
3. Provide a secure implementation

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 26[^1] - JWT attack scenarios (none algorithm, weak keys)
- API Security in Action, Chapters 3-4 (2 hours) - JWT attacks and token validation
- PortSwigger JWT Labs documentation
- Focus on: signature verification bypass, "none" algorithm attack

---

## Challenge 6: ECB Mode Vulnerability

**Scenario:** You find this encryption code in production:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(data, key):
	cipher = Cipher(
		algorithms.AES(key),
		modes.ECB(),
		backend=default_backend()
	)
	encryptor = cipher.encryptor()
	return encryptor.update(data) + encryptor.finalize()
```

**Questions:**
1. What specific security vulnerability does ECB mode introduce?
2. Explain the "penguin image problem"
3. Which AES mode should be used instead? Why?

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 22[^1] - "Common Cryptographic Mistakes" section
- Complete 48 Week Security Engineering Curriculum, Week 5, p. 16[^1] - "AES Modes of Operation"
- Focus on: ECB pattern leakage, recommended alternatives (CBC, GCM, CTR)

---

## Challenge 7: Hardcoded Keys and Weak RNG

**Scenario:** Code review reveals multiple crypto issues:

```python
import random
import hashlib

# Hardcoded encryption key
ENCRYPTION_KEY = b"supersecretkey12"

def generate_session_id():
	# Generate random session ID
	return random.randint(100000, 999999)

def hash_password(password):
	return hashlib.sha256(password.encode()).hexdigest()
```

**Questions:**
1. Identify ALL crypto mistakes in this code
2. For each mistake, explain the security impact
3. Provide corrected implementations

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 22[^1] - "Common Cryptographic Mistakes" section
- Focus on: hardcoded keys, weak RNG (random vs secrets module), password hashing without salt
- Python `secrets` module documentation
- OWASP Password Storage Cheat Sheet

---

## Challenge 8: IV/Nonce Reuse Vulnerability

**Scenario:** You're auditing this AES-GCM implementation:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = os.urandom(32)
cipher = AESGCM(key)
nonce = os.urandom(12)  # Generated once

def encrypt_message(message):
	# Reuses same nonce for every message!
	return cipher.encrypt(nonce, message.encode(), None)
```

**Questions:**
1. What security vulnerability does nonce reuse introduce?
2. Why is this more critical for GCM than CBC?
3. Write corrected code with proper nonce generation

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 22[^1] - "IV/nonce reuse" in Common Cryptographic Mistakes
- Complete 48 Week Security Engineering Curriculum, Week 5, p. 16[^1] - "Authenticated Encryption" section on AES-GCM
- API Security in Action, Chapter 6 (pages 202-203) - "What key size should you use?" section on GCM nonce reuse
- Focus on: catastrophic GCM failure when nonces repeat, MAC key recovery

---

## Challenge 9: Timing Attacks in Authentication

**Scenario:** You're reviewing password comparison code:

```python
def authenticate(username, password):
	user = db.get_user(username)
	if user is None:
		return False
	
	stored_hash = user.password_hash
	provided_hash = hashlib.sha256(password.encode()).hexdigest()
	
	# Direct string comparison
	if stored_hash == provided_hash:
		return True
	return False
```

**Questions:**
1. What timing vulnerability exists in this code?
2. How can an attacker exploit timing differences?
3. Provide a timing-safe implementation

**What You Need to Read:**
- Complete 48 Week Security Engineering Curriculum, Week 6, p. 22[^1] - "Timing Attacks & Side Channels" section
- API Security in Action, Chapter 4 (pages 134-135) - "Timing attacks" section
- Full Stack Python Security, Chapter 4 (pp. 110-115) - Timing attacks
- Focus on: variable execution time exploitation, constant-time comparison with `secrets.compare_digest()`

---

## Challenge 10: Comprehensive Security Audit

**Scenario:** You're performing a comprehensive security audit of this authentication system:

```python
import jwt
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

SECRET_KEY = "my-jwt-secret"
ENCRYPTION_KEY = b"1234567890123456"  # 16 bytes

def register_user(username, password):
	# Hash password
	password_hash = hashlib.md5(password.encode()).hexdigest()
	
	# Store in database
	db.execute(
		f"INSERT INTO users (username, password_hash) VALUES ('{username}', '{password_hash}')"
	)

def login(username, password):
	# Check credentials
	result = db.execute(
		f"SELECT * FROM users WHERE username = '{username}'"
	)
	
	if not result:
		return None
	
	stored_hash = result[0]['password_hash']
	provided_hash = hashlib.md5(password.encode()).hexdigest()
	
	if stored_hash == provided_hash:
		# Generate JWT
		token = jwt.encode(
			{"user": username},
			SECRET_KEY,
			algorithm="HS256"
		)
		
		# Encrypt token with ECB mode
		cipher = Cipher(
			algorithms.AES(ENCRYPTION_KEY),
			modes.ECB(),
			backend=default_backend()
		)
		encryptor = cipher.encryptor()
		encrypted_token = encryptor.update(token.encode()) + encryptor.finalize()
		
		return encrypted_token
	
	return None
```

**Questions:**
1. Identify ALL security vulnerabilities (there are at least 8)
2. Categorize vulnerabilities by type (injection, crypto, authentication)
3. Provide a completely secure implementation
4. Which vulnerabilities are most critical? Why?

**What You Need to Read:**
- **Everything from Challenges 1-9**
- Complete 48 Week Security Engineering Curriculum, Week 6, pp. 21-23[^1] - All sections
- API Security in Action, Chapters 3-4 - SQL injection, JWT security
- Full Stack Python Security, Chapter 9 - Password hashing
- OWASP Top 10 2025 - A01 (Injection), A02 (Cryptographic Failures), A07 (Auth Failures)

**Vulnerabilities to Find:**
- SQL injection (string concatenation)
- MD5 password hashing (broken hash function)
- No salt in password hashing
- Hardcoded secrets
- ECB mode encryption
- Timing attack in password comparison
- Missing JWT expiration claim
- Unnecessary double-layer encryption (JWT + AES)

---

## Grading Rubric

**Challenge 1-9:** 10 points each = 90 points  
**Challenge 10:** 20 points (comprehensive audit)  
**Total:** 110 points

**Grade Scale:**
- 100-110 points (91-100%): **Excellent** - Ready for Week 7
- 88-99 points (80-90%): **Good** - Review weak areas
- 77-87 points (70-79%): **Fair** - Re-study Week 6 materials
- Below 77 points (<70%): **Needs Work** - Schedule review session

---

## Study Strategy

### Day 1-2: TLS & Certificates (Challenges 1-3)
1. Read Week 6 curriculum pp. 21-22 on TLS
2. Complete Challenges 1-3
3. Review OpenSSL lab from Week 2 if needed

### Day 3-4: JWT Fundamentals (Challenges 4-5)
1. Read JWT.io introduction
2. Study JOSE standards section
3. Complete Challenges 4-5
4. Practice with jwt_tool

### Day 5-6: Crypto Mistakes (Challenges 6-8)
1. Read "Common Cryptographic Mistakes" section
2. Complete Challenges 6-8
3. Review Python `secrets` module documentation

### Day 7: Timing Attacks & Comprehensive Review (Challenges 9-10)
1. Read API Security in Action Ch 4 on timing attacks
2. Complete Challenge 9
3. Attempt Challenge 10 (full system audit)
4. Review all answers

---

## Additional Resources

**Books Referenced:**
- Complete 48 Week Security Engineering Curriculum[^1]
- API Security in Action (Chapters 3-4, 6)[^2]
- Full Stack Python Security (Chapters 4, 9)[^3]

**Online Resources:**
- JWT.io: https://jwt.io/introduction/
- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7515 (JWS): https://datatracker.ietf.org/doc/html/rfc7515
- OWASP JWT Security Cheat Sheet
- OWASP Password Storage Cheat Sheet
- Python secrets module: https://docs.python.org/3/library/secrets.html

**Tools:**
- jwt_tool: https://github.com/ticarpi/jwt_tool
- PyJWT library
- Python cryptography library

---

## References

[^1]: Complete 48 Week Security Engineering Curriculum, Week 6: "Applied Crypto + Python Functional Programming," January 20-26, 2026, pp. 21-27

[^2]: API Security in Action, Neil Madden, Manning Publications, 2020
- Chapter 3: Secure API development
- Chapter 4: Session cookie security and CSRF
- Chapter 6: Self-contained tokens and JWTs (pp. 202-203)

[^3]: Full Stack Python Security, Dennis Bryne, Manning Publications, 2021
- Chapter 4: Timing attacks (pp. 110-115)
- Chapter 9: User password management (pp. 128-133)

---

**Good luck! Remember: Applied cryptography is about auditing how developers USE crypto libraries, not implementing crypto from scratch.**[^1]
