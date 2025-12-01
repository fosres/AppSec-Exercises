---
title: "Building a Secure File Path Validator: Bytes vs Str Correctness Meets AppSec"
published: false
description: "Learn how Python's bytes/str handling intersects with real-world security vulnerabilities, featuring path traversal attacks and encoding bypasses"
tags: appsec, python, security, cybersecurity
canonical_url: 
cover_image: 
series: AppSec Python Exercises
---

# Building a Secure File Path Validator: Bytes vs Str Correctness Meets AppSec

## The Problem: When Correctness Bugs Become Security Vulnerabilities

As a security engineer, you're reviewing code for a file upload API. The code looks reasonable:

```python
def save_file(path, content):
	with open(path, 'w') as f:
		f.write(content)
```

But there's a hidden danger. What if `content` is `bytes` instead of `str`? What if `path` contains URL-encoded path traversal sequences? What if an attacker uses overlong UTF-8 encoding to bypass your input validation?

**This exercise bridges the gap between Python correctness (from *Effective Python*) and real-world security vulnerabilities (from *Hacking APIs* and *API Security in Action*).**

## Real-World Context: These Attacks Are Real

This exercise is inspired by actual CVEs:

- **CVE-2019-11510**: Pulse Secure VPN path traversal via URL encoding  
  Exploit: `/dana-na/../dana/html5acc/guacamole/../../etc/passwd`

- **CVE-2021-41773**: Apache HTTP Server path traversal  
  Exploit: `cgi-bin%2F..%2F..%2Fetc%2Fpasswd`

- **CVE-2022-24112**: Atlassian Confluence path traversal via Unicode normalization

These vulnerabilities exposed sensitive data from thousands of organizations because developers didn't properly handle encoding and path validation.

## Part 1: Effective Python's Correctness Warnings

### The bytes vs str Gotcha (Item 10)

Brett Slatkin warns us in *Effective Python* (pages 42-47) about two major gotchas:

**Gotcha #1: Silent equality failures**

```python
# This silently returns False instead of raising an error!
assert b"foo" == "foo"  # False - no exception
```

**Why this matters for security**: If you're comparing API tokens, session IDs, or file paths:

```python
def validate_token(received, stored_in_db):
	if received == stored_in_db:  # stored_in_db is bytes from DB
		return True
	return False

# Attack: Always returns False, bypassing authentication!
```

**Gotcha #2: File operations default to text mode**

```python
# Write binary data
with open("data.bin", "wb") as f:
	f.write(b"\xf1\xf2\xf3\xf4\xf5")

# Try to read in text mode - CRASHES
with open("data.bin", "r") as f:
	data = f.read()  # UnicodeDecodeError!
```

**Why this matters for security**: Attackers can upload malicious binary files that crash your application (DoS attack).

### The Unicode Reversal Bug (Item 15)

Slatkin shows this unexpected behavior (page 71):

```python
w = "寿司"
x = w.encode("utf-8")  # b'\xe5\xaf\xbf\xe5\x8f\xb8'
y = x[::-1]             # Reverse bytes
z = y.decode("utf-8")   # UnicodeDecodeError!
```

The bytes are reversed, but UTF-8 multi-byte characters are now corrupted!

## Part 2: Security Implications from AppSec Books

### Attack #1: URL Encoded Path Traversal

From *Hacking APIs* (pages 271-274):

Attackers encode path traversal sequences to bypass input validation:

```python
# Plain: ../../../etc/passwd (blocked by naive validation)
# Encoded: ..%2F..%2F..%2Fetc%2Fpasswd (bypasses blocklist!)
```

**The problem**: Your validation might check for `../` as a string, but miss the encoded version.

### Attack #2: Double Encoding

From *Hacking APIs* (page 273):

```python
# Single encode: %2F = /
# Double encode: %252F = %2F (which decodes to /)
```

Attack flow:
1. WAF decodes once: `..%252F` → `..%2F` (looks safe!)
2. Application decodes again: `..%2F` → `../` (path traversal!)

### Attack #3: Overlong UTF-8 Encoding

Attackers use non-standard UTF-8 encodings to bypass validation:

```python
# Normal: / = 0x2F (1 byte)
# Overlong: / = 0xC0 0xAF (2 bytes, technically invalid)
```

From *API Security in Action* (page 50), the solution is **allowlists, not blocklists**:

> "Always define acceptable inputs rather than unacceptable ones when validating untrusted input."

### Attack #4: Null Byte Injection (CVE-2006-7243 style)

Historically, attackers used null bytes to truncate filenames:

```python
# Attacker uploads: ../../etc/passwd\x00.jpg
# Validation sees: .jpg extension (safe!)
# System processes: ../../etc/passwd (path traversal!)
```

## The Unicode Sandwich Pattern

Slatkin recommends the **Unicode sandwich** pattern (page 42):

```
┌─────────────────────────┐
│   External Interface    │  ← bytes (HTTP, files, database)
├─────────────────────────┤
│    decode("utf-8")      │  ← Decode at boundary
├─────────────────────────┤
│   Core Application      │  ← str only (Unicode)
├─────────────────────────┤
│    encode("utf-8")      │  ← Encode at boundary
├─────────────────────────┤
│   External Interface    │  ← bytes
└─────────────────────────┘
```

**Security benefit**: Encoding/decoding at boundaries prevents encoding confusion attacks.

## Your Challenge: Implement Four Functions

### 1. `safe_decode(path_input: bytes | str) -> str`

Handle bytes/str conversion safely:

```python
# Must handle:
safe_decode(b"hello.txt")           # → "hello.txt"
safe_decode("hello.txt")            # → "hello.txt"
safe_decode(b"\xf1\xf2\xf3")       # → ValueError (invalid UTF-8)
safe_decode(b"\xc0\xaf")           # → SecurityError (overlong encoding)
```

### 2. `normalize_path(path: str) -> str`

Decode URL encoding and normalize Unicode:

```python
# Must handle:
normalize_path("..%2Fetc%2Fpasswd")  # → "../../etc/passwd"
normalize_path("café")               # → "café" (NFC normalized)
normalize_path("..%252F")            # → SecurityError (double encoding!)
```

### 3. `validate_path(path_input: bytes | str, base_dir: str) -> bool`

Detect attacks using allowlist validation:

```python
# Must reject:
validate_path("../etc/passwd")       # → False (traversal)
validate_path("/etc/passwd")         # → False (absolute)
validate_path("file\x00.jpg")        # → False (null byte)
validate_path("file;whoami.txt")     # → False (special chars)

# Must accept:
validate_path("documents/report.pdf") # → True
```

### 4. `get_safe_path(path_input: bytes | str, base_dir: str) -> str`

Combine all security checks:

```python
# Safe usage:
get_safe_path("docs/report.pdf", "/uploads")  
# → "/uploads/docs/report.pdf"

# Attack detected:
get_safe_path("..%2Fetc%2Fpasswd", "/uploads")
# → SecurityError: Path traversal detected
```

## Key Implementation Patterns

### Pattern 1: Type-Safe Helper Functions

From *Effective Python* (pages 42-43):

```python
def to_str(bytes_or_str):
	if isinstance(bytes_or_str, bytes):
		return bytes_or_str.decode("utf-8")
	return bytes_or_str

def to_bytes(bytes_or_str):
	if isinstance(bytes_or_str, str):
		return bytes_or_str.encode("utf-8")
	return bytes_or_str
```

### Pattern 2: Allowlist Validation

From *API Security in Action* (page 50):

```python
import re

def is_safe_path(path: str) -> bool:
	# Allowlist: only alphanumeric, hyphens, underscores, forward slash
	pattern = r'^[a-zA-Z0-9_\-/]+$'
	return bool(re.match(pattern, path))
```

### Pattern 3: Path Resolution Check

Use Python's `pathlib` to resolve and verify:

```python
from pathlib import Path

def stays_in_base_dir(path: str, base_dir: str) -> bool:
	base = Path(base_dir).resolve()
	target = (base / path).resolve()
	return target.is_relative_to(base)  # Python 3.9+
```

## Testing Your Implementation

The test suite includes 30+ test cases covering:

1. **Correctness** (Effective Python):
   - bytes/str type handling
   - Invalid UTF-8 sequences
   - Empty inputs
   - Unicode handling

2. **Security** (AppSec):
   - Path traversal: `../`, `..\\`
   - URL encoding: `..%2F`
   - Double encoding: `..%252F`
   - Overlong UTF-8
   - Null byte injection
   - Absolute paths
   - Special characters
   - Real CVE scenarios

Run tests with:
```bash
python -m pytest test_secure_path_validator.py -v
```

## Learning Outcomes

After completing this exercise, you will:

✅ Understand bytes/str type confusion and its security implications  
✅ Implement the Unicode sandwich pattern  
✅ Detect encoding-based attack bypasses  
✅ Use allowlist validation correctly  
✅ Prevent path traversal vulnerabilities  
✅ Handle Unicode normalization attacks  

## Sources & Further Reading

📚 **Books Referenced:**
- *Effective Python Third Edition* by Brett Slatkin
  - Item 10: "Know the Differences Between bytes and str" (pages 42-47)
  - Item 15: "Avoid Striding and Slicing in a Single Expression" (pages 70-72)

- *API Security in Action* by Neil Madden
  - Chapter 2: "Secure API development" (pages 47-50)

- *Hacking APIs* by Corey Ball
  - Chapter 13: "Applying Evasive Techniques and Rate Limit Testing" (pages 271-274)

🔗 **Additional Resources:**
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CVE-2019-11510: Pulse Secure VPN](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11510)
- [CVE-2021-41773: Apache HTTP Server](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773)
- [Unicode Security Considerations](https://unicode.org/reports/tr36/)

## Challenge Repository

Get the complete exercise with tests:
```bash
# Files:
# - secure_path_validator.py (challenge stub)
# - test_secure_path_validator.py (30+ test cases)
# - BLOG_POST.md (this article)
```

**No reference implementation is provided** - build your solution from scratch using the patterns discussed above!

---

💡 **Pro Tip**: Real AppSec engineering roles will test your ability to think about BOTH correctness and security. This exercise prepares you for interview questions at companies like Trail of Bits, NCC Group, and similar AppSec teams.

🎯 **Next Steps**: After completing this exercise, try building:
1. A secure JSON API input validator
2. A file upload type checker (detecting malicious files)
3. A SQL injection detector using allowlist validation

Happy coding, and stay secure! 🔒

---

*This exercise is part of the AppSec Python series, designed to prepare developers for Application Security Engineering roles by combining Python best practices with real-world security vulnerabilities.*
