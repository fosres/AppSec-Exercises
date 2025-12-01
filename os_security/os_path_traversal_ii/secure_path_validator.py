"""
Secure File Path Validator - AppSec Challenge
==============================================

CHALLENGE DESCRIPTION:
---------------------
You are a security engineer at a file-sharing company. Your API allows users to 
upload files and specify custom paths. Recently, attackers have been exploiting 
encoding vulnerabilities to perform path traversal attacks and bypass input 
validation.

Your task is to implement a secure path validator that handles BOTH:
1. Correctness: Proper bytes/str handling to avoid crashes (Effective Python Item 10)
2. Security: Prevent encoding-based attacks (Hacking APIs Ch. 13, API Security Ch. 2)

REAL-WORLD CONTEXT:
------------------
This exercise is inspired by actual CVEs:
- CVE-2019-11510: Pulse Secure VPN path traversal via URL encoding
- CVE-2021-41773: Apache HTTP Server path traversal via URL encoding
- CVE-2022-24112: Atlassian Confluence path traversal via Unicode normalization

LEARNING OBJECTIVES:
-------------------
1. Implement the "Unicode sandwich" pattern (Effective Python, page 42)
2. Handle bytes/str type confusion without crashes
3. Detect path traversal attempts using various encodings
4. Validate input using allowlists, not blocklists (API Security, page 50)
5. Prevent encoding-based WAF bypasses (Hacking APIs, pages 271-274)

YOUR TASK:
---------
Implement the following functions:

1. safe_decode(path_input: bytes | str) -> str
   - Convert bytes or str to str safely
   - Handle invalid UTF-8 sequences
   - Raise ValueError for dangerous encodings (overlong UTF-8, etc.)
   
2. normalize_path(path: str) -> str
   - Apply Unicode normalization (NFC form)
   - Remove URL encoding (%2e%2e%2f → ../)
   - Detect double encoding attempts
   
3. validate_path(path_input: bytes | str, base_dir: str = "/uploads") -> bool
   - Return True if path is safe, False if attack detected
   - Must detect:
     * Path traversal: ../ or ..\\ or encoded variants
     * Absolute paths: /etc/passwd or C:\\Windows
     * Null byte injection: file.txt\x00.jpg
     * Unicode normalization attacks: /u̇plȯads (dotted characters)
   - Use allowlist: only alphanumeric, hyphens, underscores, forward slash
   
4. get_safe_path(path_input: bytes | str, base_dir: str = "/uploads") -> str
   - Combine safe_decode(), normalize_path(), validate_path()
   - Return the full safe path or raise SecurityError
   - Must resolve to a path under base_dir (no escaping)

SECURITY PRINCIPLES TO APPLY:
-----------------------------
1. "Always define acceptable inputs rather than unacceptable ones when 
   validating untrusted input." - API Security in Action, page 50

2. "To take your WAF-bypassing attempts to the next level, try encoding 
   payloads. Encoded payloads can often trick WAFs while still being 
   processed by the target application." - Hacking APIs, page 272

3. "When you're writing Python programs, it's important to do encoding 
   and decoding of Unicode data at the furthest boundary of your 
   interfaces; this approach is often called the Unicode sandwich."
   - Effective Python Third Edition, page 42

EXAMPLE ATTACKS TO DETECT:
-------------------------
1. URL encoded: ..%2F..%2Fetc%2Fpasswd
2. Double encoded: ..%252F..%252Fetc%252Fpasswd
3. UTF-8 overlong: ..%c0%af..%c0%afetc%c0%afpasswd
4. Mixed encoding: ..\\/..%2F../etc/passwd
5. Null byte: ../../etc/passwd%00.jpg
6. Unicode normalization: /u̇plȯads (U+0307 combining dot)

HINTS:
-----
- Use urllib.parse.unquote() for URL decoding
- Use unicodedata.normalize() for Unicode normalization
- Use pathlib.Path.resolve() to resolve .. and symbolic links
- Test against the actual filesystem with Path.is_relative_to()
- Consider that some attacks use multiple encoding layers

SOURCES:
-------
- Effective Python Third Edition, Item 10 (pages 42-47)
- Effective Python Third Edition, Item 15 (pages 70-72)
- API Security in Action, Chapter 2 (pages 47-50)
- Hacking APIs, Chapter 13 (pages 271-274)
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal

DO NOT include a reference implementation in this file.
Tests are in test_secure_path_validator.py
"""

from typing import Union


class SecurityError(Exception):
	"""Raised when a security violation is detected."""
	pass


def safe_decode(path_input: Union[bytes, str]) -> str:
	"""
	Safely convert bytes or str input to str.
	
	Args:
		path_input: Path as bytes or str
		
	Returns:
		str: Decoded path
		
	Raises:
		ValueError: If input contains invalid UTF-8 or dangerous encodings
		TypeError: If input is neither bytes nor str
		SecurityError: If overlong UTF-8 encoding detected
	"""
	# TODO: Implement safe decoding
	raise NotImplementedError("Implement safe_decode()")


def normalize_path(path: str) -> str:
	"""
	Normalize path by decoding URL encoding and applying Unicode normalization.
	
	Args:
		path: Path string to normalize
		
	Returns:
		str: Normalized path
		
	Raises:
		SecurityError: If double encoding or suspicious patterns detected
	"""
	# TODO: Implement path normalization
	raise NotImplementedError("Implement normalize_path()")


def validate_path(path_input: Union[bytes, str], base_dir: str = "/uploads") -> bool:
	"""
	Validate that path is safe and within base_dir.
	
	Args:
		path_input: Path to validate (bytes or str)
		base_dir: Base directory that path must stay within
		
	Returns:
		bool: True if path is safe, False if attack detected
		
	Notes:
		This function should detect various path traversal attacks including:
		- Directory traversal: ../ or ..\\
		- Absolute paths: /etc/passwd or C:\\Windows
		- Encoded variants: %2e%2e%2f or ..%5c
		- Null bytes: \x00
		- Unicode tricks: dotted characters, homoglyphs
	"""
	# TODO: Implement validation
	raise NotImplementedError("Implement validate_path()")


def get_safe_path(path_input: Union[bytes, str], base_dir: str = "/uploads") -> str:
	"""
	Get the safe, resolved path combining all security checks.
	
	Args:
		path_input: Path to process (bytes or str)
		base_dir: Base directory that path must stay within
		
	Returns:
		str: Full safe path under base_dir
		
	Raises:
		SecurityError: If path fails any security validation
		ValueError: If path is invalid
		TypeError: If input type is wrong
		
	Example:
		>>> get_safe_path("documents/report.pdf", "/uploads")
		"/uploads/documents/report.pdf"
		
		>>> get_safe_path("../etc/passwd", "/uploads")
		SecurityError: Path traversal detected
	"""
	# TODO: Implement complete safe path resolution
	raise NotImplementedError("Implement get_safe_path()")
