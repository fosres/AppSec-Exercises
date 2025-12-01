"""
SOLUTION: Secure Path Validator - Production-Ready Implementation
==================================================================

This solution passes all 100 realistic test cases and demonstrates
production-grade defensive programming techniques.

Author: fosres (Intel Product Security, 7+ years threat modeling experience)
GitHub: https://github.com/fosres/AppSec-Exercises

References:
- "API Security in Action" by Neil Madden (Chapter 8, pp. 251-254)
- "Full Stack Python Security" by Dennis Byrne (Chapter 6, pp. 123-127)
- "Secure by Design" by Johnsson, Deogun, Sawano (Chapter 7, pp. 189-193)
"""

import os
from typing import Union


def is_safe_path(base_dir: str, requested_path: str) -> bool:
	"""
	Validate that requested_path stays within base_dir (no path traversal).
	
	This is a production-ready implementation that defends against:
	- Classic path traversal (../, /etc/passwd)
	- URL-encoded bypasses (path is pre-decoded by web framework)
	- Null byte injection
	- Absolute path attacks
	- Linux system file access (/proc, /sys, /dev)
	- Real CVE patterns (Git, Confluence, Zip Slip)
	
	Args:
		base_dir: The base directory that files must stay within
		requested_path: The file path requested by the user
	
	Returns:
		True if requested_path is safe (stays within base_dir)
		False if requested_path tries to escape base_dir (attack!)
	
	Security Properties:
	--------------------
	1. FAIL-SECURE: Returns False (reject) when in doubt
	2. DEFENSE-IN-DEPTH: Multiple validation layers
	3. NORMALIZATION: Uses OS-level path resolution
	4. ABSOLUTE COMPARISON: Compares canonical absolute paths
	
	Implementation Details:
	-----------------------
	Linux filesystem behavior:
	- Only forward slash (/) is a path separator (ASCII 0x2F)
	- URL-encoded slashes (%2F) are literal characters, not separators
	- Null bytes (\\x00) are invalid in paths (Python 3 blocks at OS level)
	- Special chars (;, ?, #, tabs) are valid in filenames
	- Case-sensitive filesystem (unlike Windows)
	
	This validator treats the requested_path as already decoded by the
	web framework. If you need to handle URL decoding, do it BEFORE
	calling this function.
	
	Examples:
	---------
	>>> is_safe_path("/var/www/html", "images/photo.jpg")
	True  # Safe: /var/www/html/images/photo.jpg
	
	>>> is_safe_path("/var/www/html", "../../../etc/passwd")
	False  # Attack! Tries to access /etc/passwd
	
	>>> is_safe_path("/uploads", "/etc/passwd")
	False  # Attack! Absolute path escapes base_dir
	
	>>> is_safe_path("/var/www", "%2e%2e%2fetc%2fpasswd")
	True  # Safe: Linux treats %2e as literal chars (already decoded by framework)
	
	>>> is_safe_path("/var/www", "../../../../proc/self/environ")
	False  # Attack! Tries to access /proc filesystem
	"""
	
	# ========================================================================
	# VALIDATION LAYER 1: Reject obviously invalid inputs
	# ========================================================================
	
	# Empty paths are ambiguous - reject them
	# (Is "" the base directory itself, or invalid input?)
	if not requested_path:
		return False
	
	# Null bytes are invalid in POSIX paths
	# Python 3 blocks these at OS level, but defense-in-depth says reject explicitly
	# Reference: "Hacking APIs" (null byte termination attacks)
	if '\x00' in requested_path:
		return False
	
	# ========================================================================
	# VALIDATION LAYER 2: Reject absolute paths
	# ========================================================================
	
	# Absolute paths (starting with /) always escape the base directory
	# Example: requested_path="/etc/passwd" would access /etc/passwd regardless of base_dir
	if os.path.isabs(requested_path):
		return False
	
	# ========================================================================
	# VALIDATION LAYER 3: Normalize and compare canonical paths
	# ========================================================================
	
	# Combine base_dir and requested_path
	# os.path.join() handles edge cases like trailing slashes
	full_path = os.path.join(base_dir, requested_path)
	
	# Normalize paths to resolve .., ., and redundant slashes
	# Example: "/var/www/images/../../../etc" → "/etc"
	# Reference: "API Security in Action" Ch 8, pp. 251-254
	normalized_full = os.path.normpath(full_path)
	normalized_base = os.path.normpath(base_dir)
	
	# Convert to absolute paths (canonical form)
	# This handles relative base directories and ensures consistent comparison
	# Example: base="uploads" → "/home/user/uploads"
	abs_full = os.path.abspath(normalized_full)
	abs_base = os.path.abspath(normalized_base)
	
	# ========================================================================
	# VALIDATION LAYER 4: Check if final path is within base directory
	# ========================================================================
	
	# Security-critical comparison:
	# The final absolute path must start with the base directory
	
	# Special case: If paths are identical, it's safe
	# Example: requested_path="." resolves to base_dir itself
	if abs_full == abs_base:
		return True
	
	# Standard case: Final path must be a subdirectory of base
	# IMPORTANT: Add os.sep to prevent prefix false positives
	# Example without os.sep:
	#   abs_base = "/var/www"
	#   abs_full = "/var/www_uploads/file.txt"
	#   abs_full.startswith(abs_base) → True (WRONG!)
	# Example with os.sep:
	#   abs_base = "/var/www/"
	#   abs_full = "/var/www_uploads/file.txt"
	#   abs_full.startswith("/var/www/") → False (CORRECT!)
	#
	# Reference: "Secure by Design" Ch 7, pp. 189-193
	if not abs_base.endswith(os.sep):
		abs_base += os.sep
	
	return abs_full.startswith(abs_base)


# ============================================================================
# ALTERNATIVE IMPLEMENTATION: Using os.path.commonpath()
# ============================================================================

def is_safe_path_alternative(base_dir: str, requested_path: str) -> bool:
	"""
	Alternative implementation using os.path.commonpath().
	
	This is slightly more elegant but less explicit about the security logic.
	The primary implementation above is recommended for clarity in code review.
	"""
	if not requested_path or '\x00' in requested_path:
		return False
	
	if os.path.isabs(requested_path):
		return False
	
	full_path = os.path.join(base_dir, requested_path)
	abs_full = os.path.abspath(full_path)
	abs_base = os.path.abspath(base_dir)
	
	# Check if base_dir is a common prefix
	try:
		common = os.path.commonpath([abs_base, abs_full])
		return common == abs_base
	except ValueError:
		# Paths have different drives (Windows) or are malformed
		return False


# ============================================================================
# PRODUCTION DEPLOYMENT CONSIDERATIONS
# ============================================================================

def is_safe_path_production(base_dir: str, requested_path: str) -> bool:
	"""
	Production-ready version with logging and monitoring.
	
	In production, you should:
	1. Log all rejected paths for security monitoring
	2. Add rate limiting to prevent path traversal fuzzing
	3. Combine with other defenses (file extension allowlists, etc.)
	4. Consider using chroot/containers for defense-in-depth
	"""
	import logging
	
	# Validate input
	if not requested_path:
		logging.warning(f"Path validation: Empty path rejected")
		return False
	
	if '\x00' in requested_path:
		logging.warning(f"Path validation: Null byte injection blocked - path={repr(requested_path)}")
		return False
	
	if os.path.isabs(requested_path):
		logging.warning(f"Path validation: Absolute path blocked - path={requested_path}")
		return False
	
	# Normalize and validate
	full_path = os.path.join(base_dir, requested_path)
	abs_full = os.path.abspath(os.path.normpath(full_path))
	abs_base = os.path.abspath(os.path.normpath(base_dir))
	
	if abs_full == abs_base:
		return True
	
	if not abs_base.endswith(os.sep):
		abs_base += os.sep
	
	is_safe = abs_full.startswith(abs_base)
	
	if not is_safe:
		logging.warning(
			f"Path validation: Traversal attack blocked - "
			f"base={base_dir}, requested={requested_path}, resolved={abs_full}"
		)
	
	return is_safe


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
	print("Path Validator Solution - Usage Examples")
	print("=" * 60)
	
	# Safe paths
	print("\n✅ Safe Paths (should return True):")
	print(f"  is_safe_path('/var/www', 'images/logo.png') = {is_safe_path('/var/www', 'images/logo.png')}")
	print(f"  is_safe_path('/uploads', 'user123/file.pdf') = {is_safe_path('/uploads', 'user123/file.pdf')}")
	print(f"  is_safe_path('/var/www', 'data/.../file.txt') = {is_safe_path('/var/www', 'data/.../file.txt')}")
	
	# Attack paths
	print("\n❌ Attack Paths (should return False):")
	print(f"  is_safe_path('/var/www', '../../../etc/passwd') = {is_safe_path('/var/www', '../../../etc/passwd')}")
	print(f"  is_safe_path('/var/www', '/etc/passwd') = {is_safe_path('/var/www', '/etc/passwd')}")
	print(f"  is_safe_path('/var/www', 'file.txt\\x00../etc/passwd') = {is_safe_path('/var/www', 'file.txt\x00../etc/passwd')}")
	
	# URL-encoded (treated as literal characters on Linux)
	print("\n🔒 URL-Encoded Paths (safe - already decoded by framework):")
	print(f"  is_safe_path('/var/www', '%2e%2e%2fetc%2fpasswd') = {is_safe_path('/var/www', '%2e%2e%2fetc%2fpasswd')}")
	print(f"  is_safe_path('/var/www', 'images%2flogo.png') = {is_safe_path('/var/www', 'images%2flogo.png')}")
	
	# Linux system paths
	print("\n🔒 Linux System File Access (attacks - should block):")
	print(f"  is_safe_path('/var/www', '../../../../proc/self/environ') = {is_safe_path('/var/www', '../../../../proc/self/environ')}")
	print(f"  is_safe_path('/var/www', '../../../../root/.ssh/id_rsa') = {is_safe_path('/var/www', '../../../../root/.ssh/id_rsa')}")
	
	print("\n" + "=" * 60)
	print("To test against all 100 realistic cases:")
	print("  python3 path_validator_100_tests.py")
	print("=" * 60)
