"""
Test Suite for Secure File Path Validator
==========================================

This test suite covers:
1. Effective Python Item 10: bytes/str handling correctness
2. Effective Python Item 15: Unicode encoding/decoding issues
3. Security: Path traversal attack detection
4. Security: Encoding-based bypass attempts

Run with: python -m pytest test_secure_path_validator.py -v
Or: python test_secure_path_validator.py
"""

import unittest
from secure_path_validator import (
	safe_decode,
	normalize_path,
	validate_path,
	get_safe_path,
	SecurityError
)


class TestSafeDecode(unittest.TestCase):
	"""Test safe_decode() for bytes/str handling - Effective Python Item 10"""
	
	def test_decode_valid_bytes_utf8(self):
		"""Should decode valid UTF-8 bytes to str"""
		result = safe_decode(b"hello.txt")
		self.assertEqual("hello.txt", result)
		self.assertIsInstance(result, str)
	
	def test_decode_str_passthrough(self):
		"""Should pass through str without modification"""
		result = safe_decode("hello.txt")
		self.assertEqual("hello.txt", result)
		self.assertIsInstance(result, str)
	
	def test_decode_unicode_str(self):
		"""Should handle Unicode str correctly"""
		result = safe_decode("文档.txt")
		self.assertEqual("文档.txt", result)
	
	def test_decode_unicode_bytes(self):
		"""Should decode UTF-8 encoded Unicode bytes"""
		result = safe_decode("文档.txt".encode('utf-8'))
		self.assertEqual("文档.txt", result)
	
	def test_decode_invalid_utf8_raises_error(self):
		"""Should raise ValueError for invalid UTF-8 sequences"""
		# 0xF1 is invalid UTF-8 continuation byte (Effective Python p.46)
		with self.assertRaises(ValueError):
			safe_decode(b"\xf1\xf2\xf3\xf4\xf5")
	
	def test_decode_overlong_encoding_raises_security_error(self):
		"""Should detect overlong UTF-8 encoding (security bypass attempt)"""
		# Overlong encoding of '/' = %c0%af instead of %2f
		# Reference: Hacking APIs page 272
		with self.assertRaises(SecurityError):
			safe_decode(b"\xc0\xaf")
	
	def test_decode_wrong_type_raises_type_error(self):
		"""Should raise TypeError for non-bytes, non-str input"""
		with self.assertRaises(TypeError):
			safe_decode(123)
		with self.assertRaises(TypeError):
			safe_decode(['path.txt'])
	
	def test_decode_null_byte_in_bytes(self):
		"""Should handle null bytes in bytes input"""
		# Null byte injection: CVE-2006-7243 style
		result = safe_decode(b"file.txt\x00.jpg")
		self.assertIn("\x00", result)  # Should preserve for later validation
	
	def test_decode_empty_bytes(self):
		"""Should handle empty bytes"""
		result = safe_decode(b"")
		self.assertEqual("", result)
	
	def test_decode_empty_str(self):
		"""Should handle empty str"""
		result = safe_decode("")
		self.assertEqual("", result)


class TestNormalizePath(unittest.TestCase):
	"""Test normalize_path() for URL decoding and Unicode normalization"""
	
	def test_normalize_url_encoded_path(self):
		"""Should decode URL encoded characters"""
		result = normalize_path("hello%20world.txt")
		self.assertEqual("hello world.txt", result)
	
	def test_normalize_traversal_encoded(self):
		"""Should decode URL encoded path traversal"""
		result = normalize_path("..%2F..%2Fetc%2Fpasswd")
		self.assertEqual("../../etc/passwd", result)
	
	def test_normalize_double_encoded_raises_error(self):
		"""Should detect double URL encoding (bypass attempt)"""
		# Double encoded ../ = ..%252F (Hacking APIs p.273)
		with self.assertRaises(SecurityError):
			normalize_path("..%252Fetc")
	
	def test_normalize_unicode_nfc(self):
		"""Should apply NFC Unicode normalization"""
		# Combining characters that could bypass validation
		result = normalize_path("café")  # é as single character
		self.assertEqual("café", result)
	
	def test_normalize_unicode_combining_dots(self):
		"""Should normalize combining dot characters"""
		# u̇plȯads uses U+0307 combining dots (can bypass string matching)
		# After normalization, should be detectable
		path_with_dots = "u\u0307plo\u0307ads"
		result = normalize_path(path_with_dots)
		# After normalization, this should be normalized form
		self.assertIsInstance(result, str)
	
	def test_normalize_mixed_encoding(self):
		"""Should handle mixed encoded and plain characters"""
		result = normalize_path("documents%2Freport.txt")
		self.assertEqual("documents/report.txt", result)
	
	def test_normalize_backslash_windows(self):
		"""Should preserve backslashes for later validation"""
		result = normalize_path("..\\..\\Windows\\System32")
		self.assertEqual("..\\..\\Windows\\System32", result)


class TestValidatePath(unittest.TestCase):
	"""Test validate_path() for security attack detection"""
	
	def test_validate_safe_simple_path(self):
		"""Should accept simple safe path"""
		self.assertTrue(validate_path("documents/report.pdf"))
	
	def test_validate_safe_nested_path(self):
		"""Should accept nested safe path"""
		self.assertTrue(validate_path("documents/2024/q4/report.pdf"))
	
	def test_validate_safe_with_hyphens_underscores(self):
		"""Should accept alphanumeric with hyphens and underscores"""
		self.assertTrue(validate_path("my-file_v2.txt"))
	
	def test_validate_reject_parent_traversal_unix(self):
		"""Should reject ../ path traversal"""
		self.assertFalse(validate_path("../etc/passwd"))
	
	def test_validate_reject_parent_traversal_windows(self):
		"""Should reject ..\\ path traversal"""
		self.assertFalse(validate_path("..\\..\\Windows\\System32"))
	
	def test_validate_reject_absolute_path_unix(self):
		"""Should reject absolute Unix paths"""
		self.assertFalse(validate_path("/etc/passwd"))
	
	def test_validate_reject_absolute_path_windows(self):
		"""Should reject absolute Windows paths"""
		self.assertFalse(validate_path("C:\\Windows\\System32"))
	
	def test_validate_reject_url_encoded_traversal(self):
		"""Should reject URL encoded traversal after normalization"""
		# This tests integration with normalize_path
		self.assertFalse(validate_path("..%2F..%2Fetc%2Fpasswd"))
	
	def test_validate_reject_null_byte_injection(self):
		"""Should reject null byte injection (CVE-2006-7243 style)"""
		self.assertFalse(validate_path("../../etc/passwd\x00.jpg"))
	
	def test_validate_reject_current_dir_only(self):
		"""Should reject paths with only . or ./"""
		self.assertFalse(validate_path("."))
		self.assertFalse(validate_path("./"))
	
	def test_validate_bytes_input(self):
		"""Should handle bytes input by converting first"""
		self.assertTrue(validate_path(b"documents/report.pdf"))
	
	def test_validate_reject_special_characters(self):
		"""Should reject paths with special shell characters"""
		# Allowlist approach: reject what's not explicitly allowed
		self.assertFalse(validate_path("file;rm -rf.txt"))
		self.assertFalse(validate_path("file`whoami`.txt"))
		self.assertFalse(validate_path("file|cat.txt"))


class TestGetSafePath(unittest.TestCase):
	"""Test get_safe_path() for complete security validation"""
	
	def test_get_safe_path_simple(self):
		"""Should return full safe path for valid input"""
		result = get_safe_path("report.pdf", "/uploads")
		self.assertTrue(result.startswith("/uploads"))
		self.assertIn("report.pdf", result)
	
	def test_get_safe_path_nested(self):
		"""Should return full safe path for nested directories"""
		result = get_safe_path("documents/2024/report.pdf", "/uploads")
		self.assertTrue(result.startswith("/uploads"))
		self.assertIn("2024", result)
	
	def test_get_safe_path_traversal_raises_error(self):
		"""Should raise SecurityError for path traversal"""
		with self.assertRaises(SecurityError):
			get_safe_path("../etc/passwd", "/uploads")
	
	def test_get_safe_path_absolute_raises_error(self):
		"""Should raise SecurityError for absolute paths"""
		with self.assertRaises(SecurityError):
			get_safe_path("/etc/passwd", "/uploads")
	
	def test_get_safe_path_url_encoded_attack(self):
		"""Should raise SecurityError for URL encoded attacks"""
		# CVE-2019-11510 style: Pulse Secure path traversal
		with self.assertRaises(SecurityError):
			get_safe_path("..%2F..%2Fetc%2Fpasswd", "/uploads")
	
	def test_get_safe_path_null_byte_attack(self):
		"""Should raise SecurityError for null byte injection"""
		with self.assertRaises(SecurityError):
			get_safe_path("../../etc/passwd\x00.jpg", "/uploads")
	
	def test_get_safe_path_bytes_input(self):
		"""Should handle bytes input correctly"""
		result = get_safe_path(b"report.pdf", "/uploads")
		self.assertIsInstance(result, str)
		self.assertIn("report.pdf", result)
	
	def test_get_safe_path_unicode_filename(self):
		"""Should handle Unicode filenames safely"""
		result = get_safe_path("文档.pdf", "/uploads")
		self.assertIn("文档.pdf", result)
	
	def test_get_safe_path_stays_in_base_dir(self):
		"""Should ensure final path stays within base_dir"""
		# Even with complex paths, should not escape base_dir
		result = get_safe_path("a/b/../c/./d.txt", "/uploads")
		self.assertTrue(result.startswith("/uploads"))
	
	def test_get_safe_path_mixed_encoding_attack(self):
		"""Should detect mixed encoding attacks (Hacking APIs p.274)"""
		# Mix of backslash, forward slash, and URL encoding
		with self.assertRaises(SecurityError):
			get_safe_path("..\\/..%2F../etc/passwd", "/uploads")


class TestRealWorldCVEScenarios(unittest.TestCase):
	"""Test against real CVE scenarios"""
	
	def test_cve_2019_11510_pulse_secure(self):
		"""CVE-2019-11510: Pulse Secure VPN path traversal"""
		# Original exploit: /dana-na/../dana/html5acc/guacamole/../../etc/passwd
		attack = "dana-na%2F..%2Fdana%2Fhtml5acc%2Fguacamole%2F..%2F..%2Fetc%2Fpasswd"
		with self.assertRaises(SecurityError):
			get_safe_path(attack, "/var/www")
	
	def test_cve_2021_41773_apache(self):
		"""CVE-2021-41773: Apache HTTP Server path traversal"""
		# Original exploit used URL encoding to bypass path checks
		attack = "cgi-bin%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
		with self.assertRaises(SecurityError):
			get_safe_path(attack, "/var/www")
	
	def test_unicode_normalization_bypass(self):
		"""Test Unicode normalization bypass attempt"""
		# Using combining characters to bypass string matching
		# Reference: Unicode security considerations
		attack = "u\u0307plo\u0307ads/../../etc/passwd"
		with self.assertRaises(SecurityError):
			get_safe_path(attack, "/uploads")


if __name__ == '__main__':
	unittest.main()
