"""
Cryptographic Password Generator Challenge - 50 Comprehensive Tests
Week 1 - Python Workout Chapters 1-2

CHALLENGE: Build a cryptographically secure password generator that validates
password strength using entropy calculations.

REQUIREMENTS:
1. Generate passwords using a CRYPTOGRAPHICALLY SECURE random source
   - Research which Python module to use (hint: NOT the 'random' module)
   
2. Support multiple character sets:
   - 'all': lowercase + uppercase + digits + special chars
   - 'alphanumeric': lowercase + uppercase + digits
   - 'alpha': lowercase + uppercase
   - 'passphrase': 4-6 random words (optional)

3. Password length constraints:
   - MINIMUM: 12 characters
   - MAXIMUM: 64 characters

4. Calculate and display password strength:
   - Character space size
   - Entropy in bits: length × log₂(character_set_size)
   - Strength rating based on entropy thresholds

STRENGTH RATING THRESHOLDS:
- < 50 bits: "Weak - Vulnerable to modern attacks"
- 50-64 bits: "Moderate - Acceptable for low-security contexts"
- 65-79 bits: "Strong - Recommended for most applications"
- 80-100 bits: "Very Strong - Suitable for high-security applications"
- > 100 bits: "Excellent - Resistant to nation-state attacks"

CONCEPTS FROM PYTHON WORKOUT CH 1-2:
- User input with input()
- Type conversion (str to int)
- For loops and iteration
- Comparisons and conditionals
- f-strings for formatted output
- math.log2() for entropy calculation

SECURITY WARNING:
Never use the 'random' module for password generation. It is NOT
cryptographically secure and produces predictable output.
"""

import string
import math

# Character set definitions
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = '!@#$%^&*()-_+=[]{}|;:,.<>?/~`\'"\\' # 32 special characters

# ANSI color codes for pretty output
GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'


# ============================================================================
# YOUR CODE GOES HERE - IMPLEMENT THESE FUNCTIONS
# ============================================================================

def generate_password(length, charset):
	"""
	Generate a cryptographically secure random password.
	
	Args:
		length (int): Password length (12-64)
		charset (str): String containing all possible characters
		
	Returns:
		str: Generated password
		
	TODO: Research and use the correct cryptographic random module
	"""
	# TODO: Implement password generation
	pass


def calculate_entropy(length, charset_size):
	"""
	Calculate password entropy in bits.
	
	Args:
		length (int): Password length
		charset_size (int): Number of unique characters in character set
		
	Returns:
		float: Entropy in bits
		
	Formula: entropy = length × log₂(charset_size)
	"""
	# TODO: Implement entropy calculation
	pass


def get_strength_rating(entropy_bits):
	"""
	Determine strength rating based on entropy.
	
	Args:
		entropy_bits (float): Calculated entropy
		
	Returns:
		str: Strength rating description
		
	Thresholds:
		< 50: Weak
		50-64: Moderate
		65-79: Strong
		80-100: Very Strong
		> 100: Excellent
	"""
	# TODO: Implement strength rating logic
	pass


def get_charset_size(charset):
	"""
	Calculate the size of the character set (number of unique characters).
	
	Args:
		charset (str): String containing all possible characters
		
	Returns:
		int: Number of unique characters
		
	Hint: Use len() on the charset string, or use set() to ensure uniqueness
	"""
	# TODO: Implement charset size calculation
	pass


# ============================================================================
# COMPREHENSIVE TEST SUITE - 50 TESTS
# ============================================================================

def run_tests():
	"""Run all 50 comprehensive tests"""
	
	passed = 0
	failed = 0
	
	print(f"\n{BOLD}╔══════════════════════════════════════════════════════════════╗")
	print(f"║          PASSWORD GENERATOR CHALLENGE - 50 TESTS            ║")
	print(f"╚══════════════════════════════════════════════════════════════╝{RESET}\n")
	
	# ========================================================================
	# BASIC FUNCTIONALITY TESTS (1-10)
	# ========================================================================
	
	# Test 1: Charset size - lowercase only
	try:
		result = get_charset_size(LOWERCASE)
		assert result == 26, f"Expected 26, got {result}"
		print(f"{GREEN}✓{RESET} Test 1: Charset size - lowercase only (26 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 1 FAILED: {e}")
		failed += 1
	
	# Test 2: Charset size - uppercase only
	try:
		result = get_charset_size(UPPERCASE)
		assert result == 26, f"Expected 26, got {result}"
		print(f"{GREEN}✓{RESET} Test 2: Charset size - uppercase only (26 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 2 FAILED: {e}")
		failed += 1
	
	# Test 3: Charset size - digits only
	try:
		result = get_charset_size(DIGITS)
		assert result == 10, f"Expected 10, got {result}"
		print(f"{GREEN}✓{RESET} Test 3: Charset size - digits only (10 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 3 FAILED: {e}")
		failed += 1
	
	# Test 4: Charset size - special chars
	try:
		result = get_charset_size(SPECIAL)
		assert result == 32, f"Expected 32, got {result}"
		print(f"{GREEN}✓{RESET} Test 4: Charset size - special chars (32 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 4 FAILED: {e}")
		failed += 1
	
	# Test 5: Charset size - alphanumeric (lowercase + uppercase + digits)
	try:
		result = get_charset_size(LOWERCASE + UPPERCASE + DIGITS)
		assert result == 62, f"Expected 62, got {result}"
		print(f"{GREEN}✓{RESET} Test 5: Charset size - alphanumeric (62 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 5 FAILED: {e}")
		failed += 1
	
	# Test 6: Charset size - all characters
	try:
		result = get_charset_size(LOWERCASE + UPPERCASE + DIGITS + SPECIAL)
		assert result == 94, f"Expected 94, got {result}"
		print(f"{GREEN}✓{RESET} Test 6: Charset size - all characters (94 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 6 FAILED: {e}")
		failed += 1
	
	# Test 7: Charset size - mixed case only
	try:
		result = get_charset_size(LOWERCASE + UPPERCASE)
		assert result == 52, f"Expected 52, got {result}"
		print(f"{GREEN}✓{RESET} Test 7: Charset size - mixed case (52 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 7 FAILED: {e}")
		failed += 1
	
	# Test 8: Entropy calculation - basic case
	try:
		result = calculate_entropy(12, 26)
		expected = 12 * math.log2(26)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 8: Entropy calculation - 12 chars, 26 charset (~56.4 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 8 FAILED: {e}")
		failed += 1
	
	# Test 9: Entropy calculation - alphanumeric
	try:
		result = calculate_entropy(12, 62)
		assert 71 < result < 72, f"Expected ~71.5 bits, got {result}"
		print(f"{GREEN}✓{RESET} Test 9: Entropy calculation - 12 chars, 62 charset (~71.5 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 9 FAILED: {e}")
		failed += 1
	
	# Test 10: Entropy calculation - all chars
	try:
		result = calculate_entropy(16, 94)
		assert 104 < result < 105, f"Expected ~104.8 bits, got {result}"
		print(f"{GREEN}✓{RESET} Test 10: Entropy calculation - 16 chars, 94 charset (~104.8 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 10 FAILED: {e}")
		failed += 1
	
	# ========================================================================
	# BOUNDARY CONDITION TESTS (11-20)
	# ========================================================================
	
	# Test 11: Minimum password length (12 chars)
	try:
		pwd = generate_password(12, LOWERCASE + UPPERCASE + DIGITS)
		assert len(pwd) == 12, f"Expected length 12, got {len(pwd)}"
		print(f"{GREEN}✓{RESET} Test 11: Minimum password length (12 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 11 FAILED: {e}")
		failed += 1
	
	# Test 12: Maximum password length (64 chars)
	try:
		pwd = generate_password(64, LOWERCASE + UPPERCASE + DIGITS)
		assert len(pwd) == 64, f"Expected length 64, got {len(pwd)}"
		print(f"{GREEN}✓{RESET} Test 12: Maximum password length (64 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 12 FAILED: {e}")
		failed += 1
	
	# Test 13: Entropy at minimum length (12 chars, all charset)
	try:
		result = calculate_entropy(12, 94)
		assert 78 < result < 79, f"Expected ~78.6 bits, got {result}"
		print(f"{GREEN}✓{RESET} Test 13: Entropy at minimum length (12 chars, ~78.6 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 13 FAILED: {e}")
		failed += 1
	
	# Test 14: Entropy at maximum length (64 chars, all charset)
	try:
		result = calculate_entropy(64, 94)
		assert 419 < result < 420, f"Expected ~419.2 bits, got {result}"
		print(f"{GREEN}✓{RESET} Test 14: Entropy at maximum length (64 chars, ~419.2 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 14 FAILED: {e}")
		failed += 1
	
	# Test 15: Strength rating at exactly 50 bits boundary
	try:
		rating = get_strength_rating(50.0)
		# Should be "Moderate" (50-64 bits inclusive)
		assert "Moderate" in rating, f"Expected 'Moderate', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 15: Strength rating at 50 bits boundary (Moderate)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 15 FAILED: {e}")
		failed += 1
	
	# Test 16: Strength rating at exactly 65 bits boundary
	try:
		rating = get_strength_rating(65.0)
		assert "Strong" in rating, f"Expected 'Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 16: Strength rating at 65 bits boundary (Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 16 FAILED: {e}")
		failed += 1
	
	# Test 17: Strength rating at exactly 80 bits boundary
	try:
		rating = get_strength_rating(80.0)
		assert "Very Strong" in rating, f"Expected 'Very Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 17: Strength rating at 80 bits boundary (Very Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 17 FAILED: {e}")
		failed += 1
	
	# Test 18: Strength rating at exactly 100 bits boundary
	try:
		rating = get_strength_rating(100.0)
		assert "Very Strong" in rating, f"Expected 'Very Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 18: Strength rating at 100 bits boundary (Very Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 18 FAILED: {e}")
		failed += 1
	
	# Test 19: Strength rating just above 100 bits
	try:
		rating = get_strength_rating(100.1)
		assert "Excellent" in rating, f"Expected 'Excellent', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 19: Strength rating just above 100 bits (Excellent)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 19 FAILED: {e}")
		failed += 1
	
	# Test 20: Strength rating just below 50 bits
	try:
		rating = get_strength_rating(49.9)
		assert "Weak" in rating, f"Expected 'Weak', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 20: Strength rating just below 50 bits (Weak)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 20 FAILED: {e}")
		failed += 1
	
	# ========================================================================
	# ENTROPY CALCULATION TESTS (21-30)
	# ========================================================================
	
	# Test 21: Entropy - 20 char lowercase
	try:
		result = calculate_entropy(20, 26)
		expected = 20 * math.log2(26)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 21: Entropy - 20 char lowercase (~94.0 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 21 FAILED: {e}")
		failed += 1
	
	# Test 22: Entropy - 16 char mixed case
	try:
		result = calculate_entropy(16, 52)
		expected = 16 * math.log2(52)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 22: Entropy - 16 char mixed case (~91.2 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 22 FAILED: {e}")
		failed += 1
	
	# Test 23: Entropy - 32 char alphanumeric
	try:
		result = calculate_entropy(32, 62)
		expected = 32 * math.log2(62)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 23: Entropy - 32 char alphanumeric (~190.5 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 23 FAILED: {e}")
		failed += 1
	
	# Test 24: Entropy - 48 char all charset
	try:
		result = calculate_entropy(48, 94)
		expected = 48 * math.log2(94)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 24: Entropy - 48 char all charset (~314.4 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 24 FAILED: {e}")
		failed += 1
	
	# Test 25: Entropy - 13 char alphanumeric (just above minimum)
	try:
		result = calculate_entropy(13, 62)
		expected = 13 * math.log2(62)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 25: Entropy - 13 char alphanumeric (~77.4 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 25 FAILED: {e}")
		failed += 1
	
	# Test 26: Entropy - 24 char digits only
	try:
		result = calculate_entropy(24, 10)
		expected = 24 * math.log2(10)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 26: Entropy - 24 char digits only (~79.7 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 26 FAILED: {e}")
		failed += 1
	
	# Test 27: Entropy - single character (edge case)
	try:
		result = calculate_entropy(1, 94)
		expected = 1 * math.log2(94)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 27: Entropy - single character (~6.6 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 27 FAILED: {e}")
		failed += 1
	
	# Test 28: Entropy - 100 char password (beyond max)
	try:
		result = calculate_entropy(100, 94)
		expected = 100 * math.log2(94)
		assert abs(result - expected) < 0.01, f"Expected {expected:.2f}, got {result}"
		print(f"{GREEN}✓{RESET} Test 28: Entropy - 100 char password (~655.0 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 28 FAILED: {e}")
		failed += 1
	
	# Test 29: Entropy - 15 char alphanumeric
	try:
		result = calculate_entropy(15, 62)
		assert 89 < result < 90, f"Expected ~89.3 bits, got {result}"
		print(f"{GREEN}✓{RESET} Test 29: Entropy - 15 char alphanumeric (~89.3 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 29 FAILED: {e}")
		failed += 1
	
	# Test 30: Entropy - 18 char all charset
	try:
		result = calculate_entropy(18, 94)
		assert 117 < result < 118, f"Expected ~117.9 bits, got {result}"
		print(f"{GREEN}✓{RESET} Test 30: Entropy - 18 char all charset (~117.9 bits)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 30 FAILED: {e}")
		failed += 1
	
	# ========================================================================
	# STRENGTH RATING TESTS (31-40)
	# ========================================================================
	
	# Test 31: Very weak password (10 bits)
	try:
		rating = get_strength_rating(10.0)
		assert "Weak" in rating, f"Expected 'Weak', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 31: Very weak password - 10 bits (Weak)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 31 FAILED: {e}")
		failed += 1
	
	# Test 32: Weak password (25 bits)
	try:
		rating = get_strength_rating(25.0)
		assert "Weak" in rating, f"Expected 'Weak', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 32: Weak password - 25 bits (Weak)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 32 FAILED: {e}")
		failed += 1
	
	# Test 33: Just below moderate (49 bits)
	try:
		rating = get_strength_rating(49.0)
		assert "Weak" in rating, f"Expected 'Weak', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 33: Just below moderate - 49 bits (Weak)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 33 FAILED: {e}")
		failed += 1
	
	# Test 34: Lower moderate (55 bits)
	try:
		rating = get_strength_rating(55.0)
		assert "Moderate" in rating, f"Expected 'Moderate', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 34: Lower moderate - 55 bits (Moderate)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 34 FAILED: {e}")
		failed += 1
	
	# Test 35: Upper moderate (64 bits)
	try:
		rating = get_strength_rating(64.0)
		assert "Moderate" in rating, f"Expected 'Moderate', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 35: Upper moderate - 64 bits (Moderate)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 35 FAILED: {e}")
		failed += 1
	
	# Test 36: Lower strong (70 bits)
	try:
		rating = get_strength_rating(70.0)
		assert "Strong" in rating, f"Expected 'Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 36: Lower strong - 70 bits (Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 36 FAILED: {e}")
		failed += 1
	
	# Test 37: Upper strong (80 bits - boundary test)
	try:
		rating = get_strength_rating(80.0)
		assert "Very Strong" in rating, f"Expected 'Very Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 37: Upper strong boundary - 80 bits (Very Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 37 FAILED: {e}")
		failed += 1
	
	# Test 38: Lower very strong (85 bits)
	try:
		rating = get_strength_rating(85.0)
		assert "Very Strong" in rating, f"Expected 'Very Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 38: Lower very strong - 85 bits (Very Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 38 FAILED: {e}")
		failed += 1
	
	# Test 39: Upper very strong (99 bits)
	try:
		rating = get_strength_rating(99.0)
		assert "Very Strong" in rating, f"Expected 'Very Strong', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 39: Upper very strong - 99 bits (Very Strong)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 39 FAILED: {e}")
		failed += 1
	
	# Test 40: Excellent - 128 bits
	try:
		rating = get_strength_rating(128.0)
		assert "Excellent" in rating, f"Expected 'Excellent', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 40: Excellent - 128 bits (Excellent)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 40 FAILED: {e}")
		failed += 1
	
	# ========================================================================
	# PASSWORD GENERATION TESTS (41-50)
	# ========================================================================
	
	# Test 41: Generated password contains only lowercase
	try:
		pwd = generate_password(12, LOWERCASE)
		assert all(c in LOWERCASE for c in pwd), "Password contains non-lowercase chars"
		print(f"{GREEN}✓{RESET} Test 41: Generated password contains only lowercase")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 41 FAILED: {e}")
		failed += 1
	
	# Test 42: Generated password contains only uppercase
	try:
		pwd = generate_password(12, UPPERCASE)
		assert all(c in UPPERCASE for c in pwd), "Password contains non-uppercase chars"
		print(f"{GREEN}✓{RESET} Test 42: Generated password contains only uppercase")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 42 FAILED: {e}")
		failed += 1
	
	# Test 43: Generated password contains only digits
	try:
		pwd = generate_password(12, DIGITS)
		assert all(c in DIGITS for c in pwd), "Password contains non-digit chars"
		print(f"{GREEN}✓{RESET} Test 43: Generated password contains only digits")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 43 FAILED: {e}")
		failed += 1
	
	# Test 44: Generated password uses all charset types
	try:
		charset = LOWERCASE + UPPERCASE + DIGITS + SPECIAL
		pwd = generate_password(20, charset)
		assert all(c in charset for c in pwd), "Password contains invalid chars"
		print(f"{GREEN}✓{RESET} Test 44: Generated password uses all charset types")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 44 FAILED: {e}")
		failed += 1
	
	# Test 45: Generated passwords are unique (randomness check)
	try:
		charset = LOWERCASE + UPPERCASE + DIGITS
		pwd1 = generate_password(16, charset)
		pwd2 = generate_password(16, charset)
		pwd3 = generate_password(16, charset)
		# Extremely unlikely all three are the same if truly random
		assert not (pwd1 == pwd2 == pwd3), "Generated passwords are identical (not random)"
		print(f"{GREEN}✓{RESET} Test 45: Generated passwords are unique (randomness)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 45 FAILED: {e}")
		failed += 1
	
	# Test 46: Mid-range password (28 chars)
	try:
		pwd = generate_password(28, LOWERCASE + UPPERCASE)
		assert len(pwd) == 28, f"Expected length 28, got {len(pwd)}"
		print(f"{GREEN}✓{RESET} Test 46: Mid-range password length (28 chars)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 46 FAILED: {e}")
		failed += 1
	
	# Test 47: Password with special chars only
	try:
		pwd = generate_password(12, SPECIAL)
		assert all(c in SPECIAL for c in pwd), "Password contains non-special chars"
		assert len(pwd) == 12, f"Expected length 12, got {len(pwd)}"
		print(f"{GREEN}✓{RESET} Test 47: Password with special chars only")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 47 FAILED: {e}")
		failed += 1
	
	# Test 48: Charset size with duplicate characters
	try:
		# Test that function handles duplicates correctly
		result = get_charset_size("aabbccdd")
		assert result == 4, f"Expected 4 unique chars, got {result}"
		print(f"{GREEN}✓{RESET} Test 48: Charset size handles duplicates correctly")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 48 FAILED: {e}")
		failed += 1
	
	# Test 49: Very high entropy (256 bits)
	try:
		rating = get_strength_rating(256.0)
		assert "Excellent" in rating, f"Expected 'Excellent', got '{rating}'"
		print(f"{GREEN}✓{RESET} Test 49: Very high entropy - 256 bits (Excellent)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 49 FAILED: {e}")
		failed += 1
	
	# Test 50: Integration - Full workflow
	try:
		# Generate password
		charset = LOWERCASE + UPPERCASE + DIGITS + SPECIAL
		pwd = generate_password(16, charset)
		
		# Calculate charset size
		charset_size = get_charset_size(charset)
		
		# Calculate entropy
		entropy = calculate_entropy(len(pwd), charset_size)
		
		# Get strength rating
		rating = get_strength_rating(entropy)
		
		# Verify all components work together
		assert len(pwd) == 16, "Password length incorrect"
		assert charset_size == 94, "Charset size incorrect"
		assert 104 < entropy < 105, "Entropy calculation incorrect"
		assert "Excellent" in rating, "Strength rating incorrect"
		
		print(f"{GREEN}✓{RESET} Test 50: Integration - Full workflow (16 char, 94 charset, ~105 bits, Excellent)")
		passed += 1
	except Exception as e:
		print(f"{RED}✗{RESET} Test 50 FAILED: {e}")
		failed += 1
	
	# ========================================================================
	# TEST SUMMARY
	# ========================================================================
	
	print(f"\n{BOLD}═══════════════════════════════════════════════════════════════")
	print(f"                         SUMMARY")
	print(f"═══════════════════════════════════════════════════════════════{RESET}")
	print(f"Tests Passed: {GREEN}{passed}/50{RESET}")
	print(f"Tests Failed: {RED}{failed}/50{RESET}")
	
	if passed == 50:
		print(f"\n{BOLD}{GREEN}╔══════════════════════════════════════════════════════════════╗")
		print(f"║        🎉 PERFECT! ALL 50 TESTS PASSED! 🎉                  ║")
		print(f"╚══════════════════════════════════════════════════════════════╝{RESET}\n")
	elif passed >= 40:
		print(f"\n{BOLD}{YELLOW}╔══════════════════════════════════════════════════════════════╗")
		print(f"║      Great work! Almost there - {50-passed} tests to fix            ║")
		print(f"╚══════════════════════════════════════════════════════════════╝{RESET}\n")
	else:
		print(f"\n{BOLD}{YELLOW}╔══════════════════════════════════════════════════════════════╗")
		print(f"║      Keep going! {50-passed} tests remaining                        ║")
		print(f"╚══════════════════════════════════════════════════════════════╝{RESET}\n")


if __name__ == "__main__":
	print(f"\n{BOLD}Starting comprehensive test suite...{RESET}")
	print("Implement the functions above to pass all 50 tests!\n")
	run_tests()
