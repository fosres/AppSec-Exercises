"""
Cryptographic Password Generator Challenge
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
- 65-80 bits: "Strong - Recommended for most applications"
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
SPECIAL = '!@#$%^&*()-_+=[]{}|;:,.<>?'


def password_generator():
	"""
	Main function that generates a cryptographically secure password and
	validates its strength.
	
	TODO: Implement the following:
	1. Prompt user to select character set (all, alphanumeric, alpha, passphrase)
	2. Prompt user for password length (12-64 chars) with validation
	3. Generate password using CRYPTOGRAPHICALLY SECURE randomness
	4. Calculate password entropy
	5. Determine strength rating
	6. Display results in formatted output
	7. Ask if user wants to generate another password (loop)
	
	Returns:
		None (interactive function)
	"""
	# TODO: Implement your solution here
	pass


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
		65-80: Strong
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


# Test cases (uncomment to test your implementation)
if __name__ == "__main__":
	# Run the interactive password generator
	password_generator()
	
	# Unit tests (optional - implement after completing main function)
	"""
	print("\n=== Running Unit Tests ===")
	
	# Test 1: Entropy calculation
	entropy_12_char_62_set = calculate_entropy(12, 62)
	assert 71 < entropy_12_char_62_set < 72, "12-char alphanumeric should be ~71 bits"
	print("✓ Test 1 passed: Entropy calculation")
	
	# Test 2: Strength rating
	assert "Strong" in get_strength_rating(71.5), "71 bits should be 'Strong'"
	assert "Excellent" in get_strength_rating(105), "105 bits should be 'Excellent'"
	assert "Weak" in get_strength_rating(45), "45 bits should be 'Weak'"
	print("✓ Test 2 passed: Strength ratings")
	
	# Test 3: Charset size
	test_charset = LOWERCASE + UPPERCASE + DIGITS
	assert get_charset_size(test_charset) == 62, "Alphanumeric should be 62 chars"
	print("✓ Test 3 passed: Charset size calculation")
	
	# Test 4: Password generation (check it's the right length)
	test_pwd = generate_password(16, LOWERCASE + UPPERCASE + DIGITS + SPECIAL)
	assert len(test_pwd) == 16, "Password should be 16 characters"
	print("✓ Test 4 passed: Password generation length")
	
	print("\nAll tests passed! ✓")
	"""
