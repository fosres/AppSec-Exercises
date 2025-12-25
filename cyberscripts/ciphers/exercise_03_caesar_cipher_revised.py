"""
Exercise 3: Caesar Cipher Encoder/Decoder
Week 2 - Python Strings Practice

Inspired by: Python Workout, Second Edition by Reuven M. Lerner
- Chapter 3 (Strings), pages 962-1200
- Exercise 5 (Pig Latin), demonstrating string transformation (pages 1048-1162)
- String iteration and character manipulation
- Building new strings through transformation

Security Context: Grace Nolan's Security Coding Challenges
Reference: Extended 48 Week Security Engineering Curriculum, Week 90, page 49
"Caesar cipher and basic crypto" - Common security engineering interview question

The Caesar cipher is one of the oldest encryption techniques, used by Julius Caesar
to protect military messages. While cryptographically broken today, it demonstrates
fundamental concepts in cryptography and appears in security engineering interviews.

Write two functions:
1. `caesar_encrypt(plaintext, shift)` - Encrypts text using Caesar cipher
2. `caesar_decrypt(ciphertext, shift)` - Decrypts Caesar cipher text

Rules:
1. Shift each alphabetic character by 'shift' positions in the alphabet
2. Preserve case (uppercase stays uppercase, lowercase stays lowercase)
3. Keep non-alphabetic characters (spaces, punctuation, numbers) unchanged
4. Handle wraparound: Z shifted by 1 becomes A
5. Shift can be positive (right shift) or negative (left shift)

Approach:
- For each character in input string:
  - If alphabetic: shift by 'shift' positions with wraparound
  - If not alphabetic: keep unchanged
- Hint: Think about how to convert letters to numbers (0-25), apply shift, then convert back

Examples:
>>> caesar_encrypt("HELLO", 3)
"KHOOR"

>>> caesar_encrypt("Hello, World!", 13)
"Uryyb, Jbeyq!"

>>> caesar_decrypt("KHOOR", 3)
"HELLO"

>>> caesar_encrypt("ATTACK AT DAWN", 5)
"FYYFHP FY IFBS"

>>> caesar_decrypt("FYYFHP FY IFBS", 5)
"ATTACK AT DAWN"
"""

def caesar_encrypt(plaintext, shift):
	"""
	Encrypt text using Caesar cipher.
	
	Args:
		plaintext (str): Text to encrypt
		shift (int): Number of positions to shift (positive or negative)
		
	Returns:
		str: Encrypted ciphertext
	"""
	# Your code here
	lowercase = []

	ch = 'a'

	while ch <= 'z':

		lowercase.append(ch)

		ch = chr( ord(ch) + 1)

	uppercase = []

	ch = 'A'

	while ch <= 'Z':

		uppercase.append(ch)

		ch = chr( ord(ch) + 1)

	ciphertext = ""

	for ch in plaintext:
		
		if ch.isalpha() and ch.isupper():	
			ciphertext += uppercase[(ord(ch) - ord('A') + shift) % 26]	
		
		elif ch.isalpha() and ch.islower():	
			ciphertext += lowercase[(ord(ch) - ord('a') + shift) % 26]	

		else:
			ciphertext += ch 
	
	return ciphertext	


def caesar_decrypt(ciphertext, shift):
	"""
	Decrypt Caesar cipher text.
	
	Args:
		ciphertext (str): Encrypted text
		shift (int): Number of positions used in encryption
		
	Returns:
		str: Decrypted plaintext
	"""
	# Your code here
	lowercase = []

	ch = 'a'

	while ch <= 'z':

		lowercase.append(ch)

		ch = chr( ord(ch) + 1)

	uppercase = []

	ch = 'A'

	while ch <= 'Z':

		uppercase.append(ch)

		ch = chr( ord(ch) + 1)

	plaintext = ""

	for ch in ciphertext:
		
		if ch.isalpha() and ch.isupper():	
			plaintext += uppercase[(ord(ch) - ord('A') - shift) % 26]	
		
		elif ch.isalpha() and ch.islower():	
			plaintext += lowercase[(ord(ch) - ord('a') - shift) % 26]	

		else:
			plaintext += ch
	
	return plaintext 


# DO NOT MODIFY BELOW THIS LINE - Test Cases
def test_caesar_cipher():
	"""Comprehensive test suite with 60+ test cases"""
	
	# Test 1-10: Basic encryption with positive shifts
	assert caesar_encrypt("A", 1) == "B"
	assert caesar_encrypt("Z", 1) == "A"  # Wraparound
	assert caesar_encrypt("ABC", 1) == "BCD"
	assert caesar_encrypt("XYZ", 3) == "ABC"  # Wraparound
	assert caesar_encrypt("HELLO", 3) == "KHOOR"
	assert caesar_encrypt("PYTHON", 5) == "UDYMTS"
	assert caesar_encrypt("SECURITY", 10) == "COMEBSDI"
	assert caesar_encrypt("TESTING", 7) == "ALZAPUN"
	assert caesar_encrypt("CRYPTO", 13) == "PELCGB"
	assert caesar_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1) == "BCDEFGHIJKLMNOPQRSTUVWXYZA"
	
	# Test 11-20: Lowercase encryption
	assert caesar_encrypt("a", 1) == "b"
	assert caesar_encrypt("z", 1) == "a"  # Wraparound
	assert caesar_encrypt("hello", 3) == "khoor"
	assert caesar_encrypt("python", 5) == "udymts"
	assert caesar_encrypt("security", 10) == "comebsdi"
	assert caesar_encrypt("xyz", 3) == "abc"
	assert caesar_encrypt("abcdefghijklmnopqrstuvwxyz", 13) == "nopqrstuvwxyzabcdefghijklm"
	assert caesar_encrypt("test", 1) == "uftu"
	assert caesar_encrypt("code", 2) == "eqfg"
	assert caesar_encrypt("hack", 4) == "lego"
	
	# Test 21-30: Mixed case encryption
	assert caesar_encrypt("Hello", 3) == "Khoor"
	assert caesar_encrypt("PyThOn", 5) == "UdYmTs"
	assert caesar_encrypt("SeCuRiTy", 10) == "CoMeBsDi"
	assert caesar_encrypt("HeLLo WoRLd", 13) == "UrYYb JbEYq"
	assert caesar_encrypt("ABC def GHI", 1) == "BCD efg HIJ"
	assert caesar_encrypt("The Quick Brown Fox", 7) == "Aol Xbpjr Iyvdu Mve"
	assert caesar_encrypt("Caesar Cipher", 3) == "Fdhvdu Flskhu"
	assert caesar_encrypt("Encryption Test", 5) == "Jshwduynts Yjxy"
	assert caesar_encrypt("MiXeD CaSe", 10) == "WsHoN MkCo"
	assert caesar_encrypt("AbC XyZ", 2) == "CdE ZaB"
	
	# Test 31-40: Non-alphabetic characters preserved
	assert caesar_encrypt("HELLO WORLD", 3) == "KHOOR ZRUOG"
	assert caesar_encrypt("HELLO, WORLD!", 3) == "KHOOR, ZRUOG!"
	assert caesar_encrypt("123 ABC 456", 1) == "123 BCD 456"
	assert caesar_encrypt("test@example.com", 5) == "yjxy@jcfruqj.htr"
	assert caesar_encrypt("foo-bar_baz", 3) == "irr-edu_edc"
	assert caesar_encrypt("user:password123", 7) == "bzly:whzzdvyk123"
	assert caesar_encrypt("10.0.0.1", 5) == "10.0.0.1"
	assert caesar_encrypt("Hello! How are you?", 13) == "Uryyb! Ubj ner lbh?"
	assert caesar_encrypt("a1b2c3", 1) == "b1c2d3"
	assert caesar_encrypt("test (with) [brackets]", 4) == "xiwx (amxl) [fvegoixw]"
	
	# Test 41-50: Negative shifts (left shift)
	assert caesar_encrypt("B", -1) == "A"
	assert caesar_encrypt("A", -1) == "Z"  # Wraparound backwards
	assert caesar_encrypt("KHOOR", -3) == "HELLO"
	assert caesar_encrypt("XYZ", -3) == "UVW"
	assert caesar_encrypt("ABC", -1) == "ZAB"
	assert caesar_encrypt("hello", -5) == "czggj"
	assert caesar_encrypt("PYTHON", -10) == "FOJXED"
	assert caesar_encrypt("test", -7) == "mxlm"
	assert caesar_encrypt("CAESAR", -13) == "PNRFNE"
	assert caesar_encrypt("SECURITY", -20) == "YKIAXOZE"
	
	# Test 51-60: Basic decryption
	assert caesar_decrypt("KHOOR", 3) == "HELLO"
	assert caesar_decrypt("URYYB", 13) == "HELLO"
	assert caesar_decrypt("BCD", 1) == "ABC"
	assert caesar_decrypt("ABC", 3) == "XYZ"
	assert caesar_decrypt("khoor", 3) == "hello"
	assert caesar_decrypt("Khoor", 3) == "Hello"
	assert caesar_decrypt("KHOOR ZRUOG", 3) == "HELLO WORLD"
	assert caesar_decrypt("Uryyb, Jbeyq!", 13) == "Hello, World!"
	assert caesar_decrypt("UDYMTS", 5) == "PYTHON"
	assert caesar_decrypt("COMBKDSDI", 10) == "SECRATITY"
	
	# Test 61-70: Encryption/Decryption round-trip
	assert caesar_decrypt(caesar_encrypt("HELLO", 3), 3) == "HELLO"
	assert caesar_decrypt(caesar_encrypt("Python", 7), 7) == "Python"
	assert caesar_decrypt(caesar_encrypt("SECURITY", 13), 13) == "SECURITY"
	assert caesar_decrypt(caesar_encrypt("Test123", 5), 5) == "Test123"
	assert caesar_decrypt(caesar_encrypt("Hello, World!", 10), 10) == "Hello, World!"
	assert caesar_decrypt(caesar_encrypt("abc xyz", 1), 1) == "abc xyz"
	assert caesar_decrypt(caesar_encrypt("CAESAR CIPHER", 25), 25) == "CAESAR CIPHER"
	assert caesar_decrypt(caesar_encrypt("attack at dawn", 17), 17) == "attack at dawn"
	assert caesar_decrypt(caesar_encrypt("The Quick Brown Fox", 9), 9) == "The Quick Brown Fox"
	assert caesar_decrypt(caesar_encrypt("ROT13 is shift 13", 13), 13) == "ROT13 is shift 13"
	
	# Test 71-80: Edge cases
	assert caesar_encrypt("", 5) == ""  # Empty string
	assert caesar_encrypt("   ", 3) == "   "  # Only spaces
	assert caesar_encrypt("123", 10) == "123"  # Only numbers
	assert caesar_encrypt("!@#$%", 7) == "!@#$%"  # Only punctuation
	assert caesar_encrypt("ZZZZZ", 1) == "AAAAA"  # All wraparound
	assert caesar_encrypt("aaaaa", 26) == "aaaaa"  # Full rotation (no change)
	assert caesar_encrypt("HELLO", 0) == "HELLO"  # No shift
	assert caesar_encrypt("test", 52) == "test"  # Shift > 26 (52 % 26 = 0)
	assert caesar_encrypt("ABC", -26) == "ABC"  # Negative full rotation
	assert caesar_encrypt("xyz", 27) == "yza"  # 27 % 26 = 1
	
	# Test 81-90: ROT13 (special case, shift=13)
	assert caesar_encrypt("HELLO", 13) == "URYYB"
	assert caesar_decrypt("URYYB", 13) == "HELLO"
	assert caesar_encrypt("ROT13", 13) == "EBG13"
	assert caesar_encrypt("The quick brown fox jumps over the lazy dog", 13) == "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"
	assert caesar_decrypt("Gur dhvpx oebja sbk whzcf bire gur ynml qbt", 13) == "The quick brown fox jumps over the lazy dog"
	# ROT13 property: applying twice returns original
	assert caesar_encrypt(caesar_encrypt("HELLO", 13), 13) == "HELLO"
	assert caesar_encrypt(caesar_encrypt("Python", 13), 13) == "Python"
	assert caesar_encrypt(caesar_encrypt("test123", 13), 13) == "test123"
	assert caesar_encrypt(caesar_encrypt("Hello, World!", 13), 13) == "Hello, World!"
	assert caesar_encrypt(caesar_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 13), 13) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	
	# Test 91-95: Large shifts
	assert caesar_encrypt("HELLO", 26) == "HELLO"  # Full alphabet rotation
	assert caesar_encrypt("HELLO", 29) == "KHOOR"  # 29 % 26 = 3
	assert caesar_encrypt("test", 100) == "paop"  # 100 % 26 = 22
	assert caesar_encrypt("ABC", -27) == "ZAB"  # -27 % 26 = -1
	assert caesar_encrypt("PYTHON", 1000) == "BKFTAZ"  # 1000 % 26 = 12
	
	print("✓ All 95 tests passed!")

if __name__ == "__main__":
	test_caesar_cipher()
