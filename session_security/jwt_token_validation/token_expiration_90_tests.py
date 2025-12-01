"""
Token Expiration Validator - AppSec Exercise

Security Context:
Every authentication system must validate token expiration to prevent 
unauthorized access with stale tokens. API Security in Action (p. 123-124) 
shows production code checking if tokens are expired. Session fixation 
attacks exploited systems that didn't properly invalidate old sessions.

Real-World Examples:
- Django Session Fixation (CVE-2019-11358): Old tokens reused
- JWT "none" Algorithm Attack: Expired tokens accepted indefinitely
- Password Reset Tokens: Django defaults to 3-day expiry (259,200 seconds)

Your Task:
Implement is_token_valid() that checks if a session token is still valid.

Rules:
1. Token is INVALID at exact expiry time (use >= not >)
2. Time travel (current_time < issued_at) returns False
3. Negative or zero expiry_seconds returns False
4. All parameters are floats/ints representing Unix timestamps

References:
- Python Workout Ch 2 (pp. 7-9): Numeric comparisons, subtraction
- API Security in Action Ch 4 (pp. 123-124): Token validation
- Full Stack Python Security Ch 9 (p. 138): Token expiry policies
"""


def is_token_valid(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	Validates whether an authentication token is still valid.
	
	Args:
		issued_at: Unix timestamp when token was created
		expiry_seconds: How long token remains valid (e.g., 600 = 10 minutes)
		current_time: Current Unix timestamp
	
	Returns:
		True if token is valid, False if expired or invalid
	
	Examples:
		>>> is_token_valid(1000.0, 600, 1500.0)  # 500 sec elapsed < 600 expiry
		True
		>>> is_token_valid(1000.0, 600, 1700.0)  # 700 sec elapsed > 600 expiry
		False
		>>> is_token_valid(1000.0, 600, 1600.0)  # Exactly at expiry
		False
	"""
	# TODO: Implement your solution here
	expiration_time = issued_at + expiry_seconds

	if expiry_seconds <= 0:

		return False

	elif current_time < issued_at:

		return False

	if current_time >= expiration_time:

		return False
	else:
		return True

# ============================================================================
# TEST SUITE - 30 COMPREHENSIVE TESTS
# ============================================================================

def run_all_tests():
	"""Run all 30 test cases with colored output and scoring."""
	tests_passed = 0
	total_tests = 30
	
	print("=" * 70)
	print("TOKEN EXPIRATION VALIDATOR - TEST SUITE")
	print("=" * 70)
	print()
	
	# Category 1: Basic Valid Tokens (5 tests)
	print("📋 Category 1: Basic Valid Tokens")
	print("-" * 70)
	
	# Test 1
	try:
		result = is_token_valid(1000.0, 600, 1500.0)
		assert result == True, f"Expected True, got {result}"
		print("✅ Test 1: Token with 500 seconds elapsed (< 600 expiry)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 1 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 1 ERROR: {e}")
	
	# Test 2
	try:
		result = is_token_valid(1000.0, 600, 1100.0)
		assert result == True, f"Expected True, got {result}"
		print("✅ Test 2: Token with 100 seconds elapsed")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 2 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 2 ERROR: {e}")
	
	# Test 3
	try:
		result = is_token_valid(1609459200.0, 600, 1609459500.0)
		assert result == True, f"Expected True, got {result}"
		print("✅ Test 3: Standard API session (10 min expiry, 5 min elapsed)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 3 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 3 ERROR: {e}")
	
	# Test 4
	try:
		result = is_token_valid(1000.0, 3600, 2000.0)
		assert result == True, f"Expected True, got {result}"
		print("✅ Test 4: Long-lived token (1 hour expiry, 16 min elapsed)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 4 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 4 ERROR: {e}")
	
	# Test 5
	try:
		result = is_token_valid(1000.0, 60, 1030.0)
		assert result == True, f"Expected True, got {result}"
		print("✅ Test 5: Short-lived token (1 min expiry, 30 sec elapsed)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 5 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 5 ERROR: {e}")
	
	print()
	
	# Category 2: Expired Tokens (5 tests)
	print("📋 Category 2: Expired Tokens")
	print("-" * 70)
	
	# Test 6
	try:
		result = is_token_valid(1000.0, 600, 1700.0)
		assert result == False, f"Expected False, got {result}"
		print("✅ Test 6: Token expired by 100 seconds")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 6 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 6 ERROR: {e}")
	
	# Test 7
	try:
		result = is_token_valid(1000.0, 600, 2000.0)
		assert result == False, f"Expected False, got {result}"
		print("✅ Test 7: Token expired by 400 seconds")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 7 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 7 ERROR: {e}")
	
	# Test 8
	try:
		result = is_token_valid(1609459200.0, 259200, 1609718401.0)
		assert result == False, f"Expected False, got {result}"
		print("✅ Test 8: Password reset token (3 days) expired by 1 sec")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 8 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 8 ERROR: {e}")
	
	# Test 9
	try:
		result = is_token_valid(1000.0, 60, 5000.0)
		assert result == False, f"Expected False, got {result}"
		print("✅ Test 9: Token expired long ago (4000 seconds over)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 9 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 9 ERROR: {e}")
	
	# Test 10
	try:
		result = is_token_valid(1000.0, 1, 1002.0)
		assert result == False, f"Expected False, got {result}"
		print("✅ Test 10: Very short expiry (1 sec) expired by 1 sec")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 10 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 10 ERROR: {e}")
	
	print()
	
	# Category 3: Exact Expiry Boundary (5 tests)
	print("📋 Category 3: Exact Expiry Boundary")
	print("-" * 70)
	
	# Test 11
	try:
		result = is_token_valid(1000.0, 600, 1600.0)
		assert result == False, f"Expected False (expired AT boundary), got {result}"
		print("✅ Test 11: Token exactly at expiry time (must return False)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 11 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 11 ERROR: {e}")
	
	# Test 12
	try:
		result = is_token_valid(1000.0, 600, 1599.9)
		assert result == True, f"Expected True (0.1 sec before expiry), got {result}"
		print("✅ Test 12: Token 0.1 seconds before expiry")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 12 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 12 ERROR: {e}")
	
	# Test 13
	try:
		result = is_token_valid(1000.0, 600, 1600.1)
		assert result == False, f"Expected False (0.1 sec after expiry), got {result}"
		print("✅ Test 13: Token 0.1 seconds after expiry")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 13 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 13 ERROR: {e}")
	
	# Test 14
	try:
		result = is_token_valid(1609459200.0, 259200, 1609718400.0)
		assert result == False, f"Expected False (exactly 3 days), got {result}"
		print("✅ Test 14: Password reset token exactly at 3-day boundary")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 14 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 14 ERROR: {e}")
	
	# Test 15
	try:
		result = is_token_valid(1000.0, 1, 1001.0)
		assert result == False, f"Expected False (1 sec expiry exactly), got {result}"
		print("✅ Test 15: 1-second token at exact boundary")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 15 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 15 ERROR: {e}")
	
	print()
	
	# Category 4: Time Travel / Invalid Timestamps (5 tests)
	print("📋 Category 4: Time Travel / Invalid Timestamps")
	print("-" * 70)
	
	# Test 16
	try:
		result = is_token_valid(2000.0, 600, 1500.0)
		assert result == False, f"Expected False (time travel), got {result}"
		print("✅ Test 16: Current time BEFORE issued time (time travel)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 16 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 16 ERROR: {e}")
	
	# Test 17
	try:
		result = is_token_valid(5000.0, 600, 4999.0)
		assert result == False, f"Expected False (current < issued), got {result}"
		print("✅ Test 17: Current time 1 second before issue time")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 17 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 17 ERROR: {e}")
	
	# Test 18
	try:
		result = is_token_valid(1000.0, 600, 1000.0)
		assert result == True, f"Expected True (issued NOW), got {result}"
		print("✅ Test 18: Token issued exactly NOW (0 seconds elapsed)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 18 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 18 ERROR: {e}")
	
	# Test 19
	try:
		result = is_token_valid(10000000.0, 600, 5000000.0)
		assert result == False, f"Expected False (large time difference), got {result}"
		print("✅ Test 19: Large timestamp difference (time travel)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 19 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 19 ERROR: {e}")
	
	# Test 20
	try:
		result = is_token_valid(0.0, 600, -1.0)
		assert result == False, f"Expected False (negative current time), got {result}"
		print("✅ Test 20: Negative current_time")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 20 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 20 ERROR: {e}")
	
	print()
	
	# Category 5: Invalid Expiry Policies (5 tests)
	print("📋 Category 5: Invalid Expiry Policies")
	print("-" * 70)
	
	# Test 21
	try:
		result = is_token_valid(1000.0, 0, 1500.0)
		assert result == False, f"Expected False (zero expiry), got {result}"
		print("✅ Test 21: Zero expiry_seconds (misconfigured)")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 21 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 21 ERROR: {e}")
	
	# Test 22
	try:
		result = is_token_valid(1000.0, -600, 1500.0)
		assert result == False, f"Expected False (negative expiry), got {result}"
		print("✅ Test 22: Negative expiry_seconds")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 22 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 22 ERROR: {e}")
	
	# Test 23
	try:
		result = is_token_valid(1000.0, -1, 1000.0)
		assert result == False, f"Expected False (expiry = -1), got {result}"
		print("✅ Test 23: expiry_seconds = -1")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 23 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 23 ERROR: {e}")
	
	# Test 24
	try:
		result = is_token_valid(1000.0, -999999, 1500.0)
		assert result == False, f"Expected False (large negative), got {result}"
		print("✅ Test 24: Large negative expiry_seconds")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 24 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 24 ERROR: {e}")
	
	# Test 25
	try:
		result = is_token_valid(1000.0, 0, 1000.0)
		assert result == False, f"Expected False (zero expiry at issue), got {result}"
		print("✅ Test 25: Zero expiry at exact issue time")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 25 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 25 ERROR: {e}")
	
	print()
	
	# Category 6: Real-World Scenarios (5 tests)
	print("📋 Category 6: Real-World Scenarios")
	print("-" * 70)
	
	# Test 26
	try:
		# OAuth 2.0 access token: 10 minutes
		result = is_token_valid(1609459200.0, 600, 1609459800.0)
		assert result == False, f"Expected False (OAuth access token expired), got {result}"
		print("✅ Test 26: OAuth 2.0 access token (10 min) exactly expired")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 26 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 26 ERROR: {e}")
	
	# Test 27
	try:
		# JWT session: 30 minutes, checked at 29 min 59 sec
		result = is_token_valid(1000.0, 1800, 2799.0)
		assert result == True, f"Expected True (JWT valid), got {result}"
		print("✅ Test 27: JWT session (30 min) checked 1 sec before expiry")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 27 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 27 ERROR: {e}")
	
	# Test 28
	try:
		# Remember-me cookie: 30 days (2592000 seconds)
		result = is_token_valid(1609459200.0, 2592000, 1612051199.0)
		assert result == True, f"Expected True (remember-me valid), got {result}"
		print("✅ Test 28: Remember-me cookie (30 days) 1 sec before expiry")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 28 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 28 ERROR: {e}")
	
	# Test 29
	try:
		# API key rotation: 90 days, checked at 91 days
		result = is_token_valid(1609459200.0, 7776000, 1617235201.0)
		assert result == False, f"Expected False (API key expired), got {result}"
		print("✅ Test 29: API key (90 days) expired by 1 day")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 29 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 29 ERROR: {e}")
	
	# Test 30
	try:
		# MFA code: 30 seconds, checked at 15 seconds
		result = is_token_valid(1000.0, 30, 1015.0)
		assert result == True, f"Expected True (MFA code valid), got {result}"
		print("✅ Test 30: MFA code (30 sec) checked at 15 seconds")
		tests_passed += 1
	except AssertionError as e:
		print(f"❌ Test 30 FAILED: {e}")
	except Exception as e:
		print(f"❌ Test 30 ERROR: {e}")
	
	print()
	print("=" * 70)
	print(f"RESULTS: {tests_passed}/{total_tests} tests passed")
	print("=" * 70)
	print()
	
	# Provide feedback based on score
	percentage = (tests_passed / total_tests) * 100
	
	if percentage == 100:
		print("🎉 PERFECT SCORE! You've mastered token expiration validation!")
		print()
		print("Key concepts you've demonstrated:")
		print("  ✓ Basic expiration logic (elapsed < expiry)")
		print("  ✓ Exact boundary handling (>= not >)")
		print("  ✓ Time travel detection")
		print("  ✓ Invalid expiry handling")
		print("  ✓ Real-world security scenarios")
		print()
		print("Next steps:")
		print("  → Implement token refresh logic")
		print("  → Build JWT signature validation")
		print("  → Add rate limiting to token endpoints")
	elif percentage >= 80:
		print("✨ Great job! You're almost there!")
		print()
		print("Common issues to check:")
		print("  • Exact boundary: Token invalid AT expiry (use >=)")
		print("  • Time travel: Check current_time < issued_at")
		print("  • Invalid config: expiry_seconds <= 0 returns False")
	elif percentage >= 60:
		print("📚 Good progress! Review these concepts:")
		print()
		print("Key formulas:")
		print("  elapsed_time = current_time - issued_at")
		print("  is_expired = elapsed_time >= expiry_seconds")
		print()
		print("Edge cases to handle:")
		print("  1. current_time < issued_at → False (time travel)")
		print("  2. expiry_seconds <= 0 → False (invalid config)")
		print("  3. elapsed == expiry → False (expired AT boundary)")
	else:
		print("💡 Keep practicing! Here's the approach:")
		print()
		print("Step 1: Check for invalid configs")
		print("  if expiry_seconds <= 0:")
		print("      return False")
		print()
		print("Step 2: Check for time travel")
		print("  if current_time < issued_at:")
		print("      return False")
		print()
		print("Step 3: Calculate elapsed time")
		print("  elapsed = current_time - issued_at")
		print()
		print("Step 4: Check if expired")
		print("  return elapsed < expiry_seconds")
		print()
		print("Security insight:")
		print("  API Security in Action (p. 124): 'Check if a token is")
		print("  present and not expired' - this is foundational to all")
		print("  authentication systems!")


# ============================================================================
# RANDOMIZED TEST SUITE - 60 ADDITIONAL TESTS
# ============================================================================

def run_randomized_tests():
	"""
	Run 60 randomized but deterministic test cases.
	
	These tests use seeded random number generation to ensure reproducibility
	while testing a wide variety of scenarios that wouldn't be covered by
	hand-crafted test cases.
	"""
	import random
	
	# Seed for reproducibility - same tests every run
	random.seed(42)
	
	tests_passed = 0
	total_tests = 60
	
	print()
	print("=" * 70)
	print("RANDOMIZED TEST SUITE - 60 ADDITIONAL TESTS")
	print("=" * 70)
	print()
	
	# Category 7: Random Valid Tokens (20 tests)
	print("📋 Category 7: Random Valid Tokens (20 tests)")
	print("-" * 70)
	
	for i in range(1, 21):
		try:
			# Generate random valid token scenario
			issued_at = random.uniform(1000000.0, 1700000000.0)
			expiry_seconds = random.randint(60, 7776000)  # 1 min to 90 days
			elapsed = random.uniform(1.0, expiry_seconds * 0.99)  # Valid: 1% to 99% of expiry
			current_time = issued_at + elapsed
			
			result = is_token_valid(issued_at, expiry_seconds, current_time)
			assert result == True, f"Expected True, got {result}"
			
			percentage = (elapsed / expiry_seconds) * 100
			print(f"✅ Test {30 + i}: Random valid token ({percentage:.1f}% of lifetime elapsed)")
			tests_passed += 1
		except AssertionError as e:
			print(f"❌ Test {30 + i} FAILED: {e}")
			print(f"   Details: issued={issued_at:.2f}, expiry={expiry_seconds}, current={current_time:.2f}")
		except Exception as e:
			print(f"❌ Test {30 + i} ERROR: {e}")
	
	print()
	
	# Category 8: Random Expired Tokens (15 tests)
	print("📋 Category 8: Random Expired Tokens (15 tests)")
	print("-" * 70)
	
	for i in range(21, 36):
		try:
			# Generate random expired token scenario
			issued_at = random.uniform(1000000.0, 1700000000.0)
			expiry_seconds = random.randint(60, 7776000)
			# Expired: 101% to 500% of expiry time
			elapsed = expiry_seconds + random.uniform(expiry_seconds * 0.01, expiry_seconds * 4.0)
			current_time = issued_at + elapsed
			
			result = is_token_valid(issued_at, expiry_seconds, current_time)
			assert result == False, f"Expected False, got {result}"
			
			overdue_seconds = elapsed - expiry_seconds
			print(f"✅ Test {30 + i}: Random expired token (expired by {overdue_seconds:.1f} sec)")
			tests_passed += 1
		except AssertionError as e:
			print(f"❌ Test {30 + i} FAILED: {e}")
			print(f"   Details: issued={issued_at:.2f}, expiry={expiry_seconds}, current={current_time:.2f}")
		except Exception as e:
			print(f"❌ Test {30 + i} ERROR: {e}")
	
	print()
	
	# Category 9: Random Boundary Cases (10 tests)
	print("📋 Category 9: Random Boundary Cases (10 tests)")
	print("-" * 70)
	
	for i in range(36, 46):
		try:
			# Generate random boundary scenarios
			issued_at = random.uniform(1000000.0, 1700000000.0)
			expiry_seconds = random.randint(60, 86400)  # 1 min to 1 day
			
			# Alternate between just-before and just-at/after expiry
			if i % 2 == 0:
				# Just before expiry (valid)
				delta = random.uniform(0.001, 0.999)  # 0.001 to 0.999 seconds before
				current_time = issued_at + expiry_seconds - delta
				expected = True
				status = f"valid ({delta:.3f}s before expiry)"
			else:
				# At or just after expiry (invalid)
				delta = random.uniform(0.0, 0.999)  # 0 to 0.999 seconds after
				current_time = issued_at + expiry_seconds + delta
				expected = False
				status = f"expired ({delta:.3f}s past expiry)"
			
			result = is_token_valid(issued_at, expiry_seconds, current_time)
			assert result == expected, f"Expected {expected}, got {result}"
			
			print(f"✅ Test {30 + i}: Random boundary case - {status}")
			tests_passed += 1
		except AssertionError as e:
			print(f"❌ Test {30 + i} FAILED: {e}")
			print(f"   Details: issued={issued_at:.2f}, expiry={expiry_seconds}, current={current_time:.2f}")
		except Exception as e:
			print(f"❌ Test {30 + i} ERROR: {e}")
	
	print()
	
	# Category 10: Random Time Travel Scenarios (10 tests)
	print("📋 Category 10: Random Time Travel Scenarios (10 tests)")
	print("-" * 70)
	
	for i in range(46, 56):
		try:
			# Generate random time travel scenarios
			issued_at = random.uniform(1000000.0, 1700000000.0)
			expiry_seconds = random.randint(60, 86400)
			
			# Current time is before issued time
			time_travel_delta = random.uniform(1.0, 10000.0)
			current_time = issued_at - time_travel_delta
			
			result = is_token_valid(issued_at, expiry_seconds, current_time)
			assert result == False, f"Expected False (time travel), got {result}"
			
			print(f"✅ Test {30 + i}: Random time travel ({time_travel_delta:.1f}s before issue)")
			tests_passed += 1
		except AssertionError as e:
			print(f"❌ Test {30 + i} FAILED: {e}")
			print(f"   Details: issued={issued_at:.2f}, expiry={expiry_seconds}, current={current_time:.2f}")
		except Exception as e:
			print(f"❌ Test {30 + i} ERROR: {e}")
	
	print()
	
	# Category 11: Random Invalid Configurations (5 tests)
	print("📋 Category 11: Random Invalid Configurations (5 tests)")
	print("-" * 70)
	
	for i in range(56, 61):
		try:
			# Generate random invalid config scenarios
			issued_at = random.uniform(1000000.0, 1700000000.0)
			current_time = issued_at + random.uniform(100.0, 10000.0)
			
			# Random invalid expiry (zero or negative)
			if random.random() < 0.5:
				expiry_seconds = 0
				config_type = "zero"
			else:
				expiry_seconds = random.randint(-10000, -1)
				config_type = f"negative ({expiry_seconds})"
			
			result = is_token_valid(issued_at, expiry_seconds, current_time)
			assert result == False, f"Expected False (invalid config), got {result}"
			
			print(f"✅ Test {30 + i}: Random invalid config - {config_type} expiry")
			tests_passed += 1
		except AssertionError as e:
			print(f"❌ Test {30 + i} FAILED: {e}")
			print(f"   Details: issued={issued_at:.2f}, expiry={expiry_seconds}, current={current_time:.2f}")
		except Exception as e:
			print(f"❌ Test {30 + i} ERROR: {e}")
	
	print()
	print("=" * 70)
	print(f"RANDOMIZED RESULTS: {tests_passed}/{total_tests} tests passed")
	print("=" * 70)
	
	return tests_passed, total_tests


def run_all_tests_comprehensive():
	"""
	Run both standard and randomized test suites (90 total tests).
	"""
	print("╔" + "═" * 68 + "╗")
	print("║" + " " * 10 + "TOKEN EXPIRATION VALIDATOR - COMPREHENSIVE SUITE" + " " * 10 + "║")
	print("║" + " " * 20 + "90 Total Tests (30 Standard + 60 Random)" + " " * 8 + "║")
	print("╚" + "═" * 68 + "╝")
	
	# Run standard tests
	print()
	print("PART 1: STANDARD TEST SUITE")
	standard_passed = run_standard_tests_only()
	
	# Run randomized tests
	random_passed, random_total = run_randomized_tests()
	
	# Overall results
	total_passed = standard_passed + random_passed
	total_tests = 90
	percentage = (total_passed / total_tests) * 100
	
	print()
	print("╔" + "═" * 68 + "╗")
	print("║" + " " * 22 + "COMPREHENSIVE RESULTS" + " " * 25 + "║")
	print("╠" + "═" * 68 + "╣")
	print(f"║  Standard Tests:    {standard_passed:2d}/30 passed" + " " * 36 + "║")
	print(f"║  Randomized Tests:  {random_passed:2d}/60 passed" + " " * 36 + "║")
	print("╠" + "═" * 68 + "╣")
	print(f"║  TOTAL:             {total_passed:2d}/90 passed ({percentage:.1f}%)" + " " * 28 + "║")
	print("╚" + "═" * 68 + "╝")
	print()
	
	# Final assessment
	if percentage == 100:
		print("🏆 PERFECT SCORE! You've MASTERED token expiration validation!")
		print()
		print("Your implementation correctly handles:")
		print("  ✓ All 30 standard edge cases")
		print("  ✓ All 60 randomized scenarios")
		print("  ✓ Boundary conditions at microsecond precision")
		print("  ✓ Time travel detection across all ranges")
		print("  ✓ Invalid configuration rejection")
		print()
		print("Your code is production-ready for:")
		print("  → OAuth 2.0 access token validation")
		print("  → JWT session management")
		print("  → Password reset token expiry")
		print("  → MFA code validation")
		print("  → API key rotation policies")
		print()
		print("Next challenge: Implement JWT signature verification!")
	elif percentage >= 90:
		print("🌟 EXCELLENT! Your implementation is nearly perfect!")
		print(f"   Only {total_tests - total_passed} test(s) failed - review edge cases")
	elif percentage >= 80:
		print("✨ VERY GOOD! You understand the core concepts!")
		print("   Review failed tests to catch remaining edge cases")
	elif percentage >= 70:
		print("👍 GOOD PROGRESS! Keep refining your logic")
		print("   Focus on boundary conditions and error handling")
	else:
		print("💡 KEEP PRACTICING! Review the security requirements:")
		print("   1. Token invalid AT expiry (use >= not >)")
		print("   2. Reject time travel (current_time < issued_at)")
		print("   3. Validate configuration (expiry_seconds > 0)")


def run_standard_tests_only():
	"""
	Run only the 30 standard tests (extracted for comprehensive suite).
	Returns number of tests passed.
	"""
	tests_passed = 0
	
	print("=" * 70)
	print("TOKEN EXPIRATION VALIDATOR - STANDARD TEST SUITE")
	print("=" * 70)
	print()
	
	# [Keeping all the original 30 tests exactly as they were]
	# Category 1-6 tests remain unchanged...
	
	# Category 1: Basic Valid Tokens (5 tests)
	print("📋 Category 1: Basic Valid Tokens")
	print("-" * 70)
	
	# Tests 1-5
	try:
		result = is_token_valid(1000.0, 600, 1500.0)
		assert result == True
		print("✅ Test 1: Token with 500 seconds elapsed (< 600 expiry)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 600, 1100.0)
		assert result == True
		print("✅ Test 2: Token with 100 seconds elapsed")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1609459200.0, 600, 1609459500.0)
		assert result == True
		print("✅ Test 3: Standard API session (10 min expiry, 5 min elapsed)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 3600, 2000.0)
		assert result == True
		print("✅ Test 4: Long-lived token (1 hour expiry, 16 min elapsed)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 60, 1030.0)
		assert result == True
		print("✅ Test 5: Short-lived token (1 min expiry, 30 sec elapsed)")
		tests_passed += 1
	except: pass
	
	print()
	
	# Category 2: Expired Tokens (5 tests)
	print("📋 Category 2: Expired Tokens")
	print("-" * 70)
	
	# Tests 6-10
	try:
		result = is_token_valid(1000.0, 600, 1700.0)
		assert result == False
		print("✅ Test 6: Token expired by 100 seconds")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 600, 2000.0)
		assert result == False
		print("✅ Test 7: Token expired by 400 seconds")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1609459200.0, 259200, 1609718401.0)
		assert result == False
		print("✅ Test 8: Password reset token (3 days) expired by 1 sec")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 60, 5000.0)
		assert result == False
		print("✅ Test 9: Token expired long ago (4000 seconds over)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 1, 1002.0)
		assert result == False
		print("✅ Test 10: Very short expiry (1 sec) expired by 1 sec")
		tests_passed += 1
	except: pass
	
	print()
	
	# Category 3: Exact Expiry Boundary (5 tests)
	print("📋 Category 3: Exact Expiry Boundary")
	print("-" * 70)
	
	# Tests 11-15
	try:
		result = is_token_valid(1000.0, 600, 1600.0)
		assert result == False
		print("✅ Test 11: Token exactly at expiry time (must return False)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 600, 1599.9)
		assert result == True
		print("✅ Test 12: Token 0.1 seconds before expiry")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 600, 1600.1)
		assert result == False
		print("✅ Test 13: Token 0.1 seconds after expiry")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1609459200.0, 259200, 1609718400.0)
		assert result == False
		print("✅ Test 14: Password reset token exactly at 3-day boundary")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 1, 1001.0)
		assert result == False
		print("✅ Test 15: 1-second token at exact boundary")
		tests_passed += 1
	except: pass
	
	print()
	
	# Category 4: Time Travel / Invalid Timestamps (5 tests)
	print("📋 Category 4: Time Travel / Invalid Timestamps")
	print("-" * 70)
	
	# Tests 16-20
	try:
		result = is_token_valid(2000.0, 600, 1500.0)
		assert result == False
		print("✅ Test 16: Current time BEFORE issued time (time travel)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(5000.0, 600, 4999.0)
		assert result == False
		print("✅ Test 17: Current time 1 second before issue time")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 600, 1000.0)
		assert result == True
		print("✅ Test 18: Token issued exactly NOW (0 seconds elapsed)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(10000000.0, 600, 5000000.0)
		assert result == False
		print("✅ Test 19: Large timestamp difference (time travel)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(0.0, 600, -1.0)
		assert result == False
		print("✅ Test 20: Negative current_time")
		tests_passed += 1
	except: pass
	
	print()
	
	# Category 5: Invalid Expiry Policies (5 tests)
	print("📋 Category 5: Invalid Expiry Policies")
	print("-" * 70)
	
	# Tests 21-25
	try:
		result = is_token_valid(1000.0, 0, 1500.0)
		assert result == False
		print("✅ Test 21: Zero expiry_seconds (misconfigured)")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, -600, 1500.0)
		assert result == False
		print("✅ Test 22: Negative expiry_seconds")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, -1, 1000.0)
		assert result == False
		print("✅ Test 23: expiry_seconds = -1")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, -999999, 1500.0)
		assert result == False
		print("✅ Test 24: Large negative expiry_seconds")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 0, 1000.0)
		assert result == False
		print("✅ Test 25: Zero expiry at exact issue time")
		tests_passed += 1
	except: pass
	
	print()
	
	# Category 6: Real-World Scenarios (5 tests)
	print("📋 Category 6: Real-World Scenarios")
	print("-" * 70)
	
	# Tests 26-30
	try:
		result = is_token_valid(1609459200.0, 600, 1609459800.0)
		assert result == False
		print("✅ Test 26: OAuth 2.0 access token (10 min) exactly expired")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 1800, 2799.0)
		assert result == True
		print("✅ Test 27: JWT session (30 min) checked 1 sec before expiry")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1609459200.0, 2592000, 1612051199.0)
		assert result == True
		print("✅ Test 28: Remember-me cookie (30 days) 1 sec before expiry")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1609459200.0, 7776000, 1617235201.0)
		assert result == False
		print("✅ Test 29: API key (90 days) expired by 1 day")
		tests_passed += 1
	except: pass
	
	try:
		result = is_token_valid(1000.0, 30, 1015.0)
		assert result == True
		print("✅ Test 30: MFA code (30 sec) checked at 15 seconds")
		tests_passed += 1
	except: pass
	
	print()
	print("=" * 70)
	print(f"STANDARD RESULTS: {tests_passed}/30 tests passed")
	print("=" * 70)
	
	return tests_passed


# Keep backward compatibility - redirect to comprehensive suite
def run_all_tests():
	"""Run comprehensive test suite (90 tests total)."""
	run_all_tests_comprehensive()


if __name__ == "__main__":
	# Run comprehensive test suite with all 90 tests
	run_all_tests_comprehensive()
