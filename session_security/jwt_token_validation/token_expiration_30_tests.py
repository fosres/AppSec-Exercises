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
	pass

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


if __name__ == "__main__":
	run_all_tests()
