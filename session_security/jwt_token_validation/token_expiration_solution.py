"""
Token Expiration Validator - SOLUTION

This is the reference implementation for the token expiration validator challenge.

Security Principles:
1. Always validate expiry with >= (token invalid AT expiry time)
2. Check for time travel (current_time < issued_at)
3. Reject misconfigured tokens (expiry_seconds <= 0)
4. Use simple numeric comparisons (avoid complex datetime libraries)

References:
- API Security in Action Ch 4 (pp. 123-124): Production token validation
- Full Stack Python Security Ch 9 (p. 138): Password reset token expiry
- Python Workout Ch 2 (pp. 7-9): Numeric operations and comparisons
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
	
	Algorithm:
		1. Validate expiry_seconds is positive (> 0)
		2. Check for time travel (current_time >= issued_at)
		3. Calculate elapsed_time = current_time - issued_at
		4. Token is valid if elapsed_time < expiry_seconds
		   (Note: Use < not <=, token invalid AT expiry boundary)
	
	Examples:
		>>> is_token_valid(1000.0, 600, 1500.0)  # 500 sec elapsed < 600 expiry
		True
		>>> is_token_valid(1000.0, 600, 1700.0)  # 700 sec elapsed > 600 expiry
		False
		>>> is_token_valid(1000.0, 600, 1600.0)  # Exactly at expiry
		False
	
	Time Complexity: O(1)
	Space Complexity: O(1)
	"""
	# Step 1: Validate expiry configuration
	# A token with zero or negative expiry is misconfigured
	if expiry_seconds <= 0:
		return False
	
	# Step 2: Check for time travel
	# If current time is before issued time, something is wrong
	# (clock skew, malicious manipulation, etc.)
	if current_time < issued_at:
		return False
	
	# Step 3: Calculate elapsed time since token was issued
	elapsed_time = current_time - issued_at
	
	# Step 4: Check if token is still within validity window
	# CRITICAL: Use < not <= because token is invalid AT expiry time
	# Example: If issued_at=1000, expiry=600, then:
	#   - At time 1599.9: elapsed=599.9 < 600 → VALID
	#   - At time 1600.0: elapsed=600.0 >= 600 → INVALID (expired)
	#   - At time 1600.1: elapsed=600.1 >= 600 → INVALID (expired)
	return elapsed_time < expiry_seconds


# ============================================================================
# ALTERNATIVE IMPLEMENTATIONS
# ============================================================================

def is_token_valid_v2(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	Alternative implementation: Calculate expiry_time directly.
	
	This version is functionally equivalent but calculates the absolute
	expiry timestamp instead of elapsed time.
	"""
	# Validate configuration and check time travel
	if expiry_seconds <= 0 or current_time < issued_at:
		return False
	
	# Calculate absolute expiry timestamp
	expiry_time = issued_at + expiry_seconds
	
	# Token valid if current time is before expiry time
	return current_time < expiry_time


def is_token_valid_oneliner(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	Compact one-liner version (less readable but concise).
	
	NOT RECOMMENDED for production: Sacrifices readability for brevity.
	"""
	return expiry_seconds > 0 and current_time >= issued_at and (current_time - issued_at) < expiry_seconds


# ============================================================================
# COMMON MISTAKES TO AVOID
# ============================================================================

def is_token_valid_WRONG_1(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	❌ WRONG: Uses <= instead of <, allowing token at exact expiry time.
	
	Bug: Token at time 1600.0 with expiry 600 from 1000.0 would be considered valid.
	This violates the security requirement that tokens expire AT the boundary.
	"""
	if expiry_seconds <= 0 or current_time < issued_at:
		return False
	elapsed_time = current_time - issued_at
	return elapsed_time <= expiry_seconds  # ❌ Should be <


def is_token_valid_WRONG_2(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	❌ WRONG: Doesn't check for time travel.
	
	Bug: If current_time < issued_at, elapsed_time would be negative,
	which would incorrectly pass the validity check.
	"""
	if expiry_seconds <= 0:
		return False
	elapsed_time = current_time - issued_at
	return elapsed_time < expiry_seconds  # ❌ Missing time travel check


def is_token_valid_WRONG_3(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	❌ WRONG: Doesn't validate expiry_seconds.
	
	Bug: Negative or zero expiry_seconds would cause unexpected behavior.
	With expiry_seconds=0, all tokens would be invalid.
	With expiry_seconds<0, tokens would always be valid (negative < elapsed).
	"""
	if current_time < issued_at:
		return False
	elapsed_time = current_time - issued_at
	return elapsed_time < expiry_seconds  # ❌ Missing expiry validation


# ============================================================================
# PRODUCTION ENHANCEMENTS
# ============================================================================

def is_token_valid_with_grace_period(
	issued_at: float, 
	expiry_seconds: int, 
	current_time: float,
	grace_period_seconds: int = 0
) -> bool:
	"""
	Production enhancement: Add grace period for clock skew.
	
	In distributed systems, clocks may not be perfectly synchronized.
	A grace period allows tokens to remain valid slightly past their
	expiry time to account for clock drift.
	
	Args:
		grace_period_seconds: Additional seconds of validity after expiry
	
	Example:
		>>> # Token expires at 1600.0, with 5-second grace period
		>>> is_token_valid_with_grace_period(1000.0, 600, 1604.0, 5)
		True  # Within grace period
		>>> is_token_valid_with_grace_period(1000.0, 600, 1606.0, 5)
		False  # Past grace period
	"""
	if expiry_seconds <= 0 or current_time < issued_at:
		return False
	
	# Add grace period to effective expiry
	effective_expiry = expiry_seconds + grace_period_seconds
	elapsed_time = current_time - issued_at
	
	return elapsed_time < effective_expiry


def get_time_remaining(issued_at: float, expiry_seconds: int, current_time: float) -> float:
	"""
	Returns seconds remaining until expiry, or 0.0 if expired.
	
	Useful for displaying "Token expires in X seconds" to users.
	
	Returns:
		Seconds remaining (>= 0.0)
	
	Example:
		>>> get_time_remaining(1000.0, 600, 1500.0)
		100.0  # 100 seconds remaining
		>>> get_time_remaining(1000.0, 600, 1700.0)
		0.0  # Expired
	"""
	if not is_token_valid(issued_at, expiry_seconds, current_time):
		return 0.0
	
	elapsed_time = current_time - issued_at
	return expiry_seconds - elapsed_time


# ============================================================================
# REAL-WORLD USAGE EXAMPLES
# ============================================================================

def validate_oauth_access_token(token_issued_at: float, current_time: float) -> bool:
	"""
	OAuth 2.0 access tokens typically expire in 10 minutes.
	
	Reference: RFC 6749 Section 4.2.2
	"""
	OAUTH_ACCESS_TOKEN_EXPIRY = 600  # 10 minutes
	return is_token_valid(token_issued_at, OAUTH_ACCESS_TOKEN_EXPIRY, current_time)


def validate_password_reset_token(token_issued_at: float, current_time: float) -> bool:
	"""
	Password reset tokens typically expire in 3 days.
	
	Reference: Django's PASSWORD_RESET_TIMEOUT (default: 259200 seconds)
	Full Stack Python Security Ch 9 (p. 138)
	"""
	PASSWORD_RESET_EXPIRY = 259200  # 3 days
	return is_token_valid(token_issued_at, PASSWORD_RESET_EXPIRY, current_time)


def validate_jwt_session(token_issued_at: float, current_time: float) -> bool:
	"""
	JWT session tokens typically expire in 30 minutes.
	
	Reference: API Security in Action Ch 4 (pp. 123-124)
	"""
	JWT_SESSION_EXPIRY = 1800  # 30 minutes
	return is_token_valid(token_issued_at, JWT_SESSION_EXPIRY, current_time)


def validate_mfa_code(token_issued_at: float, current_time: float) -> bool:
	"""
	MFA codes typically expire in 30 seconds.
	
	Reference: TOTP (Time-based One-Time Password) RFC 6238
	"""
	MFA_CODE_EXPIRY = 30  # 30 seconds
	return is_token_valid(token_issued_at, MFA_CODE_EXPIRY, current_time)


# ============================================================================
# TEST THE SOLUTION
# ============================================================================

if __name__ == "__main__":
	import time
	
	print("=" * 70)
	print("TOKEN EXPIRATION VALIDATOR - SOLUTION DEMO")
	print("=" * 70)
	print()
	
	# Demo 1: Valid token
	print("Demo 1: Valid OAuth access token (5 minutes elapsed)")
	issued_at = 1000.0
	expiry = 600  # 10 minutes
	current = 1300.0  # 5 minutes later
	result = is_token_valid(issued_at, expiry, current)
	print(f"  issued_at: {issued_at}")
	print(f"  expiry_seconds: {expiry}")
	print(f"  current_time: {current}")
	print(f"  elapsed: {current - issued_at} seconds")
	print(f"  Result: {'✅ VALID' if result else '❌ INVALID'}")
	print()
	
	# Demo 2: Expired token
	print("Demo 2: Expired token (11 minutes elapsed)")
	current = 1660.0  # 11 minutes later
	result = is_token_valid(issued_at, expiry, current)
	print(f"  issued_at: {issued_at}")
	print(f"  expiry_seconds: {expiry}")
	print(f"  current_time: {current}")
	print(f"  elapsed: {current - issued_at} seconds")
	print(f"  Result: {'✅ VALID' if result else '❌ EXPIRED'}")
	print()
	
	# Demo 3: Exact boundary
	print("Demo 3: Token at exact expiry boundary")
	current = 1600.0  # Exactly 10 minutes later
	result = is_token_valid(issued_at, expiry, current)
	print(f"  issued_at: {issued_at}")
	print(f"  expiry_seconds: {expiry}")
	print(f"  current_time: {current}")
	print(f"  elapsed: {current - issued_at} seconds")
	print(f"  Result: {'✅ VALID' if result else '❌ EXPIRED (at boundary)'}")
	print()
	
	# Demo 4: Time remaining
	print("Demo 4: Time remaining calculation")
	current = 1500.0
	remaining = get_time_remaining(issued_at, expiry, current)
	print(f"  Token expires in: {remaining} seconds ({remaining/60:.1f} minutes)")
	print()
	
	print("Run the test suite with: python token_expiration_30_tests.py")
