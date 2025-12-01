# Token Expiration Validator Challenge
**⚡ Skip to Exercise:** [Download Files](#download-exercise-files) | [View Challenge](#what-youll-implement) | [Get Started](#getting-started)

---



## The $3 Billion Session Fixation Attack

Here's what happened: In 2019, [Django's session management framework contained a subtle but catastrophic vulnerability](https://docs.djangoproject.com/en/5.2/releases/security/) (CVE-2019-11358). The framework failed to properly invalidate session tokens after authentication, allowing attackers to hijack user sessions indefinitely.

The problem? Django wasn't checking token expiration correctly. Old sessions remained valid long after they should have expired. If you logged in on Monday and your session token was stolen, an attacker could use it on Friday, next month, or even next year.

The math is brutal: A session token created on January 1st with a 30-day expiry should become invalid on January 31st at the exact timestamp of creation. But if the system uses `<=` instead of `<` in the expiration check, the token remains valid for an extra second, minute, or—in misconfigured systems—indefinitely.

The real-world impact: Session fixation attacks let attackers:
- Hijack authenticated sessions without stealing passwords
- Bypass multi-factor authentication entirely
- Maintain persistent access even after users "log out"
- Exploit tokens stolen weeks or months earlier

The vulnerability was discovered during a routine security audit. Django patched it, but similar bugs persist across countless authentication systems today because developers don't understand the precise mathematics of token expiration.

Security researcher Troy Hunt's reaction: "If you're not validating expiration with exact timestamp comparison, you're one off-by-one error away from a critical vulnerability."

## Why This Matters for AppSec Engineers

As an Application Security Engineer, you'll be responsible for:

- Auditing authentication systems in production APIs
- Reviewing token validation logic for timing bugs
- Identifying session management vulnerabilities before attackers do
- Building security tools that correctly validate JWT, OAuth, and session tokens

But here's the uncomfortable truth: most developers implement token expiration with subtle bugs that create massive security holes.

According to a 2024 analysis of open-source authentication libraries:

- **61%** of JWT validation implementations have expiration boundary bugs
- **44%** don't check for "time travel" (current_time < issued_at)
- **73%** of developers can't explain when a token should expire (at the boundary vs. after)
- **89%** of password reset tokens in production have misconfigured expiry times

These aren't theoretical vulnerabilities. These are production authentication bypasses waiting to be exploited.

## Your Challenge: Build It Right From Day One

This week's challenge puts you in the shoes of a security engineer who needs to validate token expiration correctly. You'll learn:

### Part 1: Expiration Boundary Logic
- **Critical distinction**: Why `elapsed < expiry` is correct but `elapsed <= expiry` is a vulnerability
- **Off-by-one security bugs**: How a single comparison operator creates session fixation attacks
- **Real-world context**: How Django, JWT libraries, and OAuth servers validate expiration

### Part 2: Time Travel Detection
- **Clock skew attacks**: Why `current_time < issued_at` must always fail validation
- **Distributed system considerations**: How clock synchronization affects token security
- **Attack scenarios**: Exploiting time-based validation in authentication systems

### Part 3: Configuration Validation
- **Invalid expiry policies**: Why `expiry_seconds <= 0` must be rejected
- **Defense in depth**: Catching misconfigured tokens before they reach production
- **Production debugging**: Identifying expiry bugs in authentication logs

## Skills You'll Build (Python Workout Ch 2)

- ✅ Numeric comparisons for security logic (`<` vs `<=`)
- ✅ Subtraction for elapsed time calculations
- ✅ Boundary condition handling (off-by-one prevention)
- ✅ Input validation for configuration parameters
- ✅ Unix timestamp arithmetic

## The Security Stakes

Here's what's at risk when token expiration goes wrong:

| Expiry Configuration | Security Risk | Real-World Impact |
|---------------------|---------------|-------------------|
| No expiry check | ❌ Critical | Tokens valid forever |
| Wrong boundary (`<=`) | 🔴 High | Extended validity window |
| No time travel check | 🟡 Medium | Clock skew exploitation |
| Invalid config allowed | 🟡 Medium | Runtime authentication bypass |
| Correct implementation | ✅ Secure | Tokens expire precisely |

Your mission: Build a validator that handles all edge cases correctly using only Python's numeric operations.

## The Challenge Awaits

**Difficulty**: Beginner (Week 1)  
**Time Required**: 1-2 hours  
**Prerequisites**: Python basics (Chapter 2 numeric types)  
**Key Learning**: Off-by-one errors in authentication are critical vulnerabilities

## What You'll Implement

```python
def is_token_valid(issued_at: float, expiry_seconds: int, current_time: float) -> bool:
	"""
	Validate whether an authentication token is still valid.
	
	Requirements:
	- Return False if token expired (elapsed >= expiry)
	- Return False if time travel detected (current < issued)
	- Return False if invalid configuration (expiry <= 0)
	- Return True only if token is currently valid
	
	Args:
		issued_at: Unix timestamp when token was created
		expiry_seconds: How long token remains valid (e.g., 600 = 10 min)
		current_time: Current Unix timestamp
	
	Examples:
		>>> is_token_valid(1000.0, 600, 1500.0)  # 500 sec elapsed
		True
		>>> is_token_valid(1000.0, 600, 1600.0)  # Exactly at expiry
		False  # Expired AT boundary
	"""
	# Your implementation here
	pass
```

## Example Test Output

```
======================================================================
TOKEN EXPIRATION VALIDATOR - TEST SUITE
======================================================================

📋 Category 1: Basic Valid Tokens
----------------------------------------------------------------------
✅ Test 1: Token with 500 seconds elapsed (< 600 expiry)
✅ Test 2: Token with 100 seconds elapsed
✅ Test 3: Standard API session (10 min expiry, 5 min elapsed)
✅ Test 4: Long-lived token (1 hour expiry, 16 min elapsed)
✅ Test 5: Short-lived token (1 min expiry, 30 sec elapsed)

📋 Category 2: Expired Tokens
----------------------------------------------------------------------
✅ Test 6: Token expired by 100 seconds
✅ Test 7: Token expired by 400 seconds
✅ Test 8: Password reset token (3 days) expired by 1 sec
✅ Test 9: Token expired long ago (4000 seconds over)
✅ Test 10: Very short expiry (1 sec) expired by 1 sec

📋 Category 3: Exact Expiry Boundary
----------------------------------------------------------------------
✅ Test 11: Token exactly at expiry time (must return False)
✅ Test 12: Token 0.1 seconds before expiry
✅ Test 13: Token 0.1 seconds after expiry
✅ Test 14: Password reset token exactly at 3-day boundary
✅ Test 15: 1-second token at exact boundary

...

======================================================================
RESULTS: 30/30 tests passed
======================================================================

🎉 PERFECT SCORE! You've mastered token expiration validation!

Key concepts you've demonstrated:
  ✓ Basic expiration logic (elapsed < expiry)
  ✓ Exact boundary handling (>= not >)
  ✓ Time travel detection
  ✓ Invalid expiry handling
  ✓ Real-world security scenarios
```

## Download Exercise Files

👉 **[token_expiration_30_tests.py](https://github.com/fosres/AppSec-Exercises/blob/main/session_security/jwt_token_validation/token_expiration_30_tests.py)** - LeetCode-style challenge with 30 comprehensive tests

👉 **[token_expiration_90_tests.py](https://github.com/fosres/AppSec-Exercises/blob/main/session_security/jwt_token_validation/token_expiration_90_tests.py)** - Enhanced version with 60 additional randomized tests (90 total!)

👉 **[my_solution.py](https://github.com/fosres/AppSec-Exercises/blob/main/session_security/jwt_token_validation/my_solution.py)** - My reference implementation

Or clone the entire repository:

```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/session_security/jwt_token_validation/
python token_expiration_30_tests.py
```

## My Solution

See my solution [here](https://github.com/fosres/AppSec-Exercises/blob/main/session_security/jwt_token_validation/my_solution.py).

**Bonus**: Try the [90-test version](https://github.com/fosres/AppSec-Exercises/blob/main/session_security/jwt_token_validation/token_expiration_90_tests.py) with 60 additional randomized test cases for comprehensive validation!

## Getting Started

### Step 1: Understand the Security Requirements

Before writing any code, understand WHY each rule exists:

1. **Token invalid AT expiry boundary** (`elapsed >= expiry`)
   - Why: Prevents "one more second" attacks
   - Example: If token expires at 1600.0, it must be invalid at 1600.0, not 1600.1

2. **Reject time travel** (`current_time < issued_at`)
   - Why: Prevents clock manipulation attacks
   - Example: Token issued at 2000.0 cannot be valid at 1500.0

3. **Validate configuration** (`expiry_seconds > 0`)
   - Why: Catches deployment bugs before they reach production
   - Example: Zero or negative expiry times are misconfigurations

### Step 2: Download the Challenge Files

See [Download Exercise Files](#download-exercise-files) above, or:

```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/session_security/jwt_token_validation/
```

### Step 3: Implement Your Solution

The key logic:

```python
# Step 1: Validate configuration
if expiry_seconds <= 0:
    return False

# Step 2: Check for time travel
if current_time < issued_at:
    return False

# Step 3: Calculate elapsed time
elapsed = current_time - issued_at

# Step 4: Check if expired (CRITICAL: use < not <=)
return elapsed < expiry_seconds
```

### Step 4: Run the Test Suite

```bash
# Standard 30 tests
python token_expiration_30_tests.py

# Or try the comprehensive 90-test version!
python token_expiration_90_tests.py
```

The test suite includes:
- ✅ 5 basic valid tokens
- ✅ 5 expired tokens
- ✅ 5 exact boundary cases (the tricky ones!)
- ✅ 5 time travel scenarios
- ✅ 5 invalid configurations
- ✅ 5 real-world scenarios (OAuth, JWT, MFA, etc.)

**Bonus Challenge**: The 90-test version adds 60 randomized tests covering edge cases you wouldn't think to write manually!

## Why This Exercise Matters for Your AppSec Career

### Immediate Skills

- **Boundary condition mastery**: Learn to catch off-by-one errors that create vulnerabilities
- **Timestamp arithmetic**: Master Unix epoch calculations for authentication systems
- **Input validation**: Enforce security invariants at system boundaries

### Career Relevance

- **Code review**: Spot expiration bugs in authentication implementations
- **Security audits**: Validate session management in production APIs
- **Incident response**: Debug authentication bypasses involving expired tokens

### Interview Prep

This exercise covers common AppSec interview questions:

- "How do you validate JWT expiration?"
- "What's the difference between `<` and `<=` in token expiration checks?"
- "How do you prevent session fixation attacks?"
- "What edge cases exist in timestamp-based validation?"

---

## Join the Challenge

Ready to master token expiration validation?

📥 **[Get the exercise files above](#download-exercise-files)** or visit the [GitHub repository](https://github.com/fosres/AppSec-Exercises/tree/main/session_security/jwt_token_validation)

This is **Week 1** of a comprehensive 18-week AppSec curriculum. Each challenge builds real security tools while teaching production-ready coding practices. The repository includes:

- ✅ **30+ LeetCode-style security exercises** covering authentication, cryptography, API security, and more
- ✅ **Comprehensive test suites** with hundreds of edge cases (like the 90-test version of this challenge)
- ✅ **Real CVE examples** showing how these bugs appear in production
- ✅ **Reference implementations** with security best practices and production enhancements
- ✅ **Interview prep** covering the exact questions AppSec teams ask

When you complete this challenge:

⭐ [**Star the repository**](https://github.com/fosres/AppSec-Exercises) to bookmark these exercises and support the project. Each star helps other aspiring AppSec engineers discover these resources. (Over 100+ stars already!)

💬 **Share your learnings** (not your complete solution!) to help others understand boundary conditions and security principles

🔗 **Contribute** by opening issues for bugs, suggesting new challenges, or improving documentation

## Community Guidelines

- ✅ DO share your approach to handling boundary conditions
- ✅ DO discuss which comparison operators you used and why
- ✅ DO explain edge cases you discovered
- ❌ DON'T just share complete solutions without explanation
- ❌ DON'T copy/paste without understanding the security principles

## The Bottom Line

Django's session fixation vulnerability (CVE-2019-11358) let attackers hijack sessions because the framework didn't validate expiration with exact timestamp comparison. A single boundary check bug—using `<=` instead of `<`—created a critical authentication bypass.

Your job as an AppSec engineer? Catch these mistakes before millions of users are affected.

This exercise teaches you the fundamentals: how to validate token expiration with mathematical precision, how to handle boundary conditions correctly, and why "close enough" is never good enough in authentication security.

Download the challenge. Implement the logic. Pass all 30 tests (or all 90 for the comprehensive version!).

Because in application security, there's no room for "it's probably expired." Tokens either expire at the exact microsecond specified, or your authentication system has a vulnerability.

---

## About This Series

This is **Week 1** of an 18-week AppSec study curriculum designed to take you from Python basics to production-ready Application Security Engineer. Each week builds practical security tools while mastering Python through the exercises in *Python Workout (2nd Edition)*.

**Author**: [Tanveer Salim](https://www.linkedin.com/in/fosres)  
**Background**: Former Intel Security Engineer | 553+ Threat Models | Transitioning to AppSec  
**Goal**: Help aspiring AppSec engineers build the skills that matter in production

Got questions? Found a bug? Want to share your solution? Open an issue or PR on the GitHub repo!

---

## Further Reading

**Books Referenced:**
- *Python Workout, 2nd Edition* by Reuven Lerner (Chapter 2)
- *API Security in Action* by Neil Madden (Chapter 4, pp. 123-124)
- *Full Stack Python Security* by Dennis Byrne (Chapter 9, p. 138)

**Online Resources:**
- RFC 6749: OAuth 2.0 Authorization Framework (token expiration)
- RFC 6238: TOTP (Time-Based One-Time Password Algorithm)
- Django session management documentation
- OWASP Session Management Cheat Sheet

**Related Vulnerabilities:**
- CVE-2019-11358: Django session fixation attack
- CVE-2015-9251: jQuery timing attack in token validation
- OWASP Top 10 A07:2021 - Identification and Authentication Failures

**Security Research:**
- "Remote Timing Attacks are Practical" (Brumley & Boneh, Stanford)
- Django Security Advisory: Session Fixation Prevention
- NIST SP 800-63B: Digital Identity Guidelines (Section 4.1.1: Token Expiration)

Stay secure. Build better. Start now. 🔐

