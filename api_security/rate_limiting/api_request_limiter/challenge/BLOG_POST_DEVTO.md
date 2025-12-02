---
series: AppSec Series
---

**You've written rate limiters before. But have you written one secure enough to protect millions of Zoom meetings?**

⭐ **[Star this repo](https://github.com/fosres/AppSec-Exercises/) to commit to building production-grade security skills** ⭐

[Subscribe for weekly security exercises](https://buttondown.com/fosres)

**Time to complete:** 30-60 minutes  
**Difficulty:** Intermediate  
**Skills tested:** Application Security, Algorithm Design, Edge Case Handling

[→ Skip to the exercise](#the-exercise)

---

## The $100M Mistake That Could Have Been Prevented

April 2, 2020. Peak pandemic. 300 million daily Zoom users. Therapy sessions. Legal consultations. Corporate strategy meetings. All behind 6-digit password protection.

Security researcher Tom Anthony spent one afternoon with basic Python code and [cracked into any password-protected Zoom meeting in under 3 minutes](https://www.tomanthony.co.uk/blog/zoom-security-exploit-crack-private-meeting-passwords/). The vulnerability? **No rate limiting** on password attempts. Attackers could brute-force all 1 million possible combinations using a handful of cloud servers before anyone noticed.

[Zoom immediately took down their web client](https://www.bleepingcomputer.com/news/security/zoom-bug-allowed-attackers-to-crack-private-meeting-passwords/) on April 2nd. But the damage was done—millions of private conversations were potentially compromised during the most critical moment in Zoom's history.

**The fix?** A properly implemented rate limiter. The same security control you're about to build.

---

## Your Challenge: Don't Be The Next Zoom

[**→ Get the challenge files**](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/rate_limiting/api_request_limiter/challenge/api_request_limiter.py) | [Skip to exercise details](#the-exercise)

You'll implement a rate limiter that protects against:
- **Brute force attacks** (what hit Zoom)
- **Credential stuffing** (what hit Dropbox, LinkedIn, Adobe)
- **API abuse** (what costs companies millions)
- **DDoS attacks** (what takes down services)

**30 comprehensive tests** will verify your implementation handles every edge case attackers exploit. Pass them all, and you've built production-ready security infrastructure.

**Can't resist? Star the repo now so you remember to come back:** ⭐ [github.com/fosres/AppSec-Exercises](https://github.com/fosres/AppSec-Exercises/)

---

## Why This Matters in Real Life

### Every API You've Used Has Rate Limiting

Ever seen this error?

```json
HTTP 429: Too Many Requests
{
  "error": "Rate limit exceeded",
  "retry_after": 38
}
```

That's rate limiting protecting the service from you. Or protecting you from attackers. Here's what's happening behind the scenes at companies you use every day:

#### **Twitter/X API**
- **Limit:** 900 requests per 15 minutes (standard users)
- **Verified accounts:** 10,000 tweets/day
- **Why:** Prevent spam, monetize premium tiers, maintain stability
- **Impact if broken:** Platform instability, bot takeover, service degradation
- **Your cost:** $5,000/month for higher limits

#### **GitHub API**
- **Unauthenticated:** 60 requests/hour
- **Authenticated:** 5,000 requests/hour
- **Enterprise:** 15,000 requests/hour
- **Why:** Prevent abuse, ensure API availability for legitimate developers
- **Impact if broken:** API unavailability, resource exhaustion attacks
- **GitHub's cost:** Millions in infrastructure to handle abuse

#### **Stripe Payment API**
- **Default:** 25 requests/second per endpoint
- **Payment Intents:** 1,000 updates per hour
- **Why:** Protect payment infrastructure, prevent race conditions, reserve capacity for critical transactions
- **Impact if broken:** Payment fraud, financial losses, PCI compliance violations
- **Stripe's cost:** Billions in fraud prevented annually

**Rate limiting isn't optional.** It's the difference between a secure API and a security incident waiting to happen.

---

## The Security Implications

Rate limiting isn't just about preventing overuse - it's a **critical security control** that stands between attackers and your users' data.

### 🔐 What Happens When Rate Limiting Fails?

**1. Brute Force Attacks (The Zoom Attack)**
```python
# Without rate limiting, attackers can try 1000s of passwords per second
for password in password_list:
	response = login(username, password)
	if response.status == 200:
		print(f"Password found: {password}")
		steal_data()  # Meeting recordings, chat logs, etc.
```

**2. Credential Stuffing (The Dropbox Attack)**
```python
# Attackers test millions of leaked username/password pairs
# Dropbox: 68 million accounts compromised in 2012
for username, password in leaked_credentials:
	if try_login(username, password):
		compromise_account(username)
		steal_files()
```

**3. API Abuse & Resource Exhaustion (The AWS Bill You Can't Afford)**
```python
# Single attacker can consume all your API capacity
# Real cost: $10,000-$50,000 per day in cloud bills
while True:
	for endpoint in expensive_endpoints:
		requests.get(endpoint)  # Each call costs you $$$
```

**4. Distributed Denial of Service (The GitHub Attack)**
```python
# In 2018, GitHub suffered the largest DDoS attack in history
# 1.35 terabits per second. Without rate limiting, game over.
botnet.attack(target_api)
```

**Every one of these attacks is prevented by proper rate limiting.** Miss one edge case, and you're the next security headline.

---

## The Challenge: Sliding Window Rate Limiter

### The Problem

You need to implement this function:

```python
from typing import List, Tuple

def check_rate_limit(
	request_times: List[float],  # Timestamps of previous requests
	current_time: float,          # Current request timestamp
	max_requests: int             # Max requests per 60 seconds
) -> Tuple[bool, float]:          # (allowed?, retry_after_seconds)
	"""
	Implement a 60-second sliding window rate limiter.
	
	Returns:
		(True, 0.0)  if request allowed
		(False, N)   if rate limited, retry after N seconds
	"""
	# YOUR CODE HERE
	pass
```

### Real-World Example

```python
# Simulating Twitter's rate limiting
request_times = [100.0, 110.0, 120.0, 121.0, 121.5]  # Previous requests
current_time = 122.0                                    # New request arrives
max_requests = 5                                        # Limit: 5 per minute

result = check_rate_limit(request_times, current_time, max_requests)
# Expected: (False, 38.0)  ← Rate limited! Wait 38 seconds
```

**Think it's easy? Keep reading.**

---

## Why This Is Harder Than It Looks

### Edge Case 1: Old Requests Should Be Ignored

```python
# Requests outside the 60-second window shouldn't count
request_times = [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0]
current_time = 120.0

# Only [60.0, 61.0, 62.0, 63.0, 64.0] count
# [1.0, 2.0, 3.0] are >60 seconds old
```

**Get this wrong:** You either block legitimate users or allow attackers through.

### Edge Case 2: The 60-Second Boundary Bug 🐛

**This is the vulnerability most developers miss.**

```python
# VULNERABLE CODE (using >):
recent = [t for t in request_times if t > window_start]

# SECURE CODE (using >=):
recent = [t for t in request_times if t >= window_start]
```

**Why it matters:**  
Using `>` instead of `>=` allows attackers to bypass the rate limit at the exact 60-second boundary. Over 1 year, this allows:
- **GitHub API:** 8,760 extra unauthorized requests per user
- **Stripe API:** 86,400 extra unauthorized payment attempts per day
- **Your startup:** The breach that kills your Series A

**One character difference. One security vulnerability.**

### Edge Case 3: Variable Rate Limits

Your code must work with **ANY** `max_requests` value. **Never hardcode `max_requests=5`:**

```python
# Strict API (1 request/minute)
check_rate_limit([119.5], 120.0, 1) → (False, 59.5)

# Typical API (5 requests/minute)
check_rate_limit([100, 110, 120], 121.0, 5) → (True, 0.0)

# High-volume API (100 requests/minute)
check_rate_limit([100, 110, 120], 121.0, 100) → (True, 0.0)
```

**Hardcode the limit, fail the interview.**

---

## The Testing Gauntlet: 30 Comprehensive Tests

Your implementation will face **30 tests** designed to expose every common mistake:

### ✅ Basic Functionality (Tests 1-5)
- Empty request history
- Single request
- Under limit scenarios
- At limit scenarios
- All requests old (>60 seconds)

### 🎯 Boundary Conditions (Tests 6-10)
- Exactly at 60-second boundary (the vulnerability!)
- Just inside/outside window
- Mixed old and new requests
- Edge case timing

### ⏱️ Timing Scenarios (Tests 11-15)
- Very recent bursts
- Spread across full window
- Gradual spacing patterns
- One request at boundary

### 🔧 Variable Limits (Tests 16-20)
- Strict limits (max=1, 2, 3)
- Typical limits (max=5)
- Lenient limits (max=10)
- High volume (max=100)

### 🔬 Fractional Seconds (Tests 21-25)
- Fractional timestamps
- Fractional retry_after
- Microsecond precision
- Precise boundaries

### ⚡ Edge Cases (Tests 26-30)
- Complex mixed scenarios
- Same timestamp requests
- High volume at limit
- Boundary with old requests

**Pass all 30 tests → Your code is production-ready**

**Fail even one → You've left a vulnerability open**

**Ready to test your skills?** ⭐ **[Star the repo](https://github.com/fosres/AppSec-Exercises/) and get started** ⭐

---

## The Exercise

### What You'll Get

1. **LeetCode-style test file** ([`api_request_limiter.py`](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/rate_limiting/api_request_limiter/challenge/rate_limiter_30_tests.py))
   - Implement your solution in a designated section
   - Run the file to see results instantly
   - Beautiful colored output showing pass/fail
   - 30 comprehensive test cases

2. **Detailed failure reports**
   - See exactly what went wrong
   - Compare expected vs actual output
   - Debug with confidence

3. **Progressive difficulty**
   - Basic functionality tests first
   - Then boundary conditions
   - Then edge cases
   - Build confidence as you go

### Sample Output

```bash
$ python3 api_request_limiter.py

╔══════════════════════════════════════════════════════════════╗
║              RATE LIMITER CHALLENGE                          ║
║                  30 TEST CASES                               ║
╚══════════════════════════════════════════════════════════════╝

✅ PASS - Test 1: Under limit (3/5 requests)
✅ PASS - Test 2: At limit (5/5 requests within window)
✅ PASS - Test 3: Empty request history
...
✅ PASS - Test 28: Single recent request at boundary
✅ PASS - Test 29: All requests at same timestamp
✅ PASS - Test 30: High volume at limit

═══════════════════════════════════════════════════════════════
SUMMARY
Tests Passed: 30/30
Success Rate: 100%
═══════════════════════════════════════════════════════════════
```

---

## Why This Exercise Builds Real AppSec Skills

### 1. **Security Boundary Conditions**
Rate limiting is all about boundaries. Get them wrong, and you have a security vulnerability that attackers **will** find.
- `>=` vs `>` (60-second boundary)
- Off-by-one errors (classic vulnerability)
- Floating-point precision (subtle but critical)

### 2. **Defensive Programming**
Production code handles the unexpected:
- Empty lists (initialization state)
- Single elements (edge cases)
- Extreme values (max=1, max=100)
- Never assume inputs are "reasonable"

### 3. **Algorithm Correctness**
Understanding matters:
- Sliding window vs fixed window (different security properties)
- Time complexity: O(n) filtering (performance matters at scale)
- Space complexity: O(1) calculation (memory matters at scale)

### 4. **Real-World API Design**
Your users deserve clarity:
- Return meaningful error codes (429 status)
- Provide `retry_after` guidance to clients (UX + security)
- Make limits configurable, not hardcoded (flexibility)

### 5. **Comprehensive Testing**
Testing is security:
- Edge cases (where vulnerabilities hide)
- Fractional seconds precision (real-world timing)
- Variable limits (1 to 100)
- Complex mixed scenarios (production reality)

**This isn't a toy exercise. This is the code that protects production systems.**

---

## Common Mistakes to Avoid

### ❌ Mistake #1: Hardcoding the Limit
```python
# BAD - Only works for max_requests=5
# Fails 10+ tests immediately
if len(recent_requests) < 5:
	return (True, 0.0)
```

```python
# GOOD - Works for any limit
if len(recent_requests) < max_requests:
	return (True, 0.0)
```

### ❌ Mistake #2: Wrong Boundary Check (THE SECURITY VULNERABILITY)
```python
# VULNERABLE - Allows bypass at 60-second boundary
# This is what attackers exploit
recent = [t for t in request_times if t > window_start]
```

```python
# SECURE - Correct boundary handling
recent = [t for t in request_times if t >= window_start]
```

### ❌ Mistake #3: Returning Wrong Type
```python
# WRONG - Returns only bool
# Clients don't know when to retry
def check_rate_limit(...):
	return True  # Missing retry_after!
```

```python
# CORRECT - Returns tuple
def check_rate_limit(...) -> Tuple[bool, float]:
	return (True, 0.0)  # Both values
```

### ❌ Mistake #4: Integer vs Float
```python
# LESS PRECISE - Loses fractional seconds
# Fails tests 21-25
retry_after = int((oldest + 60.0) - current_time)
return (False, retry_after)  # 38 instead of 38.5
```

```python
# MORE PRECISE - Keeps fractional seconds
retry_after = (oldest + 60.0) - current_time
return (False, retry_after)  # 38.5
```

**Each mistake fails multiple tests. Don't make them.**

---

## Take the Challenge

### Get the Exercise Files

#### Option 1: Clone the repo (recommended)

```bash
# Star the repo first so you don't forget!
# Then clone it:

git clone https://github.com/fosres/AppSec-Exercises.git

cd AppSec-Exercises/api_security/rate_limiting/api_request_limiter/challenge/

# Implement your solution in api_request_limiter.py

# Run the tests

python3 api_request_limiter.py
```

### Time Yourself

- ⏱️ **30 minutes:** Excellent pace, you know your algorithms
- ⏱️ **60 minutes:** Normal, especially if debugging edge cases
- ⏱️ **90+ minutes:** Take your time, security is worth it

### Share Your Results

When you pass all 30 tests:
```bash
# Share on Twitter/X
Just passed 30/30 tests on the Rate Limiter AppSec Challenge! 
🎯 Production-ready rate limiter
🔒 All security edge cases handled
💪 No vulnerabilities!

Check it out: https://github.com/fosres/AppSec-Exercises

#AppSec #Security #Python #100DaysOfCode
```

**Completed the challenge? You've earned your stripes. Star the repo to remember where you learned this:** ⭐

---

## What You'll Learn

By completing this challenge, you'll understand:

✅ **Why rate limiting is critical** for API security (and what happens when it fails)  
✅ **How to implement sliding window algorithms** correctly (no off-by-one errors)  
✅ **Security boundary conditions** that attackers exploit (`>=` vs `>`)  
✅ **Comprehensive testing approaches** with edge cases (30 tests cover everything)  
✅ **Production-grade code** vs quick prototypes (your code will be production-ready)  

**This is how you build security skills that matter.**

---

## For Hiring Managers

This exercise tests candidates on:
- ✅ **Algorithm correctness** (can they implement a sliding window?)
- ✅ **Edge case handling** (do they think like attackers?)
- ✅ **Security awareness** (do they know the `>=` vs `>` vulnerability?)
- ✅ **Code quality** (is it production-ready or a prototype?)
- ✅ **Testing thoroughness** (do they understand comprehensive testing?)

**If a candidate passes all 30 tests,** they demonstrate:
- Understanding of real-world security controls
- Ability to handle boundary conditions correctly
- Attention to detail in implementation (security-critical)
- Experience with comprehensive testing methodologies

**Use this exercise in your interview process.** It separates candidates who can build secure systems from those who can't.

---

## Level Up: After You Pass

### 1. **Optimize Your Solution**
Can you reduce your code from 70 lines to 10 lines while keeping all tests passing?

```python
# Minimal solution using list comprehension
def check_rate_limit(request_times, current_time, max_requests):
	window_start = current_time - 60.0
	recent = [t for t in request_times if t >= window_start]
	if len(recent) < max_requests:
		return (True, 0.0)
	retry_after = (recent[0] + 60.0) - current_time
	return (False, max(0.0, retry_after))
```

### 2. **Add More Features**
Real production systems need:
- Multiple time windows (1 min, 1 hour, 1 day)
- Per-user tracking with Redis
- Distributed rate limiting across servers (harder than it looks)
- Token bucket algorithm (different properties)

### 3. **Build a Real API**
```python
from fastapi import FastAPI, HTTPException
from typing import Dict
import time

app = FastAPI()
user_requests: Dict[str, List[float]] = {}

@app.get("/api/resource")
async def protected_endpoint(user_id: str):
	current_time = time.time()
	requests = user_requests.get(user_id, [])
	
	allowed, retry_after = check_rate_limit(requests, current_time, 10)
	
	if not allowed:
		raise HTTPException(
			status_code=429,
			headers={"Retry-After": str(int(retry_after))},
			detail="Rate limit exceeded"
		)
	
	# Record this request
	user_requests[user_id] = requests + [current_time]
	return {"message": "Success!"}
```

### 4. **Write About It**
Share your experience on your blog:
- What edge cases surprised you?
- How did you debug test failures?
- What did you learn about security?
- How would you handle distributed systems?

**Completed everything? You're ready for production AppSec work.**

---

## Resources

### Recommended Reading
- 📖 **"API Security in Action"** by Neil Madden (Chapter 3, pp. 67-69) - Rate limiting implementation details
- 📖 **"Hacking APIs"** by Corey Ball (Chapter 13, pp. 276-280) - How attackers bypass rate limiters
- 📖 **"Secure by Design"** by Johnsson, Deogun, and Sawano - Security architecture principles

### Real-World Examples
- [GitHub Rate Limiting Documentation](https://docs.github.com/en/rest/rate-limit) - How GitHub implements it
- [Twitter API Rate Limits](https://developer.twitter.com/en/docs/rate-limits) - Real-world limits
- [Stripe API Rate Limits](https://stripe.com/docs/rate-limits) - Payment processing rate limits

---

## Ready to Start?

**Three simple steps:**

1. ⭐ **[Star the repo](https://github.com/fosres/AppSec-Exercises/)** (takes 2 seconds, helps you remember)
2. 🔒 **Pass all 30 tests** (prove your skills)

**When you pass all 30 tests, you've built something production-ready.** Not a toy. Not a demo. Real security infrastructure that protects real systems.

**Your move.** 🚀

---

## Discussion

- What was your biggest challenge in this exercise?
- Did you catch the `>=` vs `>` boundary bug before the tests caught you?
- How would you extend this to handle distributed systems?
- Share your solution approach in the comments!

---

## Solutions & Examples

**Want to see how others solved it?**

- 🔍 **[My personal solution](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/rate_limiting/api_request_limiter/challenge/my_personal_solution.py)** - How I approach security problems
- 🤖 **[Claude Code's solution](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/rate_limiting/api_request_limiter/challenge/solution_example.py)** - AI-generated minimal solution

**But don't peek until you've passed all 30 tests yourself.** You'll learn more from struggling.

---

*This exercise is part of a [growing series](https://github.com/fosres/AppSec-Exercises) on practical AppSec skills. Star the repo for more hands-on security challenges!*

**Final reminder:** ⭐ **[Star this repo now](https://github.com/fosres/AppSec-Exercises/)** - you'll thank yourself later when you need it for interview prep.

#AppSec #Security #Python #RateLimiting #Challenge #100DaysOfCode
