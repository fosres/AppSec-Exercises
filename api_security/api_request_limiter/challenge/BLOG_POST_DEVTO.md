# Challenge: Can You Build a Production-Ready Rate Limiter?

**Time to complete:** 30-60 minutes  
**Difficulty:** Intermediate  
**Skills tested:** Application Security, Algorithm Design, Edge Case Handling

## The Challenge

You're tasked with [implementing a rate limiter](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/api_request_limiter/challenge/rate_limiter_30_tests.py) - the same defense mechanism that protects Twitter, GitHub, and Stripe from API abuse. Sounds simple? Let's see if your implementation can pass **30 comprehensive tests** covering edge cases, boundary conditions, and security vulnerabilities.

[→ Skip to the challenge](#the-exercise)

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

That's rate limiting in action. Here's what's actually happening behind the scenes:

#### **Twitter/X API**
- **Limit:** 900 requests per 15 minutes (standard users)
- **Verified accounts:** 10,000 tweets/day
- **Why:** Prevent spam, monetize premium tiers, maintain stability
- **Impact if broken:** Platform instability, bot takeover, service degradation

#### **GitHub API**
- **Unauthenticated:** 60 requests/hour
- **Authenticated:** 5,000 requests/hour
- **Enterprise:** 15,000 requests/hour
- **Why:** Prevent abuse, ensure API availability for legitimate developers
- **Impact if broken:** API unavailability, resource exhaustion attacks

#### **Stripe Payment API**
- **Default:** 25 requests/second per endpoint
- **Payment Intents:** 1,000 updates per hour
- **Why:** Protect payment infrastructure, prevent race conditions, reserve capacity for critical transactions
- **Impact if broken:** Payment fraud, financial losses, compliance violations

---

## The Security Implications

Rate limiting isn't just about preventing overuse - it's a **critical security control**.

### 🔐 What Happens When Rate Limiting Fails?

**1. Brute Force Attacks**
```python
# Without rate limiting, attackers can try 1000s of passwords per second
for password in password_list:
    response = login(username, password)
    if response.status == 200:
        print(f"Password found: {password}")
```

**2. Credential Stuffing**
```python
# Attackers test millions of leaked username/password pairs
for username, password in leaked_credentials:
    if try_login(username, password):
        compromise_account(username)
```

**3. API Abuse & Resource Exhaustion**
```python
# Single attacker can consume all your API capacity
while True:
    for endpoint in expensive_endpoints:
        requests.get(endpoint)  # Costs you $$$ per call
```

**4. Distributed Denial of Service (DDoS)**
```python
# Coordinated attack from multiple IPs
# Without per-user rate limiting, service goes down
botnet.attack(target_api)
```

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

### Edge Case 2: The 60-Second Boundary Bug 🐛

**Security vulnerability:** Many implementations get this wrong!

```python
# VULNERABLE CODE (using >):
recent = [t for t in request_times if t > window_start]

# SECURE CODE (using >=):
recent = [t for t in request_times if t >= window_start]
```

**Why it matters:**  
Using `>` instead of `>=` allows attackers to bypass the rate limit at the exact 60-second boundary. Over 1 year, this allows:
- **GitHub API:** 8,760 extra unauthorized requests
- **Stripe API:** 86,400 extra unauthorized payment attempts per day

### Edge Case 3: Variable Rate Limits

Your code must work with **ANY** `max_requests` value:

```python
# Strict API (1 request/minute)
check_rate_limit([119.5], 120.0, 1) → (False, 59.5)

# Typical API (5 requests/minute)
check_rate_limit([100, 110, 120], 121.0, 5) → (True, 0.0)

# High-volume API (100 requests/minute)
check_rate_limit([100, 110, 120], 121.0, 100) → (True, 0.0)
```

**Never hardcode `max_requests=5` in your implementation!**

---

## The Testing Gauntlet

Your implementation will face **30 comprehensive tests**:

### ✅ Basic Functionality (Tests 1-5)
- Empty request history
- Single request
- Under limit scenarios
- At limit scenarios
- All requests old (>60 seconds)

### 🎯 Boundary Conditions (Tests 6-10)
- Exactly at 60-second boundary
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

---

## The Exercise

### What You'll Get

1. **LeetCode-style test file** ([`rate_limiter_30_tests.py`](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/api_request_limiter/challenge/rate_limiter_30_tests.py))
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
$ python3 rate_limiter_30_tests.py

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
═══════════════════════════════════════════════════════════════

Tests Passed: 30/30

╔══════════════════════════════════════════════════════════════╗
║            🎉 PERFECT! ALL 30 TESTS PASSED! 🎉              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Why This Exercise Builds Real AppSec Skills

### 1. **Security Boundary Conditions**
Rate limiting is all about boundaries. Get them wrong, and you have a security vulnerability.
- `>=` vs `>` (60-second boundary)
- Off-by-one errors
- Floating-point precision

### 2. **Defensive Programming**
- Handle empty lists
- Handle single elements
- Handle extreme values (max=1, max=100)
- Never assume inputs are "reasonable"

### 3. **Algorithm Correctness**
- Sliding window vs fixed window
- Time complexity: O(n) filtering
- Space complexity: O(1) calculation

### 4. **Real-World API Design**
- Return meaningful error codes
- Provide `retry_after` guidance to clients
- Make limits configurable (not hardcoded)

### 5. **Comprehensive Testing**
- Edge cases (empty, boundary, extreme)
- Fractional seconds precision
- Variable limits (1 to 100)
- Complex mixed scenarios

---

## Common Mistakes to Avoid

### ❌ Mistake #1: Hardcoding the Limit
```python
# BAD - Only works for max_requests=5
if len(recent_requests) < 5:
    return (True, 0.0)
```

```python
# GOOD - Works for any limit
if len(recent_requests) < max_requests:
    return (True, 0.0)
```

### ❌ Mistake #2: Wrong Boundary Check
```python
# VULNERABLE - Bypass at 60-second boundary
recent = [t for t in request_times if t > window_start]
```

```python
# SECURE - Correct boundary handling
recent = [t for t in request_times if t >= window_start]
```

### ❌ Mistake #3: Returning Wrong Type
```python
# WRONG - Returns only bool
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
retry_after = int((oldest + 60.0) - current_time)
return (False, retry_after)  # 38 instead of 38.5
```

```python
# MORE PRECISE - Keeps fractional seconds
retry_after = (oldest + 60.0) - current_time
return (False, retry_after)  # 38.5
```

---

## Take the Challenge

### Get the Exercise Files

#### Option 1:

Just visit (and Star!) my [GitHub repo](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/api_request_limiter/challenge/rate_limiter_30_tests.py)

#### Option 2:


```bash
# Clone or download the exercise files

git clone https://github.com/fosres/AppSec-Exercises.git

cd AppSec-Exercises/api_security/api_request_limiter/challenge/

# You will see the [Python challenge
# file](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/api_request_limiter/challenge/rate_limiter_30_tests.py):

# Edit `rate_limiter_30_tests.py`

# Run the tests

python3 rate_limiter_30_tests.py
```

**Files included:**
- `rate_limiter_30_tests.py` - Main test file (30 tests)
- `solution_example.py` - Minimal example (for after completion)
- `README.md` - Complete instructions

### Time Yourself

- ⏱️ **30 minutes:** Good pace, you know your stuff
- ⏱️ **60 minutes:** Normal, especially if you're learning
- ⏱️ **90+ minutes:** Take your time, debug carefully

### Share Your Results

When you pass all 30 tests:
```bash
# Share on Twitter/X
Just passed 30/30 tests on the Rate Limiter AppSec Challenge! 
🎯 30 comprehensive tests
🔒 Production-ready implementation
💪 Security-focused!

#AppSec #Python #100DaysOfCode
```

---

## What You'll Learn

By completing this challenge, you'll understand:

✅ **Why rate limiting is critical** for API security  
✅ **How to implement sliding window algorithms** correctly  
✅ **Security boundary conditions** that attackers exploit  
✅ **Comprehensive testing approaches** with edge cases  
✅ **Production-grade code** vs quick prototypes  

---

## For Hiring Managers

This exercise tests candidates on:
- ✅ Algorithm correctness
- ✅ Edge case handling
- ✅ Security awareness
- ✅ Code quality
- ✅ Testing thoroughness

**If a candidate passes all 30 tests,** they demonstrate:
- Understanding of real-world security controls
- Ability to handle boundary conditions
- Attention to detail in implementation
- Experience with comprehensive testing

---

## Level Up: After You Pass

### 1. **Optimize Your Solution**
Can you reduce your code from 70 lines to 10 lines?
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
- Multiple time windows (1 min, 1 hour, 1 day)
- Per-user tracking with Redis
- Distributed rate limiting across servers
- Token bucket algorithm

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
Share your experience:
- What edge cases surprised you?
- How did you debug failures?
- What did you learn about security?

---

## Resources

### Recommended Reading
- 📖 **"API Security in Action"** by Neil Madden (Chapter 3, pp. 67-69)
- 📖 **"Hacking APIs"** by Corey Ball (Chapter 13, pp. 276-280)
- 📖 **"Secure by Design"** by Johnsson, Deogun, and Sawano

### Real-World Examples
- [GitHub Rate Limiting](https://docs.github.com/en/rest/rate-limit)
- [Twitter API Rate Limits](https://developer.twitter.com/en/docs/rate-limits)
- [Stripe API Rate Limits](https://stripe.com/docs/rate-limits)

---

## Ready to Start?

Download the exercise and prove your AppSec skills:

👉 **[Get the Exercise Files](https://github.com/fosres/AppSec-Exercises/blob/main/api_security/api_request_limiter/challenge/rate_limiter_30_tests.py)**


Good luck! And remember - if your solution passes all 30 tests, you've built something production-ready. 🚀

---

## Discussion

- What was your biggest challenge in this exercise?
- Did you discover any edge cases we didn't test?
- How would you extend this to handle distributed systems?
- Share your solution approach in the comments!

---

*This exercise is part of a [series](https://github.com/fosres/AppSec-Exercises) on practical AppSec skills. Follow for more hands-on security challenges!*

*If you like this exercise please leave a star on my [GitHub Repo!](https://github.com/fosres/AppSec-Exercises/tree/main)*

#AppSec #Security #Python #RateLimiting #Challenge #100DaysOfCode
