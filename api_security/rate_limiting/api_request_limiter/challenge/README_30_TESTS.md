# API Rate Limiter Challenge - 30 Comprehensive Tests

## 🎯 The Challenge

Implement a production-ready rate limiter that passes 30 comprehensive tests covering:
- ✅ Basic functionality
- ✅ Boundary conditions
- ✅ Timing scenarios
- ✅ Variable limits (1-100)
- ✅ Fractional seconds
- ✅ Edge cases

**No reference implementation provided** - figure it out yourself!

---

## 🚀 Quick Start

### 1. Open the file
```bash
code rate_limiter_30_tests.py
```

### 2. Find the implementation section
```python
def check_rate_limit(request_times: List[float], 
                     current_time: float, 
                     max_requests: int) -> Tuple[bool, float]:
    """YOUR SOLUTION GOES HERE"""
    pass  # Replace this with your code
```

### 3. Implement your solution

### 4. Run the tests
```bash
python3 rate_limiter_30_tests.py
```

### 5. See instant feedback
```
✅ PASS - Test 1: Under limit (3/5 requests)
✅ PASS - Test 2: At limit (5/5 requests within window)
...
Tests Passed: 30/30

🎉 PERFECT! ALL 30 TESTS PASSED! 🎉
```

---

## 📋 The 30 Tests

### Basic Functionality (1-5)
- Under limit scenarios
- At limit scenarios
- Empty lists
- Single requests
- Old requests

### Boundary Conditions (6-10)
- Exact 60-second boundary
- Just inside/outside window
- Mixed old and new

### Timing Scenarios (11-15)
- Recent bursts
- Spread across window
- Gradual spacing

### Variable max_requests (16-20)
- Strict: 1, 2, 3
- Typical: 5
- Lenient: 10, 100

### Fractional Seconds (21-25)
- Fractional timestamps
- Fractional retry_after
- Microsecond precision

### Edge Cases (26-30)
- Complex mixed scenarios
- Same timestamp
- High volume

---

## 🔑 Function Signature

```python
def check_rate_limit(
    request_times: List[float],  # Timestamps of previous requests
    current_time: float,          # Current request timestamp
    max_requests: int             # Max requests per 60 seconds
) -> Tuple[bool, float]:          # (allowed?, retry_after_seconds)
```

**Returns:**
- `(True, 0.0)` if request allowed
- `(False, N)` if rate limited, retry after N seconds

---

## 💡 Critical Requirements

1. **Return type:** MUST be `Tuple[bool, float]`
2. **Window:** Only count requests within last 60 seconds
3. **Boundary:** Use `>=` not `>` for 60-second check (security!)
4. **Configurable:** Never hardcode `max_requests`
5. **Retry calculation:** `(oldest + 60.0) - current_time`

---

## ⚠️ Common Mistakes

### ❌ Wrong Boundary Check
```python
recent = [t for t in request_times if t > window_start]  # VULNERABLE!
```

### ✅ Correct Boundary Check
```python
recent = [t for t in request_times if t >= window_start]  # SECURE!
```

### ❌ Hardcoded Limit
```python
if len(recent) < 5:  # BAD - only works for max=5
```

### ✅ Configurable Limit
```python
if len(recent) < max_requests:  # GOOD - works for any max
```

---

## 🎯 Example Usage

```python
# Scenario: Twitter-like API (5 requests per minute)
request_times = [100.0, 110.0, 120.0]
current_time = 121.0
max_requests = 5

result = check_rate_limit(request_times, current_time, max_requests)
# Returns: (True, 0.0) - Only 3 requests, under limit

# Scenario: Rate limited
request_times = [100.0, 110.0, 120.0, 121.0, 121.5]
current_time = 122.0
max_requests = 5

result = check_rate_limit(request_times, current_time, max_requests)
# Returns: (False, 38.0) - 5 requests in window, wait 38 seconds
```

---

## 🏆 Success Criteria

**Pass all 30 tests!**

When you see this:
```
╔══════════════════════════════════════════════════════════════╗
║            🎉 PERFECT! ALL 30 TESTS PASSED! 🎉              ║
╚══════════════════════════════════════════════════════════════╝
```

You've built a production-ready rate limiter! 💪

---

## 📚 Inspired By

- **"API Security in Action"** by Neil Madden (Chapter 3, pp. 67-69)
- **"Hacking APIs"** by Corey Ball (Chapter 13, pp. 276-280)

Real-world rate limiting used by:
- **Twitter/X:** 900 requests per 15 minutes
- **GitHub:** 5,000 requests per hour (authenticated)
- **Stripe:** 25 requests per second

---

## 🚀 Next Steps

After passing all tests:

1. **Optimize:** Can you reduce your code to <10 lines?
2. **Share:** Post your completion time on social media
3. **Learn:** Study minimal solutions for comparison
4. **Extend:** Add Redis, distributed rate limiting
5. **Build:** Create a real FastAPI endpoint

---

## 💬 Discussion

- What edge cases surprised you?
- How did you approach the boundary condition?
- What was your completion time?

Share your experience! 🎉

---

## 📄 License

MIT License - Use for learning, portfolios, interviews, hiring

---

**Ready to start?** Open `rate_limiter_30_tests.py` and implement your solution!
