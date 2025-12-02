# API Request Rate Limiter Exercise

## 📋 How to Use This Exercise (LeetCode Style)

### Step 1: Download the Exercise File
Get `rate_limiter_exercise.py` - this contains:
- ✅ Function signature with type hints
- ✅ Comprehensive docstring
- ✅ 12 test cases embedded in the file
- ✅ Clear pass/fail output with colors

### Step 2: Implement Your Solution
Open `rate_limiter_exercise.py` and find this section:

```python
def check_rate_limit(request_times: List[float], 
                     current_time: float, 
                     max_requests: int) -> Tuple[bool, float]:
    """..."""
    
    # TODO: Implement your solution here
    pass  # Remove this and write your code
```

Replace the `pass` statement with your implementation!

**Note:** 
- The function returns `Tuple[bool, float]` - retry_after is a float!
- `max_requests` is REQUIRED (no default) - you must specify it for each call

### Step 3: Run and Test
```bash
python3 rate_limiter_exercise.py
```

You'll see output like:
```
================================================================================
API REQUEST RATE LIMITER - TEST RESULTS
================================================================================

❌ FAIL - Test 1: Under limit (3/5 requests)
   ERROR: Must return a tuple (bool, int), got NoneType
   
✅ PASS - Test 2: At limit (5/5 requests within window)
   Input: times=[100.0, 110.0, 120.0]..., current=122.0, max=5
   Result: (False, 38)

...

================================================================================
SUMMARY
================================================================================
Tests passed: 1/12
Tests failed: 11/12
```

### Step 4: Fix Until All Tests Pass
Keep iterating until you see:
```
🎉 PERFECT! All 12 tests passed! 🎉
```

---

## 📁 Files Provided

1. **rate_limiter_exercise.py** ⭐ Main exercise file (use this!)
   - Boilerplate function to implement
   - 12 comprehensive test cases
   - Colored output showing pass/fail
   - Hints for common mistakes

2. **solution_example.py** 👀 Reference solution (don't peek!)
   - Shows correct implementation
   - Only look after you've tried yourself!

3. **exercise_2x_rate_limiter_IMPROVED.md** 📖 Full problem description
   - Detailed requirements
   - Examples with explanations
   - Security considerations
   - Background information

4. **rate_limiter_test_and_review.py** 🔍 Deep analysis
   - Comprehensive test suite
   - Detailed error explanations
   - Security perspective

---

## 🎯 Quick Start (TL;DR)

```bash
# 1. Edit the function in rate_limiter_exercise.py
# 2. Run it
python3 rate_limiter_exercise.py

# 3. See which tests pass/fail
# 4. Fix and repeat until 12/12 tests pass!
```

---

## 💡 Hints

If you're stuck, remember:
1. **Filter old requests**: `recent = [t for t in request_times if t >= window_start]`
2. **Check limit**: `if len(recent) < max_requests: return (True, 0.0)`
3. **Calculate retry**: `retry_after = (recent[0] + 60.0) - current_time`

Note: Return values are floats, not ints!

## 🔧 About max_requests (CRITICAL CONCEPT)

**`max_requests` is NOT a constant** - it's a **configurable parameter** that varies dramatically across different APIs:

### Real-World API Rate Limits:
```
┌─────────────────┬──────────────────┬────────────────────────┐
│ API Provider    │ Rate Limit       │ max_requests Value     │
├─────────────────┼──────────────────┼────────────────────────┤
│ GitHub          │ 5,000/hour       │ 5000 (3600s window)    │
│ Twitter         │ 15/15min         │ 15 (900s window)       │
│ Stripe          │ 25/second        │ 25 (1s window)         │
│ Reddit          │ 60/minute        │ 60 (60s window)        │
│ Discord         │ 5/5 seconds      │ 5 (5s window)          │
│ Internal API    │ 2/minute         │ 2 (60s window)         │
│ High-volume API │ 10,000/hour      │ 10000 (3600s window)   │
└─────────────────┴──────────────────┴────────────────────────┘
```

### Why This Matters:
- ✅ Your implementation must work with ANY `max_requests` value
- ✅ Never hardcode `5` or any specific number in your logic
- ✅ Always use the `max_requests` parameter in comparisons
- ✅ Tests use values: 1, 2, 3, 5, 10, 100 to verify flexibility

### ❌ Common Mistake:
```python
# BAD - Hardcoded value!
if len(recent_requests) < 5:  
    return (True, 0.0)
```

### ✅ Correct Approach:
```python
# GOOD - Uses parameter!
if len(recent_requests) < max_requests:  
    return (True, 0.0)
```

The exercise has **15 test cases** using different `max_requests` values to ensure your code is flexible!

---

## 🔒 Security Note

**Critical:** Use `>=` when filtering (not `>`), otherwise attackers can bypass the rate limit at the exact 60-second boundary!

```python
# ✅ SECURE
recent = [t for t in request_times if t >= window_start]

# ❌ VULNERABLE - attackers can exploit the boundary
recent = [t for t in request_times if t > window_start]
```

---

## 📚 What You'll Learn

By completing this exercise, you'll understand:
- Sliding window algorithms
- Rate limiting (used by GitHub, Twitter, Stripe APIs)
- Security boundary conditions
- Python type hints and tuple returns
- List comprehensions for filtering

This prepares you for:
- Week 3 Project: API Rate Limiter Checker
- AppSec engineering interviews
- Building production APIs

---

## ✅ Success Criteria

Your implementation is complete when:
- ✅ All 12 tests pass
- ✅ Returns `Tuple[bool, float]` (not just `bool`!)
- ✅ Uses `>=` for boundary checks
- ✅ Handles empty lists
- ✅ Calculates correct retry_after (as float)

---

## 🎓 After Completing

Once you pass all tests:
1. Add to your GitHub portfolio
2. Write a blog post explaining your approach
3. Move to next exercise or Week 3 project
4. Practice explaining the algorithm (interview prep!)

Good luck! 🚀
