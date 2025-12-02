"""
Exercise 2.X: API Request Rate Limiter
======================================

Inspired by: "API Security in Action" (Chapter 3, pp. 67-69) 
             "Hacking APIs" (Chapter 13, pp. 276-280)

OBJECTIVE:
----------
Implement a rate limiter that prevents API abuse using a sliding window algorithm.

⚠️  IMPORTANT: max_requests is CONFIGURABLE and varies by API!
   • GitHub API: 5,000 requests/hour
   • Twitter API: 15 requests/15 minutes  
   • Stripe API: 25 requests/second
   • Your function must work with ANY max_requests value (2, 5, 10, 100, 5000, etc.)


CRITICAL REQUIREMENTS:
----------------------
✅ Function signature:
   def check_rate_limit(request_times: List[float], 
                        current_time: float, 
                        max_requests: int) -> Tuple[bool, float]

✅ Return value: MUST be a tuple (bool, float)
   - Tuple[0] = bool:   True if request allowed, False if rate limited
   - Tuple[1] = float:  0.0 if allowed, else seconds to wait before retry

✅ Parameters:
   - request_times: List of timestamps for previous requests
   - current_time: Timestamp of the current request
   - max_requests: Maximum allowed requests per 60-second window (NO DEFAULT - must be specified!)

✅ Algorithm: Use 60-second sliding window
   - Only count requests within last 60 seconds from current_time
   - If request count < max_requests → ALLOW (return True, 0.0)
   - If request count >= max_requests → BLOCK (return False, retry_after)

✅ Calculate retry_after:
   retry_after = (oldest_request + 60.0) - current_time


INSTRUCTIONS:
-------------
1. Implement the check_rate_limit() function below
2. Run this file: python3 rate_limiter_exercise.py
3. See which tests pass/fail
4. Fix your implementation until all tests pass


SECURITY NOTE:
--------------
Use '>=' when filtering requests (not '>'), otherwise attackers can bypass
the rate limit at the 60-second boundary!
"""

from typing import List, Tuple


# ============================================================================
# YOUR IMPLEMENTATION GOES HERE
# ============================================================================

def check_rate_limit(request_times: List[float], 
                     current_time: float, 
                     max_requests: int) -> Tuple[bool, float]:
    """
    Check if an API request should be allowed based on rate limiting.
    
    Uses a 60-second sliding window to track requests. Returns whether
    the request is allowed and how long to wait before retrying.
    
    Args:
        request_times: List of timestamps (floats) for previous requests
        current_time: Timestamp (float) of the current request
        max_requests: Maximum requests allowed per 60-second window (REQUIRED)
    
    Returns:
        Tuple of (allowed: bool, retry_after: float)
        - allowed: True if request allowed, False if rate limited
        - retry_after: 0.0 if allowed, otherwise seconds until client can retry
    
    Examples:
        >>> # GitHub-style: 5 requests per minute
        >>> check_rate_limit([100.0, 110.0, 120.0], 121.0, max_requests=5)
        (True, 0.0)
        
        >>> # Rate limit exceeded
        >>> check_rate_limit([100.0, 110.0, 120.0, 121.0, 121.5], 122.0, 5)
        (False, 38.0)
        
        >>> # Strict API: only 2 requests per minute
        >>> check_rate_limit([100.0, 110.0], 120.0, 2)
        (False, 40.0)
        
        >>> # High-volume API: 100 requests per minute
        >>> check_rate_limit([100.0, 110.0, 120.0], 121.0, 100)
        (True, 0.0)
        
        >>> # Extremely strict: 1 request per minute
        >>> check_rate_limit([119.5], 120.0, 1)
        (False, 59.5)
    """
    
    # TODO: Implement your solution here
    # Hint: Start by filtering request_times to only include recent requests
    # Hint: Use list comprehension with >= for the window boundary
    
    pass  # Remove this and write your code


# ============================================================================
# TEST SUITE - DO NOT MODIFY
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def run_tests():
    """Run all test cases and display results."""
    
    test_cases = [
        # (test_name, request_times, current_time, max_requests, expected_result)
        (
            "Test 1: Under limit (3/5 requests)",
            [100.0, 110.0, 120.0],
            121.0,
            5,
            (True, 0),
            "Only 3 requests in window, limit is 5"
        ),
        (
            "Test 2: At limit (5/5 requests within window)",
            [100.0, 110.0, 120.0, 121.0, 121.5],
            122.0,
            5,
            (False, 38),
            "5 requests already made, must wait 38 seconds"
        ),
        (
            "Test 3: Old requests ignored",
            [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0],
            120.0,
            5,
            (False, 0),
            "Requests [1.0, 2.0, 3.0] are outside window, 5 requests at boundary"
        ),
        (
            "Test 4: Empty request history",
            [],
            122.0,
            5,
            (True, 0),
            "No previous requests, should allow"
        ),
        (
            "Test 5: Single request in history",
            [121.0],
            122.0,
            5,
            (True, 0),
            "Only 1 request in window"
        ),
        (
            "Test 6: All requests old (>60 seconds)",
            [1.0, 2.0, 3.0, 4.0, 5.0],
            122.0,
            5,
            (True, 0),
            "All requests are >60 seconds old, outside window"
        ),
        (
            "Test 7: Exactly at window boundary",
            [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            7.0,
            5,
            (False, 54),
            "6 requests within 6-second window, need to wait 54 seconds"
        ),
        (
            "Test 8: Mixed old and new requests",
            [1.0, 2.0, 3.0, 60.0, 61.0, 62.0, 63.0, 64.0],
            120.1,
            5,
            (True, 0),
            "Old requests filtered out, only 4 recent requests"
        ),
        (
            "Test 9: Requests at exact 60-second boundary",
            [60.0, 61.0, 62.0, 63.0, 64.0],
            120.0,
            5,
            (False, 0),
            "SECURITY TEST: Request at exactly 60.0 seconds should be counted"
        ),
        (
            "Test 10: Very recent burst (all within 1 second)",
            [121.0, 121.2, 121.4, 121.6, 121.8],
            122.0,
            5,
            (False, 59),
            "5 requests in last second, must wait 59 seconds"
        ),
        (
            "Test 11: Custom max_requests (limit of 2) - STRICT",
            [100.0, 110.0],
            120.0,
            2,
            (False, 40),
            "Strict limit: only 2 requests allowed"
        ),
        (
            "Test 12: Custom max_requests (limit of 10) - LENIENT",
            [100.0, 110.0, 120.0],
            121.0,
            10,
            (True, 0),
            "Lenient limit: 3/10 requests used"
        ),
        (
            "Test 13: Custom max_requests (limit of 1) - VERY STRICT",
            [119.5],
            120.0,
            1,
            (False, 59.5),
            "Extremely strict: only 1 request per minute allowed"
        ),
        (
            "Test 14: Custom max_requests (limit of 3)",
            [100.0, 110.0, 119.0],
            120.0,
            3,
            (False, 40),
            "Limit of 3: exactly at limit"
        ),
        (
            "Test 15: Custom max_requests (limit of 100) - HIGH VOLUME",
            [100.0, 110.0, 120.0],
            121.0,
            100,
            (True, 0),
            "High volume API: 3/100 requests used"
        ),
    ]
    
    print()
    print("=" * 80)
    print(f"{Colors.BOLD}API REQUEST RATE LIMITER - TEST RESULTS{Colors.END}")
    print("=" * 80)
    print()
    
    passed = 0
    failed = 0
    errors = 0
    
    for test_name, times, current, max_req, expected, explanation in test_cases:
        try:
            result = check_rate_limit(times.copy(), current, max_req)
            
            # Check if result is a tuple
            if not isinstance(result, tuple):
                print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
                print(f"   {Colors.RED}ERROR: Must return a tuple (bool, float), got {type(result).__name__}{Colors.END}")
                print(f"   Explanation: {explanation}")
                print()
                failed += 1
                continue
            
            # Check if tuple has exactly 2 elements
            if len(result) != 2:
                print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
                print(f"   {Colors.RED}ERROR: Tuple must have 2 elements, got {len(result)}{Colors.END}")
                print(f"   Explanation: {explanation}")
                print()
                failed += 1
                continue
            
            # Check types
            if not isinstance(result[0], bool):
                print(f"{Colors.YELLOW}⚠️  WARN{Colors.END} - {test_name}")
                print(f"   {Colors.YELLOW}First element should be bool, got {type(result[0]).__name__}{Colors.END}")
            
            if not isinstance(result[1], (int, float)):
                print(f"{Colors.YELLOW}⚠️  WARN{Colors.END} - {test_name}")
                print(f"   {Colors.YELLOW}Second element should be float (or int), got {type(result[1]).__name__}{Colors.END}")
            
            # Compare results (allow both int and float, compare numerically)
            # For retry_after, allow small floating point differences
            bool_matches = result[0] == expected[0]
            retry_matches = abs(float(result[1]) - float(expected[1])) < 0.01
            
            if bool_matches and retry_matches:
                print(f"{Colors.GREEN}✅ PASS{Colors.END} - {test_name}")
                print(f"   Input: times={times[:3]}{'...' if len(times) > 3 else ''}, "
                      f"current={current}, max={max_req}")
                print(f"   Result: {result}")
                passed += 1
            else:
                print(f"{Colors.RED}❌ FAIL{Colors.END} - {test_name}")
                print(f"   Input: times={times[:3]}{'...' if len(times) > 3 else ''}, "
                      f"current={current}, max={max_req}")
                print(f"   Expected: {expected}")
                print(f"   Got:      {result}")
                print(f"   Explanation: {explanation}")
                
                if not bool_matches:
                    print(f"   {Colors.RED}→ Wrong allowed/blocked decision{Colors.END}")
                if not retry_matches:
                    diff = float(result[1]) - float(expected[1])
                    print(f"   {Colors.RED}→ Wrong retry_after: off by {diff:.2f} seconds{Colors.END}")
                
                failed += 1
            
            print()
            
        except NotImplementedError:
            print(f"{Colors.RED}❌ ERROR{Colors.END} - {test_name}")
            print(f"   {Colors.RED}Function not implemented (returns None or raises error){Colors.END}")
            print()
            errors += 1
        except Exception as e:
            print(f"{Colors.RED}❌ ERROR{Colors.END} - {test_name}")
            print(f"   {Colors.RED}Exception raised: {type(e).__name__}: {e}{Colors.END}")
            print()
            errors += 1
    
    # Summary
    total = len(test_cases)
    print("=" * 80)
    print(f"{Colors.BOLD}SUMMARY{Colors.END}")
    print("=" * 80)
    
    if passed == total:
        print(f"{Colors.GREEN}{Colors.BOLD}🎉 PERFECT! All {total} tests passed! 🎉{Colors.END}")
        print()
        print("Your solution is correct and ready for production!")
        print()
        print("Next steps:")
        print("  ✅ Add this to your GitHub portfolio")
        print("  ✅ Write a blog post explaining the algorithm")
        print("  ✅ Move on to Week 3: API Rate Limiter Checker project")
    elif passed > 0:
        print(f"{Colors.YELLOW}Tests passed: {passed}/{total}{Colors.END}")
        print(f"{Colors.RED}Tests failed: {failed}/{total}{Colors.END}")
        if errors > 0:
            print(f"{Colors.RED}Errors: {errors}/{total}{Colors.END}")
        print()
        print("Keep going! You're making progress!")
        print()
        print("Common issues:")
        print("  • Forgot to return a tuple? Use: return (True, 0.0)")
        print("  • Wrong boundary check? Use: t >= window_start (not >)")
        print("  • Wrong retry_after? Calculate: (oldest + 60.0) - current_time")
    else:
        print(f"{Colors.RED}Tests passed: {passed}/{total}{Colors.END}")
        print(f"{Colors.RED}Tests failed: {failed}/{total}{Colors.END}")
        if errors > 0:
            print(f"{Colors.RED}Errors: {errors}/{total}{Colors.END}")
        print()
        print("Hints to get started:")
        print("  1. Filter request_times to only include recent requests:")
        print("     window_start = current_time - 60.0")
        print("     recent = [t for t in request_times if t >= window_start]")
        print()
        print("  2. Check if under limit (use max_requests parameter!):")
        print("     if len(recent) < max_requests:  # NOT hardcoded to 5!")
        print("         return (True, 0.0)")
        print()
        print("  3. Calculate retry_after:")
        print("     retry_after = (recent[0] + 60.0) - current_time")
        print("     return (False, retry_after)")
        print()
        print("  ⚠️  IMPORTANT: max_requests varies (1, 2, 5, 10, 100, etc.)")
        print("     Your code must work with ANY value!")
    
    print("=" * 80)
    print()


# ============================================================================
# MAIN - Run tests when file is executed
# ============================================================================

if __name__ == "__main__":
    run_tests()
